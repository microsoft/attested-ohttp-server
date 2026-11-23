use crate::{
    cache::{CACHE, CachedKey},
    err::ServerError,
    utils::Res,
};
pub const PCR0_TO_15_BITMASK: u32 = 0xFFFF;

use base64::{Engine as _, engine::general_purpose::STANDARD as b64};

use tracing::{error, info, trace};
use uuid::Uuid;
use warp::hyper;

use hpke::Deserializable;
use reqwest::{Certificate, Client, ClientBuilder, Url, redirect};
use serde::Deserialize;
use serde_json::from_str;

use ohttp::{
    Error, KeyConfig, SymmetricSuite,
    hpke::{Aead, Kdf, Kem},
};

use tokio::time::{Duration, sleep};

use serde_cbor::Value;

const KID_NOT_FOUND_RETRY_TIMER: u64 = 60;
const ATTESTATION_PROXY_MAX_RETRIES: u8 = 3;
const ATTESTATION_PROXY_RETRY_DELAY_SECS: u64 = 2;

/// Host suffix of Azure confidential ledgers; the KMS runs on one.
const LEDGER_HOST_SUFFIX: &str = ".confidential-ledger.azure.com";
/// Azure service that publishes each ledger's TLS service certificate.
const LEDGER_IDENTITY_URL: &str =
    "https://identity.confidential-ledger.core.azure.com/ledgerIdentity";
const LEDGER_IDENTITY_API_VERSION: &str = "2022-05-13";
/// Upper bound for each ledger identity or key release request.
const KMS_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const SOCKET_PATH: &str = "/var/run/azure-attestation-proxy/azure-attestation-proxy.sock";
use hyper::{Body, Method, Request, Response};
use hyper_unix_connector::{UnixClient, Uri};

#[derive(Deserialize)]
struct ExportedKey {
    kid: u8,
    key: String,
    receipt: String,
}

/// Ledger identity returned by `LEDGER_IDENTITY_URL`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LedgerIdentity {
    ledger_id: String,
    ledger_tls_certificate: String,
}

pub async fn do_gpu_attestation(socket_path: &str, x_ms_request_id: &Uuid) -> Res<()> {
    // Path to the GPU attestation Unix socket
    info!("Attempting GPU attestation at: {}", socket_path);

    // Check if the socket file exists
    if !std::path::Path::new(socket_path).exists() {
        return Err(Box::new(ServerError::GPUAttestationFailure(format!(
            "GPU Attestation socket file not found at: {socket_path}"
        ))));
    }

    // Create a URI that includes the Unix socket path
    let uri: hyper::Uri = hyper_unix_connector::Uri::new(socket_path, "/gpu_attest").into();

    // Create the request with appropriate headers
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(uri)
        .header("x-request-id", x_ms_request_id.to_string())
        .body(hyper::Body::empty())?;

    // Create a client with the UnixClient connector
    let client: hyper::Client<hyper_unix_connector::UnixClient, hyper::Body> =
        hyper::Client::builder().build(hyper_unix_connector::UnixClient);

    // Send the request with error handling
    let resp = match client.request(req).await {
        Ok(response) => response,
        Err(e) => {
            return Err(Box::new(ServerError::GPUAttestationFailure(format!(
                "Failed to connect to GPU Attestation Service at {socket_path}: {e}"
            ))));
        }
    };

    // Check response status
    let status = resp.status();

    // Get the response body
    let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
    let body_b64 = base64::engine::general_purpose::STANDARD.encode(&body_bytes);

    if !status.is_success() {
        return Err(Box::new(ServerError::GPUAttestationFailure(format!(
            "status code = {status}, body = {body_b64}"
        ))));
    }

    info!("Local GPU attestation succeeded: {body_b64}");
    Ok(())
}

pub async fn get_response(response: Response<Body>) -> Res<String> {
    let status = response.status();
    info!("Received response from Azure Attestation proxy: {}", status);

    let bytes = match hyper::body::to_bytes(response.into_body()).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return Err(Box::new(ServerError::AzureAttestationProxyFailure(
                format!("Failed to read Azure Attestation proxy response body: {e}"),
            )));
        }
    };

    let str = match String::from_utf8(bytes.to_vec()) {
        Ok(str) => str,
        Err(e) => {
            return Err(Box::new(ServerError::AzureAttestationProxyFailure(
                format!("Failed to decode Azure Attestation proxy response body as UTF-8: {e}"),
            )));
        }
    };

    if !status.is_success() {
        return Err(Box::new(ServerError::AzureAttestationProxyFailure(
            format!(
                "Azure Attestation proxy response failed: {} {}",
                status, str
            ),
        )));
    }

    Ok(str)
}

pub async fn fetch_maa_token(maa: &str, x_ms_request_id: &Uuid) -> Res<String> {
    // Get MAA token from CVM guest attestation library
    info!("Fetching MAA token from {maa}");

    let client: hyper::Client<UnixClient, Body> = hyper::Client::builder().build(UnixClient);
    let addr: hyper::Uri = Uri::new(SOCKET_PATH, "/attest").into();
    trace!("Azure Attestation proxy request URI for attest: {}", addr);

    for attempt in 1..=ATTESTATION_PROXY_MAX_RETRIES {
        let req = Request::builder()
            .method(Method::GET)
            .uri(addr.clone())
            .header("x-ms-request-id", x_ms_request_id.to_string())
            .header("maa", maa)
            .body(Body::empty())
            .expect("request builder");

        match client.request(req).await {
            Ok(response) => {
                let token = get_response(response).await?;
                trace!("Fetched MAA token: {token}");
                return Ok(token);
            }
            Err(e) if attempt < ATTESTATION_PROXY_MAX_RETRIES => {
                error!(
                    "Azure Attestation proxy attest attempt {attempt}/{} failed: {e}",
                    ATTESTATION_PROXY_MAX_RETRIES
                );
                sleep(Duration::from_secs(ATTESTATION_PROXY_RETRY_DELAY_SECS)).await;
            }
            Err(e) => {
                return Err(Box::new(ServerError::AzureAttestationProxyFailure(
                    format!(
                        "Failed to connect to Azure Attestation proxy after {} attempts: {e}",
                        ATTESTATION_PROXY_MAX_RETRIES
                    ),
                )));
            }
        }
    }

    Err(Box::new(ServerError::AzureAttestationProxyFailure(
        "Azure Attestation proxy did not return a token".to_string(),
    )))
}

pub async fn decrypt_key(enc_key: Vec<u8>, x_ms_request_id: &Uuid) -> Res<String> {
    let client: hyper::Client<UnixClient, Body> = hyper::Client::builder().build(UnixClient);
    let addr: hyper::Uri = Uri::new(SOCKET_PATH, "/decrypt").into();
    trace!("Azure Attestation proxy request URI for decrypt: {}", addr);

    let req = Request::builder()
        .method(Method::POST)
        .uri(addr)
        .header("x-ms-request-id", x_ms_request_id.to_string())
        .body(enc_key.into())
        .expect("request builder");

    let response = match client.request(req).await {
        Ok(response) => response,
        Err(e) => {
            return Err(Box::new(ServerError::AzureAttestationProxyFailure(
                format!("Failed to connect to Azure Attestation proxy : {e}"),
            )));
        }
    };

    let dec_key = get_response(response).await?;

    Ok(dec_key)
}

/// HTTPS-only client builder that does not follow redirects and bounds request time.
fn kms_client_builder() -> ClientBuilder {
    Client::builder()
        .https_only(true)
        .redirect(redirect::Policy::none())
        .timeout(KMS_REQUEST_TIMEOUT)
}

/// Returns the ledger name of an `https://<ledger>.confidential-ledger.azure.com` KMS URL.
fn ledger_name(kms: &str) -> Res<String> {
    let url = Url::parse(kms)?;
    if url.scheme() != "https" {
        return Err(ServerError::KMSUntrustedEndpoint.into());
    }
    url.host_str()
        .and_then(|host| host.strip_suffix(LEDGER_HOST_SUFFIX))
        .filter(|ledger| !ledger.is_empty() && !ledger.contains('.'))
        .map(String::from)
        .ok_or_else(|| ServerError::KMSUntrustedEndpoint.into())
}

/// Retrieves the KMS ledger's TLS service certificate (PEM) from the Azure ledger identity service.
pub async fn get_kms_service_cert(kms: &str) -> Res<String> {
    let ledger = ledger_name(kms)?;
    let identity: LedgerIdentity = kms_client_builder()
        .build()?
        .get(format!(
            "{LEDGER_IDENTITY_URL}/{ledger}?api-version={LEDGER_IDENTITY_API_VERSION}"
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let service_cert = validate_ledger_identity(identity, &ledger)?;
    info!("Retrieved service certificate for ledger {ledger}");
    Ok(service_cert)
}

/// Returns the TLS service certificate in `identity` if it belongs to `ledger`.
fn validate_ledger_identity(identity: LedgerIdentity, ledger: &str) -> Res<String> {
    if identity.ledger_id != ledger {
        return Err(
            ServerError::KMSLedgerIdentityMismatch(identity.ledger_id, ledger.to_string()).into(),
        );
    }
    Ok(identity.ledger_tls_certificate)
}

/// Retrieves the HPKE private key from Azure KMS.
///
pub async fn get_hpke_private_key_from_kms(
    kms: &str,
    kid: u8,
    token: &str,
    x_ms_request_id: &Uuid,
) -> Res<String> {
    let service_cert = get_kms_service_cert(kms).await?;
    release_hpke_private_key(kms, &service_cert, kid, token, x_ms_request_id).await
}

/// Requests the HPKE private key from KMS, trusting only KMS nodes endorsed by `service_cert`.
async fn release_hpke_private_key(
    kms: &str,
    service_cert: &str,
    kid: u8,
    token: &str,
    x_ms_request_id: &Uuid,
) -> Res<String> {
    let client = kms_client_builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(Certificate::from_pem(service_cert.as_bytes())?)
        .build()?;

    // Retrying logic for receipt
    let max_retries = 3;
    let mut retries = 0;

    loop {
        let url = format!("{kms}?kid={kid}&encrypted=true");
        info!("Sending SKR request to {url}");

        // Get HPKE private key from Azure KMS
        let response = client
            .post(url)
            .header("Authorization", format!("Bearer {token}"))
            .header("requestid", x_ms_request_id.to_string())
            .send()
            .await?;

        // We may have to wait for receipt to be ready
        match response.status().as_u16() {
            202 => {
                if retries < max_retries {
                    retries += 1;
                    trace!(
                        "Received 202 status code, retrying... (attempt {}/{})",
                        retries, max_retries
                    );
                    sleep(Duration::from_secs(1)).await;
                } else {
                    return Err(Box::new(ServerError::KMSUnreachable) as Box<dyn std::error::Error>);
                }
            }
            200 => {
                let skr_body = response.text().await?;
                info!("SKR successful");

                let skr: ExportedKey = from_str(&skr_body)?;
                trace!(
                    "requested KID={}, returned KID={}, Receipt={}",
                    kid, skr.kid, skr.receipt
                );

                if skr.kid != kid {
                    return Err(
                        Box::new(Error::KeyIdMismatch(skr.kid, kid)) as Box<dyn std::error::Error>
                    );
                }

                return Ok(skr.key);
            }
            e => {
                return Err(Box::new(ServerError::KMSUnexpected(e)) as Box<dyn std::error::Error>);
            }
        }
    }
}

async fn load_config(kms: &str, kid: u8, token: &str, x_ms_request_id: &Uuid) -> Res<KeyConfig> {
    // The KMS returns the base64-encoded, RSA2048-OAEP-SHA256 encrypted CBOR key
    let key = get_hpke_private_key_from_kms(kms, kid, token, x_ms_request_id).await?;
    let enc_key = b64.decode(&key)?;
    let decrypted_key = match decrypt_key(enc_key, x_ms_request_id).await {
        Ok(k) => k,
        _ => Err(Box::new(ServerError::TPMDecryptionFailure))?,
    };

    let decoded = b64.decode(&decrypted_key)?;
    let (d, returned_kid) = parse_cbor_key(&decoded, kid)?;
    let sk = match d {
        Some(key) => <hpke::kem::DhP384HkdfSha384 as hpke::Kem>::PrivateKey::from_bytes(&key),
        None => Err(Box::new(ServerError::PrivateKeyMissing))?,
    }?;
    let pk = <hpke::kem::DhP384HkdfSha384 as hpke::Kem>::sk_to_pk(&sk);
    let config = KeyConfig::import_p384(
        returned_kid,
        Kem::P384Sha384,
        sk,
        pk,
        vec![
            SymmetricSuite::new(Kdf::HkdfSha384, Aead::Aes256Gcm),
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm),
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
        ],
    )?;
    Ok(config)
}

fn parse_cbor_key(key: &[u8], kid: u8) -> Res<(Option<Vec<u8>>, u8)> {
    let cwk_map: Value = serde_cbor::from_slice(key)?;
    let mut d = None;
    let mut returned_kid: u8 = 0;
    if let Value::Map(map) = cwk_map {
        for (key, value) in map {
            if let Value::Integer(key) = key {
                match key {
                    // key identifier
                    4 => {
                        if let Value::Integer(k) = value {
                            returned_kid = u8::try_from(k).unwrap();
                            if returned_kid != kid {
                                return Err(Box::new(Error::KeyIdMismatch(returned_kid, kid)));
                            }
                        } else {
                            return Err(Box::new(ServerError::KMSKeyId));
                        }
                    }

                    // private exponent
                    -4 => {
                        if let Value::Bytes(vec) = value {
                            d = Some(vec);
                        } else {
                            return Err(Box::new(ServerError::KMSExponent));
                        }
                    }

                    // key type, must be P-384(2)
                    -1 => {
                        if value == Value::Integer(2) {
                        } else {
                            return Err(Box::new(ServerError::KMSCBORKeyType));
                        }
                    }

                    // Ignore public key (x,y) as we recompute it from d anyway
                    -2 | -3 => (),

                    _ => {
                        return Err(Box::new(ServerError::KMSField));
                    }
                }
            }
        }
    } else {
        return Err(Box::new(ServerError::KMSCBOREncoding));
    }
    Ok((d, returned_kid))
}

pub async fn load_config_token(
    maa: &str,
    kms: &str,
    gpu_attestation: &str,
    kid: u8,
    x_ms_request_id: &Uuid,
) -> Res<(KeyConfig, String)> {
    // Check if the key configuration is in cache
    if let Some(entry) = CACHE.get(&kid).await {
        match entry {
            CachedKey::ValidKey(config, token) => {
                info!("Found OHTTP configuration for KID {kid} in cache.");
                return Ok((*config, token));
            }
            CachedKey::SKRError(ts) => {
                if ts.elapsed()? > Duration::from_secs(KID_NOT_FOUND_RETRY_TIMER) {
                    CACHE.invalidate(&kid).await;
                } else {
                    Err(Box::new(ServerError::CachedSKRError))?;
                }
            }
        }
    }

    // Run local GPU attestation
    do_gpu_attestation(gpu_attestation, x_ms_request_id).await?;

    let token = fetch_maa_token(maa, x_ms_request_id).await?;

    let config = load_config(kms, kid, token.as_str(), x_ms_request_id).await?;

    CACHE
        .insert(
            kid,
            CachedKey::ValidKey(Box::new(config.clone()), token.clone()),
        )
        .await;

    Ok((config, token))
}

// Serialize Box<dyn StdError> as it lacks `Send` trait
pub async fn load_config_token_safe(
    maa: &str,
    kms: &str,
    gpu_attestation: &str,
    kid: u8,
    x_ms_request_id: &Uuid,
) -> Result<(KeyConfig, String), String> {
    match load_config_token(maa, kms, gpu_attestation, kid, x_ms_request_id).await {
        Ok(r) => Ok(r),
        Err(e) => {
            let err = format!("Error loading OHTTP key configuration {kid}: {e:?}");
            error!("{err}");
            Err(err)
        }
    }
}

#[cfg(test)]
mod kms_tls_tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use warp::{Filter, http::StatusCode};

    const TEST_KID: u8 = 7;
    const TEST_KEY: &str = "wrapped-key";

    /// Self-signed CA standing in for a ledger's TLS service certificate.
    struct ServiceIdentity {
        cert: rcgen::Certificate,
        key: KeyPair,
    }

    impl ServiceIdentity {
        fn new() -> Self {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::default();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let cert = params.self_signed(&key).unwrap();
            Self { cert, key }
        }
    }

    /// Starts a local KMS whose node certificate for `hostname` is endorsed by `identity`.
    /// Returns the KMS URL and a counter of key release requests it received.
    fn start_kms(
        identity: &ServiceIdentity,
        hostname: &str,
        status: StatusCode,
    ) -> (String, Arc<AtomicUsize>) {
        let node_key = KeyPair::generate().unwrap();
        let node_cert = CertificateParams::new(vec![hostname.to_string()])
            .unwrap()
            .signed_by(&node_key, &identity.cert, &identity.key)
            .unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = requests.clone();
        let route = warp::post().and(warp::path!("app" / "key")).map(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            let body = serde_json::json!({"kid": TEST_KID, "key": TEST_KEY, "receipt": ""});
            let reply = warp::reply::with_status(warp::reply::json(&body), status);
            warp::reply::with_header(reply, "location", "/app/key")
        });
        let (addr, server) = warp::serve(route)
            .tls()
            .cert(node_cert.pem())
            .key(node_key.serialize_pem())
            .bind_ephemeral(([127, 0, 0, 1], 0));
        tokio::spawn(server);
        (
            format!("https://localhost:{}/app/key", addr.port()),
            requests,
        )
    }

    async fn release(url: &str, trusted: &ServiceIdentity) -> Res<String> {
        release_hpke_private_key(url, &trusted.cert.pem(), TEST_KID, "token", &Uuid::nil()).await
    }

    #[tokio::test]
    async fn skr_accepts_node_endorsed_by_ledger_identity() {
        let identity = ServiceIdentity::new();
        let (url, requests) = start_kms(&identity, "localhost", StatusCode::OK);
        assert_eq!(release(&url, &identity).await.unwrap(), TEST_KEY);
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn skr_rejects_untrusted_node_before_sending_token() {
        let (url, requests) = start_kms(&ServiceIdentity::new(), "localhost", StatusCode::OK);
        assert!(release(&url, &ServiceIdentity::new()).await.is_err());
        assert_eq!(requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn skr_rejects_hostname_mismatch_before_sending_token() {
        let identity = ServiceIdentity::new();
        let (url, requests) = start_kms(&identity, "other.example", StatusCode::OK);
        assert!(release(&url, &identity).await.is_err());
        assert_eq!(requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn skr_does_not_follow_redirects() {
        let identity = ServiceIdentity::new();
        let (url, requests) = start_kms(&identity, "localhost", StatusCode::TEMPORARY_REDIRECT);
        let err = release(&url, &identity).await.unwrap_err();
        assert!(matches!(
            err.downcast_ref::<ServerError>(),
            Some(ServerError::KMSUnexpected(307))
        ));
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    fn ledger_identity(ledger_id: &str) -> LedgerIdentity {
        LedgerIdentity {
            ledger_id: ledger_id.to_string(),
            ledger_tls_certificate: "service-cert".to_string(),
        }
    }

    #[test]
    fn ledger_identity_returns_cert_for_matching_ledger() {
        assert_eq!(
            validate_ledger_identity(ledger_identity("example"), "example").unwrap(),
            "service-cert"
        );
    }

    #[test]
    fn ledger_identity_rejects_other_ledger() {
        let err = validate_ledger_identity(ledger_identity("other"), "example").unwrap_err();
        assert!(matches!(
            err.downcast_ref::<ServerError>(),
            Some(ServerError::KMSLedgerIdentityMismatch(returned, expected))
                if returned == "other" && expected == "example"
        ));
    }

    #[test]
    fn ledger_name_requires_https_azure_confidential_ledger_host() {
        assert_eq!(
            ledger_name("https://example.confidential-ledger.azure.com/app/key").unwrap(),
            "example"
        );
        for url in [
            "http://example.confidential-ledger.azure.com/app/key",
            "https://localhost/app/key",
            "https://example.confidential-ledger.azure.com.evil.example/app/key",
            "https://nested.example.confidential-ledger.azure.com/app/key",
            "https://confidential-ledger.azure.com/app/key",
        ] {
            assert!(
                matches!(
                    ledger_name(url).unwrap_err().downcast_ref::<ServerError>(),
                    Some(ServerError::KMSUntrustedEndpoint)
                ),
                "{url}"
            );
        }
    }
}
