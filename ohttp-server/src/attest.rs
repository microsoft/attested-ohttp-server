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
use reqwest::Client;
use serde::Deserialize;
use serde_json::from_str;

use ohttp::{
    Error, KeyConfig, SymmetricSuite,
    hpke::{Aead, Kdf, Kem},
};

use tokio::time::{Duration, sleep};

use serde_cbor::Value;

const KID_NOT_FOUND_RETRY_TIMER: u64 = 60;

const SOCKET_PATH: &str = "/var/run/azure-attestation-proxy/azure-attestation-proxy.sock";
use hyper::{Body, Method, Request, Response};
use hyper_unix_connector::{UnixClient, Uri};

#[derive(Deserialize)]
struct ExportedKey {
    kid: u8,
    key: String,
    receipt: String,
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
    if !response.status().is_success() {
        return Err(Box::new(ServerError::AzureAttestationProxyFailure(
            format!(
                "Azure Attestation proxy response status: {}",
                response.status()
            ),
        )));
    }

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

    Ok(str)
}

pub async fn fetch_maa_token(maa: &str, x_ms_request_id: &Uuid) -> Res<String> {
    // Get MAA token from CVM guest attestation library
    info!("Fetching MAA token from {maa}");

    let client: hyper::Client<UnixClient, Body> = hyper::Client::builder().build(UnixClient);
    let addr: hyper::Uri = Uri::new(SOCKET_PATH, "/attest").into();
    trace!("Azure Attestation proxy request URI for attest: {}", addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(addr)
        .header("x-ms-request-id", x_ms_request_id.to_string())
        .header("maa", maa)
        .body(Body::empty())
        .expect("request builder");

    let response = match client.request(req).await {
        Ok(response) => response,
        Err(e) => {
            return Err(Box::new(ServerError::AzureAttestationProxyFailure(
                format!("Failed to connect to Azure Attestation proxy : {e}"),
            )));
        }
    };

    let token = get_response(response).await?;
    trace!("Fetched MAA token: {token}");

    Ok(token)
}

pub async fn decrypt_key(enc_key: Vec<u8>, x_ms_request_id: &Uuid) -> Res<String> {
    let client: hyper::Client<UnixClient, Body> = hyper::Client::builder().build(UnixClient);
    let addr: hyper::Uri = Uri::new(SOCKET_PATH, "/decrypt").into();
    trace!("Azure Attestation proxy request URI for decrypt: {}", addr);

    let req = Request::builder()
        .method(Method::GET)
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

/// Retrieves the HPKE private key from Azure KMS.
///
pub async fn get_hpke_private_key_from_kms(
    kms: &str,
    kid: u8,
    token: &str,
    x_ms_request_id: &Uuid,
) -> Res<String> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
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
                    return Err(Box::new(ServerError::KMSUnreachable));
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
                    return Err(Box::new(Error::KeyIdMismatch(skr.kid, kid)));
                }

                return Ok(skr.key);
            }
            e => {
                return Err(Box::new(ServerError::KMSUnexpected(e)));
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
