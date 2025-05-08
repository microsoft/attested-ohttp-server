// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![deny(clippy::pedantic)]

pub mod err;

use std::{io::Cursor, net::SocketAddr, sync::Arc};

use moka::future::Cache;
use std::sync::LazyLock;

use futures_util::stream::unfold;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Method, Response, Url,
};

use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use bhttp::{Message, Mode};
use clap::Parser;

use ohttp::{
    hpke::{Aead, Kdf, Kem},
    Error, KeyConfig, Server as OhttpServer, ServerResponse, SymmetricSuite,
};
use warp::{hyper, hyper::Body};

use tokio::time::{sleep, Duration};

use cgpuvm_attest::AttestationClient;
use reqwest::Client;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

use serde_cbor::Value;
use serde_json::from_str;

use hpke::Deserializable;
use serde::Deserialize;

use err::ServerError;
use tracing::{error, info, instrument, trace};
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter, FmtSubscriber};
use uuid::Uuid;

const VERSION: &str = "1.0.0";

#[derive(Deserialize)]
struct ExportedKey {
    kid: u8,
    key: String,
    receipt: String,
}

const KID_NOT_FOUND_RETRY_TIMER: u64 = 60;
const DEFAULT_KMS_URL: &str = "https://accconfinferenceprod.confidential-ledger.azure.com/app/key";
const DEFAULT_MAA_URL: &str = "https://confinfermaaeus2test.eus2.test.attest.azure.net";
const DEFAULT_GPU_ATTESTATION_SOCKET: &str = "/var/run/gpu-attestation/gpu-attestation.sock";
const FILTERED_RESPONSE_HEADERS: [&str; 2] = ["content-type", "content-length"];
const PCR0_TO_15_BITMASK: u32 = 0xFFFF;

// We cache both successful key releases from the KMS as well as SKR errors,
// as guest attestation is very expensive (IMDS + TPM createPrimary + RSA decrypt x2)
// ValidKey expire based on the TTL of the cache (24 hours)
// SKRError are manually invalidated (see import_config), after 60 seconds
#[derive(Clone)]
enum CachedKey {
    SKRError(std::time::SystemTime),
    ValidKey(Box<KeyConfig>, String),
}

static CACHE: LazyLock<Arc<Cache<u8, CachedKey>>> = LazyLock::new(|| {
    Arc::new(
        Cache::builder()
            .time_to_live(Duration::from_secs(24 * 60 * 60))
            .build(),
    )
});

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

/// Retrieves the HPKE private key from Azure KMS.
///
async fn get_hpke_private_key_from_kms(
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
                        retries,
                        max_retries
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
                    kid,
                    skr.kid,
                    skr.receipt
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

fn fetch_maa_token(attestation_client: &mut AttestationClient, maa: &str) -> Res<String> {
    // Get MAA token from CVM guest attestation library
    info!("Fetching MAA token from {maa}");

    let t = attestation_client.attest("{}".as_bytes(), PCR0_TO_15_BITMASK, maa)?;

    let token = String::from_utf8(t).unwrap();
    trace!("Fetched MAA token: {token}");
    Ok(token)
}

async fn load_config(
    attestation_client: &mut AttestationClient,
    kms: &str,
    kid: u8,
    token: &str,
    x_ms_request_id: &Uuid,
) -> Res<KeyConfig> {
    // The KMS returns the base64-encoded, RSA2048-OAEP-SHA256 encrypted CBOR key
    let key = get_hpke_private_key_from_kms(kms, kid, token, x_ms_request_id).await?;
    let enc_key: &[u8] = &b64.decode(&key)?;
    let decrypted_key = match attestation_client.decrypt(enc_key, PCR0_TO_15_BITMASK) {
        Ok(k) => k,
        _ => Err(Box::new(ServerError::TPMDecryptionFailure))?,
    };

    let (d, returned_kid) = parse_cbor_key(&decrypted_key, kid)?;
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

async fn load_config_token(
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

    let mut attestation_client = match AttestationClient::new() {
        Ok(cli) => cli,
        _ => Err(Box::new(ServerError::AttestationLibraryInit))?,
    };

    let token = fetch_maa_token(&mut attestation_client, maa)?;

    let config = load_config(
        &mut attestation_client,
        kms,
        kid,
        token.as_str(),
        x_ms_request_id,
    )
    .await?;

    CACHE
        .insert(
            kid,
            CachedKey::ValidKey(Box::new(config.clone()), token.clone()),
        )
        .await;

    Ok((config, token))
}

// Serialize Box<dyn StdError> as it lacks `Send` trait
async fn load_config_token_safe(
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

/// Copies headers from the encapsulated request and logs them.
///
fn get_headers_from_request(bin_request: &Message) -> HeaderMap {
    info!("Inner request headers");
    let mut headers = HeaderMap::new();
    for field in bin_request.header().fields() {
        info!(
            "    {}: {}",
            std::str::from_utf8(field.name()).unwrap(),
            std::str::from_utf8(field.value()).unwrap()
        );

        headers.append(
            HeaderName::from_bytes(field.name()).unwrap(),
            HeaderValue::from_bytes(field.value()).unwrap(),
        );
    }
    headers
}

fn decapsulate_request(ohttp: &OhttpServer, enc_request: &[u8]) -> Res<(Message, ServerResponse)> {
    let (request, server_response) = ohttp.decapsulate(enc_request)?;
    let bin_request = Message::read_bhttp(&mut Cursor::new(&request[..]))?;
    Ok((bin_request, server_response))
}

async fn post_request_to_target(
    inject_headers: HeaderMap,
    bin_request: &Message,
    target: Url,
    target_path: Option<&HeaderValue>,
    _mode: Mode,
    x_ms_request_id: &Uuid,
) -> Res<Response> {
    let method: Method = if let Some(method_bytes) = bin_request.control().method() {
        Method::from_bytes(method_bytes)?
    } else {
        Method::GET
    };

    // Copy headers from the encapsulated request
    let mut headers = get_headers_from_request(&bin_request);

    // Inject additional headers from the outer request
    if !inject_headers.is_empty() {
        info!("Appending injected headers");
        for (key, value) in inject_headers {
            if let Some(key) = key {
                info!("    {}: {}", key.as_str(), value.to_str().unwrap());
                headers.append(key, value);
            }
        }
    }

    let mut t = target;

    // Set resource path to either the one provided in the outer request header
    // If none provided, use the path set by the client
    if let Some(path_bytes) = target_path {
        if let Ok(path_str) = std::str::from_utf8(path_bytes.as_bytes()) {
            t.set_path(path_str);
        }
    } else if let Some(path_bytes) = bin_request.control().path() {
        if let Ok(path_str) = std::str::from_utf8(path_bytes) {
            t.set_path(path_str);
        }
    }

    let client = reqwest::ClientBuilder::new().build()?;
    let response = client
        .request(method, t)
        .headers(headers)
        .header("x-request-id", x_ms_request_id.to_string())
        .body(bin_request.content().to_vec())
        .send()
        .await?;

    if !response.status().is_success() {
        let error_msg = format!("{}", response.text().await.unwrap_or_default());
        error!(error_msg);
        return Err(Box::new(ServerError::TargetRequestError(error_msg)));
    }

    Ok(response)
}

// Compute the set of headers that need to be injected into the inner request
fn compute_injected_headers(headers: &HeaderMap, keys: Vec<String>) -> HeaderMap {
    let mut result = HeaderMap::new();
    for key in keys {
        if let Ok(header_name) = HeaderName::try_from(key) {
            if let Some(value) = headers.get(&header_name) {
                result.insert(header_name, value.clone());
            }
        }
    }
    result
}

pub async fn cache_local_config() -> Res<()> {
    let config = KeyConfig::new(
        0,
        Kem::P384Sha384,
        vec![
            SymmetricSuite::new(Kdf::HkdfSha384, Aead::Aes256Gcm),
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm),
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
        ],
    )
    .map_err(|e| {
        error!("{e}");
        e
    })?;

    CACHE
        .insert(
            0,
            CachedKey::ValidKey(
                Box::new(config),
                "<LOCALLY GENERATED KEY, NO ATTESTATION TOKEN>".to_owned(),
            ),
        )
        .await;
    Ok(())
}

pub fn init() {
    // Build a simple subscriber that outputs to stdout
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_span_events(FmtSpan::NEW)
        .json()
        .finish();

    // Set the subscriber as global default
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    ::ohttp::init();
}

async fn do_gpu_attestation(socket_path: &str, x_ms_request_id: &Uuid) -> Res<()> {
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
