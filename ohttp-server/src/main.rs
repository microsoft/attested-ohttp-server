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
use clap::{error, Parser};

use ohttp::{
    hpke::{Aead, Kdf, Kem},
    Error, KeyConfig, Server as OhttpServer, ServerResponse, SymmetricSuite,
};
use warp::{hyper, hyper::Body, Filter};

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

const VERSION: &str = "0.0.74.2";

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

#[derive(Debug, Parser, Clone)]
#[command(name = "ohttp-server", about = "Serve oblivious HTTP requests.")]
struct Args {
    /// The address to bind to.
    #[arg(default_value = "127.0.0.1:9443")]
    address: SocketAddr,

    /// When creating message/bhttp, use the indeterminate-length form.
    #[arg(long, short = 'n', alias = "indefinite")]
    indeterminate: bool,

    /// Target server
    #[arg(long, short = 't', default_value = "http://127.0.0.1:8000")]
    target: Url,

    /// Use locally generated key, for testing without KMS
    #[arg(long, short = 'l')]
    local_key: bool,

    /// MAA endpoint
    #[arg(long, short = 'm')]
    maa_url: Option<String>,

    /// KMS endpoint
    #[arg(long, short = 's')]
    kms_url: Option<String>,

    /// GPU Attestation socket path
    #[arg(long, short = 'g', default_value = DEFAULT_GPU_ATTESTATION_SOCKET)]
    gpu_attestation_socket: Option<String>,

    #[arg(long, short = 'i')]
    inject_request_headers: Vec<String>,
}

impl Args {
    fn mode(&self) -> Mode {
        if self.indeterminate {
            Mode::IndeterminateLength
        } else {
            Mode::KnownLength
        }
    }
}

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
        let error_msg = format!("{}{}", response.status(), response.text().await.unwrap_or_default());
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

#[instrument(skip(headers, body, args), fields(version = %VERSION))]
async fn score(
    headers: warp::hyper::HeaderMap,
    body: warp::hyper::body::Bytes,
    args: Arc<Args>,
    x_ms_request_id: Uuid,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    let target = args.target.clone();
    info!("Received encapsulated score request for target {}", target);
    info!("Request headers length = {}", headers.len());
    let return_token = headers.contains_key("x-attestation-token");
    let mut builder = warp::http::Response::builder()
        .header("x-ms-client-request-id", x_ms_request_id.to_string());
    // The KID is normally the first byte of the request
    let kid = match body.first().copied() {
        None => {
            let error_msg = "No key found in request.";
            error!("{error_msg}");
            return Ok(builder.status(500).body(Body::from(error_msg.as_bytes())));
        }
        Some(kid) => kid,
    };

    let maa_url = args.maa_url.clone().unwrap_or(DEFAULT_MAA_URL.to_string());
    let kms_url = args.kms_url.clone().unwrap_or(DEFAULT_KMS_URL.to_string());
    let gpu_attestation_socket = args.gpu_attestation_socket.as_ref().unwrap();
    let (config, token) = match load_config_token_safe(
        &maa_url,
        &kms_url,
        &gpu_attestation_socket,
        kid,
        &x_ms_request_id,
    )
    .await
    {
        Ok((config, token)) => (config, token),
        Err(_e) => {
            CACHE
                .insert(kid, CachedKey::SKRError(std::time::SystemTime::now()))
                .await;
            let error_msg = "Failed to load the requested OHTTP key identifier.";
            return Ok(builder.status(500).body(Body::from(error_msg.as_bytes())));
        }
    };

    let ohttp = match OhttpServer::new(config) {
        Ok(server) => server,
        Err(e) => {
            let error_msg = "Failed to create OHTTP server from config.";
            error!("{error_msg} {e}");
            return Ok(builder.status(500).body(Body::from(error_msg.as_bytes())));
        }
    };

    let inject_request_headers = args.inject_request_headers.clone();
    info!(
        "Request inject headers length = {}",
        inject_request_headers.len()
    );
    for key in &inject_request_headers {
        info!("    {}", key);
    }
    let inject_headers = compute_injected_headers(&headers, inject_request_headers);
    info!("Injected headers length = {}", inject_headers.len());
    for (key, value) in &inject_headers {
        info!("    {}: {}", key, value.to_str().unwrap());
    }

    let (request, server_response) = match decapsulate_request(&ohttp, &body[..]) {
        Ok(s) => s,
        Err(e) => {
            error!("{:?}", e);
            if let Ok(oe) = e.downcast::<::ohttp::Error>() {
                return Ok(builder
                    .status(422)
                    .body(Body::from(format!("Error: {oe:?}"))));
            }
            let error_msg = "Request error.";
            error!("{error_msg}");
            return Ok(builder.status(400).body(Body::from(error_msg.as_bytes())));
        }
    };

    let target_path = headers.get("enginetarget");
    let mode = args.mode();
    let response = match post_request_to_target(
        inject_headers,
        &request,
        target,
        target_path,
        mode,
        &x_ms_request_id,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            error!("{}", b64.encode(e.to_string()));
            let chunk = e.to_string().into_bytes();
            let stream = futures::stream::once(async { Ok::<Vec<u8>, ohttp::Error>(chunk) });
            let stream = server_response.encapsulate_stream(stream);
            return Ok(builder.status(400).body(Body::wrap_stream(stream)));
        }
    };

    builder = builder.header("Content-Type", "message/ohttp-chunked-res");
    // Add HTTP header with MAA token, for client auditing.
    if return_token {
        builder = builder.header(
            HeaderName::from_static("x-attestation-token"),
            token.clone(),
        );
    }

    // Move headers from the inner response into the outer response
    info!("Response headers:");
    for (key, value) in response.headers() {
        if !FILTERED_RESPONSE_HEADERS
            .iter()
            .any(|h| h.eq_ignore_ascii_case(key.as_str()))
        {
            info!(
                "    {}: {}",
                key,
                std::str::from_utf8(value.as_bytes()).unwrap()
            );
            builder = builder.header(key.as_str(), value.as_bytes());
        }
    }

    let stream = Box::pin(unfold(response, |mut response| async move {
        match response.chunk().await {
            Ok(Some(chunk)) => Some((Ok::<Vec<u8>, ohttp::Error>(chunk.to_vec()), response)),
            _ => None,
        }
    }));
    let stream = server_response.encapsulate_stream(stream);
    Ok(builder.body(Body::wrap_stream(stream)))
}

async fn discover(args: Arc<Args>) -> Result<impl warp::Reply, std::convert::Infallible> {
    let kms_url = &args.kms_url.clone().unwrap_or(DEFAULT_KMS_URL.to_string());
    let maa_url = &args.maa_url.clone().unwrap_or(DEFAULT_MAA_URL.to_string());
    let gpu_attestation_socket = &args.gpu_attestation_socket.as_ref().unwrap();

    // The discovery endpoint is only enabled for local testing
    if !args.local_key {
        return Ok(warp::http::Response::builder()
            .status(404)
            .body(Body::from(&b"Not found"[..])));
    }

    match load_config_token(maa_url, kms_url, gpu_attestation_socket, 0, &Uuid::nil()).await {
        Ok((config, _)) => match KeyConfig::encode_list(&[config]) {
            Ok(list) => {
                let hex = hex::encode(list);
                trace!("Discover config: {}", hex);

                Ok(warp::http::Response::builder()
                    .status(200)
                    .body(Vec::from(hex).into()))
            }
            Err(e) => {
                error!("{e}");
                Ok(warp::http::Response::builder().status(500).body(Body::from(
                    &b"Invalid key configuration (check KeyConfig written to initial cache)"[..],
                )))
            }
        },
        Err(e) => {
            error!(e);
            Ok(warp::http::Response::builder().status(500).body(Body::from(
                &b"KID 0 missing from cache (should be impossible with local keying)"[..],
            )))
        }
    }
}

async fn cache_local_config() -> Res<()> {
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

fn init() {
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

#[tokio::main]
async fn main() -> Res<()> {
    init();

    let args = Args::parse();
    let address = args.address;

    // Generate a fresh key for local testing. KID is set to 0.
    if args.local_key {
        cache_local_config().await.map_err(|e| {
            error!("{e}");
            e
        })?;
    }

    let argsc = Arc::new(args);
    let args1 = Arc::clone(&argsc);
    let score = warp::post()
        .and(warp::path::path("score"))
        .and(warp::path::end())
        .and(warp::header::headers_cloned())
        .and(warp::body::bytes())
        .and(warp::any().map(move || Arc::clone(&args1)))
        .and(warp::any().map(Uuid::new_v4))
        .and_then(score);

    let args2 = Arc::clone(&argsc);
    let discover = warp::get()
        .and(warp::path("discover"))
        .and(warp::path::end())
        .and(warp::any().map(move || Arc::clone(&args2)))
        .and_then(discover);

    let routes = score.or(discover);
    warp::serve(routes).run(address).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ohttp_client::{HexArg, OhttpClientBuilder};
    use std::{
        fs::File,
        io::{Read, Write},
        path::PathBuf,
        str::FromStr,
    };
    use tokio::sync::mpsc;
    use tracing::subscriber::DefaultGuard;
    use warp::Filter;

    const OHTTP_ADDRESS: &str = "127.0.0.1:9443";

    fn init_test() -> DefaultGuard {
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
        let default_guard = tracing::subscriber::set_default(subscriber);
        ::ohttp::init();

        CACHE.invalidate_all();

        default_guard
    }

    fn create_args() -> Arc<Args> {
        Arc::new(Args {
            address: OHTTP_ADDRESS.parse().unwrap(),
            indeterminate: false,
            target: "http://127.0.0.1:3000".parse().unwrap(),
            local_key: false,
            maa_url: None,
            kms_url: None,
            gpu_attestation_socket: Some(DEFAULT_GPU_ATTESTATION_SOCKET.to_string()),
            inject_request_headers: vec![],
        })
    }

    const URL_SCORE: &str = "http://localhost:9443/score";
    const TARGET_PATH: &str = "/whisper";
    const URL_DISCOVER: &str = "http://localhost:9443/discover";

    fn start_server(args: &Arc<Args>) -> (tokio::task::JoinHandle<()>, mpsc::Sender<()>) {
        let args1 = Arc::clone(args);
        let score = warp::post()
            .and(warp::path::path("score"))
            .and(warp::path::end())
            .and(warp::header::headers_cloned())
            .and(warp::body::bytes())
            .and(warp::any().map(move || Arc::clone(&args1)))
            .and(warp::any().map(Uuid::new_v4))
            .and_then(score);

        let args2 = Arc::clone(args);
        let discover = warp::get()
            .and(warp::path("discover"))
            .and(warp::path::end())
            .and(warp::any().map(move || Arc::clone(&args2)))
            .and_then(discover);

        let routes = score.or(discover);

        let (shutdown_channel_sender, mut shutdown_channel_receiver) = mpsc::channel::<()>(1);

        let (addr, server) =
            warp::serve(routes).bind_with_graceful_shutdown(([127, 0, 0, 1], 9443), async move {
                shutdown_channel_receiver
                    .recv()
                    .await
                    .expect("Failed to send request"); // Wait for shutdown signal
            });

        info!("Server started at: {}", addr);

        // Spawn the server as a separate task
        let server_handle = tokio::spawn(server);

        (server_handle, shutdown_channel_sender)
    }

    async fn get_config_from_discover_endpoint(url: &str) -> Option<HexArg> {
        let client = reqwest::Client::new();
        let response = client
            .get(url)
            .send()
            .await
            .expect("Failed to send request");

        if url == URL_DISCOVER {
            assert_eq!(response.status(), 200);
        } else {
            assert_ne!(response.status(), 200);
            return None;
        }

        let body = response.text().await.expect("Failed to read response");
        info!("body = {body}");

        Some(HexArg::from_str(&body).expect("Invalid hex string"))
    }

    async fn shutdown_server(
        server_handle: tokio::task::JoinHandle<()>,
        shutdown_channel_sender: mpsc::Sender<()>,
    ) {
        shutdown_channel_sender
            .send(())
            .await
            .expect("Could not send shutdown signal");

        // Wait for the server to shut down
        server_handle.await.expect("Waiting for server failed");
    }

    #[tokio::test]
    async fn local_test_basic() {
        let _default_guard = init_test();

        let mut args = create_args();

        if let Some(args_mut) = Arc::get_mut(&mut args) {
            args_mut.local_key = true;
        }

        cache_local_config()
            .await
            .expect("Could not cache local config");

        let (server_handle, shutdown_channel_sender) = start_server(&args);

        let hex_arg = get_config_from_discover_endpoint(URL_DISCOVER).await;

        let ohttp_client = OhttpClientBuilder::new()
            .config(&hex_arg)
            .build()
            .await
            .expect("Could not create new ohttp client builder");

        let url: String = URL_SCORE.to_string();
        let target_path: String = TARGET_PATH.to_string();
        let headers = None;
        let data = None;
        let form_fields = Some(vec![String::from("file=@../examples/audio.mp3")]);
        let outer_headers = None;

        let mut response = ohttp_client
            .post(
                &url,
                &target_path,
                &headers,
                &data,
                &form_fields,
                &outer_headers,
            )
            .await
            .expect("Could not post to scoring endpoint");

        let status = response.status();
        info!("status: {status}");
        assert!(status.is_success());

        while let Some(chunk) = response
            .chunk()
            .await
            .expect("Could not get chunked response")
        {
            let chunk = std::str::from_utf8(&chunk).expect("Could not get chunk");
            info!("{chunk}");
        }

        shutdown_server(server_handle, shutdown_channel_sender).await;
    }

    #[tokio::test]
    // Invalid discover endpoint for local testing
    async fn local_test_invalid_discover_endpoint() {
        let _default_guard = init_test();

        let mut args = create_args();

        if let Some(args_mut) = Arc::get_mut(&mut args) {
            args_mut.local_key = true;
        }

        cache_local_config()
            .await
            .expect("Could not cache local config");

        let (server_handle, shutdown_channel_sender) = start_server(&args);

        let url = "http://localhost:9443/discovery";
        let response = get_config_from_discover_endpoint(url).await;
        if response.is_some() {
            unreachable!("This should never happen!");
        }
        shutdown_server(server_handle, shutdown_channel_sender).await;
    }

    #[tokio::test]
    // Invalid client config for local testing
    async fn local_test_invalid_client_config() {
        let _default_guard = init_test();

        let hex_arg = None;
        let client = OhttpClientBuilder::new().config(&hex_arg).build().await;
        assert!(client.is_err());
    }

    fn get_service_cert_path_from_str(cart_value: &str) -> Option<PathBuf> {
        // Write the result to a file
        let mut file = File::create("service_cert.pem").expect("Failed to create file");
        file.write_all(cart_value.as_bytes())
            .expect("Failed to write to file");

        info!("Certificate written to service_cert.pem");

        // Convert the file name to PathBuf
        let path = PathBuf::from("service_cert.pem");

        // Check if the file exists
        if path.exists() {
            info!("Successfully created file at: {:?}", path);
            return Some(path);
        }

        error!("Failed to find the file at: {:?}", path);

        let path = PathBuf::from(cart_value);
        if path.exists() {
            info!("Successfully created file at: {:?}", path);
            return Some(path);
        }

        error!("Failed to find the file at: {:?}", path);
        None
    }

    #[tokio::test]
    // Invalid client paramaters for local testing
    async fn local_test_invalid_client_paramaters() {
        let _default_guard = init_test();

        let mut args = create_args();

        if let Some(args_mut) = Arc::get_mut(&mut args) {
            args_mut.local_key = true;
        }

        cache_local_config()
            .await
            .expect("Could not cache local config");

        let (server_handle, shutdown_channel_sender) = start_server(&args);

        let hex_arg = get_config_from_discover_endpoint(URL_DISCOVER).await;

        let ohttp_client = OhttpClientBuilder::new()
            .config(&hex_arg)
            .build()
            .await
            .expect("Could not create new ohttp client builder");

        let mut url: String = "http://localhost:9443/scoreee".to_string();
        let mut target_path: String = TARGET_PATH.to_string();
        let headers = None;
        let data = None;
        let mut form_fields = Some(vec![String::from("file=@../examples/audio.mp3")]);
        let outer_headers = None;

        let mut response = ohttp_client
            .post(
                &url,
                &target_path,
                &headers,
                &data,
                &form_fields,
                &outer_headers,
            )
            .await
            .unwrap();
        let status = response.status();
        info!("status: {status}");
        assert!(!status.is_success());

        let ohttp_client = OhttpClientBuilder::new()
            .config(&hex_arg)
            .build()
            .await
            .expect("Could not create new ohttp client builder");

        url = URL_SCORE.to_string();
        target_path = "/whisperrr".to_string();

        response = ohttp_client
            .post(
                &url,
                &target_path,
                &headers,
                &data,
                &form_fields,
                &outer_headers,
            )
            .await
            .expect("Could not post to scoring endpoint");

        let status = response.status();
        info!("status: {status}");
        assert!(!status.is_success());

        let ohttp_client = OhttpClientBuilder::new()
            .config(&hex_arg)
            .build()
            .await
            .expect("Could not create new ohttp client builder");

        target_path = TARGET_PATH.to_string();
        form_fields = Some(vec![String::from("file=@../examples/audioo.mp3")]);

        if ohttp_client
            .post(
                &url,
                &target_path,
                &headers,
                &data,
                &form_fields,
                &outer_headers,
            )
            .await
            .is_ok()
        {
            panic!("This should never happen!");
        }

        shutdown_server(server_handle, shutdown_channel_sender).await;
    }

    const DEFAULT_KMS_URL_CLIENT: &str =
        "https://accconfinferenceprod.confidential-ledger.azure.com";
    const DEFAULT_KMS_URL_SERVER: &str =
        "https://accconfinferenceprod.confidential-ledger.azure.com/app/key";
    const DEFAULT_MAA_URL: &str = "https://confinfermaaeus2test.eus2.test.attest.azure.net";

    async fn get_kms_cert() -> Option<PathBuf> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true) // Equivalent to -k in curl
            .build()
            .expect("reqwest::Client::builder() failed");

        let response = client
            .get("https://accconfinferenceprod.confidential-ledger.azure.com/node/network")
            .send()
            .await
            .expect("reqwest::Client::get() failed");

        let body: Value = response.json().await.expect("Failed to read response");
        info!("body = {:?}", body);

        // Accessing the "service_certificate" field
        if let Value::Map(map) = body {
            for (key, value) in map {
                if let Value::Text(key_str) = key {
                    info!("Key: {}", key_str);
                    if key_str == "service_certificate" {
                        if let Value::Text(value_str) = value {
                            info!("service_certificate: {}", value_str);

                            return get_service_cert_path_from_str(&value_str);
                        }
                    }
                }
            }
            error!("service_certificate not found or not in expected format");
        }

        None
    }

    #[tokio::test]
    async fn kms_test_basic() {
        let _default_guard = init_test();

        let mut args = create_args();

        if let Some(args_mut) = Arc::get_mut(&mut args) {
            args_mut.maa_url = Some(String::from(DEFAULT_MAA_URL));
            args_mut.kms_url = Some(String::from(DEFAULT_KMS_URL_SERVER));
        }

        let (server_handle, shutdown_channel_sender) = start_server(&args);

        let kms_url = Some(String::from(DEFAULT_KMS_URL_CLIENT));
        let kms_cert = get_kms_cert().await;
        let ohttp_client = OhttpClientBuilder::new()
            .kms_url(&kms_url)
            .kms_cert(&kms_cert)
            .build()
            .await
            .expect("Could not create new ohttp client builder");

        let url: String = URL_SCORE.to_string();
        let target_path: String = TARGET_PATH.to_string();
        let headers = None;
        let data = None;
        let form_fields = Some(vec![String::from("file=@../examples/audio.mp3")]);
        let outer_headers = None;

        let mut response = ohttp_client
            .post(
                &url,
                &target_path,
                &headers,
                &data,
                &form_fields,
                &outer_headers,
            )
            .await
            .expect("Could not post to scoring endpoint");

        let status = response.status();
        info!("status: {status}");
        assert!(status.is_success());

        while let Some(chunk) = response
            .chunk()
            .await
            .expect("Could not get chunked response")
        {
            let chunk = std::str::from_utf8(&chunk).expect("Could not get chunk");
            info!("{chunk}");
        }

        shutdown_server(server_handle, shutdown_channel_sender).await;
    }

    const DEFAULT_KMS_URL_CLIENT_INVALID: &str =
        "https://accconfinferenceprodbad.confidential-ledger.azure.com";

    #[tokio::test]
    // Invalid kms url set for client
    async fn kms_test_invalid_kms_url() {
        let _default_guard = init_test();

        let kms_url = Some(String::from(DEFAULT_KMS_URL_CLIENT_INVALID));
        let kms_cert = get_kms_cert().await;
        if OhttpClientBuilder::new()
            .kms_url(&kms_url)
            .kms_cert(&kms_cert)
            .build()
            .await
            .is_ok()
        {
            panic!("This should never happen!")
        }
    }

    const KMS_URL_SERVER_DEBUG: &str =
        "https://accconfinferencedebug.confidential-ledger.azure.com/app/key";

    #[tokio::test]
    // mismatched KMS for client and server
    async fn kms_test_mismatched_kms_url() {
        let _default_guard = init_test();

        let mut args = create_args();

        if let Some(args_mut) = Arc::get_mut(&mut args) {
            args_mut.maa_url = Some(String::from(DEFAULT_MAA_URL));
            args_mut.kms_url = Some(String::from(KMS_URL_SERVER_DEBUG));
        }

        let (server_handle, shutdown_channel_sender) = start_server(&args);

        let kms_url = Some(String::from(DEFAULT_KMS_URL_CLIENT));
        let kms_cert = get_kms_cert().await;
        let ohttp_client = OhttpClientBuilder::new()
            .kms_url(&kms_url)
            .kms_cert(&kms_cert)
            .build()
            .await
            .expect("Could not create new ohttp client builder");

        let url: String = URL_SCORE.to_string();
        let target_path: String = TARGET_PATH.to_string();
        let headers = None;
        let data = None;
        let form_fields = Some(vec![String::from("file=@../examples/audio.mp3")]);
        let outer_headers = None;

        let response = ohttp_client
            .post(
                &url,
                &target_path,
                &headers,
                &data,
                &form_fields,
                &outer_headers,
            )
            .await
            .expect("Could not post to scoring endpoint");

        let status = response.status();
        info!("status: {status}");
        assert!(!status.is_success());

        shutdown_server(server_handle, shutdown_channel_sender).await;
    }

    #[tokio::test]
    async fn test_maa_invalid_url() {
        let mut attestation_client = AttestationClient::new().unwrap();
        let maa_url = "https://invalid-maa-url.com";
        let result = fetch_maa_token(&mut attestation_client, maa_url);
        assert!(result.is_err());
    }

    const TPM_EVENT_LOG_PATH: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";
    fn event_in_tpm_event_log(search_string: &str) -> bool {
        let mut file = File::open(TPM_EVENT_LOG_PATH)
            .unwrap_or_else(|_| panic!("Failed to open {TPM_EVENT_LOG_PATH}"));
        let mut buffer = Vec::new();
        let _ = file
            .read_to_end(&mut buffer)
            .unwrap_or_else(|_| panic!("Failed to read {TPM_EVENT_LOG_PATH}"));
        let search_bytes = search_string.as_bytes();
        buffer
            .windows(search_bytes.len())
            .any(|window| window == search_bytes)
    }

    #[tokio::test]
    async fn test_maa_valid_urls() {
        const OS_IMAGE_IDENTITY_EVENTNAME: &str = "os-image-identity";
        const NODE_POLICY_IDENTITY_EVENTNAME: &str = "node-policy-identity";
        let os_identity_event_present = event_in_tpm_event_log(OS_IMAGE_IDENTITY_EVENTNAME);
        let node_policy_event_present = event_in_tpm_event_log(NODE_POLICY_IDENTITY_EVENTNAME);

        let mut attestation_client = AttestationClient::new().unwrap();
        let maa_urls = std::env::var("TEST_MAA_URLS").unwrap();
        let maa_urls = maa_urls.split(',').collect::<Vec<&str>>();
        // loop over maa_url list
        // check MAA attestation succeeds
        // and, if os identity and node policy claims are present in TPM event log, they should be present in claims returned by MAA
        for url in maa_urls {
            let result = fetch_maa_token(&mut attestation_client, url);
            assert!(result.is_ok());
            let token = result.unwrap();
            // valid MAA JWT is dot separated list of header.payload.signature
            let token_arr: Vec<&str> = token.split('.').collect();
            assert!(token_arr.len() == 3);
            let payload_b64 = token_arr[1];
            let claims = URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
            let claims = String::from_utf8(claims).unwrap();
            if os_identity_event_present {
                assert!(claims.contains(OS_IMAGE_IDENTITY_EVENTNAME));
            }
            if node_policy_event_present {
                assert!(claims.contains(NODE_POLICY_IDENTITY_EVENTNAME));
            }
        }
    }
}
