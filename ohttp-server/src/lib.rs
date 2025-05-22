pub mod attest;
pub mod cache;
pub mod err;
pub mod utils;

use err::ServerError;
use ohttp::{Server as OhttpServer, ServerResponse};

use tracing::info;
use utils::Res;
use uuid::Uuid;

use bhttp::{Message, Mode};
use std::io::Cursor;

use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Method, Response, Url,
};

use attest::{load_config_token, load_config_token_safe};
use cache::{CachedKey, CACHE};
use std::sync::Arc;
use utils::{Args, DEFAULT_MAA_URL};

pub const FILTERED_RESPONSE_HEADERS: [&str; 2] = ["content-type", "content-length"];
const DEFAULT_KMS_URL: &str =
    "https://accconfinferenceproduction.confidential-ledger.azure.com/app/key";

use futures_util::stream::unfold;

use base64::{engine::general_purpose::STANDARD as b64, Engine as _};

use ohttp::KeyConfig;
use warp::hyper::Body;

use tracing::{error, instrument, trace};
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter, FmtSubscriber};

const VERSION: &str = "0.0.74.3";

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

pub async fn post_request_to_target(
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
    let mut headers = get_headers_from_request(bin_request);

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
        let error_msg = format!(
            "{}{}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
        return Err(Box::new(ServerError::TargetRequestError(error_msg)));
    }

    Ok(response)
}

pub fn decapsulate_request(
    ohttp: &OhttpServer,
    enc_request: &[u8],
) -> Res<(Message, ServerResponse)> {
    let (request, server_response) = ohttp.decapsulate(enc_request)?;
    let bin_request = Message::read_bhttp(&mut Cursor::new(&request[..]))?;
    Ok((bin_request, server_response))
}

// Compute the set of headers that need to be injected into the inner request
pub fn compute_injected_headers(headers: &HeaderMap, keys: Vec<String>) -> HeaderMap {
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
pub async fn score(
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
        gpu_attestation_socket,
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

pub async fn discover(args: Arc<Args>) -> Result<impl warp::Reply, std::convert::Infallible> {
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

#[cfg(test)]
mod tests;
