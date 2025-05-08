// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![deny(clippy::pedantic)]

use ohttp_server::{cache_local_config, init};

pub mod err;

use std::sync::Arc;


use warp:: Filter;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

use serde::Deserialize;

use tracing::error;
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

use clap::Parser;
use std::net::SocketAddr;

#[derive(Debug, Parser, Clone)]
#[command(name = "ohttp-server", about = "Serve oblivious HTTP requests.")]
pub struct Args {
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
            error!(e);
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
