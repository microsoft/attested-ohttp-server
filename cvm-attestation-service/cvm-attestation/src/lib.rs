use cgpuvm_attest::AttestationClient;
use tokio::net::UnixListener;
use tracing::{error, info, instrument, trace};

const VERSION: &str = "0.0.74.3";

pub type Res<T> = Result<T, Box<dyn std::error::Error>>;

use std::{os::unix::fs::PermissionsExt, path::Path};

pub const PCR0_TO_15_BITMASK: u32 = 0xFFFF;

use thiserror::Error;
#[derive(Error, Debug)]
pub enum ServerError {
    #[error("CVM guest attestation library initialization failure")]
    AttestationLibraryInit,
}

pub fn fetch_maa_token(attestation_client: &mut AttestationClient, maa: &str) -> Res<String> {
    // Get MAA token from CVM guest attestation library
    info!("Fetching MAA token from {maa}");

    let t = attestation_client.attest("{}".as_bytes(), PCR0_TO_15_BITMASK, maa)?;

    let token = String::from_utf8(t).unwrap();
    trace!("Fetched MAA token: {token}");
    Ok(token)
}

pub async fn get_listener(socket_path: &str) -> Res<UnixListener> {
    trace!("Starting unix-socket-service on {}", socket_path);

    // Remove existing socket file if it exists
    if Path::new(socket_path).exists() {
        match std::fs::remove_file(socket_path) {
            Ok(_) => trace!("Removed existing socket file"),
            Err(e) => {
                error!("Failed to remove existing socket file: {}", e);
                return Err(Box::new(e));
            }
        }
        trace!("Removed existing socket file");
    }

    // Bind to Unix socket
    let listener = match UnixListener::bind(socket_path) {
        Ok(listener) => listener,
        Err(e) => {
            error!("Failed to bind to socket: {}", e);
            return Err(Box::new(e));
        }
    };
    info!("Server listening on {}", socket_path);

    // Set permissions for the socket file (e.g., readable/writable by all)
    match std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666)) {
        Ok(_) => trace!("Set socket permissions to 0666"),
        Err(e) => {
            error!("Failed to set socket permissions: {}", e);
            return Err(Box::new(e));
        }
    }

    Ok(listener)
}

#[instrument(skip(maa), fields(version = %VERSION))]
pub async fn do_attest(
    maa: &str,
    x_ms_request_id: &str,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    // Log the received headers and body

    let mut attestation_client = match AttestationClient::new() {
        Ok(cli) => cli,
        _ => {
            // Return a failure response
            return Ok(warp::reply::with_status(
                "CVM guest attestation library initialization failure".to_string(),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    let token = fetch_maa_token(&mut attestation_client, maa).unwrap_or_default();

    Ok(warp::reply::with_status(token, warp::http::StatusCode::OK))
}
pub async fn attest(
    headers: warp::hyper::HeaderMap,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    // Process the attestation request here
    let header_str = format!("{:?}", headers);
    trace!("Headers: {:?}", header_str);

    let mut maa: &str = "";
    let mut x_ms_request_id: &str = "";
    for header in headers.iter() {
        if header.0 == "maa" {
            maa = header.1.to_str().unwrap_or("");
            trace!("Maa: {}", maa);
        } else if header.0 == "x-ms-request-id" {
            x_ms_request_id = header.1.to_str().unwrap_or("");
            info!("x-ms-request-id: {}", x_ms_request_id);
        }
    }

    do_attest(maa, x_ms_request_id).await
}

#[cfg(test)]
mod tests;
