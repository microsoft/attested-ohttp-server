use std::{os::unix::fs::PermissionsExt, path::Path};
use tokio::net::UnixListener;
use tracing::{error, info, instrument, trace};

pub const VERSION: &str = "0.0.74.3";

pub type Res<T> = Result<T, Box<dyn std::error::Error>>;

pub const PCR0_TO_15_BITMASK: u32 = 0xFFFF;

use base64::{Engine as _, engine::general_purpose::STANDARD as b64};
use cgpuvm_attest::AttestationClient;

use thiserror::Error;
#[derive(Error, Debug)]
pub enum ServerError {
    #[error("CVM guest attestation library initialization failure")]
    AttestationLibraryInit,
    #[error("Guest attestation library failed to decrypt HPKE private key")]
    TPMDecryptionFailure,
}

pub async fn get_socket_listener(socket_path: &str) -> Res<UnixListener> {
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

    // Create a new UnixListener bound to the specified socket path
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

fn create_attestation_client() -> Res<AttestationClient> {
    let attestation_client = match AttestationClient::new() {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create AttestationClient: {}", e);
            return Err(Box::new(ServerError::AttestationLibraryInit));
        }
    };
    trace!("Created AttestationClient successfully");
    Ok(attestation_client)
}

#[instrument(skip(maa), fields(version = %VERSION))]
pub async fn attest(
    maa: String,
    x_ms_request_id: String,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    trace!("Maa: {}", maa);

    let mut attestation_client = match create_attestation_client() {
        Ok(attestation_client) => attestation_client,
        Err(e) => {
            return Ok(warp::reply::with_status(
                format!("{}", e),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    let token = match fetch_maa_token(&mut attestation_client, &maa) {
        Ok(token) => token,
        Err(e) => {
            error!("Failed to fetch MAA token: {}", e);
            return Ok(warp::reply::with_status(
                format!("{e}"),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    Ok(warp::reply::with_status(token, warp::http::StatusCode::OK))
}

fn fetch_maa_token(attestation_client: &mut AttestationClient, maa: &str) -> Res<String> {
    // Get MAA token from CVM guest attestation library
    info!("Fetching MAA token from {maa}");

    let t = attestation_client.attest("{}".as_bytes(), PCR0_TO_15_BITMASK, maa)?;

    let token = String::from_utf8(t).unwrap();
    trace!("Fetched MAA token: {token}");
    Ok(token)
}

#[instrument(skip( body), fields(version = %VERSION))]
pub async fn decrypt(
    x_ms_request_id: String,
    body: bytes::Bytes,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    let enc_key: &[u8] = &body.to_vec();
    trace!("Encrypted key: {:?}", enc_key);

    let mut attestation_client = match create_attestation_client() {
        Ok(attestation_client) => attestation_client,
        Err(e) => {
            return Ok(warp::reply::with_status(
                format!("{}", e),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    let decrypted_key = match attestation_client.decrypt(&enc_key, PCR0_TO_15_BITMASK) {
        Ok(decrypted_key) => decrypted_key,
        Err(e) => {
            error!("Failed to decrypt key: {}", e);
            return Ok(warp::reply::with_status(
                format!("{}", ServerError::TPMDecryptionFailure),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    let encoded = b64.encode(&decrypted_key);
    Ok(warp::reply::with_status(
        encoded,
        warp::http::StatusCode::OK,
    ))
}

#[cfg(test)]
mod tests;
