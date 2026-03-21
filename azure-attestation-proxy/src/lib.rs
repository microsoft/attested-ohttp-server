use std::{os::unix::fs::PermissionsExt, path::Path, sync::Arc};
use tokio::net::UnixListener;
use tracing::{error, info, instrument, trace};

pub const VERSION: &str = "0.0.88.0";

pub type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// PCR indices 0–15 (equivalent to the old C library's PCR0_TO_15_BITMASK = 0xFFFF).
pub const PCRS: [u32; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

use azure_guest_attestation_sdk::client::{AttestOptions, AttestationClient, Provider};
use base64::{Engine as _, engine::general_purpose::STANDARD as b64};

use thiserror::Error;
#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Failed to initialize attestation client (TPM access requires root)")]
    AttestationClientInit,
    #[error("Guest attestation library failed to decrypt HPKE private key")]
    TPMDecryptionFailure,
}

/// Shared [`AttestationClient`] handle.
///
/// The ephemeral RSA key used for attestation is a deterministic TPM2 primary
/// that can be recreated from the same PCR selection at any time, so no
/// per-request state (key handle, PCR list) needs to be carried between
/// `/attest` and `/decrypt`.
pub type SharedClient = Arc<AttestationClient>;

/// Open the platform TPM and create a shared [`AttestationClient`].
///
/// Call this once at process start and pass the result to
/// [`attest`] / [`decrypt`] via warp filters.
pub fn create_shared_client() -> Res<SharedClient> {
    let client = AttestationClient::new().map_err(|e| {
        error!("Failed to open TPM / create AttestationClient: {e}");
        Box::<dyn std::error::Error>::from(ServerError::AttestationClientInit.to_string())
    })?;
    trace!("Created AttestationClient successfully");
    Ok(Arc::new(client))
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

#[instrument(skip(client, maa), fields(version = %VERSION))]
pub async fn attest(
    client: SharedClient,
    maa: String,
    x_ms_request_id: String,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    trace!("Maa: {}", maa);

    let result = tokio::task::spawn_blocking(move || {
        info!("Fetching MAA token from {maa}");

        let opts = AttestOptions {
            pcr_selection: Some(PCRS.to_vec()),
            ..Default::default()
        };

        let result = client
            .attest_guest(Provider::maa(&maa), Some(&opts))
            .map_err(|e| format!("attest_guest failed: {e}"))?;

        let token = result.token.unwrap_or_default();
        trace!("Fetched MAA token ({} bytes)", token.len());
        Ok::<String, String>(token)
    })
    .await;

    match result {
        Ok(Ok(token)) => Ok(warp::reply::with_status(token, warp::http::StatusCode::OK)),
        Ok(Err(e)) => {
            error!("Attestation failed: {e}");
            Ok(warp::reply::with_status(
                e,
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
        Err(e) => {
            error!("spawn_blocking panicked: {e}");
            Ok(warp::reply::with_status(
                format!("internal error: {e}"),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

#[instrument(skip(client, body), fields(version = %VERSION))]
pub async fn decrypt(
    client: SharedClient,
    x_ms_request_id: String,
    body: bytes::Bytes,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    let token_b64url = match String::from_utf8(body.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            error!("Invalid UTF-8 in request body: {e}");
            return Ok(warp::reply::with_status(
                format!("{}", ServerError::TPMDecryptionFailure),
                warp::http::StatusCode::BAD_REQUEST,
            ));
        }
    };
    trace!("Token envelope: {} bytes", token_b64url.len());

    let result = tokio::task::spawn_blocking(move || {
        client
            .decrypt_token(&PCRS, &token_b64url)
            .map_err(|e| format!("decrypt_token failed: {e}"))
    })
    .await;

    match result {
        Ok(Ok(Some(jwt))) => {
            let encoded = b64.encode(jwt.as_bytes());
            Ok(warp::reply::with_status(
                encoded,
                warp::http::StatusCode::OK,
            ))
        }
        Ok(Ok(None)) => Ok(warp::reply::with_status(
            "Token is not in encrypted envelope format".to_string(),
            warp::http::StatusCode::BAD_REQUEST,
        )),
        Ok(Err(e)) => {
            error!("Decryption failed: {e}");
            Ok(warp::reply::with_status(
                format!("{}", ServerError::TPMDecryptionFailure),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
        Err(e) => {
            error!("spawn_blocking panicked: {e}");
            Ok(warp::reply::with_status(
                format!("internal error: {e}"),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

#[cfg(test)]
mod tests;
