use std::{os::unix::fs::PermissionsExt, path::Path};
use tokio::{net::UnixListener, task};
use tracing::{error, info, instrument, trace};

pub const VERSION: &str = "0.0.88.0";

pub type Res<T> = Result<T, Box<dyn std::error::Error>>;

pub const PCR0_TO_15_BITMASK: u32 = 0xFFFF;

use azure_guest_attestation_sdk::{
    AttestOptions, AttestationClient, Provider,
    tpm::types::{ALG_SHA256, TpmtRsaDecryptScheme},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as b64};

use thiserror::Error;
#[derive(Error, Debug)]
pub enum ServerError {
    #[error("CVM guest attestation library initialization failure")]
    AttestationLibraryInit,
    #[error("Guest attestation library failed to decrypt HPKE private key")]
    TPMDecryptionFailure,
}

fn attestation_pcrs() -> Vec<u32> {
    (0..=15).collect()
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
    trace!(
        "attest request maa_url: {} x_ms_request_id: {}",
        maa, x_ms_request_id
    );

    let attest_result = task::spawn_blocking(move || -> Result<String, String> {
        let attestation_client = create_attestation_client().map_err(|e| e.to_string())?;
        fetch_maa_token(&attestation_client, &maa).map_err(|e| e.to_string())
    })
    .await;

    let token = match attest_result {
        Ok(Ok(token)) => token,
        Ok(Err(e)) => {
            error!("Failed to fetch MAA token: {}", e);
            return Ok(warp::reply::with_status(
                format!("{e}"),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
        Err(e) => {
            error!("Attestation worker task failed: {}", e);
            return Ok(warp::reply::with_status(
                "Attestation worker task failed".to_string(),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    Ok(warp::reply::with_status(token, warp::http::StatusCode::OK))
}

fn fetch_maa_token(attestation_client: &AttestationClient, maa: &str) -> Res<String> {
    // Get MAA token from Azure Guest Attestation SDK
    info!("Fetching MAA token from {maa}");

    let pcrs = attestation_pcrs();

    let result = attestation_client.attest_guest(
        Provider::maa(maa),
        Some(&AttestOptions {
            pcr_selection: Some(pcrs.clone()),
            client_payload: None,
            ..Default::default()
        }),
    )?;
    let token = result.token.unwrap_or_default();
    trace!("Fetched MAA token: {token}");
    Ok(token)
}

#[instrument(skip( body), fields(version = %VERSION))]
pub async fn decrypt(
    x_ms_request_id: String,
    body: bytes::Bytes,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    let enc_key = body.to_vec();
    trace!(
        "decrypt request encrypted_key: {:?} x_ms_request_id: {}",
        enc_key, x_ms_request_id
    );

    let pcrs = attestation_pcrs();
    let decrypt_result = task::spawn_blocking(move || -> Result<Vec<u8>, String> {
        let attestation_client = create_attestation_client().map_err(|e| e.to_string())?;
        attestation_client
            .decrypt_with_tpm_ephemeral_key(&pcrs, &enc_key, TpmtRsaDecryptScheme::Oaep(ALG_SHA256))
            .map_err(|e| e.to_string())
    })
    .await;

    let decrypted_key = match decrypt_result {
        Ok(Ok(decrypted_key)) => decrypted_key,
        Ok(Err(e)) => {
            error!("Failed to decrypt key: {}", e);
            return Ok(warp::reply::with_status(
                format!("{}", ServerError::TPMDecryptionFailure),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
        Err(e) => {
            error!("Decrypt worker task failed: {}", e);
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
