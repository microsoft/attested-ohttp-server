use azure_attestation_proxy::{Res, attest, create_shared_client, decrypt, get_socket_listener};
use azure_guest_attestation_sdk::{LogFormat, TracingConfig};
use warp::Filter;

const SOCKET_PATH: &str = "/var/run/azure-attestation-proxy/azure-attestation-proxy.sock";

#[tokio::main]
async fn main() -> Res<()> {
    // Use the SDK's tracing initializer with JSON format and flush-on-drop.
    azure_guest_attestation_sdk::init_tracing_with(TracingConfig {
        filter: "trace".into(),
        format: LogFormat::Json,
    });

    // Open the TPM and create the shared attestation client once at startup.
    let client = create_shared_client()?;

    let listener = match get_socket_listener(SOCKET_PATH).await {
        Ok(listener) => listener,
        Err(e) => return Err(e),
    };

    let stream = tokio_stream::wrappers::UnixListenerStream::new(listener);

    let client_for_attest = client.clone();
    let attest_route = warp::get()
        .and(warp::path::path("attest"))
        .and(warp::path::end())
        .and(warp::any().map(move || client_for_attest.clone()))
        .and(warp::header::header::<String>("maa"))
        .and(warp::header::header::<String>("x-ms-request-id"))
        .and_then(attest);

    let client_for_decrypt = client.clone();
    let decrypt_route = warp::post()
        .and(warp::path::path("decrypt"))
        .and(warp::path::end())
        .and(warp::any().map(move || client_for_decrypt.clone()))
        .and(warp::header::header::<String>("x-ms-request-id"))
        .and(warp::body::bytes())
        .and_then(decrypt);

    let routes = attest_route.or(decrypt_route);

    warp::serve(routes).serve_incoming(stream).await;

    Ok(())
}
