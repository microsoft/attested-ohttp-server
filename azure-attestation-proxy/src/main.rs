use azure_attestation_proxy::{Res, attest, decrypt, get_socket_listener};
use tracing::subscriber;
use tracing_subscriber::{EnvFilter, FmtSubscriber, fmt::format::FmtSpan};
use warp::Filter;

const SOCKET_PATH: &str = "/var/run/azure-attestation-proxy/azure-attestation-proxy.sock";

#[tokio::main]
async fn main() -> Res<()> {
    // Build a simple subscriber that outputs to stdout
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("trace")),
        )
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_span_events(FmtSpan::NEW)
        .json()
        .finish();

    // Set the subscriber as global default
    subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let listener = match get_socket_listener(SOCKET_PATH).await {
        Ok(listener) => listener,
        Err(e) => return Err(e),
    };

    let stream = tokio_stream::wrappers::UnixListenerStream::new(listener);

    let attest = warp::get()
        .and(warp::path::path("attest"))
        .and(warp::path::end())
        .and(warp::header::header::<String>("maa"))
        .and(warp::header::header::<String>("x-ms-request-id"))
        .and_then(attest);

    let decrypt = warp::post()
        .and(warp::path::path("decrypt"))
        .and(warp::path::end())
        .and(warp::header::header::<String>("x-ms-request-id"))
        .and(warp::body::bytes())
        .and_then(decrypt);

    let routes = attest.or(decrypt);

    warp::serve(routes).serve_incoming(stream).await;

    Ok(())
}
