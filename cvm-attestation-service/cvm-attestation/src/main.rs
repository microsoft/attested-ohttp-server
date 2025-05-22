use cvm_attestation::{attest, get_listener, Res};

use tracing::subscriber;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter, FmtSubscriber};
use warp::Filter;

const DEFAULT_SOCKET_PATH: &str = "/var/run/cvm-attestation/cvm-attestation.sock";

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

    let listener = match get_listener(DEFAULT_SOCKET_PATH).await {
        Ok(listener) => listener,
        Err(e) => return Err(e),
    };

    let attest = warp::get()
        .and(warp::path::path("attest"))
        .and(warp::path::end())
        .and(warp::header::headers_cloned())
        .and_then(attest);

    let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);
    warp::serve(attest).serve_incoming(incoming).await;

    Ok(())
}
