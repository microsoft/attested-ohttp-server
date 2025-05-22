use super::*;
use crate::get_listener;
use hyper::{Body, Method, Request};
use hyper_unix_connector::{UnixClient, Uri};
use tokio::sync::mpsc;
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter, FmtSubscriber};
use warp::Filter;

const TEST_SOCKET_PATH: &str = "/var/run/cvm-attestation/cvm-attestation-test.sock";

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

    default_guard
}

#[derive(Debug)]
struct TestServer {
    shutdown_channel_sender: mpsc::Sender<()>,
}

impl TestServer {
    async fn start() -> Res<Self> {
        let listener = match get_listener(TEST_SOCKET_PATH).await {
            Ok(listener) => listener,
            Err(e) => return Err(e),
        };

        let attest = warp::get()
            .and(warp::path::path("attest"))
            .and(warp::path::end())
            .and(warp::header::headers_cloned())
            .and_then(attest);

        let stream = tokio_stream::wrappers::UnixListenerStream::new(listener);

        let (shutdown_channel_sender, mut shutdown_channel_receiver) = mpsc::channel::<()>(1);

        // Spawn the server as a separate task
        tokio::spawn(async move {
            warp::serve(attest)
                .serve_incoming_with_graceful_shutdown(stream, async move {
                    shutdown_channel_receiver.recv().await;
                })
                .await;
        });

        Ok(TestServer {
            shutdown_channel_sender,
        })
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Trigger shutdown when Server goes out of scope
        let shutdown_channel_sender = self.shutdown_channel_sender.clone();
        tokio::spawn(async move {
            let _ = shutdown_channel_sender.send(()).await;
        });
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}

#[tokio::test]
async fn send_attestation_request() {
    let _default_guard = init_test();

    let _test_server = TestServer::start()
        .await
        .expect("Could not create new TestServer.");

    let client: hyper::Client<UnixClient, Body> = hyper::Client::builder().build(UnixClient);
    let addr : hyper::Uri = Uri::new(TEST_SOCKET_PATH, "/attest").into();
    info!("Connecting to: {}", addr);



    let req = Request::builder()
        .method(Method::GET)
        .uri(addr)
        .header("x-ms-request-id", "12345678-1234-5678-1234-567812345678")
        .header(
            "maa",
            "https://confinfermaaeus2test.eus2.test.attest.azure.net",
        )
        .body(Body::empty())
        .expect("request builder");

    let response = client.request(req).await.unwrap();
    info!("Received: {}", response.status());
    assert_eq!(response.status(), 200);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    info!("Received: {}", body_str);
}
