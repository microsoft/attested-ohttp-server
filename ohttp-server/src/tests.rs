use super::*;
use crate::{
    attest::fetch_maa_token, cache::cache_local_config, utils::DEFAULT_GPU_ATTESTATION_SOCKET,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cgpuvm_attest::AttestationClient;
use ohttp_client::{HexArg, OhttpClientBuilder};
use serde_cbor::Value;
use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    str::FromStr,
};
use tokio::sync::mpsc;
use tracing::subscriber::DefaultGuard;
use warp::Filter;

const OHTTP_ADDRESS: &str = "127.0.0.1:9443";

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
    ::ohttp::init();

    CACHE.invalidate_all();

    default_guard
}

fn create_args() -> Arc<Args> {
    Arc::new(Args {
        address: OHTTP_ADDRESS.parse().unwrap(),
        indeterminate: false,
        target: "http://127.0.0.1:3000".parse().unwrap(),
        local_key: false,
        maa_url: None,
        kms_url: None,
        gpu_attestation_socket: Some(DEFAULT_GPU_ATTESTATION_SOCKET.to_string()),
        inject_request_headers: vec![],
    })
}

const URL_SCORE: &str = "http://localhost:9443/score";
const TARGET_PATH: &str = "/whisper";
const URL_DISCOVER: &str = "http://localhost:9443/discover";

#[derive(Debug)]
struct TestServer {
    shutdown_channel_sender: mpsc::Sender<()>,
}

impl TestServer {
    fn start(args: &Arc<Args>) -> Res<Self> {
        let args1 = Arc::clone(args);
        let score = warp::post()
            .and(warp::path::path("score"))
            .and(warp::path::end())
            .and(warp::header::headers_cloned())
            .and(warp::body::bytes())
            .and(warp::any().map(move || Arc::clone(&args1)))
            .and(warp::any().map(Uuid::new_v4))
            .and_then(score);

        let args2 = Arc::clone(args);
        let discover = warp::get()
            .and(warp::path("discover"))
            .and(warp::path::end())
            .and(warp::any().map(move || Arc::clone(&args2)))
            .and_then(discover);

        let routes = score.or(discover);

        let (shutdown_channel_sender, mut shutdown_channel_receiver) = mpsc::channel::<()>(1);

        // Spawn the server as a separate task
        tokio::spawn(async move {
            let (addr, server_handle) = warp::serve(routes).bind_with_graceful_shutdown(
                ([127, 0, 0, 1], 9443),
                async move {
                    shutdown_channel_receiver.recv().await;
                },
            );
            server_handle.await;
            info!("Server started at: {}", addr);
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

async fn get_config_from_discover_endpoint(url: &str) -> Option<HexArg> {
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .send()
        .await
        .expect("Failed to send request");

    if url == URL_DISCOVER {
        assert_eq!(response.status(), 200);
    } else {
        assert_ne!(response.status(), 200);
        return None;
    }

    let body = response.text().await.expect("Failed to read response");
    info!("body = {body}");

    Some(HexArg::from_str(&body).expect("Invalid hex string"))
}

#[tokio::test]
async fn local_test_basic() {
    let _default_guard = init_test();

    let mut args = create_args();

    if let Some(args_mut) = Arc::get_mut(&mut args) {
        args_mut.local_key = true;
    }

    cache_local_config()
        .await
        .expect("Could not cache local config");

    let _test_server = TestServer::start(&args).expect("Could not create new TestServer.");

    let hex_arg = get_config_from_discover_endpoint(URL_DISCOVER).await;

    let ohttp_client = OhttpClientBuilder::new()
        .config(&hex_arg)
        .build()
        .await
        .expect("Could not create new ohttp client builder");

    let url: String = URL_SCORE.to_string();
    let target_path: String = TARGET_PATH.to_string();
    let headers = None;
    let data = None;
    let form_fields = Some(vec![String::from("file=@../examples/audio.mp3")]);
    let outer_headers = None;

    let mut response = ohttp_client
        .post(
            &url,
            &target_path,
            &headers,
            &data,
            &form_fields,
            &outer_headers,
        )
        .await
        .expect("Could not post to scoring endpoint");

    let status = response.status();
    info!("status: {status}");
    assert!(status.is_success());

    while let Some(chunk) = response
        .chunk()
        .await
        .expect("Could not get chunked response")
    {
        let chunk = std::str::from_utf8(&chunk).expect("Could not get chunk");
        info!("{chunk}");
    }
}

#[tokio::test]
// Invalid discover endpoint for local testing
async fn local_test_invalid_discover_endpoint() {
    let _default_guard = init_test();

    let mut args = create_args();

    if let Some(args_mut) = Arc::get_mut(&mut args) {
        args_mut.local_key = true;
    }

    cache_local_config()
        .await
        .expect("Could not cache local config");

    let _test_server = TestServer::start(&args).expect("Could not create new TestServer.");

    let url = "http://localhost:9443/discovery";
    let response = get_config_from_discover_endpoint(url).await;
    if response.is_some() {
        unreachable!("This should never happen!");
    }
}

#[tokio::test]
// Invalid client config for local testing
async fn local_test_invalid_client_config() {
    let _default_guard = init_test();

    let hex_arg = None;
    let client = OhttpClientBuilder::new().config(&hex_arg).build().await;
    assert!(client.is_err());
}

fn get_service_cert_path_from_str(cart_value: &str) -> Option<PathBuf> {
    // Write the result to a file
    let mut file = File::create("service_cert.pem").expect("Failed to create file");
    file.write_all(cart_value.as_bytes())
        .expect("Failed to write to file");

    info!("Certificate written to service_cert.pem");

    // Convert the file name to PathBuf
    let path = PathBuf::from("service_cert.pem");

    // Check if the file exists
    if path.exists() {
        info!("Successfully created file at: {:?}", path);
        return Some(path);
    }

    error!("Failed to find the file at: {:?}", path);

    let path = PathBuf::from(cart_value);
    if path.exists() {
        info!("Successfully created file at: {:?}", path);
        return Some(path);
    }

    error!("Failed to find the file at: {:?}", path);
    None
}

#[tokio::test]
// Invalid client paramaters for local testing
async fn local_test_invalid_client_url() {
    let _default_guard = init_test();

    let mut args = create_args();

    if let Some(args_mut) = Arc::get_mut(&mut args) {
        args_mut.local_key = true;
    }

    cache_local_config()
        .await
        .expect("Could not cache local config");

    let _test_server = TestServer::start(&args).expect("Could not create new TestServer.");

    let hex_arg = get_config_from_discover_endpoint(URL_DISCOVER).await;

    let ohttp_client = OhttpClientBuilder::new()
        .config(&hex_arg)
        .build()
        .await
        .expect("Could not create new ohttp client builder");

    let url: String = "http://localhost:9443/scoreee".to_string();
    let target_path: String = TARGET_PATH.to_string();
    let headers = None;
    let data = None;
    let form_fields = Some(vec![String::from("file=@../examples/audio.mp3")]);
    let outer_headers = None;

    let response = ohttp_client
        .post(
            &url,
            &target_path,
            &headers,
            &data,
            &form_fields,
            &outer_headers,
        )
        .await
        .unwrap();
    let status = response.status();
    info!("status: {status}");
    assert!(!status.is_success());
}

#[tokio::test]
// Invalid client paramaters for local testing
async fn local_test_invalid_target_path() {
    let _default_guard = init_test();

    let mut args = create_args();

    if let Some(args_mut) = Arc::get_mut(&mut args) {
        args_mut.local_key = true;
    }

    cache_local_config()
        .await
        .expect("Could not cache local config");

    let _test_server = TestServer::start(&args).expect("Could not create new TestServer.");

    let hex_arg = get_config_from_discover_endpoint(URL_DISCOVER).await;

    let ohttp_client = OhttpClientBuilder::new()
        .config(&hex_arg)
        .build()
        .await
        .expect("Could not create new ohttp client builder");

    let url = URL_SCORE.to_string();
    let target_path = "/whisperrr".to_string();
    let headers = None;
    let data = None;
    let form_fields = Some(vec![String::from("file=@../examples/audio.mp3")]);
    let outer_headers = None;

    match ohttp_client
        .post(
            &url,
            &target_path,
            &headers,
            &data,
            &form_fields,
            &outer_headers,
        )
        .await
    {
        Ok(response) => {
            let error_msg = response.text().await.unwrap_or_default();
            error!("Error message: {error_msg}");
            assert!(error_msg.contains("404 Not Found"));
            assert!(error_msg.contains("The requested URL was not found on the server."));
        }
        Err(_) => {
            panic!("This should never happen!");
        }
    }
}

#[tokio::test]
// Invalid client paramaters for local testing
async fn local_test_invalid_target_file() {
    let _default_guard = init_test();

    let mut args = create_args();

    if let Some(args_mut) = Arc::get_mut(&mut args) {
        args_mut.local_key = true;
    }

    cache_local_config()
        .await
        .expect("Could not cache local config");

    let _test_server = TestServer::start(&args).expect("Could not create new TestServer.");

    let hex_arg = get_config_from_discover_endpoint(URL_DISCOVER).await;

    let ohttp_client = OhttpClientBuilder::new()
        .config(&hex_arg)
        .build()
        .await
        .expect("Could not create new ohttp client builder");

    let url = URL_SCORE.to_string();
    let target_path = TARGET_PATH.to_string();
    let headers = None;
    let data = None;
    let form_fields = Some(vec![String::from("file=@../examples/audioo.mp3")]);
    let outer_headers = None;

    if ohttp_client
        .post(
            &url,
            &target_path,
            &headers,
            &data,
            &form_fields,
            &outer_headers,
        )
        .await
        .is_ok()
    {
        panic!("This should never happen!");
    }
}

const DEFAULT_KMS_URL_CLIENT: &str = "https://accconfinferenceprod.confidential-ledger.azure.com";
const DEFAULT_KMS_URL_SERVER: &str =
    "https://accconfinferenceprod.confidential-ledger.azure.com/app/key";

async fn get_kms_cert() -> Option<PathBuf> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // Equivalent to -k in curl
        .build()
        .expect("reqwest::Client::builder() failed");

    let response = client
        .get("https://accconfinferenceprod.confidential-ledger.azure.com/node/network")
        .send()
        .await
        .expect("reqwest::Client::get() failed");

    let body: Value = response.json().await.expect("Failed to read response");
    info!("body = {:?}", body);

    // Accessing the "service_certificate" field
    if let Value::Map(map) = body {
        for (key, value) in map {
            if let Value::Text(key_str) = key {
                info!("Key: {}", key_str);
                if key_str == "service_certificate" {
                    if let Value::Text(value_str) = value {
                        info!("service_certificate: {}", value_str);

                        return get_service_cert_path_from_str(&value_str);
                    }
                }
            }
        }
        error!("service_certificate not found or not in expected format");
    }

    None
}

#[tokio::test]
async fn kms_test_basic() {
    let _default_guard = init_test();

    let mut args = create_args();

    if let Some(args_mut) = Arc::get_mut(&mut args) {
        args_mut.maa_url = Some(String::from(DEFAULT_MAA_URL));
        args_mut.kms_url = Some(String::from(DEFAULT_KMS_URL_SERVER));
    }

    let _test_server = TestServer::start(&args).expect("Could not create new TestServer.");

    let kms_url = Some(String::from(DEFAULT_KMS_URL_CLIENT));
    let kms_cert = get_kms_cert().await;
    let ohttp_client = OhttpClientBuilder::new()
        .kms_url(&kms_url)
        .kms_cert(&kms_cert)
        .build()
        .await
        .expect("Could not create new ohttp client builder");

    let url: String = URL_SCORE.to_string();
    let target_path: String = TARGET_PATH.to_string();
    let headers = None;
    let data = None;
    let form_fields = Some(vec![String::from("file=@../examples/audio.mp3")]);
    let outer_headers = None;

    let mut response = ohttp_client
        .post(
            &url,
            &target_path,
            &headers,
            &data,
            &form_fields,
            &outer_headers,
        )
        .await
        .expect("Could not post to scoring endpoint");

    let status = response.status();
    info!("status: {status}");
    assert!(status.is_success());

    while let Some(chunk) = response
        .chunk()
        .await
        .expect("Could not get chunked response")
    {
        let chunk = std::str::from_utf8(&chunk).expect("Could not get chunk");
        info!("{chunk}");
    }
}

const DEFAULT_KMS_URL_CLIENT_INVALID: &str =
    "https://accconfinferenceprodbad.confidential-ledger.azure.com";

#[tokio::test]
// Invalid kms url set for client
async fn kms_test_invalid_kms_url() {
    let _default_guard = init_test();

    let kms_url = Some(String::from(DEFAULT_KMS_URL_CLIENT_INVALID));
    let kms_cert = get_kms_cert().await;
    if OhttpClientBuilder::new()
        .kms_url(&kms_url)
        .kms_cert(&kms_cert)
        .build()
        .await
        .is_ok()
    {
        panic!("This should never happen!")
    }
}

const KMS_URL_SERVER_DEBUG: &str =
    "https://accconfinferencedebug.confidential-ledger.azure.com/app/key";

#[tokio::test]
// mismatched KMS for client and server
async fn kms_test_mismatched_kms_url() {
    let _default_guard = init_test();

    let mut args = create_args();

    if let Some(args_mut) = Arc::get_mut(&mut args) {
        args_mut.maa_url = Some(String::from(DEFAULT_MAA_URL));
        args_mut.kms_url = Some(String::from(KMS_URL_SERVER_DEBUG));
    }

    let _test_server = TestServer::start(&args).expect("Could not create new TestServer.");

    let kms_url = Some(String::from(DEFAULT_KMS_URL_CLIENT));
    let kms_cert = get_kms_cert().await;
    let ohttp_client = OhttpClientBuilder::new()
        .kms_url(&kms_url)
        .kms_cert(&kms_cert)
        .build()
        .await
        .expect("Could not create new ohttp client builder");

    let url: String = URL_SCORE.to_string();
    let target_path: String = TARGET_PATH.to_string();
    let headers = None;
    let data = None;
    let form_fields = Some(vec![String::from("file=@../examples/audio.mp3")]);
    let outer_headers = None;

    let response = ohttp_client
        .post(
            &url,
            &target_path,
            &headers,
            &data,
            &form_fields,
            &outer_headers,
        )
        .await
        .expect("Could not post to scoring endpoint");

    let status = response.status();
    info!("status: {status}");
    assert!(!status.is_success());
}

#[tokio::test]
async fn test_maa_invalid_url() {
    let mut attestation_client = AttestationClient::new().unwrap();
    let maa_url = "https://invalid-maa-url.com";
    let result = fetch_maa_token(&mut attestation_client, maa_url);
    assert!(result.is_err());
}

const TPM_EVENT_LOG_PATH: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";
fn event_in_tpm_event_log(search_string: &str) -> bool {
    let mut file = File::open(TPM_EVENT_LOG_PATH)
        .unwrap_or_else(|_| panic!("Failed to open {TPM_EVENT_LOG_PATH}"));
    let mut buffer = Vec::new();
    let _ = file
        .read_to_end(&mut buffer)
        .unwrap_or_else(|_| panic!("Failed to read {TPM_EVENT_LOG_PATH}"));
    let search_bytes = search_string.as_bytes();
    buffer
        .windows(search_bytes.len())
        .any(|window| window == search_bytes)
}

#[tokio::test]
async fn test_maa_valid_urls() {
    const OS_IMAGE_IDENTITY_EVENTNAME: &str = "os-image-identity";
    const NODE_POLICY_IDENTITY_EVENTNAME: &str = "node-policy-identity";
    let os_identity_event_present = event_in_tpm_event_log(OS_IMAGE_IDENTITY_EVENTNAME);
    let node_policy_event_present = event_in_tpm_event_log(NODE_POLICY_IDENTITY_EVENTNAME);

    let mut attestation_client = AttestationClient::new().unwrap();
    let maa_urls = std::env::var("TEST_MAA_URLS").unwrap();
    let maa_urls = maa_urls.split(',').collect::<Vec<&str>>();
    // loop over maa_url list
    // check MAA attestation succeeds
    // and, if os identity and node policy claims are present in TPM event log, they should be present in claims returned by MAA
    for url in maa_urls {
        let result = fetch_maa_token(&mut attestation_client, url);
        assert!(result.is_ok());
        let token = result.unwrap();
        // valid MAA JWT is dot separated list of header.payload.signature
        let token_arr: Vec<&str> = token.split('.').collect();
        assert!(token_arr.len() == 3);
        let payload_b64 = token_arr[1];
        let claims = URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
        let claims = String::from_utf8(claims).unwrap();
        if os_identity_event_present {
            assert!(claims.contains(OS_IMAGE_IDENTITY_EVENTNAME));
        }
        if node_policy_event_present {
            assert!(claims.contains(NODE_POLICY_IDENTITY_EVENTNAME));
        }
    }
}
