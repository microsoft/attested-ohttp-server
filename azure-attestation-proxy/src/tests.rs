use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cgpuvm_attest::AttestationClient;
use std::{fs::File, io::Read};

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
