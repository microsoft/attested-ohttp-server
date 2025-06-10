pub type Res<T> = Result<T, Box<dyn std::error::Error>>;

pub const DEFAULT_KMS_URL: &str =
    "https://accconfinferenceproduction.confidential-ledger.azure.com/app/key";
pub const DEFAULT_MAA_URL: &str = "https://maanosecureboottestyfu.eus.attest.azure.net";
pub const DEFAULT_GPU_ATTESTATION_SOCKET: &str = "/var/run/gpu-attestation/gpu-attestation.sock";

use bhttp::Mode;
use clap::Parser;
use reqwest::Url;
use std::net::SocketAddr;

#[derive(Debug, Parser, Clone)]
#[command(name = "ohttp-server", about = "Serve oblivious HTTP requests.")]
pub struct Args {
    /// The address to bind to.
    #[arg(default_value = "127.0.0.1:9443")]
    pub address: SocketAddr,

    /// When creating message/bhttp, use the indeterminate-length form.
    #[arg(long, short = 'n', alias = "indefinite")]
    pub indeterminate: bool,

    /// Target server
    #[arg(long, short = 't', default_value = "http://127.0.0.1:8000")]
    pub target: Url,

    /// Use locally generated key, for testing without KMS
    #[arg(long, short = 'l')]
    pub local_key: bool,

    /// MAA endpoint
    #[arg(long, short = 'm')]
    pub maa_url: Option<String>,

    /// KMS endpoint
    #[arg(long, short = 's')]
    pub kms_url: Option<String>,

    /// GPU Attestation socket path
    #[arg(long, short = 'g', default_value = DEFAULT_GPU_ATTESTATION_SOCKET)]
    pub gpu_attestation_socket: Option<String>,

    #[arg(long, short = 'i')]
    pub inject_request_headers: Vec<String>,
}

impl Args {
    pub fn mode(&self) -> Mode {
        if self.indeterminate {
            Mode::IndeterminateLength
        } else {
            Mode::KnownLength
        }
    }
}
