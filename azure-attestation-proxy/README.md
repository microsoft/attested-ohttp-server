## Installation
sudo make install-attestation-proxy

## Testing
sudo make test-attestation-proxy

sudo make run-whisper &
RUST_LOG=trace sudo -E env "PATH=$PATH"  cargo test -- --test tests::test_attestation_proxy

## Debugging
systemctl status azure-attestation-proxy.service
journalctl -xeu azure-attestation-proxy.service