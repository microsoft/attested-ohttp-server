## Installation
sudo make install-attestation-proxy

## Testing
sudo make test-attestation-proxy

sudo RUST_LOG=trace cargo test -- tests

## Debugging
systemctl status azure-attestation-proxy.service
journalctl -xeu azure-attestation-proxy.service