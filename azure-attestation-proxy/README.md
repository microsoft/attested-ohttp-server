## Installation
sudo ./install.sh --enable-service

## Testing
curl --unix-socket /var/run/azure-attestation-proxy/azure-attestation-proxy.sock http://localhost/attest -H "maa: https://confinfermaaeus2test.eus2.test.attest.azure.net" -H "x-ms-request-id: 12345678-1234-5678-1234-567812345678"

sudo RUST_LOG=trace cargo test -- tests

## Debugging
systemctl status azure-attestation-proxy.service
journalctl -xeu azure-attestation-proxy.service