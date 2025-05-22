## Installation
sudo ./install.sh --enable-service

## Testing
curl --unix-socket /var/run/cvm-attestation/cvm-attestation.sock http://localhost/attest -H "maa: https://confinfermaaeus2test.eus2.test.attest.azure.net"

sudo cargo test

## Debugging
systemctl status cvm-attestation.service
journalctl -xeu cvm-attestation.service