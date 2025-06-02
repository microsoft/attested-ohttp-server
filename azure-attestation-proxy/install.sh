#!/usr/bin/env bash
#
# A script to build and install the CVM attestation service.
#
# Usage:
#   cd azure-attestation-proxy
#   sudo bash ./install.sh [--enable-service]
#

set -e

# Default values for arguments
ENABLE_SERVICE=0

# Parse command-line arguments
for arg in "$@"; do
    case "$arg" in
        --enable-service)
            ENABLE_SERVICE=1
            ;;
        *)
            echo "Invalid argument: $arg"
            echo "Usage: $0 [--enable-service]"
            exit 1
            ;;
    esac
done

# Go to the directory of this script
cd "$(dirname "$0")"

CVM_ATTESTATION_PATH="/usr/local/bin/azure-attestation-proxy"
SERVICE_NAME="azure-attestation-proxy"

# Stop the existing systemd service BEFORE copying the new binary if it's running
if [ "$ENABLE_SERVICE" = "1" ]; then
    echo "Stopping existing '$SERVICE_NAME' service (if running)..."
    sudo systemctl stop "$SERVICE_NAME" || true
fi

# Install the binary
echo "Installing azure-attestation-proxy-service to $CVM_ATTESTATION_PATH..."
sudo mkdir -p "$CVM_ATTESTATION_PATH"
sudo cp ./bin/azure-attestation-proxy "$CVM_ATTESTATION_PATH"
sudo chmod +x "$CVM_ATTESTATION_PATH/azure-attestation-proxy"

echo "Installation complete!"
echo "Binary installed at: $CVM_ATTESTATION_PATH/azure-attestation-proxy"

# Enable and start the service
if [ "$ENABLE_SERVICE" = "1" ]; then
    echo "Setting up systemd service for '$SERVICE_NAME'..."
    sudo cp azure-attestation-proxy.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable "$SERVICE_NAME"
    sudo systemctl start "$SERVICE_NAME"
    echo "Service '$SERVICE_NAME' is enabled and running."
fi