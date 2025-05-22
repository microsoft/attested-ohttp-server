#!/usr/bin/env bash
#
# A script to build and install the CVM attestation service.
#
# Usage:
#   cd cvm-attestation-service
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

IMAGE_NAME="cvm-attestation-build"
CVM_ATTESTATION_PATH="/usr/local/bin/cvm-attestation"
SERVICE_NAME="cvm-attestation"

cargo install --path cvm-attestation --debug

# Build the binary in a Docker container
#echo "Building Docker image for CVM attestation service..."
#docker build -f Dockerfile -t "$IMAGE_NAME" ../.. --no-cache

#echo "Creating a temporary container..."
#CONTAINER_ID=$(docker create "$IMAGE_NAME")

#echo "Copying compiled binary from container to host..."
#mkdir -p ./bin
#rm -rf ./bin/*
#docker cp "$CONTAINER_ID:/app/bin/cvm-attestation" ./bin/

#echo "Removing temporary container..."
#docker rm "$CONTAINER_ID"

# Set permissions
#chmod +x ./bin/cvm-attestation

# Stop the existing systemd service BEFORE copying the new binary if it's running
if [ "$ENABLE_SERVICE" = "1" ]; then
    echo "Stopping existing '$SERVICE_NAME' service (if running)..."
    sudo systemctl stop "$SERVICE_NAME" || true
fi

# Install the binary
echo "Installing cvm-attestation-service to $CVM_ATTESTATION_PATH..."
sudo mkdir -p "$CVM_ATTESTATION_PATH"
sudo cp ../target/debug/cvm-attestation "$CVM_ATTESTATION_PATH"
sudo chmod +x "$CVM_ATTESTATION_PATH/cvm-attestation"

echo "Installation complete!"
echo "Binary installed at: $CVM_ATTESTATION_PATH/cvm-attestation"

# Enable and start the service
if [ "$ENABLE_SERVICE" = "1" ]; then
    echo "Setting up systemd service for '$SERVICE_NAME'..."
    sudo cp cvm-attestation.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable "$SERVICE_NAME"
    sudo systemctl start "$SERVICE_NAME"
    echo "Service '$SERVICE_NAME' is enabled and running."
fi
