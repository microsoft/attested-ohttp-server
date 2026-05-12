FROM rust:1.94 AS builder

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get upgrade -y && apt-get install -yq openssl libssl-dev libtss2-dev

WORKDIR /usr/src/ohttp
COPY . .
RUN cargo install --path azure-attestation-proxy --debug