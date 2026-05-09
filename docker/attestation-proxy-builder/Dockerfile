FROM rust:1.86 AS builder

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get upgrade -y && apt-get install -yq openssl libssl-dev

WORKDIR /usr/src/ohttp
COPY . .
RUN cargo install --path azure-attestation-proxy --debug
