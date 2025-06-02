FROM rust:1.85.1 AS builder

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get upgrade -y && apt-get install -yq openssl libssl-dev libtss2-dev

WORKDIR /usr/src/ohttp
COPY . .
RUN ln -s /usr/src/ohttp/azure-attestation-proxy/libazguestattestation.so.1.0.5 /usr/lib/libazguestattestation.so
RUN cargo install --path azure-attestation-proxy --debug