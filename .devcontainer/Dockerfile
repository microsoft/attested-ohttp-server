FROM rust:1.75
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -yq \
ca-certificates coreutils curl git make mercurial \
build-essential clang llvm libclang-dev lld \
gyp ninja-build pkg-config zlib1g-dev libssl-dev libtss2-dev
