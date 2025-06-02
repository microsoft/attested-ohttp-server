FROM rust:1.85.1 AS builder

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get upgrade -y && apt-get install -yq openssl libssl-dev libtss2-dev

WORKDIR /usr/src/ohttp
COPY . .
RUN ln -s /usr/src/ohttp/ohttp-server/libazguestattestation.so.1.0.5 /usr/lib/libazguestattestation.so
RUN cargo install --path ohttp-server --debug

FROM ubuntu:22.04
RUN apt-get update && apt-get upgrade -y && apt-get install -y ca-certificates openssl libssl-dev libtss2-dev && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/ohttp-server /usr/local/bin/ohttp-server
COPY ./ohttp-server/libazguestattestation.so.1.0.5 /usr/bin/
RUN ln -s /usr/bin/libazguestattestation.so.1.0.5 /usr/lib/libazguestattestation.so.1
COPY --chmod=755 ./docker/server/run.sh .
CMD ["./run.sh"]
