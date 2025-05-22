FROM rust:1.84.1 AS builder

WORKDIR /app

COPY ../.. .

RUN cargo install --path /app/attested-ohttp-server/cvm-attestation-service/cvm-attestation --debug

FROM ubuntu:22.04 as minimal

RUN mkdir -p /app/bin

# Copy the release binary from the builder stage
COPY --from=builder /app/cvm-attestation/target/debug/cvm-attestation /app/bin

COPY --from=builder /app/cvm-attestation/libazguestattestation.so.1.0.5 /usr/bin/
RUN ln -s /usr/bin/libazguestattestation.so.1.0.5 /usr/lib/libazguestattestation.so.1

