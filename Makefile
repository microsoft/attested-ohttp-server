KMS ?= https://accconfinferenceproduction.confidential-ledger.azure.com
MAA ?= https://maanosecureboottestyfu.eus.attest.azure.net
REQUEST_ID ?= "12345678-1234-5678-1234-567812345678"

export TARGET ?= http://127.0.0.1:3000
export TARGET_PATH ?= '/whisper'
export SCORING_ENDPOINT ?= 'http://localhost:9443/score'

export INPUT_DIR ?= $(CURDIR)/examples
export MOUNTED_INPUT_DIR ?= /test
export INPUT_FILE ?= audio.mp3
export INJECT_HEADERS ?= openai-internal-enableasrsupport
export DETACHED ?= 

# Build commands

build-server:
	cargo build --bin ohttp-server

build-attestation-proxy:
	cargo build --bin azure-attestation-proxy

build-whisper-container:
	docker build -f docker/whisper/Dockerfile -t whisper-api ./docker/whisper

build-attestation-proxy-builder:
	docker build -f docker/attestation-proxy-builder/Dockerfile -t attestation-proxy-builder .

build-server-container:
	docker build -f docker/server/Dockerfile -t attested-ohttp-server .

build-client-container:
	docker build -f external/attested-ohttp-client/docker/Dockerfile -t attested-ohttp-client external/attested-ohttp-client/

build: build-attestation-proxy-builder build-server-container build-client-container build-whisper-container

format-checks:
	cargo fmt --all -- --check --config imports_granularity=Crate
	cargo clippy --tests --no-default-features --features rust-hpke

# Containerized server deployments

run-server-container: 
	docker compose -f ./docker/docker-compose-server.yml up

run-server-container-cvm:
	docker run -e TARGET=${TARGET} --network=host \
	-e MAA_URL=${MAA} -e KMS_URL=${KMS}/app/key -e INJECT_HEADERS=${INJECT_HEADERS} \
	--mount type=bind,source=/var/run/gpu-attestation,target=/var/run/gpu-attestation \
	--mount type=bind,source=/var/run/azure-attestation-proxy,target=/var/run/azure-attestation-proxy \
	attested-ohttp-server

run-attestation-proxy-builder:
	docker run --name attestation-proxy-builder_tmp attestation-proxy-builder
	mkdir -p azure-attestation-proxy/bin
	docker cp attestation-proxy-builder_tmp:/usr/local/cargo/bin/azure-attestation-proxy azure-attestation-proxy/bin/azure-attestation-proxy
	docker rm attestation-proxy-builder_tmp
	chmod 755 azure-attestation-proxy/bin/azure-attestation-proxy

install-attestation-proxy: build-attestation-proxy-builder run-attestation-proxy-builder
	cp azure-attestation-proxy/libazguestattestation.so.1.0.5 /usr/bin
	ln -sf /usr/bin/libazguestattestation.so.1.0.5 /usr/lib/libazguestattestation.so.1
	ln -sf /usr/bin/libazguestattestation.so.1.0.5 /usr/lib/libazguestattestation.so
	ldconfig
	azure-attestation-proxy/install.sh --enable-service

test-attestation-proxy:
	curl --unix-socket /var/run/azure-attestation-proxy/azure-attestation-proxy.sock http://localhost/attest \
	 -H "maa: ${MAA}" -H "x-ms-request-id: ${REQUEST_ID}"


# Whisper deployments

run-whisper:
	docker run ${DETACHED} --network=host whisper-api 

run-whisper-faster: 
	docker run --network=host fedirz/faster-whisper-server:latest-cuda

run-server-faster:
	docker compose -f ./docker/docker-compose-faster-whisper.yml up

service-cert:
	curl -s -k ${KMS}/node/network | jq -r .service_certificate > service_cert.pem

# Server and whisper deployment

run-server-whisper:
	docker compose -f ./docker/docker-compose-whisper.yml up ${DETACHED}

run-server-whisper-gpu:
	docker compose -f ./docker/docker-compose-whisper-gpu.yml up ${DETACHED}

# Containerized client deployments

run-client-container:
	docker run --net=host --volume ${INPUT_DIR}:${MOUNTED_INPUT_DIR} attested-ohttp-client \
	$(SCORING_ENDPOINT) -F "file=@${MOUNTED_INPUT_DIR}/${INPUT_FILE}" --target-path ${TARGET_PATH}

run-client-container-cvm:
	docker run --net=host --volume ${INPUT_DIR}:${MOUNTED_INPUT_DIR} -e KMS_URL=${KMS} attested-ohttp-client \
	$(SCORING_ENDPOINT) -F "file=@${MOUNTED_INPUT_DIR}/${INPUT_FILE}" --target-path ${TARGET_PATH}

run-client-container-aoai:
	docker run --volume ${INPUT_DIR}:${MOUNTED_INPUT_DIR} -e KMS_URL=${KMS} attested-ohttp-client \
	${SCORING_ENDPOINT} -F "file=@${MOUNTED_INPUT_DIR}/${INPUT_FILE}" --target-path ${TARGET_PATH} \
	-O "api-key: ${API_KEY}" -F "response_format=json"