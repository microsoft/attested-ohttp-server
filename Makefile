KMS ?= https://accconfinferencedebug.confidential-ledger.azure.com
MAA ?= https://maanosecureboottestyfu.eus.attest.azure.net

# MODEL can be whisper_opensource, whisper_aoai or whisper_aoai_local
MODEL ?= whisper_opensource
ifeq ($(MODEL), whisper_opensource)
	export TARGET ?= http://127.0.0.1:3000
	export TARGET_PATH ?= '/whisper'
	export SCORING_ENDPOINT ?= 'http://localhost:9443/score'
else ifeq ($(MODEL), whisper_aoai)
	TARGET ?= http://127.0.0.1:5001
	TARGET_PATH ?= '/v1/engines/whisper/audio/transcriptions'
	SCORING_ENDPOINT ?= 'http://localhost:9443/score'
else
	echo "Unknown model"
endif
	
export INPUT ?= ${PWD}/examples/audio.mp3
export MOUNTED_INPUT ?= /examples/audio.mp3
export INJECT_HEADERS ?= openai-internal-enableasrsupport

# Build commands

build-server:
	cargo build --bin ohttp-server

build-whisper-container:
	docker build -f docker/whisper/Dockerfile -t whisper-api ./docker/whisper

build-server-container:
	docker build -f docker/server/Dockerfile -t attested-ohttp-server .

build-client-container:
	docker build -f external/attested-ohttp-client/docker/Dockerfile -t attested-ohttp-client external/attested-ohttp-client/

build: build-server-container build-client-container build-whisper-container

format-checks:
	cargo fmt --all -- --check --config imports_granularity=Crate
	cargo clippy --tests --no-default-features --features rust-hpke,server

# Containerized server deployments

run-server-container: 
	docker compose -f ./docker/docker-compose-server.yml up

run-server-container-cvm: 
	docker run --privileged --net=host \
	-e TARGET=${TARGET} -e MAA_URL=${MAA} -e KMS_URL=${KMS}/app/key -e INJECT_HEADERS=${INJECT_HEADERS} \
	--mount type=bind,source=/sys/kernel/security,target=/sys/kernel/security \
	--device /dev/tpmrm0  attested-ohttp-server

# Whisper deployments

run-whisper:
	docker run --network=host whisper-api 

run-whisper-faster: 
	docker run --network=host fedirz/faster-whisper-server:latest-cuda

run-server-faster:
	docker compose -f ./docker/docker-compose-faster-whisper.yml up

service-cert:
	curl -s -k ${KMS}/node/network | jq -r .service_certificate > service_cert.pem

# Server and whisper deployment

run-server-whisper:
	docker compose -f ./docker/docker-compose-whisper.yml up

run-server-whisper-gpu:
	docker compose -f ./docker/docker-compose-whisper-gpu.yml up

# Containerized client deployments

run-client-container:
	docker run --net=host \
	attested-ohttp-client $(SCORING_ENDPOINT) -F "file=@${MOUNTED_INPUT}" --target-path ${TARGET_PATH}

run-client-container-aoai:
	docker run --volume -e KMS_URL=${KMS} \
	attested-ohttp-client ${SCORING_ENDPOINT} -F "file=@${MOUNTED_INPUT}" --target-path ${TARGET_PATH} \
	-O "api-key: ${API_KEY}" -F "response_format=json"