KMS ?= https://accconfinferenceprod.confidential-ledger.azure.com
MAA ?= https://confinfermaaeus2test.eus2.test.attest.azure.net

export TARGET ?= http://127.0.0.1:3000
export TARGET_PATH ?= '/whisper'
export SCORING_ENDPOINT ?= 'http://localhost:9443/score'

export INPUT_DIR ?= ${PWD}/examples
export MOUNTED_INPUT_DIR ?= /test
export INPUT_FILE ?= audio.mp3
export INJECT_HEADERS ?= openai-internal-enableasrsupport
export DETACHED ?= 

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
	cargo clippy --tests --no-default-features --features rust-hpke

# Containerized server deployments

run-server-container: 
	docker compose -f ./docker/docker-compose-server.yml up

run-server-container-cvm: 
	docker run --privileged --net=host \
	-e TARGET=${TARGET} -e MAA_URL=${MAA} -e KMS_URL=${KMS}/app/key -e INJECT_HEADERS=${INJECT_HEADERS} \
	--mount type=bind,source=/sys/kernel/security,target=/sys/kernel/security \
	--device /dev/tpmrm0  attested-ohttp-server

run-server-container-cvm-sudo: 
	sudo docker run --privileged --net=host \
	-e TARGET=${TARGET} -e MAA_URL=${MAA} -e KMS_URL=${KMS}/app/key -e INJECT_HEADERS=${INJECT_HEADERS} \
	--mount type=bind,source=/sys/kernel/security,target=/sys/kernel/security \
	--device /dev/tpmrm0  attested-ohttp-server

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

run-client-container-cvm-sudo:
	sudo docker run --net=host --volume ${INPUT_DIR}:${MOUNTED_INPUT_DIR} -e KMS_URL=${KMS} attested-ohttp-client \
	$(SCORING_ENDPOINT) -F "file=@${MOUNTED_INPUT_DIR}/${INPUT_FILE}" --target-path ${TARGET_PATH}

run-client-container-aoai:
	docker run --volume ${INPUT_DIR}:${MOUNTED_INPUT_DIR} -e KMS_URL=${KMS} attested-ohttp-client \
	${SCORING_ENDPOINT} -F "file=@${MOUNTED_INPUT_DIR}/${INPUT_FILE}" --target-path ${TARGET_PATH} \
	-O "api-key: ${API_KEY}" -F "response_format=json"