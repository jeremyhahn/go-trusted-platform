ORG                     := automatethethingsllc
TARGET_OS               := linux
TARGET_ARCH             := $(shell uname -m)

ARCH                    := $(shell go env GOARCH)
OS                      := $(shell go env GOOS)
LONG_BITS               := $(shell getconf LONG_BIT)

GOBIN                   := $(shell dirname `which go`)
PYTHONBIN               ?= python3
PIPBIN                  ?= pip

ARM_CC                  ?= arm-linux-gnueabihf-gcc-8
ARM_CC_64				?= aarch64-linux-gnu-gcc

REPO                    ?= github.com
PACKAGE                 ?= go-trusted-platform
APPNAME                 ?= trusted-platform

APP_VERSION       		?= $(shell git describe --tags --abbrev=0)
GIT_TAG                 = $(shell git describe --tags)
GIT_HASH                = $(shell git rev-parse HEAD)
GIT_BRANCH              = $(shell git branch --show-current)	
BUILD_DATE              = $(shell date '+%Y-%m-%d_%H:%M:%S')

VERSION_FILE            ?= VERSION

ifneq ("$(wildcard $(VERSION_FILE))","")
    APP_VERSION = $(shell cat $(VERSION_FILE))
else
    APP_VERSION = $(shell git branch --show-current)
endif

LDFLAGS=-X github.com/jeremyhahn/$(PACKAGE)/app.Name=${APPNAME}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/app.Repository=${REPO}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/app.Package=${PACKAGE}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/app.GitBranch=${GIT_BRANCH}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/app.GitHash=${GIT_HASH}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/app.GitTag=${GIT_TAG}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/app.BuildUser=${USER}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/app.BuildDate=${BUILD_DATE}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/app.Version=${APP_VERSION}

GREEN=\033[0;32m
NO_COLOR=\033[0m

ATTESTATION_DIR ?= attestation
ATTESTOR_DIR    ?= $(ATTESTATION_DIR)/attestor
VERIFIER_DIR    ?= $(ATTESTATION_DIR)/verifier
PLATFORM_DIR    ?= platform
CONFIG_DIR      ?= $(PLATFORM_DIR)/etc
LOG_DIR         ?= $(PLATFORM_DIR)/log
CA_DIR          ?= $(PLATFORM_DIR)/ca

VERIFIER_CONF   ?= $(VERIFIER_DIR)/$(CONFIG_DIR)/config.yaml
VERIFIER_CA     ?= $(VERIFIER_DIR)/$(PLATFORM_DIR)/ca

ATTESTOR_CONF   ?= $(ATTESTOR_DIR)/$(CONFIG_DIR)/config.yaml
ATTESTOR_CA     ?= $(ATTESTOR_DIR)/$(PLATFORM_DIR)/ca

PROTO_DIR       ?= proto
PROTOC          ?= protoc

ROOT_CA         ?= root-ca
INTERMEDIATE_CA ?= intermediate-ca
DOMAIN          ?= example.com

VERIFIER_HOSTNAME ?= verifier
ATTESTOR_HOSTNAME ?= attestor

CONFIG_YAML  ?= config.dev.yaml

ANSIBLE_USER     ?= ansible

# The TPM Endorsement Key file name. This is set to a default value that
# aligns with the EK cert name used in the tpm2_getekcertificate docs:
# https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_getekcertificate.1.md
EK_CERT_NAME ?= ECcert.bin


.PHONY: deps build build-debug build-static build-debug-static clean test initlog \
	swagger verifier attestor proto

default: proto build

env:
	@echo "ORG: \t\t\t$(ORG)"
	@echo "TARGET_OS: \t\t$(TARGET_OS)"
	@echo "TARGET_ARCH: \t\t$(TARGET_ARCH)"
	@echo "ARCH: \t\t\t$(ARCH)"
	@echo "OS: \t\t\t$(OS)"
	@echo "LONG_BITS: \t\t$(LONG_BITS)"
	@echo "GOBIN: \t\t\t$(GOBIN)"
	@echo "REPO: \t\t\t$(REPO)"
	@echo "PACKAGE: \t\t$(PACKAGE)"
	@echo "APP_VERSION: \t\t$(APP_VERSION)"
	@echo "GIT_TAG: \t\t$(GIT_TAG)"
	@echo "GIT_HASH: \t\t$(GIT_HASH)"
	@echo "GIT_BRANCH: \t\t$(GIT_BRANCH)"
	@echo "BUILD_DATE: \t\t$(BUILD_DATE)"
	@echo "VERSION_FILE: \t\t$(VERSION_FILE)"
	@echo "ATTESTATION_DIR: \t$(ATTESTATION_DIR)"
	@echo "ATTESTOR_DIR: \t\t$(ATTESTOR_DIR)"
	@echo "VERIFIER_DIR: \t\t$(VERIFIER_DIR)"
	@echo "PLATFORM_DIR: \t\t$(PLATFORM_DIR)"
	@echo "CONFIG_DIR: \t\t$(CONFIG_DIR)"
	@echo "LOG_DIR: \t\t$(LOG_DIR)"
	@echo "CA_DIR: \t\t$(CA_DIR)"
	@echo "VERIFIER_CONF: \t\t$(VERIFIER_CONF)"
	@echo "VERIFIER_CA: \t\t$(VERIFIER_CA)"
	@echo "ATTESTOR_CONF: \t\t$(ATTESTOR_CONF)"
	@echo "ATTESTOR_CA: \t\t$(ATTESTOR_CA)"
	@echo "PROTO_DIR: \t\t$(PROTO_DIR)"
	@echo "PROTOC: \t\t$(PROTOC)"
	@echo "ROOT_CA: \t\t$(ROOT_CA)"
	@echo "INTERMEDIATE_CA: \t$(INTERMEDIATE_CA)"
	@echo "DOMAIN: \t\t$(DOMAIN)"
	@echo "VERIFIER_HOSTNAME: \t$(VERIFIER_HOSTNAME)"
	@echo "ATTESTOR_HOSTNAME: \t$(ATTESTOR_HOSTNAME)"
	@echo "CONFIG_YAML: \t\t$(CONFIG_YAML)"

deps:
	go get

swagger:
	swag init \
		--dir webservice,webservice/v1/router,webservice/v1/response,service,model,app,config \
		--generalInfo webserver_v1.go \
		--parseDependency \
		--parseInternal \
		--parseDepth 1 \
		--output public_html/swagger

# x86_64
build:
	$(GOBIN)/go build -o $(APPNAME) -ldflags="-w -s ${LDFLAGS}"

build-debug:
	$(GOBIN)/go build -gcflags='all=-N -l' -o $(APPNAME) -gcflags='all=-N -l' -ldflags="-w -s ${LDFLAGS}"

build-static:
	$(GOBIN)/go build -o $(APPNAME) --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

build-debug-static:
	$(GOBIN)/go build -o $(APPNAME) -gcflags='all=-N -l' --ldflags '-extldflags -static -v ${LDFLAGS}'


# x86
build-x86:
	GOARCH=386 $(GOBIN)/go build -o $(APPNAME) -ldflags="-w -s ${LDFLAGS}"

build-x86-debug:
	GOARCH=386 $(GOBIN)/go build -gcflags='all=-N -l' -o $(APPNAME) -gcflags='all=-N -l' -ldflags="-w -s ${LDFLAGS}"

build-x86-static:
	GOARCH=386 $(GOBIN)/go build -o $(APPNAME) --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

build-x86-debug-static:
	GOARCH=386 $(GOBIN)/go build -o $(APPNAME) -gcflags='all=-N -l' --ldflags '-extldflags -static -v ${LDFLAGS}'


# ARM 32-bit
build-arm:
	CC=$(ARM_CC) CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 \
	$(GOBIN)/go build -o $(APP) -ldflags="-w -s ${LDFLAGS}"

build-arm-static:
	CC=$(ARM_CC) CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 \
	$(GOBIN)/go build -v -a -o $(APP) -v --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

build-arm-debug:
	CC=$(ARM_CC) CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 \
	$(GOBIN)/go build -gcflags "all=-N -l" -o $(APP) --ldflags="-v $(LDFLAGS)"

build-arm-debug-static:
	CC=$(ARM_CC) CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 \
	$(GOBIN)/go build -gcflags "all=-N -l" -v -a -o $(APP) -v --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'


# ARM 64-bit
build-arm64:
	CC=$(ARM_CC_64) CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -o $(APP) -ldflags="-w -s ${LDFLAGS}"

build-arm64-static:
	CC=$(ARM_CC_64) CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -o $(APP) --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

build-arm64-debug:
	CC=$(ARM_CC_64) CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -gcflags "all=-N -l" -o $(APP) --ldflags="$(LDFLAGS)"

build-arm64-debug-static:
	CC=$(ARM_CC_64) CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -gcflags "all=-N -l" -o $(APP) --ldflags '-extldflags -static -v ${LDFLAGS}'


clean:
	$(GOBIN)/go clean
	rm -rf $(APPNAME) \
		$(APPNAME).log \
		/usr/local/bin/$(APPNAME) \
		db/ \
		logs \
		$(CA_DIR) \
		tpm2/certs \
		tpm2/$(EK_CERT_NAME) \
		$(PLATFORM_DIR)/ca \
		$(ATTESTOR_DIR)/platform \
		$(VERIFIER_DIR)/platform


test: test-ca test-tpm

test-ca:
	cd ca && go test -v -run TestRSA
	cd ca && go test -v -run TestECC

test-tpm:
	cd tpm2 && go test -v


proto:
	cd $(ATTESTATION_DIR) && $(PROTOC) \
		--go_out=. \
		--go_opt=paths=source_relative \
    	--go-grpc_out=. \
		--go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/attestation.proto


# Certificate Authority
ca-verify-all: ca-root-verify ca-intermediate-verify ca-server-=verify

ca-show-all: ca-root-show ca-intermediate-show ca-server-show

ca-root-verify:
	cd $(CA_DIR) && \
		openssl verify -CAfile $(ROOT_CA)/$(ROOT_CA).crt $(ROOT_CA)/$(ROOT_CA).crt

ca-root-show:
	cd $(CA_DIR) && \
		openssl x509 -in $(ROOT_CA)/$(ROOT_CA).crt -text -noout

ca-intermediate-verify:
	cd $(CA_DIR) && \
		openssl verify \
			-CAfile $(ROOT_CA)/$(ROOT_CA).crt \
			$(INTERMEDIATE_CA)/$(INTERMEDIATE_CA).crt

ca-intermediate-show:
	cd $(CA_DIR) && \
		openssl x509 -in $(INTERMEDIATE_CA)/$(INTERMEDIATE_CA).crt -text -noout

ca-server-verify:
	cd $(CA_DIR) && \
		openssl verify \
			-CAfile $(ROOT_CA)/$(ROOT_CA).crt \
			-untrusted $(INTERMEDIATE_CA)/$(INTERMEDIATE_CA).crt \
			$(INTERMEDIATE_CA)/issued/localhost/localhost.crt

ca-server-show:
	cd $(CA_DIR) && \
		openssl x509 -in $(INTERMEDIATE_CA)/issued/localhost/localhost.crt -text -noout

ca-decrypt-root-key:
	openssl rsa -in $(CA_DIR)/$(ROOT_CA)/$(ROOT_CA).key -out $(ROOT_CA).pem

ca-decrypt-intermediate-key:
	openssl rsa -in $(CA_DIR)/$(INTERMEDIATE_CA)/$(INTERMEDIATE_CA).key -out $(INTERMEDIATE_CA).pem


# Verifier
verifier-init:
	mkdir -p $(VERIFIER_DIR)/$(CONFIG_DIR)
	cp $(CONFIG_YAML) $(VERIFIER_CONF)
	sed -i 's/domain: $(DOMAIN)/domain: $(VERIFIER_HOSTNAME).$(DOMAIN)/' $(VERIFIER_CONF)
	sed -i 's/- $(DOMAIN)/- $(VERIFIER_HOSTNAME).$(DOMAIN)/' $(VERIFIER_CONF)
	cp $(EK_CERT_NAME) $(VERIFIER_DIR)

verifier-no-clean: build verifier-init
	cd $(VERIFIER_DIR) && \
		../../trusted-platform verifier \
			--debug \
			--config-dir $(CONFIG_DIR) \
			--platform-dir $(PLATFORM_DIR) \
			--log-dir $(LOG_DIR)

verifier: verifier-clean build verifier-init
	cd $(VERIFIER_DIR) && \
		../../trusted-platform verifier \
			--debug \
			--config-dir $(CONFIG_DIR) \
			--platform-dir $(PLATFORM_DIR) \
			--log-dir $(LOG_DIR)
			--attestor $(ATTESTOR_HOSTNAME).$(DOMAIN)

verifier-clean: 
	rm -rf \
		$(VERIFIER_DIR)/$(PLATFORM_DIR) \
		$(VERIFIER_DIR)/$(EK_CERT_NAME)

verifier-cert-chain:
	cd $(ATTESTATION_DIR) && \
	openssl verify \
		-CAfile $(VERIFIER_CA)/$(ROOT_CA).$(DOMAIN)/$(ROOT_CA).$(DOMAIN).crt \
		-untrusted $(VERIFIER_CA)/$(INTERMEDIATE_CA).$(DOMAIN)/$(INTERMEDIATE_CA).$(DOMAIN).crt \
		$(VERIFIER_CA)/$(INTERMEDIATE_CA).$(DOMAIN)/issued/$(VERIFIER_HOSTNAME).$(DOMAIN)/$(VERIFIER_HOSTNAME).$(DOMAIN).crt


# Attestor
attestor-init:
	mkdir -p $(ATTESTOR_DIR)/$(CONFIG_DIR)
	cp $(CONFIG_YAML) $(ATTESTOR_CONF)
	sed -i 's/domain: $(DOMAIN)/domain: $(ATTESTOR_HOSTNAME).$(DOMAIN)/' $(ATTESTOR_CONF)
	sed -i 's/- $(DOMAIN)/- $(ATTESTOR_HOSTNAME).$(DOMAIN)/' $(ATTESTOR_CONF)
	cp $(EK_CERT_NAME) $(ATTESTOR_DIR)

attestor-clean: 
	rm -rf \
		$(ATTESTOR_DIR)/$(PLATFORM_DIR) \
		$(ATTESTOR_DIR)/$(EK_CERT_NAME)

attestor-no-clean: build attestor-init
	cd $(ATTESTOR_DIR) && \
		../../trusted-platform attestor \
			--debug \
			--config-dir $(CONFIG_DIR) \
			--platform-dir $(PLATFORM_DIR) \
			--log-dir $(PLATFORM_DIR)/$(LOG_DIR)

attestor: attestor-clean build attestor-init
	cd $(ATTESTOR_DIR) && \
		../../trusted-platform attestor \
			--debug \
			--config-dir $(CONFIG_DIR) \
			--platform-dir $(PLATFORM_DIR) \
			--log-dir $(LOG_DIR)
#			--password=teGDF!234st

attestor-verify-cert-chain:
	cd $(ATTESTATION_DIR) && \
	openssl verify \
		-CAfile $(ATTESTOR_CA)/$(ROOT_CA).$(DOMAIN)/$(ROOT_CA).$(DOMAIN).crt \
		-untrusted $(ATTESTOR_CA)/$(INTERMEDIATE_CA).$(DOMAIN)/$(INTERMEDIATE_CA).$(DOMAIN).crt \
		$(ATTESTOR_CA)/$(INTERMEDIATE_CA).$(DOMAIN)/issued/$(ATTESTOR_HOSTNAME).$(DOMAIN)/$(ATTESTOR_HOSTNAME).$(DOMAIN).crt

attestor-verify-tls:
	cd $(ATTESTATION_DIR) && \
	openssl s_client \
		-connect localhost:8082 \
		-showcerts \
		-servername localhost \
		-CAfile $(ATTESTOR_CA)/$(INTERMEDIATE_CA).$(DOMAIN)/$(INTERMEDIATE_CA).$(DOMAIN).bundle.crt \
		| openssl x509 -noout -text


# Web Services
webservice-verify-tls:
	cd $(ATTESTATION_DIR) && \
	openssl s_client \
		-connect localhost:8081 \
		-showcerts \
		-servername localhost \
		-CAfile $(ATTESTOR_CA)/$(INTERMEDIATE_CA).$(DOMAIN)/trusted-root/$(ROOT_CA).$(DOMAIN).crt \
		| openssl x509 -noout -text


# Ansible
ansible-install:
	$(PYTHONBIN) -m $(PIPBIN) install --upgrade pip
	$(PYTHONBIN) -m $(PIPBIN) install --user $(ANSIBLE_USER)
	$(PYTHONBIN) -m $(PIPBIN) install --upgrade --user $(ANSIBLE_USER)

