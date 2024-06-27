ORG                     := automatethethingsllc
TARGET_OS               := linux
TARGET_ARCH             := $(shell uname -m)

ARCH                    := $(shell go env GOARCH)
OS                      := $(shell go env GOOS)
LONG_BITS               := $(shell getconf LONG_BIT)

GOBIN                   := $(shell dirname `which go`)

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

CLONE_HOST              ?= github.com
CLONE_OWNER             ?= jeremyhahn
CLONE_APP_NAME          ?= new-app
CLONE_PACKAGE           ?= go-$(CLONE_APP_NAME)
CLONE_DIR               ?= ../$(CLONE_PACKAGE)

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
	@echo "CLONE_HOST: \t\t$(CLONE_HOST)"
	@echo "CLONE_OWNER: \t\t$(CLONE_OWNER)"
	@echo "CLONE_APP_NAME: \t$(CLONE_APP_NAME)"
	@echo "CLONE_PACKAGE: \t\t$(CLONE_PACKAGE)"
	@echo "CLONE_DIR: \t\t$(CLONE_DIR)"
	@echo "VERSION_FILE: \t\t$(VERSION_FILE)"

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
		pki/tpm2/$(EK_CERT_NAME)


test: test-ca test-tpm

test-ca:
	cd ca && go test -v -run TestRSA
	cd ca && go test -v -run TestECC

test-tpm:
	cd tpm2 && go test -v


proto:
	cd attestation && protoc \
		--go_out=. \
		--go_opt=paths=source_relative \
    	--go-grpc_out=. \
		--go-grpc_opt=paths=source_relative \
		proto/attestation.proto


# Certificate Authority
ca-verify-all: ca-root-verify ca-intermediate-verify ca-server-=verify

ca-show-all: ca-root-show ca-intermediate-show ca-server-show

ca-root-verify:
	cd ca/certs && \
		openssl verify -CAfile root-ca/root-ca.crt root-ca/root-ca.crt

ca-root-show:
	cd ca/certs && \
		openssl x509 -in root-ca/root-ca.crt -text -noout

ca-intermediate-verify:
	cd ca/certs && \
		openssl verify \
			-CAfile root-ca/root-ca.crt \
			intermediate-ca/intermediate-ca.crt

ca-intermediate-show:
	cd ca/certs && \
		openssl x509 -in intermediate-ca/intermediate-ca.crt -text -noout

ca-server-verify:
	cd ca/certs && \
		openssl verify \
			-CAfile root-ca/root-ca.crt \
			-untrusted intermediate-ca/intermediate-ca.crt \
			intermediate-ca/issued/localhost/localhost.crt

ca-server-show:
	cd ca/certs && \
		openssl x509 -in intermediate-ca/issued/localhost/localhost.crt -text -noout


# Verifier
verifier-init:
	cp config.yaml attestation/verifier
	sed -i 's/domain: example.com/domain: verifier.example.com/' attestation/verifier/config.yaml
	sed -i 's/- example.com/- verifier.example.com/' attestation/verifier/config.yaml
	cp $(EK_CERT_NAME) attestation/verifier

verifier-no-clean: build verifier-init
	cd attestation/verifier && \
		../../trusted-platform verifier \
			--debug \
			--config-dir ./ \
			--data-dir ./db \
			--log-dir ./logs

verifier: verifier-clean build verifier-init
	cd attestation/verifier && \
		../../trusted-platform verifier \
			--debug \
			--data-dir ./db \
			--log-dir ./logs \
			--attestor attestor.example.com

verifier-clean: 
	rm -rf \
		attestation/verifier/logs \
		attestation/verifier/db \
		attestation/verifier/$(EK_CERT_NAME)

verifier-cert-chain:
	cd attestation && \
	openssl verify \
		-CAfile verifier/db/certs/root-ca.example.com/root-ca.example.com.crt \
		-untrusted verifier/db/certs/intermediate-ca.example.com/intermediate-ca.example.com.crt \
		verifier/db/certs/intermediate-ca.example.com/issued/verifier.example.com/verifier.example.com.crt


# Attestor
attestor-init:
	cp config.yaml attestation/attestor
	sed -i 's/domain: example.com/domain: attestor.example.com/' attestation/attestor/config.yaml
	sed -i 's/- example.com/- attestor.example.com/' attestation/attestor/config.yaml
	cp $(EK_CERT_NAME) attestation/attestor/

attestor-clean: 
	rm -rf \
		attestation/attestor/logs \
		attestation/attestor/db \
		attestation/verifier/$(EK_CERT_NAME)

attestor-no-clean: build attestor-init
	cd attestation/attestor && \
		../../trusted-platform attestor \
			--debug \
			--config-dir ./ \
			--data-dir ./db \
			--log-dir ./logs

attestor: attestor-clean build attestor-init
	cd attestation/attestor && \
		../../trusted-platform attestor \
			--debug \
			--config-dir ./ \
			--data-dir ./db \
			--log-dir ./logs

attestor-verify-cert-chain:
	cd attestation && \
	openssl verify \
		-CAfile attestor/db/certs/root-ca.example.com/root-ca.example.com.crt \
		-untrusted attestor/db/certs/intermediate-ca.example.com/intermediate-ca.example.com.crt \
		attestor/db/certs/intermediate-ca.example.com/issued/attestor.example.com/attestor.example.com.crt

attestor-verify-tls:
	cd attestation && \
	openssl s_client \
		-connect localhost:8082 \
		-showcerts \
		-servername localhost \
		-CAfile attestor/db/certs/intermediate-ca.example.com/intermediate-ca.example.com.bundle.crt \
		| openssl x509 -noout -text


# Web Services
webservice-verify-tls:
	cd attestation && \
	openssl s_client \
		-connect localhost:8081 \
		-showcerts \
		-servername localhost \
		-CAfile attestor/db/certs/intermediate-ca.example.com/trusted-root/root-ca.example.com.crt \
		| openssl x509 -noout -text

