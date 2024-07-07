ORG                     := automatethethingsllc
TARGET_OS               := linux
TARGET_ARCH             := $(shell uname -m)

ARCH                    := $(shell go env GOARCH)
OS                      := $(shell go env GOOS)
LONG_BITS               := $(shell getconf LONG_BIT)

GOBIN                   := $(shell dirname `which go`)
PYTHONBIN               ?= /usr/bin/python3.8
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

RPI_HOST                ?= rpi

ifneq ("$(wildcard $(VERSION_FILE))","")
    APP_VERSION = $(shell cat $(VERSION_FILE))
else
    APP_VERSION = $(shell git branch --show-current)
endif

LDFLAGS=-X github.com/jeremyhahn/$(PACKAGE)/pkg/app.Name=${APPNAME}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.Repository=${REPO}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.Package=${PACKAGE}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.GitBranch=${GIT_BRANCH}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.GitHash=${GIT_HASH}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.GitTag=${GIT_TAG}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.BuildUser=${USER}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.BuildDate=${BUILD_DATE}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.Version=${APP_VERSION}

GREEN=\033[0;32m
NO_COLOR=\033[0m

ATTESTATION_ECCERT ?= ../../ECcert.bin
ATTESTATION_DIR    ?= attestation
ATTESTOR_DIR       ?= $(ATTESTATION_DIR)/attestor
VERIFIER_DIR       ?= $(ATTESTATION_DIR)/verifier
PLATFORM_DIR       ?= trusted-data
CONFIG_DIR         ?= $(PLATFORM_DIR)/etc
LOG_DIR            ?= $(PLATFORM_DIR)/log
CA_DIR             ?= $(PLATFORM_DIR)/ca

VERIFIER_CONF      ?= $(VERIFIER_DIR)/$(CONFIG_DIR)/config.yaml
VERIFIER_CA        ?= $(VERIFIER_DIR)/$(PLATFORM_DIR)/ca

ATTESTOR_CONF      ?= $(ATTESTOR_DIR)/$(CONFIG_DIR)/config.yaml
ATTESTOR_CA        ?= $(ATTESTOR_DIR)/$(PLATFORM_DIR)/ca

PROTO_DIR          ?= proto
PROTOC             ?= protoc

ROOT_CA            ?= root-ca
INTERMEDIATE_CA    ?= intermediate-ca
DOMAIN             ?= example.com

VERIFIER_HOSTNAME  ?= verifier
ATTESTOR_HOSTNAME  ?= attestor

CONFIG_YAML        ?= config.dev.yaml

ANSIBLE_USER       ?= ansible

LUKS_KEYFILE       ?= luks.key
LUKS_SIZE          ?= 5G
LUKS_TYPE          ?= luks2

SOFTHSM_DIR        ?= /usr/local/bin
SOFTHSM_LIB        ?= /usr/local/lib/softhsm/libsofthsm2.so
SOFTHSM_TOKEN_DIR  ?= /var/lib/softhsm/tokens
SOFTHSM_CONFIG     ?= configs/softhsm2.conf

TPM2_PTOOL         ?= ../go-trusted-platform-ansible/setup/trusted-data/build/tpm2-pkcs11/tools/tpm2_ptool.py

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
	cd pkg; \
	$(GOBIN)/go build -o ../$(APPNAME) -ldflags="-w -s ${LDFLAGS}"

build-debug:
	cd pkg; \
	$(GOBIN)/go build -gcflags='all=-N -l' -o ../$(APPNAME) -gcflags='all=-N -l' -ldflags="-w -s ${LDFLAGS}"

build-static:
	cd pkg; \
	$(GOBIN)/go build -o ../$(APPNAME) --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

build-debug-static:
	cd pkg; \
	$(GOBIN)/go build -o ../$(APPNAME) -gcflags='all=-N -l' --ldflags '-extldflags -static -v ${LDFLAGS}'


# x86
build-x86:
	cd pkg; \
	GOARCH=386 $(GOBIN)/go build -o ../$(APPNAME) -ldflags="-w -s ${LDFLAGS}"

build-x86-debug:
	cd pkg; \
	GOARCH=386 $(GOBIN)/go build -gcflags='all=-N -l' -o ../$(APPNAME) -gcflags='all=-N -l' -ldflags="-w -s ${LDFLAGS}"

build-x86-static:
	cd pkg; \
	GOARCH=386 $(GOBIN)/go build -o ../$(APPNAME) --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

build-x86-debug-static:
	cd pkg; \
	GOARCH=386 $(GOBIN)/go build -o ../$(APPNAME) -gcflags='all=-N -l' --ldflags '-extldflags -static -v ${LDFLAGS}'


# ARM 32-bit
build-arm:
	cd pkg; \
	CC=$(ARM_CC) CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 \
	$(GOBIN)/go build -o ../$(APP) -ldflags="-w -s ${LDFLAGS}"

build-arm-static:
	cd pkg; \
	CC=$(ARM_CC) CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 \
	$(GOBIN)/go build -v -a -o ../$(APP) -v --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

build-arm-debug:
	cd pkg; \
	CC=$(ARM_CC) CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 \
	$(GOBIN)/go build -gcflags "all=-N -l" -o ../$(APP) --ldflags="-v $(LDFLAGS)"

build-arm-debug-static:
	cd pkg; \
	CC=$(ARM_CC) CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 \
	$(GOBIN)/go build -gcflags "all=-N -l" -v -a -o ../$(APP) -v --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'


# ARM 64-bit
build-arm64:
	cd pkg; \
	CC=$(ARM_CC_64) CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -o ../$(APP) -ldflags="-w -s ${LDFLAGS}"

build-arm64-static:
	cd pkg; \
	CC=$(ARM_CC_64) CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -o ../$(APP) --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

build-arm64-debug:
	cd pkg; \
	CC=$(ARM_CC_64) CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -gcflags "all=-N -l" -o ../$(APP) --ldflags="$(LDFLAGS)"

build-arm64-debug-static:
	cd pkg; \
	CC=$(ARM_CC_64) CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -gcflags "all=-N -l" -o ../$(APP) --ldflags '-extldflags -static -v ${LDFLAGS}'


clean:
	cd pkg; \
	$(GOBIN)/go clean
	rm -rf \
		$(APPNAME) \
		/usr/local/bin/$(APPNAME) \
		$(PLATFORM_DIR) \
		$(ATTESTATION_DIR) \
		pkg/ca/certs \
		pkg/tpm2/certs \
		pkg/tpm2/$(EK_CERT_NAME) \
		pkg/$(EK_CERT_NAME)


test: test-ca test-tpm test-hash

test-ca:
	cd pkg/ca && go test -v

test-tpm:
	cp $(EK_CERT_NAME) pkg/tpm2/
	cd pkg/tpm2 && go test -v

test-pkcs11:
	cd pkg/pkcs11 && go test -v

test-hash:
	cd pkg/hash && go test -v

proto:
	cd pkg/$(ATTESTATION_DIR) && $(PROTOC) \
		--go_out=. \
		--go_opt=paths=source_relative \
    	--go-grpc_out=. \
		--go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/attestation.proto

install: luks-create ansible-install ansible-setup
uninstall: uninstall-ansible


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
	cp configs/platform/$(CONFIG_YAML) $(VERIFIER_CONF)
	sed -i 's/domain: $(DOMAIN)/domain: $(VERIFIER_HOSTNAME).$(DOMAIN)/' $(VERIFIER_CONF)
	sed -i 's/- $(DOMAIN)/- $(VERIFIER_HOSTNAME).$(DOMAIN)/' $(VERIFIER_CONF)

verifier-no-clean: build verifier-init
	cd $(VERIFIER_DIR) && \
		../../trusted-platform verifier \
			--debug \
			--config-dir $(CONFIG_DIR) \
			--platform-dir $(PLATFORM_DIR) \
			--log-dir $(LOG_DIR)

verifier: verifier-clean verifier-init build
	cd $(VERIFIER_DIR) && \
		../../trusted-platform verifier \
			--debug \
			--config-dir $(CONFIG_DIR) \
			--platform-dir $(PLATFORM_DIR) \
			--log-dir $(LOG_DIR) \
			--ca-dir $(PLATFORM_DIR)/ca \
			--ca-password ca-intermediate-password \
			--server-password server-password \
			--ek-cert $(ATTESTATION_ECCERT) \
			--ak-password ak-password \
			--attestor $(ATTESTOR_HOSTNAME).$(DOMAIN)

verifier-clean: 
	rm -rf \
		$(VERIFIER_DIR)/$(PLATFORM_DIR) \
		$(VERIFIER_DIR)/$(EK_CERT_NAME)

verifier-cert-chain:
	openssl verify \
		-CAfile $(VERIFIER_CA)/$(ROOT_CA).$(DOMAIN)/$(ROOT_CA).$(DOMAIN).crt \
		-untrusted $(VERIFIER_CA)/$(INTERMEDIATE_CA).$(DOMAIN)/$(INTERMEDIATE_CA).$(DOMAIN).crt \
		$(VERIFIER_CA)/$(INTERMEDIATE_CA).$(DOMAIN)/issued/$(VERIFIER_HOSTNAME).$(DOMAIN)/$(VERIFIER_HOSTNAME).$(DOMAIN).crt


# Attestor
attestor-init:
	mkdir -p $(ATTESTOR_DIR)/$(CONFIG_DIR)
	cp configs/platform/$(CONFIG_YAML) $(ATTESTOR_CONF)
	sed -i 's/domain: $(DOMAIN)/domain: $(ATTESTOR_HOSTNAME).$(DOMAIN)/' $(ATTESTOR_CONF)
	sed -i 's/- $(DOMAIN)/- $(ATTESTOR_HOSTNAME).$(DOMAIN)/' $(ATTESTOR_CONF)

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

attestor: attestor-clean attestor-init build
	cd $(ATTESTOR_DIR) && \
		../../trusted-platform attestor \
			--debug \
			--config-dir $(CONFIG_DIR) \
			--platform-dir $(PLATFORM_DIR) \
			--log-dir $(LOG_DIR) \
			--ca-dir $(PLATFORM_DIR)/ca \
			--ek-cert $(ATTESTATION_ECCERT) \
			--ca-password ca-intermediate-password \
			--server-password server-password

attestor-verify-cert-chain:
	openssl verify \
		-CAfile $(ATTESTOR_CA)/$(ROOT_CA).$(DOMAIN)/$(ROOT_CA).$(DOMAIN).crt \
		-untrusted $(ATTESTOR_CA)/$(INTERMEDIATE_CA).$(DOMAIN)/$(INTERMEDIATE_CA).$(DOMAIN).crt \
		$(ATTESTOR_CA)/$(INTERMEDIATE_CA).$(DOMAIN)/issued/$(ATTESTOR_HOSTNAME).$(DOMAIN)/$(ATTESTOR_HOSTNAME).$(DOMAIN).crt

attestor-verify-tpm-certs:
	openssl pkeyutl -verify \
		-in $(ATTESTOR_DIR)/$(PLATFORM_DIR)/ca/$(INTERMEDIATE_CA).$(DOMAIN)/blobs/tpm/$(ATTESTOR_HOSTNAME).$(DOMAIN)/$(INTERMEDIATE_CA).$(DOMAIN)/attestation-key.cer.digest \
		-sigfile $(ATTESTOR_DIR)/$(PLATFORM_DIR)/ca/$(INTERMEDIATE_CA).$(DOMAIN)/blobs/tpm/$(ATTESTOR_HOSTNAME).$(DOMAIN)/$(INTERMEDIATE_CA).$(DOMAIN)/attestation-key.cer.sig \
		-inkey $(ATTESTOR_DIR)/$(PLATFORM_DIR)/ca/$(INTERMEDIATE_CA).$(DOMAIN)/$(INTERMEDIATE_CA).$(DOMAIN).key

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



## tpm2-pkcs11
tpm2pkcs11-init:
	$(TPM2_PTOOL) init --path=/tmp
	$(TPM2_PTOOL) addtoken \
		--pid=1 --sopin=mysopin \
		--userpin=myuserpin \
		--label=label --path /tmp
	tpm2pkcs11-tool \
		--label="label" \
		--login \
		--pin myuserpin \
		--change-pin \
		--new-pin mynewpin
		--path /tmp

# https://github.com/tpm2-software/tpm2-pkcs11/blob/master/docs/PKCS11_TOOL.md
tpm2pkcs11-create-key:
	tpm2pkcs11-tool --label="label" --login --pin=mynewpin --keypairgen


# LUKS Encrypted Platform Data Container
luks-create:
	dd if=/dev/zero of=$(PLATFORM_DIR).$(LUKS_TYPE) bs=1 count=0 seek=$(LUKS_SIZE)
	dd if=/dev/urandom of=$(LUKS_KEYFILE) bs=2048 count=8
	sudo cryptsetup luksFormat --type $(LUKS_TYPE) $(PLATFORM_DIR).$(LUKS_TYPE) $(LUKS_KEYFILE)
	sudo cryptsetup luksOpen $(PLATFORM_DIR).$(LUKS_TYPE) $(APPNAME) --key-file $(LUKS_KEYFILE)
	sudo mkfs.ext4 /dev/mapper/$(APPNAME) -L $(PLATFORM_DIR)

luks-mount:
	mkdir -p $(PLATFORM_DIR)
	-sudo cryptsetup luksOpen $(PLATFORM_DIR).$(LUKS_TYPE) $(APPNAME) --key-file $(LUKS_KEYFILE)
	-sudo mount /dev/mapper/$(APPNAME) $(PLATFORM_DIR)
	sudo chown -R $(USER).$(USER) $(PLATFORM_DIR)

luks-umount:
	sudo umount $(PLATFORM_DIR)
	sudo cryptsetup luksClose /dev/mapper/$(APPNAME)
	rm -rf $(PLATFORM_DIR)


# SoftHSM
softhsm-init:
	export SOFTHSM_CONF=$(SOFTHSM_CONFIG); \
	chown $(USER):$(USER) $(SOFTHSM_TOKEN_DIR); \
	$(SOFTHSM_DIR)/softhsm2-util \
		--init-token \
		--slot 0 \
		--label test \
		--so-pin 1234 \
		--pin 5678 ; \
	$(SOFTHSM_DIR)/softhsm2-util --show-slots


# Ansible
ansible-install:
	$(PYTHONBIN) -m venv python-venv
	cd python-venv && \
		./bin/python3 -m pip install --upgrade pip && \
		./bin/python3 -m pip install cryptography==3.0

ansible-setup:
	cd python-venv && \
	ansible-playbook \
		../../go-trusted-platform-ansible/setup/platform-setup.yml \
		-e PLATFORM_DIR=$(PLATFORM_DIR) \
		-e CONFIG_DIR=$(CONFIG_DIR) \
		-e LOG_DIR=$(LOG_DIR) \
		-e CA_DIR=$(CA_DIR) \
		-e platform_dir=$(PLATFORM_DIR) \
		-e config_dir=$(PLATFORM_DIR)/etc \
    	-e log_dir=$(PLATFORM_DIR)/log \
		-e ca_dir=$(PLATFORM_DIR)/ca \
	    -e platform_build_dir=$(PLATFORM_DIR)/build \
		--ask-become-pass

# Raspbery PI
rpi-sync:
	rsync -av --progress \
		../$(PACKAGE) $(RPI_HOST): \
		--exclude ../$(PACKAGE)/.git/

rpi-sync-ansible:
	rsync -av --progress \
		../$(PACKAGE)-ansible $(RPI_HOST): \
		--exclude ../$(PACKAGE)-ansible/.git/

rpi-qemu:
	qemu-system-aarch64 \
		-machine type=raspi3 \
		-m 1024 \
		-kernel vmlinux \
		-initrd initramfs

#  http://localhost:3000/
webapp-run:
	cd public_html/$(APPNAME) && npm run dev
