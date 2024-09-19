ORG                     := automatethethingsllc
TARGET_OS               := linux
TARGET_ARCH             := $(shell uname -m)

ARCH                    := $(shell go env GOARCH)
OS                      := $(shell go env GOOS)
LONG_BITS               := $(shell getconf LONG_BIT)

GOBIN                   := $(shell dirname `which go`)
PYTHONBIN               ?= /usr/bin/python3.8
PIPBIN                  ?= pip

ARM_CC                  ?= arm-linux-gnueabihf-gcc
ARM_CC_64				?= aarch64-linux-gnu-gcc

REPO                    ?= github.com
PACKAGE                 ?= go-trusted-platform
APPNAME                 ?= trusted-platform
APPBIN                  ?= tpadm

APP_VERSION       		?= $(shell git describe --tags --abbrev=0)
GIT_TAG                 = $(shell git describe --tags)
GIT_HASH                = $(shell git rev-parse HEAD)
GIT_BRANCH              = $(shell git branch --show-current)	
BUILD_DATE              = $(shell date '+%Y-%m-%d_%H:%M:%S')

VERSION_FILE            ?= VERSION

ENV                     ?= dev
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

ATTESTATION_DIR    ?= attestation
ATTESTOR_DIR       ?= $(ATTESTATION_DIR)/attestor
VERIFIER_DIR       ?= $(ATTESTATION_DIR)/verifier
PLATFORM_DIR       ?= trusted-data
CONFIG_DIR         ?= $(PLATFORM_DIR)/etc
LOG_DIR            ?= $(PLATFORM_DIR)/log
CA_DIR             ?= $(PLATFORM_DIR)/ca
ATTESTATION_CONFIG ?= attestation.yaml

VERIFIER_CA        ?= $(VERIFIER_DIR)/$(PLATFORM_DIR)/ca
VERIFIER_CONF      ?= $(VERIFIER_DIR)/$(CONFIG_DIR)/config.yaml
VERIFIER_DOMAIN    ?= verifier.example.com
VERIFIER_HOSTNAME  ?= www

ATTESTOR_CA        ?= $(ATTESTOR_DIR)/$(PLATFORM_DIR)/ca
ATTESTOR_CONF      ?= $(ATTESTOR_DIR)/$(CONFIG_DIR)/config.yaml
ATTESTOR_HOSTNAME  ?= www
ATTESTOR_DOMAIN    ?= attestor.example.com

CONFIG_YAML        ?= config.debug.pkcs11.yaml

PROTO_DIR          ?= proto
PROTOC             ?= protoc

ROOT_CA            ?= root-ca
INTERMEDIATE_CA    ?= intermediate-ca
DOMAIN             ?= example.com

ANSIBLE_USER       ?= ansible

LUKS_KEYFILE       ?= luks.key
LUKS_SIZE          ?= 5G
LUKS_TYPE          ?= luks2

SOFTHSM_DIR        ?= /usr/local/bin
SOFTHSM_LIB        ?= /usr/local/lib/softhsm/libsofthsm2.so
SOFTHSM_TOKEN_DIR  ?= /var/lib/softhsm/tokens
SOFTHSM_CONFIG     ?= configs/softhsm2.conf


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
	go install -v golang.org/x/tools/gopls@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2


swagger:
	swag init \
		--dir pkg/webservice,pkg/webservice/v1/router,pkg/webservice/v1/response,pkg/app,pkg/config \
		--generalInfo webserver_v1.go \
		--parseDependency \
		--parseInternal \
		--parseDepth 1 \
		--output public_html/swagger

swagger-ui:
	mkdir -p public_html/swagger
	git clone --depth=1 https://github.com/swagger-api/swagger-ui.git && \
		cp -R swagger-ui/dist/* public_html/swagger && \
		rm -rf swagger-ui


# x86_64
build:
	cd pkg; \
	$(GOBIN)/go build -o ../$(APPBIN) -ldflags="-w -s ${LDFLAGS}"

build-debug:
	cd pkg; \
	$(GOBIN)/go build -gcflags='all=-N -l' -o ../$(APPBIN) -gcflags='all=-N -l' -ldflags="-w -s ${LDFLAGS}"

build-static:
	cd pkg; \
	$(GOBIN)/go build -o ../$(APPBIN) --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

build-debug-static:
	cd pkg; \
	$(GOBIN)/go build -o ../$(APPBIN) -gcflags='all=-N -l' --ldflags '-extldflags -static -v ${LDFLAGS}'


# x86
build-x86:
	cd pkg; \
	GOARCH=386 $(GOBIN)/go build -o ../$(APPBIN) -ldflags="-w -s ${LDFLAGS}"

build-x86-debug:
	cd pkg; \
	GOARCH=386 $(GOBIN)/go build -gcflags='all=-N -l' -o ../$(APPBIN) -gcflags='all=-N -l' -ldflags="-w -s ${LDFLAGS}"

build-x86-static:
	cd pkg; \
	GOARCH=386 $(GOBIN)/go build -o ../$(APPBIN) --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

build-x86-debug-static:
	cd pkg; \
	GOARCH=386 $(GOBIN)/go build -o ../$(APPBIN) -gcflags='all=-N -l' --ldflags '-extldflags -static -v ${LDFLAGS}'


# ARM 32-bit
build-arm:
	cd pkg; \
	CC=$(ARM_CC) CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 \
	$(GOBIN)/go build -o ../$(APPBIN) -ldflags="-w -s ${LDFLAGS}"

build-arm-static:
	cd pkg; \
	CC=$(ARM_CC) CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 \
	$(GOBIN)/go build -v -a -o ../$(APPBIN) -v --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

build-arm-debug:
	cd pkg; \
	CC=$(ARM_CC) CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 \
	$(GOBIN)/go build -gcflags "all=-N -l" -o ../$(APPBIN) --ldflags="-v $(LDFLAGS)"

build-arm-debug-static:
	cd pkg; \
	CC=$(ARM_CC) CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 \
	$(GOBIN)/go build -gcflags "all=-N -l" -v -a -o ../$(APPBIN) -v --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'


# ARM 64-bit
build-arm64:
	cd pkg; \
	CC=$(ARM_CC_64) CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -o ../$(APPBIN) -ldflags="-w -s ${LDFLAGS}"

build-arm64-static:
	cd pkg; \
	CC=$(ARM_CC_64) APPBIN=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -o ../$(APPBIN) --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

build-arm64-debug:
	cd pkg; \
	CC=$(ARM_CC_64) CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -gcflags "all=-N -l" -o ../$(APPBIN) --ldflags="$(LDFLAGS)"

build-arm64-debug-static:
	cd pkg; \
	CC=$(ARM_CC_64) CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -gcflags "all=-N -l" -o ../$(APPBIN) --ldflags '-extldflags -static -v ${LDFLAGS}'


build-dev: clean build-debug
	sudo chown $(USER):$(USER) /dev/tpmrm0
	-sudo chown $(USER):$(USER) /sys/kernel/security/tpm0/binary_bios_measurements
	mkdir -p $(PLATFORM_DIR)/etc/
	cp configs/platform/config.dev.yaml config.yaml
	cp configs/softhsm.conf $(PLATFORM_DIR)/etc/softhsm.conf
	cp configs/platform/config.debug.yaml pkg/config.yaml
	cp -R public_html pkg/


config:
	mkdir -p pkg/$(PLATFORM_DIR)/etc/
	cp configs/platform/$(CONFIG_YAML) pkg/config.yaml
	cp configs/softhsm.conf pkg/trusted-data/etc/softhsm.conf


clear-auth:
	sudo tpm2_changeauth -c e -p test
	sudo tpm2_changeauth -c o -p test
	sudo tpm2_changeauth -c l -p test


clean:
	cd pkg; \
	$(GOBIN)/go clean
	rm -rf \
		$(APPBIN) \
		/usr/local/bin/$(APPBIN) \
		$(PLATFORM_DIR) \
		$(ATTESTATION_DIR) \
		pkg/$(PLATFORM_DIR) \
		pkg/config.yaml \
		pkg/public_html \
		pkg/ca/testdata \
		pkg/platform/testdata \
		pkg/store/blob/testdata \
		pkg/store/certstore/testdata \
		pkg/store/keystore/testdata \
		pkg/store/keystore/pkcs8/testdata \
		pkg/store/keystore/pkcs11/testdata \
		pkg/store/keystore/tpm2/testdata \
		pkg/tpm2/testdata \
		pkg/tpm2/blobs \
		pkg/ca/testdata \
		pkg/tpm2/testdata \
		config.yaml


test: test-tpm test-crypto test-store test-webservice test-cli

test-cli: test-tpm-cli test-ca-cli test-platform-cli

test-tpm-cli:
	cd pkg/cmd/tpm && go test -v -run ^Test_EK$
	cd pkg/cmd/tpm && go test -v -run ^Test_EK_Certificate$
	cd pkg/cmd/tpm && go test -v -run ^Test_SRK$
	cd pkg/cmd/tpm && go test -v -run ^Test_SealUnseal$
	cd pkg/cmd/tpm && go test -v -run ^Test_Provision$
	cd pkg/cmd/tpm && go test -v -run ^Test_Info$

test-ca-cli:
	cd pkg/cmd/ca && go test -v -run ^Test_Certificate$
	cd pkg/cmd/ca && go test -v -run ^Test_Info$
	cd pkg/cmd/ca && go test -v -run ^Test_Init$
	cd pkg/cmd/ca && go test -v -run ^Test_Install$
	cd pkg/cmd/ca && go test -v -run ^Test_Issue$
	cd pkg/cmd/ca && go test -v -run ^Test_Revoke$

test-platform-cli:
	cd pkg/cmd/platform && go test -v -run ^Test_Install$
	cd pkg/cmd/platform && go test -v -run ^Test_Keyring$
	cd pkg/cmd/platform && go test -v -run ^Test_Policy$
	cd pkg/cmd/platform && go test -v -run ^Test_Provision$

test-ca:
	cd pkg/ca && \
		go test -v -run ^TestInit$ && \
		go test -v -run ^TestPasswordComplexity$ && \
		go test -v -run ^TestImportIssuingCAs$ && \
		go test -v -run ^TestDownloadDistribuitionCRLs$ && \
		go test -v -run ^TestIssueCertificateWithPassword$ && \
		go test -v -run ^TestIssueCertificateWithoutPassword$ && \
		go test -v -run ^TestIssueCertificate_CA_RSA_WITH_LEAF_ECDSA$ && \
		go test -v -run ^TestRSAGenerateAndSignCSR_Then_VerifyAndRevoke$

test-tpm:
	cd pkg/tpm2 && go test -v

test-crypto:
	cd pkg/crypto/aesgcm && go test -v
	cd pkg/crypto/argon2 && go test -v

test-store: test-store-pkcs11 test-store-tpm2 test-store-datastore
	cd pkg/store/keystore && go test -v
	cd pkg/store/keystore/pkcs8 && go test -v

test-store-pkcs11:
	cd pkg/store/keystore/pkcs11 && \
		go test -v -run ^TestConnection$ && \
		go test -v -run ^TestSignEd25519_WithoutFileIntegrityCheck$ && \
		go test -v -run ^TestSignECDSA_WithoutFileIntegrityCheck$ && \
		go test -v -run ^TestSignRSASSA_WithoutFileIntegrityCheck$ && \
		go test -v -run ^TestSignRSAPSS_WithoutFileIntegrityCheck$ && \
		go test -v -run ^TestSignRSAPSS_WithFileIntegrityCheck$ && \
		go test -v -run ^TestInitHSM$

test-store-tpm2:
	cd pkg/store/keystore/tpm2 && \
		go test -v -run ^TestKeyStoreNotInitialized$ && \
		go test -v -run ^TestKeyStoreInitialization$ && \
		go test -v -run ^TestSignerRSA_PSS$ && \
		go test -v -run ^TestSignerRSA_PKCS1v15$ && \
		go test -v -run ^TestSignerECDSA$ && \
		go test -v -run ^TestRSA_PKCS1v15_WithPasswordWithoutPolicy$ && \
		go test -v -run ^TestKeyStoreGenerateRSAWithPolicy$ && \
		go test -v -run ^TestRSA_PSS_WithPasswordWithoutPolicy$

test-store-datastore:
	cd pkg/store/datastore && \
		go test -v
	cd pkg/store/datastore/kvstore && \
		go test -v

test-webservice: test-webservice-jwt

test-webservice-jwt:
	cd pkg/webservice/v1/jwt && \
		go test -v -run ^TestSigningMethodRS$ && \
		go test -v -run ^TestSigningMethodPS$ && \
		go test -v -run ^TestSigningMethodES$ && \
		go test -v -run ^TestSigningMethodES_Ed25519$

proto:
	cd pkg/$(ATTESTATION_DIR) && $(PROTOC) \
		--go_out=. \
		--go_opt=paths=source_relative \
    	--go-grpc_out=. \
		--go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/attestation.proto

install: luks-create ansible-install ansible-setup
uninstall: uninstall-ansible


# Verifier
verifier-init:
	mkdir -p $(VERIFIER_DIR)/$(CONFIG_DIR)
	cp configs/platform/$(ATTESTATION_CONFIG) $(VERIFIER_CONF)
	sed -i 's/$(DOMAIN)/$(VERIFIER_DOMAIN)/' $(VERIFIER_CONF)
	sed -i 's|trusted-data/etc/softhsm.conf|$(shell pwd)/$(VERIFIER_DIR)/$(CONFIG_DIR)/softhsm.conf|' $(VERIFIER_CONF)
	sed -i 's/- __VERIFIER_CA__/-  $(VERIFIER_HOSTNAME).$(VERIFIER_DOMAIN)/' $(VERIFIER_CONF)
	cp configs/softhsm.conf $(VERIFIER_DIR)/$(CONFIG_DIR)
	sed -i 's|trusted-data/softhsm2|$(shell pwd)/$(VERIFIER_DIR)/$(PLATFORM_DIR)|' $(VERIFIER_DIR)/$(CONFIG_DIR)/softhsm.conf

verifier-no-clean: build verifier-init
	cd $(VERIFIER_DIR) && \
		../../$(APPBIN) verifier \
			--debug \
			--config-dir $(CONFIG_DIR) \
			--platform-dir $(PLATFORM_DIR) \
			--log-dir $(LOG_DIR)

verifier: verifier-clean verifier-init build
	cd $(VERIFIER_DIR) && \
		../../$(APPBIN) verifier \
			--debug \
			--init \
			--config-dir $(CONFIG_DIR) \
			--platform-dir $(PLATFORM_DIR) \
			--log-dir $(LOG_DIR) \
			--ca-dir $(PLATFORM_DIR)/ca \
			--attestor $(ATTESTOR_HOSTNAME).$(ATTESTOR_DOMAIN) \
			--raw-so-pin 123456 \
            --raw-pin 123456

verifier-clean: 
	rm -rf \
		$(VERIFIER_DIR)/$(PLATFORM_DIR) \
		pkg/$(PLATFORM_DIR)

verifier-cert-chain:
	openssl verify \
		-CAfile $(VERIFIER_CA)/$(ROOT_CA).$(DOMAIN)/$(ROOT_CA).$(DOMAIN).crt \
		-untrusted $(VERIFIER_CA)/$(INTERMEDIATE_CA).$(DOMAIN)/$(INTERMEDIATE_CA).$(DOMAIN).crt \
		$(VERIFIER_CA)/$(INTERMEDIATE_CA).$(DOMAIN)/issued/$(VERIFIER_HOSTNAME).$(DOMAIN)/$(VERIFIER_HOSTNAME).$(DOMAIN).crt


# Attestor
attestor-init:
	mkdir -p $(ATTESTOR_DIR)/$(CONFIG_DIR)
	cp configs/platform/$(ATTESTATION_CONFIG) $(ATTESTOR_CONF)
	sed -i 's/$(DOMAIN)/$(ATTESTOR_DOMAIN)/' $(ATTESTOR_CONF)
	sed -i 's|trusted-data/etc/softhsm.conf|$(shell pwd)/$(ATTESTOR_DIR)/$(CONFIG_DIR)/softhsm.conf|' $(ATTESTOR_CONF)
	sed -i 's/- __VERIFIER_CA__/- $(ROOT_CA).$(VERIFIER_DOMAIN)/' $(ATTESTOR_CONF)
	cp configs/softhsm.conf $(ATTESTOR_DIR)/$(CONFIG_DIR)
	sed -i 's|trusted-data/softhsm2|$(shell pwd)/$(ATTESTOR_DIR)/$(PLATFORM_DIR)|' $(ATTESTOR_DIR)/$(CONFIG_DIR)/softhsm.conf


attestor-clean: 
	rm -rf \
		$(ATTESTOR_DIR)/$(PLATFORM_DIR) \
		pkg/$(PLATFORM_DIR)

attestor-no-clean: build attestor-init
	cd $(ATTESTOR_DIR) && \
		../../$(APPBIN) attestor \
			--debug \
			--config-dir $(CONFIG_DIR) \
			--platform-dir $(PLATFORM_DIR) \
			--log-dir $(PLATFORM_DIR)/$(LOG_DIR)

attestor: attestor-clean attestor-init build
	cd $(ATTESTOR_DIR) && \
		../../$(APPBIN) attestor \
			--debug \
			--init \
			--config-dir $(CONFIG_DIR) \
			--platform-dir $(PLATFORM_DIR) \
			--log-dir $(LOG_DIR) \
			--ca-dir $(PLATFORM_DIR)/ca \
			--raw-so-pin 123456 \
            --raw-pin 123456

attestor-verify-cert-chain:
	openssl verify \
		-CAfile $(ATTESTOR_CA)/$(ROOT_CA).$(ATTESTOR_DOMAIN)/x509/$(ROOT_CA).$(ATTESTOR_DOMAIN).tpm2.rsa.cer \
		-untrusted $(ATTESTOR_CA)/$(INTERMEDIATE_CA).$(ATTESTOR_DOMAIN)/x509/$(INTERMEDIATE_CA).$(ATTESTOR_DOMAIN).tpm2.rsa.cer \
		$(ATTESTOR_CA)/$(INTERMEDIATE_CA).$(ATTESTOR_DOMAIN)/x509/$(ATTESTOR_HOSTNAME).$(ATTESTOR_DOMAIN).tpm2.rsa.cer

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
webservice: build-debug config
	cd pkg && ../$(APPBIN) webservice --init

webservice-verify-tls:
	cd $(ATTESTATION_DIR) && \
	openssl s_client \
		-connect localhost:8443 \
		-showcerts \
		-servername localhost \
		-CAfile pkg/$(PLATFORM_DIR)/ca/$(INTERMEDIATE_CA).$(DOMAIN)/x509/$(ROOT_CA).$(DOMAIN).pkcs8.rsa.crt \
		| openssl x509 -noout -text


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

# Docker
docker-load-builder: build-debug
	docker build --load \
		-t $(APPNAME)-builder \
		-f build/docker/$(APPNAME)-builder/Dockerfile .

docker-run: build-debug
	docker run -it --privileged \
	-v .:/mnt \
	-v /dev/bus/usb:/dev/bus/usb \
	trusted-platform-builder bash

docker-run-builder-with-usb:
	docker run -it --rm --privileged \
		-v /dev/bus/usb:/dev/bus/usb \
		# -v /sys/devices/:/sys/devices/ \
		# -v /dev/hidraw4:/dev/hidraw4 \
		$(APPNAME)-builder \
		bash
		# /usr/local/bin/yubico-piv-tool -astatus

docker-run-builder2:
	docker run -ti --rm \
		-v /dev/bus/usb:/dev/bus/usb \
		-v /sys/bus/usb/:/sys/bus/usb/ \
		-v /sys/devices/:/sys/devices/ \
		-v /dev/hidraw4:/dev/hidraw4 \
		--device /dev/usb:/dev/usb \
		--device /dev/bus/usb:/dev/bus/usb \
		--privileged \
		$(APPNAME)-builder \
		/usr/local/bin/yubico-piv-tool -astatus
