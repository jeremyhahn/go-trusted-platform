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

PLATFORM_DIR             ?= trusted-data
CONFIG_DIR               ?= configs
EXAMPLE_DIR              ?= examples
PLATFORM_CONFIG_DIR      ?= $(CONFIG_DIR)/platform

CONFIG_YAML              ?= config.debug.pkcs11.yaml

ROOT_CA                  ?= root-ca
INTERMEDIATE_CA          ?= intermediate-ca
DOMAIN                   ?= trusted-platform.io

ANSIBLE_USER             ?= ansible

LUKS_KEYFILE             ?= luks.key
LUKS_SIZE                ?= 5G
LUKS_TYPE                ?= luks2

SOFTHSM_DIR              ?= /usr/local/bin
SOFTHSM_LIB              ?= /usr/local/lib/softhsm/libsofthsm2.so
SOFTHSM_TOKEN_DIR        ?= /var/lib/softhsm/tokens
SOFTHSM_CONFIG           ?= configs/softhsm2.conf

WEB_PUBLIC_HTML          ?= public_html
WEB_PACKAGE              ?= $(PACKAGE)-web
WEB_SRC                  ?= ../$(WEB_PACKAGE)

SWAGGER_HOST             ?= $(DOMAIN)

DOCKER_HOME              ?= build/docker
DOCKER_ISO_BUILDER       ?= trusted-platform-iso-builder
DOCKER_ISO_TAG           ?= latest

ISO_NAME                 ?= trusted-platform.iso

PACKER_HOME              ?= build/packer
PACKER_FILE              ?= $(PACKER_HOME)/rpi/raspios-bookworm-arm64.json
PACKER_BUILDER_RASPIOS64 ?= raspios-bookworm-arm64
PACKER_BUILDER_UBUNTU64  ?= ubuntu-20.04.01-arm64
PACKER_BUILDER           ?= $(PACKER_BUILDER_RASPIOS64)

ANSIBLE_HOME             ?= build/ansible
ANSIBLE_ROLES 		     ?= $(ANSIBLE_HOME)/roles/$(APP)
ANSIBLE_FILES            ?= $(ANSIBLE_CROPDROID)/files

RPI_IMAGE_NAME		     ?= $(APPNAME)-$(APP_VERSION)-$(ENV)
RPI_IMAGE_FILENAME       ?= $(RPI_IMAGE_NAME).img
RPI_IMAGE_ARTIFACT       ?= $(PACKER_HOME)/$(RPI_IMAGE_FILENAME)
RPI_SDCARD               ?= /dev/sda
RPI_USER                 ?= jhahn
RPI_HOST                 ?= rpi

VM_DISK_SIZE_MB          ?= 2000

UID                      := $(shell id -u)
GID                      := $(shell id -g)


.PHONY: env run deps swagger swagger-ui build build-debug build-static build-debug-static \
		build-x86 build-x86-debug build-x86-static build-x86-debug-static build-arm \
		build-arm-static build-arm-debug build-arm-debug-static build-arm64 build-arm64-static \
		build-arm64-debug build-arm64-debug-static build-dev build-public-html firefox firefox-debug \
		firefox-bin config clear-auth clean test test-cli test-tpm-cli test-ca-cli test-platform-cli \
		test-ca test-tpm test-crypto test-store test-store-pkcs11 test-store-tpm2 test-store-datastore \
		test-webservice test-webservice-jwt install uninstall luks-create luks-mount luks-umount \
		ansible-install ansible-setup rpi-sync rpi-sync-ansible rpi-qemu docker-load-builder \
		docker-run docker-run-builder-with-usb docker-run-yubico-piv-tool packer packer-builder-arm \
		iso


default: build


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
	@echo "PLATFORM_DIR: \t\t$(PLATFORM_DIR)"
	@echo "CONFIG_DIR: \t\t$(CONFIG_DIR)"
	@echo "LOG_DIR: \t\t$(LOG_DIR)"
	@echo "CA_DIR: \t\t$(CA_DIR)"
	@echo "PROTO_DIR: \t\t$(PROTO_DIR)"
	@echo "PROTOC: \t\t$(PROTOC)"
	@echo "ROOT_CA: \t\t$(ROOT_CA)"
	@echo "INTERMEDIATE_CA: \t$(INTERMEDIATE_CA)"
	@echo "DOMAIN: \t\t$(DOMAIN)"
	@echo "CONFIG_YAML: \t\t$(CONFIG_YAML)"
	@echo "WEB_PUBLIC_HTML: \t\t$(WEB_PUBLIC_HTML)"


run:
	cp $(EXAMPLE_DIR)/config.yaml config.yaml
	./$(APPBIN) webservice \
		--debug \
		--init \
		--platform-dir trusted-data \
		--config-dir trusted-data/etc \
		--log-dir trusted-data/log \
		--ca-dir trusted-data/ca \
		--raw-so-pin 123456 \
		--raw-pin 123456


ensure-root:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Root required, starting sudo session..."; \
		exec sudo $(MAKE) $(MAKECMDGOALS); \
	fi


deps: ensure-root
	go install github.com/swaggo/swag/cmd/swag@latest
	apt-get -y update
	apt-get install -y libssl-dev softhsm2 libsofthsm2


swagger:
	~/go/bin/swag init \
		--dir pkg/webservice,pkg/webservice/v1/jwt,pkg/webservice/v1/router,pkg/webservice/v1/response,pkg/acme/server/handlers,pkg/store/datastore/entities,pkg/acme,pkg/app,pkg/config,pkg/crypto/argon2 \
		--generalInfo webserver_v1.go \
		--parseDependency \
		--parseInternal \
		--parseDepth 1 \
		--output $(WEB_PUBLIC_HTML)/swagger

swagger-ui:
	mkdir -p $(WEB_PUBLIC_HTML)/swagger
	git clone --depth=1 https://github.com/swagger-api/swagger-ui.git && \
		cp -R swagger-ui/dist/* $(WEB_PUBLIC_HTML)/swagger && \
		rm -rf swagger-ui


# x86_64
build:
	cd pkg; \
	CGO_ENABLED=1 $(GOBIN)/go build -o ../$(APPBIN) -ldflags="-w -s ${LDFLAGS}"

build-debug:
	cd pkg; \
	CGO_ENABLED=1 $(GOBIN)/go build -gcflags='all=-N -l' -o ../$(APPBIN) -gcflags='all=-N -l' -ldflags="-w -s ${LDFLAGS}"

build-static:
	cd pkg; \
	CGO_ENABLED=1 $(GOBIN)/go build -o ../$(APPBIN) --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

build-debug-static:
	cd pkg; \
	CGO_ENABLED=1 $(GOBIN)/go build -o ../$(APPBIN) -gcflags='all=-N -l' --ldflags '-extldflags -static -v ${LDFLAGS}'


# x86
build-x86:
	cd pkg; \
	CGO_ENABLED=1 GOARCH=386 $(GOBIN)/go build -o ../$(APPBIN) -ldflags="-w -s ${LDFLAGS}"

build-x86-debug:
	cd pkg; \
	GCGO_ENABLED=1 OARCH=386 $(GOBIN)/go build -gcflags='all=-N -l' -o ../$(APPBIN) -gcflags='all=-N -l' -ldflags="-w -s ${LDFLAGS}"

build-x86-static:
	cd pkg; \
	CGO_ENABLED=1 GOARCH=386 $(GOBIN)/go build -o ../$(APPBIN) --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

build-x86-debug-static:
	cd pkg; \
	CGO_ENABLED=1 GOARCH=386 $(GOBIN)/go build -o ../$(APPBIN) -gcflags='all=-N -l' --ldflags '-extldflags -static -v ${LDFLAGS}'


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
	mkdir -p $(PLATFORM_DIR)/etc/ $(PLATFORM_DIR)/softhsm2 pkg/$(PLATFORM_DIR)/softhsm2
	cp configs/platform/config.dev.yaml config.yaml
	cp configs/softhsm.conf $(PLATFORM_DIR)/etc/softhsm.conf
	cp configs/platform/config.debug.yaml pkg/config.yaml
	cp -R $(WEB_PUBLIC_HTML) pkg/



# Build the public_html directory
build-public-html:
	# Start with a clean directory
	rm -rf $(WEB_PUBLIC_HTML)/ pkg/$(WEB_PUBLIC_HTML)/
	mkdir -p $(WEB_PUBLIC_HTML)/ pkg/$(WEB_PUBLIC_HTML)/
	
	# Build the swagger / OpenAPI docs 
	make swagger
	make swagger-ui
	
	# Configure SwaggerInfo
	sed -i '/var SwaggerInfo = &swag.Spec{/,/}}/c\var SwaggerInfo = \&swag.Spec{\n\tVersion:          "$(APP_VERSION)",\n\tHost:             "$(SWAGGER_HOST)",\n\tBasePath:         "/api/v1",\n\tSchemes:          []string{},\n\tTitle:            "Trusted Platform",\n\tDescription:      "The Trusted Platform RESTful Web Services API",\n\tInfoInstanceName: "swagger",\n\tSwaggerTemplate:  docTemplate,\n\tLeftDelim:        "{{",\n\tRightDelim:       "}}",' $(WEB_PUBLIC_HTML)/swagger/docs.go

	# Configure the web server annotations
	sed -i 's|@version .*|@version $(APP_VERSION)|g' pkg/webservice/webserver_v1.go
	sed -i 's|@host .*|@host $(SWAGGER_HOST)|g' pkg/webservice/webserver_v1.go

	# Copy into the pkg directory for debugging
	-cp -R $(WEB_PUBLIC_HTML)/swagger pkg/$(WEB_PUBLIC_HTML)/	

	# Build the go-trusted-platform-web project
	cd $(WEB_SRC) && \
		yarn build && \
		cp -R out/* ../$(PACKAGE)/$(WEB_PUBLIC_HTML)/

	# Copy into the pkg directory for debugging
	cp -R $(WEB_SRC)/out/* ../$(PACKAGE)/pkg/$(WEB_PUBLIC_HTML)/


firefox:
	sudo mkdir -p /etc/firefox/policies/ /etc/firefox/certificates
	sudo cp configs/firefox/policies.json /etc/firefox/policies/policies.json
	sudo rm -rf /etc/firefox/certificates/*.cer
	sudo cp $(PLATFORM_DIR)/ca/$(ROOT_CA).$(DOMAIN)/x509/*.cer /etc/firefox/certificates
	/usr/bin/firefox https://localhost:8443/

firefox-debug:
	sudo mkdir -p /etc/firefox/policies/ /etc/firefox/certificates /usr/local/share/ca-certificates/
	sudo cp configs/firefox/policies.json /etc/firefox/policies/policies.json
	sudo rm -rf /etc/firefox/certificates/*.cer /usr/local/share/ca-certificates/*.cer
	sudo cp pkg/$(PLATFORM_DIR)/ca/$(ROOT_CA).$(DOMAIN)/x509/*.cer /etc/firefox/certificates
	sudo cp pkg/$(PLATFORM_DIR)/ca/$(ROOT_CA).$(DOMAIN)/x509/*.cer /usr/local/share/ca-certificates/
	sudo update-ca-certificates
	/usr/bin/firefox https://localhost:8443/

firefox-bin:
	/usr/bin/firefox https://localhost:8443/

config:
	mkdir -p pkg/$(PLATFORM_DIR)/etc/ pkg/$(PLATFORM_DIR)/softhsm2
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
		examples/tss/attestor/$(PLATFORM_DIR) \
		examples/tss/verifier/$(PLATFORM_DIR) \
		examples/client/$(PLATFORM_DIR) \
		examples/server/$(PLATFORM_DIR) \
		pkg/$(PLATFORM_DIR) \
		pkg/config.yaml \
		pkg/$(WEB_PUBLIC_HTML) \
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


install: luks-create ansible-install ansible-setup
uninstall: uninstall-ansible


# Web Services
webservice: build-debug config
	cd pkg && ../$(APPBIN) webservice --init

webservice-verify-tls:
	openssl s_client \
		-connect localhost:8443 \
		-showcerts \
		-servername localhost \
		-CAfile pkg/$(PLATFORM_DIR)/ca/$(INTERMEDIATE_CA).$(DOMAIN)/x509/$(ROOT_CA).$(DOMAIN).pkcs8.rsa.pem \
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
	sudo apt-get install python3 pipx docker.io ansible-core
	pipx install ansible ansible-builder

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
	rsync -av --progress ../$(PACKAGE) $(RPI_USER)@$(RPI_HOST): --exclude .git/

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

docker-run-yubico-piv-tool:
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


# Packer
packer:
	PACKER_FILE=$(PACKER_BUILDER).json \
	$(MAKE) packer-build

packer-builder-arm:
	docker run \
		--rm \
		--privileged \
		-v /dev:/dev \
		-v ${HOME}:${HOME} \
		-v ${PWD}:/build:ro \
		-v ${PWD}/build/packer/packer_cache:/build/packer_cache \
		-v ${PWD}/build/packer/output-arm-image:/build/output-arm-image \
		ghcr.io/solo-io/packer-plugin-arm-image build \
			-var ssh_key_src="$(HOME)/.ssh/id_rsa.pub" \
			-var "aws_access_key_id=$(AWS_ACCESS_KEY_ID)" \
			-var "aws_secret_access_key=$(AWS_SECRET_ACCESS_KEY)" \
			-var "aws_region=${AWS_REGION}" \
			-var "aws_profile=${AWS_PROFILE}" \
			-var "local_user=$(USER)" \
			-var "appname=$(APP)" \
			-var "apptype=$(APPTYPE)" \
			-var "appenv=$(ENV)" \
			-var "timezone=$(TIMEZONE)" \
			-var "hostname=$(HOSTNAME)" \
			-var "platform_home=$(DEPLOY_HOME)" \
			-var "eth0_cidr=$(ETH0_CIDR)" \
			-var "eth0_routers=$(ETH0_ROUTERS)" \
			-var "eth0_dns=$(ETH0_DNS)" \
			-var "wlan_cidr=$(WLAN_CIDR)" \
			-var "wlan_routers=$(WLAN_ROUTERS)" \
			-var "wlan_dns=$(WLAN_DNS)" \
			-var "wlan_ssid=$(WLAN_SSID)" \
			-var "wlan_psk=$(WLAN_PSK)" \
			-var "wlan_key_mgmt=$(WLAN_KEY_MGMT)" \
			-var "wlan_country=$(WLAN_COUNTRY)" \
			-var "datastore=$(CROPDROID_DATASTORE)" \
			$(PACKER_FILE)
	sudo -E cp ${PWD}/build/packer/output-arm-image/image $(RPI_IMAGE_ARTIFACT)
	sudo chown $(USER) $(RPI_IMAGE_ARTIFACT) ${PWD}/build/packer/output-arm-image/image


# ISO
iso:
	docker build \
		--memory 32g \
		--build-arg CONFIG_DIR=$(DOCKER_HOME)/$(DOCKER_ISO_BUILDER)/ \
		--load \
		-t $(DOCKER_ISO_BUILDER) \
		-f build/docker/$(DOCKER_ISO_BUILDER)/Dockerfile .
	docker create --name $(DOCKER_ISO_BUILDER)-container $(DOCKER_ISO_BUILDER):$(DOCKER_ISO_TAG)
	docker cp $(DOCKER_ISO_BUILDER)-container:/root/LIVE_BOOT_TRUSTED_PLATFORM/TrustedPlatformOS-1.0.iso ./$(ISO_NAME)
	docker rm $(DOCKER_ISO_BUILDER)-container
