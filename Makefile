ORG                     := automatethethingsllc
TARGET_OS               := linux
TARGET_ARCH             := $(shell uname -m)

ARCH                    := $(shell go env GOARCH)
OS                      := $(shell go env GOOS)
LONG_BITS               := $(shell getconf LONG_BIT)

GOBIN                   := $(shell dirname `which go`)
PYTHONBIN               ?= /usr/bin/python3.8
PIPBIN                  ?= pip

ARM_CC				    ?= aarch64-linux-gnu-gcc-14
ARM_CXX                 ?= aarch64-linux-gnu-g++-14

GIT_REPO                ?= github.com
GIT_OWNER               ?= jeremyhahn
PACKAGE                 ?= go-trusted-platform
APPNAME                 ?= trusted-platform
PLATFORMD               ?= platformd
PLATFORMCTL             ?= platformctl

APP_VERSION       		?= $(shell git describe --tags --abbrev=0)
GIT_TAG                 = $(shell git describe --tags)
GIT_HASH                = $(shell git rev-parse HEAD)
GIT_BRANCH              = $(shell git branch --show-current)
GIT_TOKEN               ?=
BUILD_DATE              = $(shell date '+%Y-%m-%d_%H:%M:%S')

VERSION_FILE            ?= VERSION

ENV                     ?= dev

ifneq ("$(wildcard $(VERSION_FILE))","")
    APP_VERSION = $(shell cat $(VERSION_FILE))
else
    APP_VERSION = $(shell git branch --show-current)
endif

LDFLAGS=-X github.com/jeremyhahn/$(PACKAGE)/pkg/app.Name=${APPNAME}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.Repository=${GIT_REPO}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.Package=${PACKAGE}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.GitBranch=${GIT_BRANCH}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.GitHash=${GIT_HASH}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.GitTag=${GIT_TAG}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.BuildUser=${USER}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.BuildDate=${BUILD_DATE}
LDFLAGS+= -X github.com/jeremyhahn/$(PACKAGE)/pkg/app.Version=${APP_VERSION}

PLATFORM_DIR                ?= trusted-data
CONFIG_DIR                  ?= configs
EXAMPLE_DIR                 ?= examples
PLATFORM_CONFIG_DIR         ?= $(CONFIG_DIR)/platform

CONFIG_YAML                 ?= config.dev.server.yaml

ROOT_CA                     ?= root-ca
INTERMEDIATE_CA             ?= intermediate-ca
DOMAIN                      ?= trusted-platform.io

SOFTHSM_DIR                 ?= /usr/local/bin
SOFTHSM_LIB                 ?= /usr/local/lib/softhsm/libsofthsm2.so
SOFTHSM_TOKEN_DIR           ?= /var/lib/softhsm/tokens
SOFTHSM_CONFIG              ?= configs/softhsm2.conf

WEB_PUBLIC_HTML             ?= public_html
WEB_PACKAGE                 ?= $(PACKAGE)-web
WEB_SRC                     ?= ../$(WEB_PACKAGE)

SWAGGER_HOST                ?= $(DOMAIN)

SYNC_USER                   ?= pi
SYNC_HOST                   ?= rpi

DOCKER_HOME                 ?= build/docker
DOCKER_REPO                 ?= docker.io
DOCKER_USER                 ?= jeremyhahn
DOCKER_BUILDER_BASE         ?= alpine
DOCKER_BUILDER_DOCKERFILE   ?= Dockerfile-$(DOCKER_BUILDER_BASE)
DOCKER_PLATFORM_BUILDER     ?= trusted-platform-builder
DOCKER_PLATFORM_BUILDER_TAG ?= latest
DOCKER_ISO_BUILDER          ?= trusted-platform-iso-builder
DOCKER_ISO_BUILDER_SWTPM    ?= trusted-platform-iso-builder-swtpm
DOCKER_ISO_TAG              ?= latest
DOCKER_ANSIBLE_BUILDER      ?= ansible-ee
DOCKER_AARCH64_CONTEXT      ?= arm64
DOCKER_AARCH64_HOST         ?= $(SYNC_HOST)
DOCKER_AARCH64_SSHKEY       ?= ~/.ssh/id_rsa

ISO_DIR                     ?= build/docker/$(DOCKER_ISO_BUILDER)
ISO_NAME                    ?= trusted-platform.iso
ISO_NAME_SWTPM		        ?= trusted-platform-swtpm.iso

RPI_OS                      ?= raspios
RPI_IMAGE_NAME		        ?= $(APPNAME)-$(APP_VERSION)-$(ENV)
RPI_IMAGE_FILENAME          ?= $(RPI_IMAGE_NAME).img
RPI_IMAGE_ARTIFACT          ?= $(PACKER_HOME)/$(RPI_IMAGE_FILENAME)
RPI_SDCARD                  ?= /dev/sda

PACKER_HOME                 ?= build/packer
PACKER_FILE                 ?= $(PACKER_HOME)/rpi/$(RPI_OS).json
PACKER_BUILDER_RASPIOS64    ?= raspbian
PACKER_BUILDER_UBUNTU64     ?= ubuntu-20.04.01-arm64
PACKER_BUILDER              ?= $(PACKER_BUILDER_RASPIOS64)

UID                         := $(shell id -u)
GID                         := $(shell id -g)

BUILDKIT_WORKER_CONCURRENCY = $(shell nproc)

# Text colors
RED=\033[0;31m
GREEN=\033[0;32m
YELLOW=\033[1;33m
NO_COLOR=\033[0m


default: build


.PHONY: init
init:
	-docker buildx rm $(DOCKER_BUILDER_AMD64)
	-docker buildx rm $(DOCKER_BUILDER_AAARCH64)
	-docker context rm $(DOCKER_AARCH64_HOST)
	sudo apt-get install -y \
		libssl-dev \
		docker.io \
		docker-buildx \
		efitools \
		binfmt-support \
		qemu-user-static \
		rsync \
		pipx
	pipx ensurepath
	pipx install virt-firmware
	sudo mkdir -p /etc/qemu/
	sudo /bin/bash -c 'echo "allow virbr0" > /etc/qemu/bridge.conf'
	sudo chmod u+s /usr/lib/qemu/qemu-bridge-helper
	docker run --rm --privileged multiarch/qemu-user-static --reset -p yes || true
	docker context create $(DOCKER_AARCH64_CONTEXT) --docker "host=ssh://$(DOCKER_AARCH64_HOST)"
	ssh-copy-id -i $(DOCKER_AARCH64_SSHKEY) $(DOCKER_AARCH64_HOST) || true


.PHONY: tools
tools:
	sudo apt-get install -y tpm2-tools


.PHONY: env
env:
	@$(foreach var,$(filter-out MAKE% __%,$(.VARIABLES)),\
		printf "%-35s %s\n" "$(var):" "$($(var))";)


.PHONY: run
run:
	cp $(EXAMPLE_DIR)/config.yaml config.yaml
	./$(PLATFORMD) webservice \
		--debug \
		--init \
		--platform-dir trusted-data \
		--config-dir trusted-data/etc \
		--log-dir trusted-data/log \
		--ca-dir trusted-data/ca \
		--raw-so-pin 123456 \
		--raw-pin 123456


# Native local build
.PHONY: build
build:
	cd pkg; \
	go clean ; \
	CGO_ENABLED=1 $(GOBIN)/go build -v -o ../$(PLATFORMD) -ldflags="-w -s ${LDFLAGS}"

.PHONY: build-debug
build-debug:
	cd pkg; \
	go clean ; \
	CGO_ENABLED=1 $(GOBIN)/go build -v -o ../$(PLATFORMD)-debug -gcflags='all=-N -l' -ldflags="${LDFLAGS}"

.PHONY: build-static
build-static:
	cd pkg; \
	go clean ; \
	CGO_ENABLED=1 $(GOBIN)/go build -v -o ../$(PLATFORMD)-static --ldflags '-w -s -linkmode external -extldflags -static -v ${LDFLAGS}'

.PHONY: build-debug-static
build-debug-static:
	cd pkg; \
	go clean ; \
	CGO_ENABLED=1 $(GOBIN)/go build -v -o ../$(PLATFORMD)-debug-static -gcflags='all=-N -l' --ldflags '-extldflags -static -v ${LDFLAGS}'

# Cross-compile ARM 64-bit
.PHONY: build-arm64
build-arm64:
	cd pkg; \
	CC=$(ARM_CC) CXX=$(ARM_CXX) CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -o ../$(PLATFORMD) -ldflags="-w -s ${LDFLAGS}"

.PHONY: build-arm64-static
build-arm64-static:
	cd pkg; \
	CC=$(ARM_CC) PLATFORMD=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -o ../$(PLATFORMD)-static --ldflags '-w -s -extldflags -static -v ${LDFLAGS}'

.PHONY: build-arm64-debug
build-arm64-debug:
	cd pkg; \
	CC=$(ARM_CC) CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -gcflags "all=-N -l" -o ../$(PLATFORMD)-debug --ldflags="$(LDFLAGS)"

.PHONY: build-arm64-debug-static
build-arm64-debug-static:
	cd pkg; \
	CC=$(ARM_CC) CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	$(GOBIN)/go build -gcflags "all=-N -l" -o ../$(PLATFORMD)-debug-static --ldflags '-extldflags -static -v ${LDFLAGS}'


.PHONY: build-dev
build-dev: clean build-debug
	sudo chown $(USER):$(USER) /dev/tpmrm0
	-sudo chown $(USER):$(USER) /sys/kernel/security/tpm0/binary_bios_measurements
	mkdir -p $(PLATFORM_DIR)/etc/ $(PLATFORM_DIR)/softhsm2 pkg/$(PLATFORM_DIR)/softhsm2
	cp configs/platform/config.dev.yaml config.yaml
	cp configs/softhsm.conf $(PLATFORM_DIR)/etc/softhsm.conf
	cp configs/platform/config.debug.yaml pkg/config.yaml
	cp -R $(WEB_PUBLIC_HTML) pkg/


# Build the public_html directory
.PHONY: build-public-html
build-public-html:
	# Start with a clean directory
	rm -rf $(WEB_PUBLIC_HTML)/ pkg/$(WEB_PUBLIC_HTML)/
	mkdir -p $(WEB_PUBLIC_HTML)/ pkg/$(WEB_PUBLIC_HTML)/
	
	# Build the swagger / OpenAPI docs
	make swagger
	make swagger-ui
	
	# Configure SwaggerInfo
	sed -i '/var SwaggerInfo = &swag.Spec{/,/}}/c\var SwaggerInfo = \&swag.Spec{\n\tVersion:          "$(APP_VERSION)",\n\tHost:             "$(SWAGGER_HOST)",\n\tBasePath:         "/api/v1",\n\tSchemes:          []string{},\n\tTitle:            "Trusted Platform",\n\tDescription:      "The Trusted Platform RESTful Web Services API",\n\tInfoInstanceName: "swagger",\n\tSwaggerTemplate:  docTemplate,\n\tLeftDelim:        "{{",\n\tRightDelim:       "}}",' $(WEB_PUBLIC_HTML)/swagger/docs.go

	# Set the version and host annotations
	sed -i 's|@version .*|@version $(APP_VERSION)|g' pkg/webservice/webserver_v1.go
	sed -i 's|@host .*|@host $(SWAGGER_HOST)|g' pkg/webservice/webserver_v1.go

	# Copy into the pkg directory for debugging
	-cp -R $(WEB_PUBLIC_HTML)/swagger pkg/$(WEB_PUBLIC_HTML)/

	# Build the go-trusted-platform-web project
	if [ ! -d "${WEB_SRC}" ]; then \
		echo "Directory '$(WEB_SRC)' does not exist. Cloning repository..."; \
		git clone https://$(GIT_REPO)/$(GIT_OWNER)/$(WEB_PACKAGE).git $(WEB_SRC); \
	fi

	cd $(WEB_SRC) && \
		yarn install && \
		yarn build && \
		cp -R out/* ../$(PACKAGE)/$(WEB_PUBLIC_HTML)/

	# Copy into the pkg directory for debugging
	cp -R $(WEB_SRC)/out/* ../$(PACKAGE)/pkg/$(WEB_PUBLIC_HTML)/

.PHONY: swagger
swagger:
	~/go/bin/swag init \
		--dir pkg/webservice,pkg/webservice/v1/jwt,pkg/webservice/v1/router,pkg/webservice/v1/response,pkg/acme/server/handlers,pkg/store/datastore/entities,pkg/acme,pkg/app,pkg/config,pkg/crypto/argon2 \
		--generalInfo webserver_v1.go \
		--parseDependency \
		--parseInternal \
		--parseDepth 1 \
		--output $(WEB_PUBLIC_HTML)/swagger

.PHONY: swagger-ui
swagger-ui:
	mkdir -p $(WEB_PUBLIC_HTML)/swagger
	git clone --depth=1 https://github.com/swagger-api/swagger-ui.git && \
		mv swagger-ui/dist/* $(WEB_PUBLIC_HTML)/swagger && \
		rm -rf swagger-ui
	sed -i '/var SwaggerInfo = &swag.Spec{/,/}}/c\var SwaggerInfo = \&swag.Spec{\n\tVersion:          "$(APP_VERSION)",\n\tHost:             "$(SWAGGER_HOST)",\n\tBasePath:         "/api/v1",\n\tSchemes:          []string{},\n\tTitle:            "Trusted Platform",\n\tDescription:      "The Trusted Platform RESTful Web Services API",\n\tInfoInstanceName: "swagger",\n\tSwaggerTemplate:  docTemplate,\n\tLeftDelim:        "{{",\n\tRightDelim:       "}}",' $(WEB_PUBLIC_HTML)/swagger/docs.go
	sed -i 's|@version .*|@version $(APP_VERSION)|g' pkg/webservice/webserver_v1.go
	sed -i 's|@host .*|@host $(SWAGGER_HOST)|g' pkg/webservice/webserver_v1.go


.PHONY: clean
clean:
	cd pkg; \
	$(GOBIN)/go clean
	rm -rf \
		$(PLATFORMD) \
		$(PLATFORMD)-* \
		/usr/local/bin/$(PLATFORMD) \
		$(PLATFORM_DIR) \
		$(WEB_PUBLIC_HTML) \
		$(WEB_PUBLIC_HTML).tar.gz \
		build/docker/trusted-platform/platformd \
		build/docker/trusted-platform/platformd-debug \
		build/docker/trusted-platform/trusted-data \
		build/docker/trusted-platform-iso-builder/ansible/ \
		build/docker/trusted-platform-iso-builder/secure-boot-keys \
		build/docker/trusted-platform-iso-builder/*.iso \
		build/docker/trusted-platform-iso-builder/*.qcow2 \
		build/docker/pxe-server/*.qcow2 \
		build/docker/pxe-server/volume \
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
		config.yaml \
		*.iso
	cd build/packer/rpi && sudo make clean

# Platform Web Services
.PHONY: webservice
webservice: build-debug config
	cd pkg && ../$(PLATFORMD) webservice --init

.PHONY: webservice-verify-tls
webservice-verify-tls:
	openssl s_client \
		-connect localhost:8443 \
		-showcerts \
		-servername localhost \
		-CAfile pkg/$(PLATFORM_DIR)/ca/$(INTERMEDIATE_CA).$(DOMAIN)/x509/$(ROOT_CA).$(DOMAIN).pkcs8.rsa.pem \
		| openssl x509 -noout -text


# SoftHSM
.PHONY: softhsm-init
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

# Tests
.PHONY: test
test: test-tpm test-crypto test-store test-webservice test-cli

.PHONY: test-cli
test-cli: test-tpm-cli test-ca-cli test-platform-cli

.PHONY: test-tpm-cli
test-tpm-cli:
	cd pkg/cmd/tpm && go test -v -run ^Test_EK$
	cd pkg/cmd/tpm && go test -v -run ^Test_EK_Certificate$
	cd pkg/cmd/tpm && go test -v -run ^Test_SRK$
	cd pkg/cmd/tpm && go test -v -run ^Test_SealUnseal$
	cd pkg/cmd/tpm && go test -v -run ^Test_Provision$
	cd pkg/cmd/tpm && go test -v -run ^Test_Info$

.PHONY: test-ca-cli
test-ca-cli:
	cd pkg/cmd/ca && go test -v -run ^Test_Certificate$
	cd pkg/cmd/ca && go test -v -run ^Test_Info$
	cd pkg/cmd/ca && go test -v -run ^Test_Init$
	cd pkg/cmd/ca && go test -v -run ^Test_Install$
	cd pkg/cmd/ca && go test -v -run ^Test_Issue$
	cd pkg/cmd/ca && go test -v -run ^Test_Revoke$

.PHONY: test-platform-cli
test-platform-cli:
	cd pkg/cmd/platform && go test -v -run ^Test_Install$
	cd pkg/cmd/platform && go test -v -run ^Test_Keyring$
	cd pkg/cmd/platform && go test -v -run ^Test_Policy$
	cd pkg/cmd/platform && go test -v -run ^Test_Provision$

.PHONY: test-ca
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

.PHONY: test-tpm
test-tpm:
	cd pkg/tpm2 && go test -v

.PHONY: test-crypto
test-crypto:
	cd pkg/crypto/aesgcm && go test -v
	cd pkg/crypto/argon2 && go test -v

.PHONY: test-store
test-store: test-store-pkcs11 test-store-tpm2 test-store-datastore
	cd pkg/store/keystore && go test -v
	cd pkg/store/keystore/pkcs8 && go test -v

.PHONY: test-store-pkcs11
test-store-pkcs11:
	cd pkg/store/keystore/pkcs11 && \
		go test -v -run ^TestConnection$ && \
		go test -v -run ^TestSignEd25519_WithoutFileIntegrityCheck$ && \
		go test -v -run ^TestSignECDSA_WithoutFileIntegrityCheck$ && \
		go test -v -run ^TestSignRSASSA_WithoutFileIntegrityCheck$ && \
		go test -v -run ^TestSignRSAPSS_WithoutFileIntegrityCheck$ && \
		go test -v -run ^TestSignRSAPSS_WithFileIntegrityCheck$ && \
		go test -v -run ^TestInitHSM$

.PHONY: test-store-tpm2
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

.PHONY: test-store-datastore
test-store-datastore:
	cd pkg/store/datastore && \
		go test -v
	cd pkg/store/datastore/kvstore && \
		go test -v

.PHONY: test-webservice
test-webservice: test-webservice-jwt

.PHONY: test-webservice-jwt
test-webservice-jwt:
	cd pkg/webservice/v1/jwt && \
		go test -v -run ^TestSigningMethodRS$ && \
		go test -v -run ^TestSigningMethodPS$ && \
		go test -v -run ^TestSigningMethodES$ && \
		go test -v -run ^TestSigningMethodES_Ed25519$

# Releases
.PHONY: release
release: clean \
	release-version-bump \
	release-commit \
	docker-builder-push \
	docker-platform-push \
	docker-iso-builder-push \
	docker-pxe-server-push \
	docker-nfs-server-push \
	release-public-html \
	release-binaries \
	isos \
	packer-rpi \
	release-github

.PHONY: release-local
release-local: clean \
	docker-builder-load \
	docker-platform-load \
	docker-iso-builder-load \
	docker-pxe-server-load \
	docker-nfs-server-load \
	release-public-html \
	release-binaries \
	isos \
	packer-rpi

.PHONY: release-commit
release-commit:
	git add -A
	git commit -F CHANGELOG
	git push origin $(GIT_BRANCH)

.PHONY: release-binaries
release-binaries:
	# glibc
	CONTAINER=$$(docker create $(APPNAME)-builder-debian:amd64); \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD) $(PLATFORMD)-glibc-x86_64; \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD)-debug $(PLATFORMD)-debug-glibc-x86_64
	CONTAINER=$$(docker create $(APPNAME)-builder-debian:arm64); \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD) $(PLATFORMD)-glibc-aarch64; \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD)-debug $(PLATFORMD)-debug-glibc-aarch64
	# musl
	CONTAINER=$$(docker create $(APPNAME)-builder-alpine:amd64); \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD) $(PLATFORMD)-musl-x86_64; \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD)-debug $(PLATFORMD)-debug-musl-x86_64; \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD)-static $(PLATFORMD)-static-musl-x86_64; \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD)-debug-static $(PLATFORMD)-debug-static-musl-x86_64
	CONTAINER=$$(docker create $(APPNAME)-builder-alpine:arm64); \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD) $(PLATFORMD)-musl-aarch64; \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD)-debug $(PLATFORMD)-debug-musl-aarch64; \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD)-static $(PLATFORMD)-static-musl-aarch64; \
		docker cp $$CONTAINER:/builder/go-trusted-platform/$(PLATFORMD)-debug-static $(PLATFORMD)-debug-static-musl-aarch64

.PHONY:
release-public-html:
	CONTAINER=$$(docker create $(APPNAME)-builder-debian:amd64); \
		docker cp $$CONTAINER:/builder/go-trusted-platform/public_html/ .; \
		tar czf public_html.tar.gz public_html

.PHONY: release-version-bump
release-version-bump:
	@if [ -z "$(RELEASE_TYPE)" ]; then \
		echo "Error: RELEASE_TYPE must be specified (e.g., make increment_version RELEASE_TYPE=major)"; \
		exit 1; \
	fi
	@if [ ! -f $(VERSION_FILE) ]; then \
		echo "Error: VERSION file not found"; \
		exit 1; \
	fi
	@OLD_VERSION=$$(cat $(VERSION_FILE)); \
	MAJOR=$$(echo $$OLD_VERSION | cut -d. -f1); \
	MINOR=$$(echo $$OLD_VERSION | cut -d. -f2); \
	BUGFIX=$$(echo $$OLD_VERSION | cut -d. -f3 | cut -d- -f1); \
	PRERELEASE=$$(echo $$OLD_VERSION | grep -o -E '(-.*|$$)'); \
	if [ "$(RELEASE_TYPE)" = "major" ]; then \
		NEW_MAJOR=$$((MAJOR + 1)); \
		NEW_VERSION="$$NEW_MAJOR.0.0"; \
	elif [ "$(RELEASE_TYPE)" = "minor" ]; then \
		NEW_MINOR=$$((MINOR + 1)); \
		NEW_VERSION="$$MAJOR.$$NEW_MINOR.0"; \
	elif [ "$(RELEASE_TYPE)" = "bugfix" ]; then \
		NEW_BUGFIX=$$((BUGFIX + 1)); \
		NEW_VERSION="$$MAJOR.$$MINOR.$$NEW_BUGFIX"; \
	else \
		echo "Error: Invalid RELEASE_TYPE. Use 'major', 'minor', or 'bugfix'."; \
		exit 1; \
	fi; \
	if [ -n "$$PRERELEASE" ]; then \
		NEW_VERSION="$$NEW_VERSION$$PRERELEASE"; \
	fi; \
	echo $$NEW_VERSION > $(VERSION_FILE); \
	echo "Version updated: $$OLD_VERSION -> $$NEW_VERSION"

.PHONY: release-github
release-github:
	@VERSION=$$(cat $(VERSION_FILE)); \
	echo "Creating GitHub release v$$VERSION..."; \
	gh release create v$$VERSION \
		-t "v$$VERSION" \
		-F CHANGELOG \
		$(PLATFORMD)-debug-glibc-aarch64 \
		$(PLATFORMD)-debug-glibc-x86_64 \
		$(PLATFORMD)-debug-musl-aarch64 \
		$(PLATFORMD)-debug-musl-x86_64 \
		$(PLATFORMD)-debug-static-musl-aarch64 \
		$(PLATFORMD)-debug-static-musl-x86_64 \
		$(PLATFORMD)-glibc-aarch64 \
		$(PLATFORMD)-glibc-x86_64 \
		$(PLATFORMD)-musl-aarch64 \
		$(PLATFORMD)-musl-x86_64 \
		$(PLATFORMD)-static-musl-aarch64 \
		$(PLATFORMD)-static-musl-x86_64 \
		trusted-platform.iso \
		trusted-platform-swtpm.iso \
		trusted-platform-raspbian.img \
		$(WEB_PUBLIC_HTML).tar.gz

.PHONY: release-github-delete
release-github-delete:
	@VERSION=$$(cat $(VERSION_FILE)); \
	echo "Deleting GitHub release v$$VERSION..."; \
	gh release delete v$$VERSION --yes; \
	git push origin --delete v$$VERSION


# Docker
.PHONY: docker-bake-load
docker-bake-load:
	docker context use default
	docker buildx bake amd64 --load
	docker context use $(DOCKER_AARCH64_CONTEXT)
	docker buildx bake arm64 --load

.PHONY: docker-bake-push
docker-bake-push:
	docker context use default
	docker buildx bake amd64 --push
	docker context use $(DOCKER_AARCH64_CONTEXT)
	docker buildx bake arm64 --push

# Docker :: PXE server
.PHONY: docker-pxe-server-load
docker-pxe-server-load:
	cd build/docker/pxe-server && make -j$(shell nproc) build

.PHONY: docker-pxe-server-push
docker-pxe-server-push:
	cd build/docker/pxe-server && make -j$(shell nproc) push

# Docker :: NFS server
.PHONY: docker-nfs-server-load
docker-nfs-server-load:
	cd build/docker/nfs-server && make -j$(shell nproc) build

.PHONY: docker-nfs-server-push
docker-nfs-server-push:
	cd build/docker/nfs-server && make -j$(shell nproc) push

# Docker :: Trusted Platform Builder :: Local
.PHONY: docker-builder-load
docker-builder-load:
	@start_time=$$(date +%s); \
		$(MAKE) \
			docker-builder-load-debian \
			docker-builder-load-alpine; \
	end_time=$$(date +%s); \
	elapsed_time=$$((end_time - start_time)); \
	hours=$$((elapsed_time/3600)); \
	minutes=$$(( (elapsed_time % 3600)/60 )); \
	seconds=$$((elapsed_time % 60)); \
	printf "${GREEN}Build execution time: %02d:%02d:%02d${NO_COLOR}\n" $$hours $$minutes $$seconds

docker-builder-load-alpine:
	@start_time=$$(date +%s); \
		$(MAKE) \
			docker-builder-load-amd64 \
			docker-builder-load-aarch64; \
	end_time=$$(date +%s); \
	elapsed_time=$$((end_time - start_time)); \
	hours=$$((elapsed_time/3600)); \
	minutes=$$(( (elapsed_time % 3600)/60 )); \
	seconds=$$((elapsed_time % 60)); \
	printf "${GREEN}Alpine build execution time: %02d:%02d:%02d${NO_COLOR}\n" $$hours $$minutes $$seconds

docker-builder-load-debian:
	@start_time=$$(date +%s); \
		DOCKER_BUILDER_BASE=debian $(MAKE) \
			docker-builder-load-amd64 \
			docker-builder-load-aarch64; \
	end_time=$$(date +%s); \
	elapsed_time=$$((end_time - start_time)); \
	hours=$$((elapsed_time/3600)); \
	minutes=$$(( (elapsed_time % 3600)/60 )); \
	seconds=$$((elapsed_time % 60)); \
	printf "${GREEN}Debian build execution time: %02d:%02d:%02d${NO_COLOR}\n" $$hours $$minutes $$seconds

.PHONY: docker-builder-load-amd64
docker-builder-load-amd64:
	BUILDKIT_DEBUG=1 docker buildx build --load \
		--progress=plain \
	 	--platform=linux/amd64 \
		-t $(APPNAME)-builder-$(DOCKER_BUILDER_BASE):amd64 \
		-f build/docker/$(APPNAME)-builder/$(DOCKER_BUILDER_DOCKERFILE) .

.PHONY: docker-builder-load-aarch64
docker-builder-load-aarch64:
	BUILDKIT_DEBUG=1 docker buildx build --load \
		--progress=plain \
	    --platform=linux/arm64 \
		-t $(APPNAME)-builder-$(DOCKER_BUILDER_BASE):arm64 \
		-f build/docker/$(APPNAME)-builder/$(DOCKER_BUILDER_DOCKERFILE) .


# Docker :: Trusted Platform Builder :: Remote
.PHONY: docker-builder-push
docker-builder-push:
	@start_time=$$(date +%s); \
		docker buildx build --push \
			--platform=linux/amd64,linux/arm64 \
			-t $(DOCKER_REPO)/$(DOCKER_USER)/$(APPNAME)-builder-alpine:latest \
			-t $(DOCKER_REPO)/$(DOCKER_USER)/$(APPNAME)-builder-alpine:$(APP_VERSION) \
			-f build/docker/$(APPNAME)-builder/Dockerfile-alpine .; \
		docker buildx build --push \
			--platform=linux/amd64,linux/arm64 \
			-t $(DOCKER_REPO)/$(DOCKER_USER)/$(APPNAME)-builder-debian:latest \
			-t $(DOCKER_REPO)/$(DOCKER_USER)/$(APPNAME)-builder-debian:$(APP_VERSION) \
			-f build/docker/$(APPNAME)-builder/Dockerfile-debian .; \
	end_time=$$(date +%s); \
	elapsed_time=$$((end_time - start_time)); \
	hours=$$((elapsed_time/3600)); \
	minutes=$$(( (elapsed_time % 3600)/60 )); \
	seconds=$$((elapsed_time % 60)); \
	printf "${GREEN}Docker trusted-platform-builder execution time: %02d:%02d:%02d${NO_COLOR}\n" $$hours $$minutes $$seconds

# Docker :: Trusted Platform ISO Builder :: Local (x86_64 only)
.PHONY: docker-iso-builder-load
docker-iso-builder-load: 
	@start_time=$$(date +%s); \
		cd build/docker/$(APPNAME)-iso-builder && \
			make clean secure-boot-keys ansible build-all; \
	end_time=$$(date +%s); \
	elapsed_time=$$((end_time - start_time)); \
	hours=$$((elapsed_time/3600)); \
	minutes=$$(( (elapsed_time % 3600)/60 )); \
	seconds=$$((elapsed_time % 60)); \
	printf "Build execution time: %02d:%02d:%02d\n" $$hours $$minutes $$seconds

# Docker :: Trusted Platform ISO Builder :: Remote (x86_64 only)
.PHONY: docker-iso-builder-push
docker-iso-builder-push:
	@start_time=$$(date +%s); \
		cd build/docker/$(APPNAME)-iso-builder && \
		make clean secure-boot-keys ansible; \
		docker buildx build --push \
			-t $(DOCKER_REPO)/$(DOCKER_USER)/$(DOCKER_ISO_BUILDER):latest \
			-t $(DOCKER_REPO)/$(DOCKER_USER)/$(DOCKER_ISO_BUILDER):$(APP_VERSION) \
			-f Dockerfile .; \
	end_time=$$(date +%s); \
	elapsed_time=$$((end_time - start_time)); \
	hours=$$((elapsed_time/3600)); \
	minutes=$$(( (elapsed_time % 3600)/60 )); \
	seconds=$$((elapsed_time % 60)); \
	printf "Build execution time: %02d:%02d:%02d\n" $$hours $$minutes $$seconds

# Docker :: Trusted Platform :: Local
.PHONY: docker-platform-load
docker-platform-load: 
	@start_time=$$(date +%s); \
		cd build/docker/$(APPNAME) && make -j20; \
	end_time=$$(date +%s); \
	elapsed_time=$$((end_time - start_time)); \
	hours=$$((elapsed_time/3600)); \
	minutes=$$(( (elapsed_time % 3600)/60 )); \
	seconds=$$((elapsed_time % 60)); \
	printf "Build execution time: %02d:%02d:%02d\n" $$hours $$minutes $$seconds

.PHONY: docker-platform-load-amd64
docker-platform-load-amd64:
	docker buildx build --load \
		--platform=linux/arm64 \
		--build-arg APPNAME=$(PLATFORMD)-static \
		-t $(APPNAME) \
		-f build/docker/$(APPNAME)/Dockerfile .


# Docker :: Trusted Platform :: Remote
.PHONY: docker-platform-push
docker-platform-push:
	docker buildx build --push \
		--platform=linux/amd64,linux/arm64 \
		--build-arg APPNAME=$(PLATFORMD)-static \
		-t $(DOCKER_REPO)/$(DOCKER_USER)/$(APPNAME)-alpine:latest \
		-t $(DOCKER_REPO)/$(DOCKER_USER)/$(APPNAME)-alpine:$(APP_VERSION) \
		-f build/docker/$(APPNAME)/Dockerfile-alpine .
	docker buildx build --push \
		--platform=linux/amd64,linux/arm64 \
		--build-arg APPNAME=$(PLATFORMD)-static \
		-t $(DOCKER_REPO)/$(DOCKER_USER)/$(APPNAME)-debian:latest \
		-t $(DOCKER_REPO)/$(DOCKER_USER)/$(APPNAME)-debian:$(APP_VERSION) \
		-f build/docker/$(APPNAME)/Dockerfile-alpine .


# Docker run targets
.PHONY: docker-run
docker-run: build-debug
	docker run -it --privileged \
	-v .:/mnt \
	-v /dev/bus/usb:/dev/bus/usb \
	trusted-platform-builder bash

.PHONY: docker-run-builder-with-usb
docker-run-builder-with-usb:
	docker run -it --rm --privileged \
		-v /dev/bus/usb:/dev/bus/usb \
		# -v /sys/devices/:/sys/devices/ \
		# -v /dev/hidraw4:/dev/hidraw4 \
		$(APPNAME)-builder \
		bash
		# /usr/local/bin/yubico-piv-tool -astatus

.PHONY: docker-run-yubico-piv-tool
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


# ISO 
.PHONY: isos
isos:
	@start_time=$$(date +%s); \
		$(MAKE) -j$(shell nproc) iso-hwtpm iso-swtpm; \
	end_time=$$(date +%s); \
	elapsed_time=$$((end_time - start_time)); \
	hours=$$((elapsed_time/3600)); \
	minutes=$$(( (elapsed_time % 3600)/60 )); \
	seconds=$$((elapsed_time % 60)); \
	printf "Build execution time: %02d:%02d:%02d\n" $$hours $$minutes $$seconds

.PHONY: iso-hwtpm
iso-hwtpm:
	@echo "Building $(APPNAME).iso ..."
	@docker run --rm -v $(PWD):/iso $(DOCKER_ISO_BUILDER)

.PHONY: iso-swtpm
iso-swtpm:
	@echo "Building $(APPNAME)-swtpm.iso ..."
	@docker run --rm -v $(PWD):/iso $(DOCKER_ISO_BUILDER_SWTPM)


# Packer
.PHONY: packer-rpi
packer-rpi:
	@start_time=$$(date +%s); \
		cd build/packer/rpi && make && mv -f trusted-platform.img ../../../trusted-platform-raspbian.img; \
	end_time=$$(date +%s); \
	elapsed_time=$$((end_time - start_time)); \
	hours=$$((elapsed_time/3600)); \
	minutes=$$(( (elapsed_time % 3600)/60 )); \
	seconds=$$((elapsed_time % 60)); \
	printf "Build execution time: %02d:%02d:%02d\n" $$hours $$minutes $$seconds


# rsync
.PHONY: rsync
rsync:
	rsync \
		-av \
		--progress \
		--exclude .git/ \
		--exclude *.img \
		--exclude *.iso \
		--exclude *.xz \
		../$(PACKAGE) $(SYNC_USER)@$(SYNC_HOST):

.PHONY: rsync-ansible
rsync-ansible:
	rsync -av --progress \
		../$(PACKAGE)-ansible $(SYNC_HOST): \
		--exclude ../$(PACKAGE)-ansible/.git/


# Firefox
.PHONY: firefox
firefox:
	sudo mkdir -p /etc/firefox/policies/ /etc/firefox/certificates
	sudo cp configs/firefox/policies.json /etc/firefox/policies/policies.json
	sudo rm -rf /etc/firefox/certificates/*.cer
	sudo cp $(PLATFORM_DIR)/ca/$(ROOT_CA).$(DOMAIN)/x509/*.cer /etc/firefox/certificates
	/usr/bin/firefox https://localhost:8443/

.PHONY: firefox-debug
firefox-debug:
	sudo mkdir -p /etc/firefox/policies/ /etc/firefox/certificates /usr/local/share/ca-certificates/
	sudo cp configs/firefox/policies.json /etc/firefox/policies/policies.json
	sudo rm -rf /etc/firefox/certificates/*.cer /usr/local/share/ca-certificates/*.cer
	sudo cp pkg/$(PLATFORM_DIR)/ca/$(ROOT_CA).$(DOMAIN)/x509/*.cer /etc/firefox/certificates
	sudo cp pkg/$(PLATFORM_DIR)/ca/$(ROOT_CA).$(DOMAIN)/x509/*.cer /usr/local/share/ca-certificates/
	sudo update-ca-certificates
	/usr/bin/firefox https://localhost:8443/

.PHONY: firefox-bin
firefox-bin:
	/usr/bin/firefox https://localhost:8443/


# TPM 2.0
.PHONY: clear-auth
clear-auth:
	sudo tpm2_changeauth -c e -p test
	sudo tpm2_changeauth -c o -p test
	sudo tpm2_changeauth -c l -p test

.PHONY: config
config:
	mkdir -p pkg/$(PLATFORM_DIR)/etc/ pkg/$(PLATFORM_DIR)/softhsm2
	cp configs/platform/$(CONFIG_YAML) pkg/config.yaml
	cp configs/softhsm.conf pkg/trusted-data/etc/softhsm.conf
