# strongSwan builder for the Trusted Platform overlay (docs/sdn/engineering.md, "IPsec transport").

STRONGSWAN_VERSION ?= 6.0.7
STRONGSWAN_SHA256  ?= e518e34e159514f4c6ba80d1f926cb151e0dd4e3a1d94213171234b8b9ae6f55
# The strongSwan release signing key's fingerprint (strongswan-release-key.asc).
STRONGSWAN_SIGNER  ?= 948F158A4E76A27BF3D07532DF42C170B34DBA77
# The complete plugin set; the APKBUILD fails on any other installed plugin.
STRONGSWAN_PLUGINS ?= openssl pkcs11 vici counters nonce kernel-netlink socket-default pem revocation constraints updown
ARCHES             ?= amd64 arm64
# The PKCS#11 module host: the go-xkms release its module is built from, and the root filesystem directory per architecture.
XKMS_VERSION       ?=
MODULE_HOST_DIR    ?=
# An apk version has no leading v and writes -alpha as _alpha.
P11_HOST_VERSION    = $(subst -,_,$(patsubst v%,%,$(XKMS_VERSION)))
# The apks every node installs for the overlay's IPsec transport.
PLATFORM_APKS       = trusted-platform-strongswan trusted-platform-strongswan-openrc trusted-platform-p11-host trusted-platform-p11-host-openrc

OUTPUT_DIR   ?= $(CURDIR)/output
# The tarball cache is a named docker volume, so it works from a CI job container.
CACHE_VOLUME ?= trusted-platform-strongswan-src
DOCKER       ?= docker
RUN_BUILDER  ?= ../run-builder.sh
DOCKER_IMAGE ?= trusted-platform-strongswan-builder:$(STRONGSWAN_VERSION)

APK_SIGNING_KEY ?=
EPHEMERAL_KEY_DIR := $(OUTPUT_DIR)/.ephemeral-key
EPHEMERAL_KEY     := trusted-platform-dev-ephemeral.rsa

ifneq ($(APK_SIGNING_KEY),)
KEY_DIR  := $(dir $(abspath $(APK_SIGNING_KEY)))
KEY_NAME := $(notdir $(APK_SIGNING_KEY))
else
KEY_DIR  := $(EPHEMERAL_KEY_DIR)
KEY_NAME := $(EPHEMERAL_KEY)
endif

.PHONY: all build image key module-host-inputs verify clean FORCE

# FORCE makes the image-<arch> and build-<arch> pattern rules always run.
FORCE:

all: build

image: $(addprefix image-,$(ARCHES))

image-%: FORCE
	$(DOCKER) build --platform linux/$* -t $(DOCKER_IMAGE)-$* .

key: image-amd64
ifeq ($(APK_SIGNING_KEY),)
	@echo "WARNING: APK_SIGNING_KEY not set -- signing with a per-build ephemeral key (dev only)."
	@test -f $(EPHEMERAL_KEY_DIR)/$(EPHEMERAL_KEY) || DOCKER=$(DOCKER) $(RUN_BUILDER) -o /tmp/k:$(EPHEMERAL_KEY_DIR) -- \
		--platform linux/amd64 --entrypoint sh $(DOCKER_IMAGE)-amd64 -c \
		'umask 077 && mkdir -p /tmp/k && openssl genrsa -out /tmp/k/$(EPHEMERAL_KEY) 4096 2>/dev/null && openssl rsa -in /tmp/k/$(EPHEMERAL_KEY) -pubout -out /tmp/k/$(EPHEMERAL_KEY).pub 2>/dev/null && chmod 644 /tmp/k/$(EPHEMERAL_KEY).pub'
else
	@test -r "$(APK_SIGNING_KEY)" || { echo "ERROR: APK_SIGNING_KEY '$(APK_SIGNING_KEY)' is not readable"; exit 1; }
	@test -r "$(APK_SIGNING_KEY).pub" || { echo "ERROR: $(APK_SIGNING_KEY).pub must sit beside the private key"; exit 1; }
endif

module-host-inputs:
	@test -n "$(XKMS_VERSION)" || { echo "ERROR: XKMS_VERSION is required: the go-xkms release of the module host, e.g. v0.48.0-alpha (make strongswan-build at the repository root sets it)"; exit 1; }
	@for a in $(ARCHES); do \
		test -f "$(MODULE_HOST_DIR)/modulehost-$$a.tar" || { echo "ERROR: $(MODULE_HOST_DIR)/modulehost-$$a.tar missing (run make ipsec-module-host at the repository root)"; exit 1; }; \
	done

build: key module-host-inputs $(addprefix build-,$(ARCHES))
	@echo ""
	@echo "Build complete. Artifacts in: $(OUTPUT_DIR)"
	@ls -lR $(OUTPUT_DIR) | grep -v '^total'

build-%: image-% key module-host-inputs FORCE
	DOCKER=$(DOCKER) $(RUN_BUILDER) \
		-i $(KEY_DIR)$(KEY_NAME):/keys/$(KEY_NAME) -i $(KEY_DIR)$(KEY_NAME).pub:/keys/$(KEY_NAME).pub \
		-i $(abspath $(MODULE_HOST_DIR))/modulehost-$*.tar:/build/modulehost.tar \
		-o /output:$(abspath $(OUTPUT_DIR)) -- \
		--platform linux/$* \
		-v $(CACHE_VOLUME):/build/src \
		-e STRONGSWAN_VERSION=$(STRONGSWAN_VERSION) \
		-e STRONGSWAN_SHA256=$(STRONGSWAN_SHA256) \
		-e STRONGSWAN_SIGNER=$(STRONGSWAN_SIGNER) \
		-e STRONGSWAN_PLUGINS="$(STRONGSWAN_PLUGINS)" \
		-e P11_HOST_VERSION=$(P11_HOST_VERSION) \
		-e APK_KEY_NAME=$(KEY_NAME) \
		$(DOCKER_IMAGE)-$*

# verify re-checks every output: checksums, apk and APKINDEX signatures, the manifest against the pins and the cached tarball.
verify: image-amd64
	@test -n "$(XKMS_VERSION)" || { echo "ERROR: XKMS_VERSION is required (the go-xkms release of the module host)"; exit 1; }
	@for a in $(ARCHES); do \
		d=$(OUTPUT_DIR)/$$(case $$a in amd64) echo x86_64;; arm64) echo aarch64;; esac); \
		test -d "$$d" || { echo "ERROR: $$d missing (run make build)"; exit 1; }; \
		(cd "$$d" && sha256sum -c --quiet SHA256SUMS) || exit 1; \
		grep -q '"strongswan_version": "$(STRONGSWAN_VERSION)"' "$$d/manifest.json" || { echo "ERROR: $$d/manifest.json is not $(STRONGSWAN_VERSION)"; exit 1; }; \
		want=$$(for p in $(STRONGSWAN_PLUGINS); do printf '"%s", ' $$p; done | sed 's/, $$//'); \
		grep -qF "\"plugins\": [$$want]" "$$d/manifest.json" || { echo "ERROR: $$d/manifest.json plugin set differs from STRONGSWAN_PLUGINS"; exit 1; }; \
		grep -q '"p11_host_version": "$(P11_HOST_VERSION)"' "$$d/manifest.json" || { echo "ERROR: $$d/manifest.json module host is not $(P11_HOST_VERSION)"; exit 1; }; \
		for p in $(PLATFORM_APKS); do \
			ls "$$d/$$p"-[0-9]*.apk >/dev/null 2>&1 || { echo "ERROR: $$d has no $$p apk"; exit 1; }; \
		done; \
		echo "$$d: checksums, versions, plugin set and apks ok"; \
	done
	DOCKER=$(DOCKER) $(RUN_BUILDER) -i $(abspath $(OUTPUT_DIR)):/output -- \
		--platform linux/amd64 \
		-v $(CACHE_VOLUME):/build/src:ro \
		-e STRONGSWAN_VERSION=$(STRONGSWAN_VERSION) \
		-e STRONGSWAN_SHA256=$(STRONGSWAN_SHA256) \
		-e STRONGSWAN_SIGNER=$(STRONGSWAN_SIGNER) \
		--entrypoint /bin/sh $(DOCKER_IMAGE)-amd64 -euc '\
		t=/build/src/strongswan-$$STRONGSWAN_VERSION.tar.bz2; \
		s=$$(gpgv --status-fd 1 --keyring /build/strongswan-release-key.gpg $$t.sig $$t 2>/dev/null | awk "\$$2 == \"VALIDSIG\" { print \$$NF }"); \
		test "$$s" = "$$STRONGSWAN_SIGNER" || { echo "source signature: signer \"$$s\" is not $$STRONGSWAN_SIGNER"; exit 1; }; \
		echo "$$STRONGSWAN_SHA256  $$t" | sha256sum -c -; \
		cp /output/keys/*.rsa.pub /etc/apk/keys/; \
		for f in /output/*/*.apk /output/*/APKINDEX.tar.gz; do apk verify "$$f" >/dev/null || { echo "$$f: signature verification FAILED"; exit 1; }; echo "$$f: signature ok"; done'

clean:
	rm -rf $(OUTPUT_DIR)/x86_64 $(OUTPUT_DIR)/aarch64 $(OUTPUT_DIR)/keys $(EPHEMERAL_KEY_DIR)
