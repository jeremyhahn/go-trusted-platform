# strongSwan builder for the Trusted Platform overlay (docs/sdn/engineering.md,
# "IPsec transport").
#
# Builds trusted-platform-strongswan (charon + swanctl) for Alpine 3.22 on
# amd64 and arm64 from a pinned upstream release whose tarball must carry a
# good signature by the pinned strongSwan release key AND match the pinned
# SHA-256, then packages it as signed apks with an OpenRC service.
#
#   make build                                     # both arches, dev signing key
#   make build APK_SIGNING_KEY=$(HOME)/.trusted-platform/apk/<name>.rsa
#   make verify                                    # SHA256SUMS + apk signatures + plugin set
#
# APK_SIGNING_KEY is an abuild RSA private key with <name>.rsa.pub beside it;
# the nodes trust it by carrying the .pub in /etc/apk/keys. It is mounted
# read-only and never enters an image. Without it a per-build EPHEMERAL key is
# generated under $(OUTPUT_DIR)/.ephemeral-key (dev builds only: nothing
# outside this build trusts it).

STRONGSWAN_VERSION ?= 6.0.7
STRONGSWAN_SHA256  ?= e518e34e159514f4c6ba80d1f926cb151e0dd4e3a1d94213171234b8b9ae6f55
# Andreas Steffen <andreas.steffen@strongswan.org>, the strongSwan release
# signing key (strongswan-release-key.asc, from
# https://download.strongswan.org/STRONGSWAN-RELEASE-PGP-KEY).
STRONGSWAN_SIGNER  ?= 948F158A4E76A27BF3D07532DF42C170B34DBA77
# The complete plugin set; the APKBUILD enables exactly these and fails the
# package if any other plugin is installed.
# counters is not optional: configure enables it whenever vici is (VICI's
# get-counters command), so it is pinned here rather than discovered.
STRONGSWAN_PLUGINS ?= openssl pkcs11 vici counters nonce kernel-netlink socket-default pem revocation constraints updown
ARCHES             ?= amd64 arm64

OUTPUT_DIR   ?= $(CURDIR)/output
# The source tarball cache is a named docker volume, not a host path: the
# daemon owns it, so it works when the build runs in a CI job container.
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

.PHONY: all build image key verify clean FORCE

# image-<arch> and build-<arch> are pattern rules, which GNU make never
# applies to .PHONY targets; FORCE makes them always run instead.
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

build: key $(addprefix build-,$(ARCHES))
	@echo ""
	@echo "Build complete. Artifacts in: $(OUTPUT_DIR)"
	@ls -lR $(OUTPUT_DIR) | grep -v '^total'

build-%: image-% key FORCE
	DOCKER=$(DOCKER) $(RUN_BUILDER) \
		-i $(KEY_DIR)$(KEY_NAME):/keys/$(KEY_NAME) -i $(KEY_DIR)$(KEY_NAME).pub:/keys/$(KEY_NAME).pub \
		-o /output:$(abspath $(OUTPUT_DIR)) -- \
		--platform linux/$* \
		-v $(CACHE_VOLUME):/build/src \
		-e STRONGSWAN_VERSION=$(STRONGSWAN_VERSION) \
		-e STRONGSWAN_SHA256=$(STRONGSWAN_SHA256) \
		-e STRONGSWAN_SIGNER=$(STRONGSWAN_SIGNER) \
		-e STRONGSWAN_PLUGINS="$(STRONGSWAN_PLUGINS)" \
		-e APK_KEY_NAME=$(KEY_NAME) \
		$(DOCKER_IMAGE)-$*

# verify re-checks everything a consumer relies on, from the output alone:
# the SHA256SUMS of each arch, every apk's and APKINDEX's signature against
# the published key, the manifest's version and plugin set against the pins,
# and the cached source tarball's signature and hash.
verify: image-amd64
	@for a in $(ARCHES); do \
		d=$(OUTPUT_DIR)/$$(case $$a in amd64) echo x86_64;; arm64) echo aarch64;; esac); \
		test -d "$$d" || { echo "ERROR: $$d missing (run make build)"; exit 1; }; \
		(cd "$$d" && sha256sum -c --quiet SHA256SUMS) || exit 1; \
		grep -q '"strongswan_version": "$(STRONGSWAN_VERSION)"' "$$d/manifest.json" || { echo "ERROR: $$d/manifest.json is not $(STRONGSWAN_VERSION)"; exit 1; }; \
		want=$$(for p in $(STRONGSWAN_PLUGINS); do printf '"%s", ' $$p; done | sed 's/, $$//'); \
		grep -qF "\"plugins\": [$$want]" "$$d/manifest.json" || { echo "ERROR: $$d/manifest.json plugin set differs from STRONGSWAN_PLUGINS"; exit 1; }; \
		echo "$$d: checksums, version and plugin set ok"; \
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
