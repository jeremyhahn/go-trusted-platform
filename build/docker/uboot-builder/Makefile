# U-Boot builder for the Trusted Platform Raspberry Pi image.

UBOOT_VERSION ?= 2026.07
UBOOT_SHA256  ?= 78e8bfc382fe388f9b55aa1daf8c563522a037779b5d4c349d1415e381f1243e
UBOOT_BOARDS  ?= rpi_arm64 qemu_arm64
# SignatureOwner GUID for the preseeded lists.
UBOOT_OWNER_GUID ?= 7e5a1c6e-0b3f-4a5e-9c2d-3f1a2b4c5d6e

OUTPUT_DIR   ?= $(CURDIR)/output
KEYS_DIR     ?= $(HOME)/.trusted-platform/secure-boot
# The tarball cache is a named docker volume, so it works from a CI job container.
CACHE_VOLUME ?= trusted-platform-uboot-src
DOCKER       ?= docker
RUN_BUILDER  ?= ../run-builder.sh
DOCKER_IMAGE ?= trusted-platform-uboot-builder:$(UBOOT_VERSION)

# Everything that shapes the binary; a change to any of them misses the cache.
CONFIG_INPUTS := configs/common-efi.config configs/rpi_arm64-tpm.config configs/qemu_arm64-tpm.config configs/tpm-soft-spi.dts patches/0001-mbedtls-glue-return-errno-for-parse-failures.patch Dockerfile build-uboot.sh mkesl.py
KEY_INPUTS    := $(KEYS_DIR)/PK.crt $(KEYS_DIR)/KEK.crt $(KEYS_DIR)/DB.crt

.PHONY: all build image cache-key verify clean

all: build

# UBOOT_CACHE_KEY: the same key pkg/diskimage/uboot.CacheKey computes (a unit test pins them).
UBOOT_CACHE_KEY = $(shell { printf 'uboot:%s\nowner:%s\n' '$(UBOOT_VERSION)' '$(UBOOT_OWNER_GUID)'; for f in $(CONFIG_INPUTS) $(KEY_INPUTS); do sha256sum "$$f" 2>/dev/null | cut -d' ' -f1; done; } | sha256sum | cut -d' ' -f1)

cache-key:
	@echo $(UBOOT_CACHE_KEY)

image:
	$(DOCKER) build -t $(DOCKER_IMAGE) .

build: image
	@for f in $(KEY_INPUTS); do test -r "$$f" || { echo "ERROR: missing Secure Boot certificate $$f (PK.crt, KEK.crt, DB.crt are required; see docs/installer/iso-building.md)"; exit 1; }; done
	DOCKER=$(DOCKER) $(RUN_BUILDER) \
		-i $(abspath $(KEYS_DIR)):/keys -i $(CURDIR)/configs:/configs -i $(CURDIR)/patches:/patches \
		-o /output:$(abspath $(OUTPUT_DIR)) -- \
		-v $(CACHE_VOLUME):/build/src \
		-e UBOOT_VERSION=$(UBOOT_VERSION) \
		-e UBOOT_SHA256=$(UBOOT_SHA256) \
		-e UBOOT_BOARDS="$(UBOOT_BOARDS)" \
		-e UBOOT_OWNER_GUID=$(UBOOT_OWNER_GUID) \
		-e UBOOT_CACHE_KEY=$(UBOOT_CACHE_KEY) \
		$(DOCKER_IMAGE)
	@echo ""
	@echo "Build complete. Artifacts in: $(OUTPUT_DIR)"
	@ls -lR $(OUTPUT_DIR) | grep -v '^total'

# verify recomputes every SHA256SUMS in the output directory.
verify:
	@for d in $(OUTPUT_DIR)/*/; do (cd "$$d" && sha256sum -c --quiet SHA256SUMS && echo "$$d: ok"); done

clean:
	rm -rf $(OUTPUT_DIR)/rpi_arm64 $(OUTPUT_DIR)/qemu_arm64 $(OUTPUT_DIR)/manifest.json
