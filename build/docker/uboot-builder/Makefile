# U-Boot builder for the Trusted Platform Raspberry Pi image.
#
# Builds rpi_arm64 and qemu_arm64 U-Boot binaries from a pinned upstream
# release inside a container, with the platform's Secure Boot PK/KEK/db
# preseeded into the binary (U-Boot does not trust authenticated variables
# read back from the ESP file store, so a Secure Boot key set means a
# U-Boot build). One build per key set; the cache key in
# output/manifest.json records which inputs produced the output.
#
#   make build KEYS_DIR=$(HOME)/.trusted-platform/secure-boot
#
# KEYS_DIR must hold PK.crt, KEK.crt and DB.crt (PEM or DER) — the same files
# `platformctl iso create` stages on the install media.

UBOOT_VERSION ?= 2026.07
UBOOT_SHA256  ?= 78e8bfc382fe388f9b55aa1daf8c563522a037779b5d4c349d1415e381f1243e
UBOOT_BOARDS  ?= rpi_arm64 qemu_arm64
# SignatureOwner GUID for the preseeded lists; any stable GUID the platform
# owns. Override per fleet if the owner identity matters to your policy.
UBOOT_OWNER_GUID ?= 7e5a1c6e-0b3f-4a5e-9c2d-3f1a2b4c5d6e

OUTPUT_DIR   ?= $(CURDIR)/output
KEYS_DIR     ?= $(HOME)/.trusted-platform/secure-boot
CACHE_DIR    ?= $(HOME)/.cache/trusted-platform/uboot
DOCKER       ?= docker
DOCKER_IMAGE ?= trusted-platform-uboot-builder:$(UBOOT_VERSION)

# Everything that shapes the binary: the fragments, the overlay, the patch,
# and the builder itself (the image recipe, the build script and the ESL
# writer) — a fix to any of them must miss the cache, or an old u-boot.bin
# is staged into a new image while its manifest reports a matching key.
CONFIG_INPUTS := configs/common-efi.config configs/rpi_arm64-tpm.config configs/qemu_arm64-tpm.config configs/tpm-soft-spi.dts patches/0001-mbedtls-glue-return-errno-for-parse-failures.patch Dockerfile build-uboot.sh mkesl.py
KEY_INPUTS    := $(KEYS_DIR)/PK.crt $(KEYS_DIR)/KEK.crt $(KEYS_DIR)/DB.crt

.PHONY: all build image cache-key verify clean

all: build

# UBOOT_CACHE_KEY is the key every build input contributes to, in the exact
# form pkg/diskimage/uboot.CacheKey computes (a unit test there pins the two
# implementations to each other): "uboot:<version>", "owner:<GUID>", then
# the sha256 of each CONFIG_INPUTS file and each certificate, in this order,
# one per line, all fed to sha256. The owner GUID is in the key because it
# is written into every preseeded signature list. Computed lazily by the
# shell, never by a recursive make, so `make -n` stays a dry run.
UBOOT_CACHE_KEY = $(shell { printf 'uboot:%s\nowner:%s\n' '$(UBOOT_VERSION)' '$(UBOOT_OWNER_GUID)'; for f in $(CONFIG_INPUTS) $(KEY_INPUTS); do sha256sum "$$f" 2>/dev/null | cut -d' ' -f1; done; } | sha256sum | cut -d' ' -f1)

cache-key:
	@echo $(UBOOT_CACHE_KEY)

image:
	$(DOCKER) build -t $(DOCKER_IMAGE) .

build: image
	@for f in $(KEY_INPUTS); do test -r "$$f" || { echo "ERROR: missing Secure Boot certificate $$f (PK.crt, KEK.crt, DB.crt are required; see docs/installer/iso-building.md)"; exit 1; }; done
	@mkdir -p $(OUTPUT_DIR) $(CACHE_DIR)
	$(DOCKER) run --rm \
		-v $(abspath $(OUTPUT_DIR)):/output \
		-v $(abspath $(KEYS_DIR)):/keys:ro \
		-v $(CURDIR)/configs:/configs:ro \
		-v $(CURDIR)/patches:/patches:ro \
		-v $(abspath $(CACHE_DIR)):/build/src \
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
