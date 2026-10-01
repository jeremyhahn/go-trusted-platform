# iPXE builder for the Trusted Platform network boot.
#
# Builds the arm64 EFI iPXE from a pinned upstream release inside a
# container, with the platform's config/local overrides (configs/*.h)
# applied. The cache key in output/manifest.json records which inputs
# produced the output.
#
#   make build
#
# or, from the repository root, `make ipxe-build`.

IPXE_VERSION ?= 2.0.0
IPXE_SHA256  ?= 9ed6d029be901a0ccc87cb2e5f9c774620f30f84ebdd507c6dd3e1e6229b7bd5
IPXE_TARGETS ?= bin-arm64-efi/snponly.efi

OUTPUT_DIR   ?= $(CURDIR)/output
CACHE_DIR    ?= $(HOME)/.cache/trusted-platform/ipxe
DOCKER       ?= docker
DOCKER_IMAGE ?= trusted-platform-ipxe-builder:$(IPXE_VERSION)

# Everything that shapes the binary: the config overrides and the builder
# itself — a fix to any of them must miss the cache.
CONFIG_INPUTS := configs/nap.h Dockerfile build-ipxe.sh

.PHONY: all build image cache-key verify clean

all: build

# IPXE_CACHE_KEY: "ipxe:<version>", "sha256:<pinned tarball digest>",
# "targets:<targets>", then the sha256 of each CONFIG_INPUTS file, one per
# line, all fed to sha256. The digest is part of the key so a corrected
# source pin always rebuilds, even at the same version. Computed lazily
# by the shell, never by a recursive make, so `make -n` stays a dry run.
IPXE_CACHE_KEY = $(shell { printf 'ipxe:%s\nsha256:%s\ntargets:%s\n' '$(IPXE_VERSION)' '$(IPXE_SHA256)' '$(IPXE_TARGETS)'; for f in $(CONFIG_INPUTS); do sha256sum "$$f" 2>/dev/null | cut -d' ' -f1; done; } | sha256sum | cut -d' ' -f1)

cache-key:
	@echo $(IPXE_CACHE_KEY)

image:
	$(DOCKER) build -t $(DOCKER_IMAGE) .

# build skips the container when the manifest already carries the cache
# key of the current inputs and every output verifies.
build: image
	@mkdir -p $(OUTPUT_DIR) $(CACHE_DIR)
	@if [ -f $(OUTPUT_DIR)/manifest.json ] && grep -q '"cache_key": "$(IPXE_CACHE_KEY)"' $(OUTPUT_DIR)/manifest.json && $(MAKE) -s verify OUTPUT_DIR=$(OUTPUT_DIR) >/dev/null 2>&1; then \
		echo "iPXE output is current (cache key $(IPXE_CACHE_KEY)); skipping build"; \
	else \
		$(DOCKER) run --rm \
			-v $(abspath $(OUTPUT_DIR)):/output \
			-v $(CURDIR)/configs:/configs:ro \
			-v $(abspath $(CACHE_DIR)):/build/src \
			-e IPXE_VERSION=$(IPXE_VERSION) \
			-e IPXE_SHA256=$(IPXE_SHA256) \
			-e IPXE_TARGETS="$(IPXE_TARGETS)" \
			-e IPXE_CACHE_KEY=$(IPXE_CACHE_KEY) \
			$(DOCKER_IMAGE); \
	fi
	@echo ""
	@echo "Build complete. Artifacts in: $(OUTPUT_DIR)"
	@ls -lR $(OUTPUT_DIR) | grep -v '^total'

# verify recomputes every SHA256SUMS in the output directory.
verify:
	@for d in $(OUTPUT_DIR)/*/; do (cd "$$d" && sha256sum -c --quiet SHA256SUMS && echo "$$d: ok"); done

clean:
	rm -rf $(OUTPUT_DIR)/bin-arm64-efi $(OUTPUT_DIR)/manifest.json
