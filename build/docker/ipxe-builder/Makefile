# iPXE builder for the Trusted Platform network boot.

IPXE_VERSION ?= 2.0.0
IPXE_SHA256  ?= 9ed6d029be901a0ccc87cb2e5f9c774620f30f84ebdd507c6dd3e1e6229b7bd5
IPXE_TARGETS ?= bin-arm64-efi/snponly.efi

OUTPUT_DIR   ?= $(CURDIR)/output
# The tarball cache is a named docker volume, so it works from a CI job container.
CACHE_VOLUME ?= trusted-platform-ipxe-src
DOCKER       ?= docker
RUN_BUILDER  ?= ../run-builder.sh
DOCKER_IMAGE ?= trusted-platform-ipxe-builder:$(IPXE_VERSION)

# Everything that shapes the binary; a change to any of them misses the cache.
CONFIG_INPUTS := configs/nap.h Dockerfile build-ipxe.sh

.PHONY: all build image cache-key verify clean

all: build

# IPXE_CACHE_KEY: sha256 over the version, the tarball digest, the targets and each CONFIG_INPUTS file's sha256.
IPXE_CACHE_KEY = $(shell { printf 'ipxe:%s\nsha256:%s\ntargets:%s\n' '$(IPXE_VERSION)' '$(IPXE_SHA256)' '$(IPXE_TARGETS)'; for f in $(CONFIG_INPUTS); do sha256sum "$$f" 2>/dev/null | cut -d' ' -f1; done; } | sha256sum | cut -d' ' -f1)

cache-key:
	@echo $(IPXE_CACHE_KEY)

image:
	$(DOCKER) build -t $(DOCKER_IMAGE) .

# build skips the container when the manifest carries the current cache key and every output verifies.
build: image
	@if [ -f $(OUTPUT_DIR)/manifest.json ] && grep -q '"cache_key": "$(IPXE_CACHE_KEY)"' $(OUTPUT_DIR)/manifest.json && $(MAKE) -s verify OUTPUT_DIR=$(OUTPUT_DIR) >/dev/null 2>&1; then \
		echo "iPXE output is current (cache key $(IPXE_CACHE_KEY)); skipping build"; \
	else \
		DOCKER=$(DOCKER) $(RUN_BUILDER) \
				-i $(CURDIR)/configs:/configs -o /output:$(abspath $(OUTPUT_DIR)) -- \
				-v $(CACHE_VOLUME):/build/src \
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
