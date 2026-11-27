# Virt kernel builder for the QEMU stand-in of the Raspberry Pi factory image.

KERNEL_VERSION ?= 6.12.110
KERNEL_SHA256  ?= 8cee19e1839bb6ff4d5254d761933ae6ab670492d5ed030e09a80538320d5c4c
KERNEL_LOCALVERSION ?= -0-virt
KERNEL_FLAVOR  ?= virt

OUTPUT_DIR   ?= $(CURDIR)/output
# The tarball cache is a named docker volume, so it works from a CI job container.
CACHE_VOLUME ?= trusted-platform-virt-kernel-src
DOCKER       ?= docker
RUN_BUILDER  ?= ../run-builder.sh
DOCKER_IMAGE ?= trusted-platform-virt-kernel-builder:$(KERNEL_VERSION)

# The shared platform kernel options are inputs too.
KERNEL_CONFIG_DIR := ../kernel-config
CONFIG_INPUTS := configs/virt.config build-virt-kernel.sh Dockerfile $(KERNEL_CONFIG_DIR)/platform-required.config $(KERNEL_CONFIG_DIR)/require-config.sh

.PHONY: all build config-check image cache-key verify clean

all: build

# KERNEL_CACHE_KEY: the same key pkg/diskimage/virtkernel.CacheKey computes (a unit test pins them).
KERNEL_CACHE_KEY = $(shell { printf 'virt-kernel:%s%s\n' '$(KERNEL_VERSION)' '$(KERNEL_LOCALVERSION)'; for f in $(CONFIG_INPUTS); do sha256sum "$$f" 2>/dev/null | cut -d' ' -f1; done; } | sha256sum | cut -d' ' -f1)

cache-key:
	@echo $(KERNEL_CACHE_KEY)

image:
	$(DOCKER) build --build-context kernelconfig=$(KERNEL_CONFIG_DIR) -t $(DOCKER_IMAGE) .

build: image
	DOCKER=$(DOCKER) $(RUN_BUILDER) -o /output:$(abspath $(OUTPUT_DIR)) -- \
		-v $(CACHE_VOLUME):/build/src \
		-e KERNEL_VERSION=$(KERNEL_VERSION) \
		-e KERNEL_SHA256=$(KERNEL_SHA256) \
		-e KERNEL_LOCALVERSION=$(KERNEL_LOCALVERSION) \
		-e KERNEL_FLAVOR=$(KERNEL_FLAVOR) \
		-e KERNEL_CACHE_KEY=$(KERNEL_CACHE_KEY) \
		$(DOCKER_IMAGE)
	@echo ""
	@echo "Build complete. Artifacts in: $(OUTPUT_DIR)"
	@ls -lR $(OUTPUT_DIR) | grep -v '^total'

# config-check runs the configuration phase only and builds nothing.
config-check: image
	DOCKER=$(DOCKER) $(RUN_BUILDER) -- \
		-v $(CACHE_VOLUME):/build/src \
		-e KERNEL_VERSION=$(KERNEL_VERSION) \
		-e KERNEL_SHA256=$(KERNEL_SHA256) \
		-e KERNEL_LOCALVERSION=$(KERNEL_LOCALVERSION) \
		-e KERNEL_FLAVOR=$(KERNEL_FLAVOR) \
		-e KERNEL_CACHE_KEY=$(KERNEL_CACHE_KEY) \
		-e KERNEL_CONFIG_ONLY=1 \
		$(DOCKER_IMAGE)

verify:
	@for d in $(OUTPUT_DIR)/*/; do (cd "$$d" && sha256sum -c --quiet SHA256SUMS && echo "$$d: ok"); done

clean:
	rm -rf $(OUTPUT_DIR)/$(KERNEL_FLAVOR) $(OUTPUT_DIR)/manifest.json
