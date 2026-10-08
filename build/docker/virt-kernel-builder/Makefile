# Virt kernel builder for the QEMU stand-in of the Raspberry Pi factory image.
#
# Cross-builds Alpine's linux-lts version of the upstream stable kernel for
# arm64 with the memory-mapped TIS TPM driver the emulated boot needs (see
# the Dockerfile for why Alpine's own kernels cannot serve). One build per
# input set; the cache key in output/manifest.json records which inputs
# produced the output, computed exactly as pkg/diskimage/virtkernel does.
#
#   make build

KERNEL_VERSION ?= 6.12.110
KERNEL_SHA256  ?= 8cee19e1839bb6ff4d5254d761933ae6ab670492d5ed030e09a80538320d5c4c
KERNEL_LOCALVERSION ?= -0-virt
KERNEL_FLAVOR  ?= virt

OUTPUT_DIR   ?= $(CURDIR)/output
# The kernel tarball cache is a named docker volume, not a host path: the
# daemon owns it, so it works when the build runs in a CI job container.
CACHE_VOLUME ?= trusted-platform-virt-kernel-src
DOCKER       ?= docker
RUN_BUILDER  ?= ../run-builder.sh
DOCKER_IMAGE ?= trusted-platform-virt-kernel-builder:$(KERNEL_VERSION)

# The shared platform kernel options (build/docker/kernel-config) are inputs
# too: the image bakes them in through the kernelconfig build context.
KERNEL_CONFIG_DIR := ../kernel-config
CONFIG_INPUTS := configs/virt.config build-virt-kernel.sh Dockerfile $(KERNEL_CONFIG_DIR)/platform-required.config $(KERNEL_CONFIG_DIR)/require-config.sh

.PHONY: all build config-check image cache-key verify clean

all: build

# KERNEL_CACHE_KEY: "virt-kernel:<version><localversion>", then the sha256 of
# each input, one per line, all fed to sha256 — the form
# pkg/diskimage/virtkernel.CacheKey computes (a unit test pins them).
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

# config-check runs the configuration phase only (defconfig, the fragments,
# olddefconfig, require-config.sh) and builds nothing: the quick proof that
# every fragment line survives Kconfig, e.g. after a kernel version bump.
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
