# FIPS kernel builder.

# Matches the Alpine 3.22 LTS kernel.
KERNEL_VERSION ?= 6.12.8
OUTPUT_DIR ?= $(PWD)/output
DOCKER_IMAGE ?= fips-kernel-builder
# The options every platform kernel carries, baked into the image through the kernelconfig build context.
KERNEL_CONFIG_DIR := ../kernel-config

# Stable platform module-signing key (PEM bundle: private key and certificate).
MODULE_SIGNING_KEY ?=
DEFAULT_MODULE_SIGNING_KEY := $(HOME)/.trusted-platform/secure-boot/module-signing-key.pem

# A provided key is copied into the container at /keys.
RUN_BUILDER ?= ../run-builder.sh
ifneq ($(MODULE_SIGNING_KEY),)
KEY_COPY_ARGS := -i $(abspath $(MODULE_SIGNING_KEY)):/keys/$(notdir $(MODULE_SIGNING_KEY))
KEY_ENV_ARGS := -e MODULE_SIGNING_KEY=/keys/$(notdir $(MODULE_SIGNING_KEY))
else
KEY_COPY_ARGS :=
KEY_ENV_ARGS :=
endif

.PHONY: all build image config-check module-key clean test

all: build

image:
	docker build --build-context kernelconfig=$(KERNEL_CONFIG_DIR) -t $(DOCKER_IMAGE) .

# config-check runs the configuration phase only and builds nothing.
config-check: image
	docker run --rm -e KERNEL_VERSION=$(KERNEL_VERSION) -e KERNEL_CONFIG_ONLY=1 $(DOCKER_IMAGE)

build: image
	@echo "Building FIPS-capable kernel ${KERNEL_VERSION}..."
ifeq ($(MODULE_SIGNING_KEY),)
	@echo "WARNING: MODULE_SIGNING_KEY not set — kernel will use a per-build ephemeral module-signing key (dev only)."
	@echo "         Production: make module-key && make build MODULE_SIGNING_KEY=$(DEFAULT_MODULE_SIGNING_KEY)"
else
	@test -f "$(MODULE_SIGNING_KEY)" || { echo "ERROR: MODULE_SIGNING_KEY '$(MODULE_SIGNING_KEY)' does not exist (run 'make module-key')"; exit 1; }
endif
	$(RUN_BUILDER) $(KEY_COPY_ARGS) -o /output:$(OUTPUT_DIR) -- \
		$(KEY_ENV_ARGS) \
		-e KERNEL_VERSION=$(KERNEL_VERSION) \
		$(DOCKER_IMAGE)
	@echo ""
	@echo "Build complete. Artifacts in: $(OUTPUT_DIR)"
	@ls -lh $(OUTPUT_DIR)

# Generate the stable platform module-signing key at the default operator location, outside the repository.
module-key:
	cd ../../.. && go run ./cmd/platformctl iso module-signing-key

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(OUTPUT_DIR)
	@docker rmi $(DOCKER_IMAGE) 2>/dev/null || true

test:
	@echo "Testing FIPS kernel artifacts..."
	@if [ ! -f $(OUTPUT_DIR)/vmlinuz-fips ]; then \
		echo "ERROR: Kernel image not found. Run 'make build' first."; \
		exit 1; \
	fi
	@if [ ! -f $(OUTPUT_DIR)/kernel-version.txt ]; then \
		echo "ERROR: Version file not found."; \
		exit 1; \
	fi
	@echo "✓ Kernel image exists: $(OUTPUT_DIR)/vmlinuz-fips"
	@stat -c "Size: %s bytes" $(OUTPUT_DIR)/vmlinuz-fips
	@echo "Kernel version: $$(cat $(OUTPUT_DIR)/kernel-version.txt)"
	@echo "SHA256:"
	@cat $(OUTPUT_DIR)/vmlinuz-fips.sha256
	@echo ""
	@echo "✓ Modules tarball: $(OUTPUT_DIR)/modules-fips-$$(cat $(OUTPUT_DIR)/kernel-version.txt).tar.gz"
	@stat -c "Size: %s bytes" "$(OUTPUT_DIR)/modules-fips-$$(cat $(OUTPUT_DIR)/kernel-version.txt).tar.gz"
