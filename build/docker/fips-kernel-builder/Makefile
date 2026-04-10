# FIPS Kernel Builder
#
# Builds FIPS-capable Linux kernel in Docker container

# Use 6.12.8 to match Alpine 3.22 LTS kernel (NOT 6.13!)
KERNEL_VERSION ?= 6.12.8
OUTPUT_DIR ?= $(PWD)/output
DOCKER_IMAGE ?= fips-kernel-builder

.PHONY: all build clean test

all: build

build:
	@echo "Building FIPS-capable kernel ${KERNEL_VERSION}..."
	@mkdir -p $(OUTPUT_DIR)
	docker build -t $(DOCKER_IMAGE) .
	docker run --rm \
		-v $(OUTPUT_DIR):/output \
		-e KERNEL_VERSION=$(KERNEL_VERSION) \
		$(DOCKER_IMAGE)
	@echo ""
	@echo "Build complete. Artifacts in: $(OUTPUT_DIR)"
	@ls -lh $(OUTPUT_DIR)

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
