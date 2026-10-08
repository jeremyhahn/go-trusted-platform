# OpenSSL FIPS Provider Builder
#
# Builds OpenSSL FIPS provider module in Docker container

OPENSSL_VERSION ?= 3.4.1
OUTPUT_DIR ?= $(PWD)/output
DOCKER_IMAGE ?= openssl-fips-provider-builder
RUN_BUILDER ?= ../run-builder.sh

.PHONY: all build clean test

all: build

build:
	@echo "Building OpenSSL FIPS provider module..."
	docker build -t $(DOCKER_IMAGE) .
	$(RUN_BUILDER) -o /output:$(OUTPUT_DIR) -- \
		-e OPENSSL_VERSION=$(OPENSSL_VERSION) \
		$(DOCKER_IMAGE)
	@echo ""
	@echo "Build complete. Artifacts in: $(OUTPUT_DIR)"
	@ls -lh $(OUTPUT_DIR)

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(OUTPUT_DIR)
	@docker rmi $(DOCKER_IMAGE) 2>/dev/null || true

test:
	@echo "Testing FIPS provider module..."
	@if [ ! -f $(OUTPUT_DIR)/fips.so ]; then \
		echo "ERROR: FIPS module not found. Run 'make build' first."; \
		exit 1; \
	fi
	@echo "✓ FIPS module exists: $(OUTPUT_DIR)/fips.so"
	@stat -c "Size: %s bytes" $(OUTPUT_DIR)/fips.so
	@echo "SHA256:"
	@cat $(OUTPUT_DIR)/fips.so.sha256
