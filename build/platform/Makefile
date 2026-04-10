# Makefile for platform-initrd build targets
# Simplifies building and packaging the platform-initrd static binary

.PHONY: help build build-static clean copy-iso sign install test coverage

# Variables
BINARY_NAME       := platform-initrd
BINARY_PATH       := $(CURDIR)/../../$(BINARY_NAME)-static
BUILD_DIR         := $(CURDIR)/build
ISO_BUILD_DIR     := $(CURDIR)/../iso/alpine/amd64/work/iso
ISO_OVERLAY_DIR   := $(CURDIR)/../iso/alpine/amd64/work/overlay
ISO_BIN_DIR       := $(ISO_BUILD_DIR)/platform-initrd-bin

# Go build flags
GO_BUILD_FLAGS    := -ldflags "-X github.com/jeremyhahn/go-trusted-platform/pkg/app.Name=platform-initrd"
GO_STATIC_FLAGS   := CGO_ENABLED=0 GOOS=linux GOARCH=amd64

help:
	@echo "Platform-initrd Build Targets"
	@echo "=============================="
	@echo ""
	@echo "Targets:"
	@echo "  build           - Build platform-initrd binary (with cgo/dynamic linking)"
	@echo "  build-static    - Build static platform-initrd binary (no external dependencies)"
	@echo "  copy-iso        - Copy platform-initrd binary to ISO overlay directory"
	@echo "  sign            - Sign platform-initrd binary with Secure Boot keys (if available)"
	@echo "  install         - Build and install platform-initrd to system"
	@echo "  clean           - Remove build artifacts"
	@echo "  test            - Run platform-initrd tests"
	@echo "  coverage        - Run test coverage analysis"
	@echo ""
	@echo "Build Commands:"
	@echo "  make build-static        # Build static binary"
	@echo "  make copy-iso            # Copy to ISO build area"
	@echo "  make install             # Install to /usr/bin"
	@echo ""

# Build platform-initrd binary (dynamic linking)
build:
	@echo "Building platform-initrd..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) $(GO_BUILD_FLAGS) ../../cmd/platform-initrd/main.go
	@echo "✓ Built: $(BUILD_DIR)/$(BINARY_NAME)"

# Build static platform-initrd binary (no external dependencies)
build-static:
	@echo "Building static platform-initrd binary..."
	@mkdir -p $(BUILD_DIR)
	$(GO_STATIC_FLAGS) go build -o $(BINARY_PATH) $(GO_BUILD_FLAGS) ../../cmd/platform-initrd/main.go
	@echo "✓ Built static binary: $(BINARY_PATH)"
	@echo "Static binary size: $$(stat -f%z "$(BINARY_PATH)" 2>/dev/null || stat -c%s "$(BINARY_PATH)" 2>/dev/null) bytes"

# Copy platform-initrd to ISO build directory
copy-iso: build-static
	@echo "Copying platform-initrd to ISO build directory..."
	@mkdir -p $(ISO_BIN_DIR)
	@mkdir -p $(ISO_OVERLAY_DIR)/usr/bin
	cp $(BINARY_PATH) $(ISO_BIN_DIR)/
	cp $(BINARY_PATH) $(ISO_OVERLAY_DIR)/usr/bin/$(BINARY_NAME)
	chmod +x $(ISO_OVERLAY_DIR)/usr/bin/$(BINARY_NAME)
	@echo "✓ Copied to:"
	@echo "  - $(ISO_BIN_DIR)/"
	@echo "  - $(ISO_OVERLAY_DIR)/usr/bin/"

# Sign platform-initrd binary (Secure Boot) using native authenticode
sign: copy-iso
	@echo "Signing platform-initrd binary with native authenticode..."
	@if [ -f "$(ISO_OVERLAY_DIR)/usr/bin/$(BINARY_NAME)" ]; then \
		if [ -f /etc/platform/sb-signing-key.pem ] && [ -f /etc/platform/sb-cert.pem ]; then \
			platformd authenticode sign \
				--key /etc/platform/sb-signing-key.pem \
				--cert /etc/platform/sb-cert.pem \
				--input $(ISO_OVERLAY_DIR)/usr/bin/$(BINARY_NAME) \
				--output $(ISO_OVERLAY_DIR)/usr/bin/$(BINARY_NAME); \
			echo "✓ Signed with Secure Boot keys (native authenticode)"; \
		else \
			echo "WARNING: Secure Boot keys not found at /etc/platform/"; \
			echo "Skipping signature (binary will work unsigned)"; \
		fi; \
	else \
		echo "ERROR: Binary not found at $(ISO_OVERLAY_DIR)/usr/bin/$(BINARY_NAME)"; \
		exit 1; \
	fi

# Install platform-initrd to system
install: build
	@echo "Installing platform-initrd..."
	install -m 0755 $(BUILD_DIR)/$(BINARY_NAME) /usr/bin/
	@echo "✓ Installed: /usr/bin/$(BINARY_NAME)"

# Run platform-initrd tests
test:
	@echo "Running platform-initrd tests..."
	go test -v -race ./... -run TestInitrd

# Test coverage for initrd package
coverage:
	@echo "Generating coverage report for initrd package..."
	go test -v -coverprofile=$(BUILD_DIR)/coverage.out ./pkg/initrd/...
	go tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "✓ Coverage report: $(BUILD_DIR)/coverage.html"

# Clean build artifacts
clean:
	@echo "Cleaning platform-initrd build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY_PATH)
	@echo "✓ Cleaned"

# Verify script syntax
lint-scripts:
	@echo "Checking script syntax..."
	@for script in ../iso/alpine/amd64/scripts/install/*.sh; do \
		if [ -f "$$script" ]; then \
			echo "Checking: $$script"; \
			sh -n "$$script" || exit 1; \
		fi; \
	done
	@echo "✓ All scripts have valid syntax"

# Full build and deploy to ISO
all: clean build-static copy-iso
	@echo ""
	@echo "================================"
	@echo "Build complete!"
	@echo "================================"
	@echo "Platform-initrd binary:"
	@echo "  Static binary: $(BINARY_PATH)"
	@echo "  ISO location: $(ISO_BIN_DIR)/$(BINARY_NAME)"
	@echo "  System path: $(ISO_OVERLAY_DIR)/usr/bin/$(BINARY_NAME)"
	@echo ""
