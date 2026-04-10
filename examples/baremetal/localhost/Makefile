# Unified Makefile for Trusted Platform Localhost Example
# This demonstrates a complete server/client setup using TPM simulator

# Configuration
APPBIN             := $(PWD)/../../../platformd
PASSWORD           ?= test
HOSTNAME           ?= $(shell hostname)
PUBLIC_DOMAIN      ?= $(HOSTNAME).local
INTERNAL_DOMAIN    ?= $(HOSTNAME).internal
TPM_SIMULATOR      ?= true

# Server configuration
SERVER_DIR         := server
SERVER_PORT        ?= 8443
SERVER_ACME_URL    := https://$(PUBLIC_DOMAIN):$(SERVER_PORT)/api/v1/acme/directory

# Client configuration  
CLIENT_DIR         := client
CLIENT_PORT        ?= 8081
CLIENT_TLS_PORT    ?= 9443
CLIENT_HOSTNAME    ?= edge-001
CLIENT_ENROLLMENT  := enroll-$(CLIENT_PORT)
CLIENT_CHALLENGE   := http-$(CLIENT_PORT)

# Public HTML source
PUBLIC_HTML_SRC    := ../../../public_html

# Colors for output
GREEN  := \033[0;32m
YELLOW := \033[0;33m
RED    := \033[0;31m
NC     := \033[0m

.PHONY: all
all: clean build setup
	@echo "$(GREEN)✓ Setup complete!$(NC)"
	@echo ""
	@echo "$(YELLOW)To run the demo:$(NC)"
	@echo "  1. Terminal 1: make run-server"
	@echo "  2. Terminal 2: make run-client"
	@echo ""
	@echo "The client will auto-enroll with the server."

.PHONY: help
help:
	@echo "Trusted Platform Localhost Example"
	@echo "================================="
	@echo ""
	@echo "Quick start:"
	@echo "  make all         - Build and setup everything"
	@echo "  make run-server  - Run server (terminal 1)"
	@echo "  make run-client  - Run client (terminal 2)"
	@echo "  make firefox     - Launch Firefox with trusted CA"
	@echo "  make test-webauthn - Test WebAuthn status"
	@echo ""
	@echo "Other commands:"
	@echo "  make status      - Check server/client status"
	@echo "  make logs        - Show recent logs"
	@echo "  make stop-all    - Stop all services"
	@echo "  make clean       - Remove all generated files"
	@echo ""
	@echo "Configuration:"
	@echo "  HOSTNAME=$(HOSTNAME)"
	@echo "  PUBLIC_DOMAIN=$(PUBLIC_DOMAIN)"
	@echo "  SERVER_PORT=$(SERVER_PORT)"
	@echo "  CLIENT_TLS_PORT=$(CLIENT_TLS_PORT)"

.PHONY: build
build:
	@echo "$(GREEN)Building platform binary...$(NC)"
	@cd ../../.. && make build

.PHONY: setup
setup: setup-dirs copy-public-html init-server init-client check-hosts

.PHONY: setup-dirs
setup-dirs:
	@echo "$(GREEN)Creating directory structure...$(NC)"
	@mkdir -p $(SERVER_DIR) $(CLIENT_DIR)

.PHONY: copy-public-html
copy-public-html:
	@echo "$(GREEN)Copying public HTML files...$(NC)"
	@if [ ! -d $(PUBLIC_HTML_SRC) ]; then \
		cd ../../.. && make build-public-html; \
	fi
	@cp -r $(PUBLIC_HTML_SRC) $(SERVER_DIR)/public_html
	@cp -r $(PUBLIC_HTML_SRC) $(CLIENT_DIR)/public_html

.PHONY: init-server
init-server:
	@echo "$(GREEN)Initializing server configuration...$(NC)"
	@cd $(SERVER_DIR) && $(APPBIN) config gen \
		--debug=true \
		--debug-secrets=true \
		--fips=false \
		--platform-dir trusted-data \
		--datastore-dir trusted-data/datastore \
		--dns-datastore-dir trusted-data \
		--tpm-simulator $(TPM_SIMULATOR) \
		--public-domain $(PUBLIC_DOMAIN) \
		--public-ip $(shell hostname -I | awk '{print $$1}' || echo "127.0.0.1") \
		--internal-domain $(INTERNAL_DOMAIN) \
		--acme-directory-url $(SERVER_ACME_URL) \
		--webauthn-rp-id $(PUBLIC_DOMAIN) \
		--raw-so-pin $(PASSWORD) \
		--raw-pin $(PASSWORD)

.PHONY: init-client
init-client:
	@echo "$(GREEN)Initializing client configuration...$(NC)"
	@cd $(CLIENT_DIR) && $(APPBIN) config gen \
		--type client \
		--debug=true \
		--debug-secrets=true \
		--fips=false \
		--platform-dir trusted-data \
		--tpm-simulator $(TPM_SIMULATOR) \
		--public-domain $(PUBLIC_DOMAIN) \
		--public-ip $(shell hostname -I | awk '{print $$1}' || echo "127.0.0.1") \
		--internal-domain $(INTERNAL_DOMAIN) \
		--acme-directory-url "https://$(PUBLIC_DOMAIN):$(SERVER_PORT)/api/v1/acme/directory" \
		--acme-client-enrollment-challenge $(CLIENT_ENROLLMENT) \
		--acme-client-webservice-challenge $(CLIENT_CHALLENGE) \
		--webservice-port $(CLIENT_PORT) \
		--webservice-tls-port $(CLIENT_TLS_PORT) \
		--webauthn-rp-id $(PUBLIC_DOMAIN) \
		--tpm-ek-cert-handle 0 \
		--raw-so-pin $(PASSWORD) \
		--raw-pin $(PASSWORD) && \
	echo "$(YELLOW)Setting WebAuthn origins for port $(CLIENT_TLS_PORT)...$(NC)" && \
	sed -i '/webauthn:/,/^[^ ]/ { /origins:/,/^  [^ ]/ d; }' config.yaml && \
	sed -i '/webauthn:/a\    origins:\n    - https://$(PUBLIC_DOMAIN):$(CLIENT_TLS_PORT)\n    - https://localhost:$(CLIENT_TLS_PORT)' config.yaml

.PHONY: run-server
run-server:
	@if [ ! -f $(APPBIN) ]; then \
		echo "$(YELLOW)Platform binary not found. Building...$(NC)"; \
		$(MAKE) build; \
	fi
	@if [ ! -d $(SERVER_DIR) ]; then \
		echo "$(YELLOW)Server directory not found. Running setup...$(NC)"; \
		$(MAKE) setup; \
	fi
	@echo "$(GREEN)Starting server on https://localhost:$(SERVER_PORT)$(NC)"
	@cd $(SERVER_DIR) && $(APPBIN) \
		--init \
		--raw-so-pin $(PASSWORD) \
		--raw-pin $(PASSWORD) \
		webservice

.PHONY: run-client
run-client:
	@if [ ! -f $(APPBIN) ]; then \
		echo "$(YELLOW)Platform binary not found. Building...$(NC)"; \
		$(MAKE) build; \
	fi
	@if [ ! -d $(CLIENT_DIR) ]; then \
		echo "$(YELLOW)Client directory not found. Running setup...$(NC)"; \
		$(MAKE) setup; \
	fi
	@echo "$(GREEN)Starting client on http://localhost:$(CLIENT_PORT)$(NC)"
	@echo "$(YELLOW)Client will auto-enroll with the server...$(NC)"
	@cd $(CLIENT_DIR) && $(APPBIN) \
		--init \
		--raw-so-pin $(PASSWORD) \
		--raw-pin $(PASSWORD) \
		webservice

.PHONY: status
status:
	@echo "$(GREEN)=== Server Status ===$(NC)"
	@curl -sk https://localhost:$(SERVER_PORT)/api/v1/status 2>/dev/null | jq -r '.message // .' || echo "$(RED)Server not running$(NC)"
	@echo ""
	@echo "$(GREEN)=== Client Status ===$(NC)"
	@curl -sk https://localhost:$(CLIENT_TLS_PORT)/api/v1/status 2>/dev/null | jq -r '.message // .' || echo "$(RED)Client not enrolled yet$(NC)"

.PHONY: logs
logs:
	@echo "$(GREEN)=== Recent Server Logs ===$(NC)"
	@tail -n 10 $(SERVER_DIR)/trusted-data/log/trusted-platform.log 2>/dev/null || echo "No server logs"
	@echo ""
	@echo "$(GREEN)=== Recent Client Logs ===$(NC)"
	@tail -n 10 $(CLIENT_DIR)/trusted-data/log/trusted-platform.log 2>/dev/null || echo "No client logs"

.PHONY: clean
clean:
	@echo "$(YELLOW)Cleaning up...$(NC)"
	@$(MAKE) stop-all 2>/dev/null || true
	@rm -rf $(SERVER_DIR) $(CLIENT_DIR) firefox-config firefox firefox-profile
	@rm -f server.log client.log server.pid client.pid cert-analysis.tmp
	@echo "$(GREEN)✓ Clean complete$(NC)"



.PHONY: stop-all
stop-all:
	@echo "$(YELLOW)Stopping all services...$(NC)"
	@if [ -f server.pid ]; then \
		kill $$(cat server.pid) 2>/dev/null || true; \
		rm -f server.pid; \
		echo "$(GREEN)✓ Server stopped$(NC)"; \
	fi
	@if [ -f client.pid ]; then \
		kill $$(cat client.pid) 2>/dev/null || true; \
		rm -f client.pid; \
		echo "$(GREEN)✓ Client stopped$(NC)"; \
	fi
	@pkill -f "$(APPBIN).*webservice" 2>/dev/null || true


.PHONY: check-hosts
check-hosts:
	@if ! grep -q "$(PUBLIC_DOMAIN)" /etc/hosts 2>/dev/null; then \
		echo "$(YELLOW)Warning: $(PUBLIC_DOMAIN) not found in /etc/hosts$(NC)"; \
		echo "$(YELLOW)Please add this line to /etc/hosts:$(NC)"; \
		echo "127.0.0.1    $(PUBLIC_DOMAIN)"; \
		echo ""; \
		echo "You can do this by running:"; \
		echo "echo '127.0.0.1    $(PUBLIC_DOMAIN)' | sudo tee -a /etc/hosts"; \
	fi

.PHONY: test-webauthn
test-webauthn:
	@echo "$(GREEN)Testing WebAuthn registration status...$(NC)"
	@response=$$(curl -sk https://localhost:$(CLIENT_TLS_PORT)/api/v1/webauthn/registration/status 2>/dev/null); \
	if [ -z "$$response" ]; then \
		echo "$(RED)✗ Client not running or not accessible$(NC)"; \
		exit 1; \
	fi; \
	if [ "$$response" = '"not_registered"' ]; then \
		echo "$(YELLOW)WebAuthn not registered yet$(NC)"; \
		echo ""; \
		echo "To register:"; \
		echo "1. Run 'make firefox'"; \
		echo "2. Navigate to WebAuthn page"; \
		echo "3. Complete registration"; \
	elif [ "$$response" = '"registered"' ]; then \
		echo "$(GREEN)✓ WebAuthn is registered and working$(NC)"; \
	else \
		status=$$(echo "$$response" | jq -r '.payload.status' 2>/dev/null || echo ""); \
		if [ "$$status" = "registered" ]; then \
			echo "$(GREEN)✓ WebAuthn is registered and working$(NC)"; \
		elif [ "$$status" = "not_registered" ]; then \
			echo "$(YELLOW)WebAuthn not registered yet$(NC)"; \
			echo ""; \
			echo "To register:"; \
			echo "1. Run 'make firefox'"; \
			echo "2. Navigate to WebAuthn page"; \
			echo "3. Complete registration"; \
		else \
			echo "$(RED)✗ Error checking WebAuthn status$(NC)"; \
			echo "Response: $$response"; \
		fi; \
	fi

# Firefox support targets
.PHONY: firefox-setup
firefox-setup:
	@echo "$(GREEN)Setting up Firefox with trusted CA certificates...$(NC)"
	@# Find all available CA certificates (root and intermediate)
	@ROOT_CA_CERTS=$$(find $(SERVER_DIR)/trusted-data/ca/root-ca.$(PUBLIC_DOMAIN)/x509 -name "root-ca.$(PUBLIC_DOMAIN).*.cer" 2>/dev/null); \
	INTERMEDIATE_CA_CERTS=$$(find $(SERVER_DIR)/trusted-data/ca/intermediate-ca.$(PUBLIC_DOMAIN)/x509 -name "intermediate-ca.$(PUBLIC_DOMAIN).*.cer" 2>/dev/null); \
	ALL_CA_CERTS="$$ROOT_CA_CERTS $$INTERMEDIATE_CA_CERTS"; \
	if [ -z "$$ALL_CA_CERTS" ]; then \
		echo "$(RED)Error: CA certificates not found. Run the server first.$(NC)"; \
		exit 1; \
	fi; \
	echo "$(GREEN)Creating Firefox policy configuration...$(NC)"; \
	mkdir -p firefox-config/certs; \
	echo "$(GREEN)Converting certificates to PEM format...$(NC)"; \
	for cert in $$ALL_CA_CERTS; do \
		certname=$$(basename $$cert .cer); \
		openssl x509 -inform DER -in "$$cert" -outform PEM -out "firefox-config/certs/$$certname.pem" 2>/dev/null || \
		openssl x509 -inform PEM -in "$$cert" -outform PEM -out "firefox-config/certs/$$certname.pem" 2>/dev/null; \
	done; \
	echo '{' > firefox-config/policies.json; \
	echo '    "policies": {' >> firefox-config/policies.json; \
	echo '        "Certificates": {' >> firefox-config/policies.json; \
	echo '            "ImportEnterpriseRoots": true,' >> firefox-config/policies.json; \
	echo '            "Install": [' >> firefox-config/policies.json; \
	first=true; \
	for cert in firefox-config/certs/*.pem; do \
		if [ "$$first" = "true" ]; then \
			first=false; \
		else \
			echo ',' >> firefox-config/policies.json; \
		fi; \
		printf '                "%s"' "$$(realpath $$cert)" >> firefox-config/policies.json; \
	done; \
	echo '' >> firefox-config/policies.json; \
	echo '            ]' >> firefox-config/policies.json; \
	echo '        }' >> firefox-config/policies.json; \
	echo '    }' >> firefox-config/policies.json; \
	echo '}' >> firefox-config/policies.json; \
	echo "$(GREEN)✓ Firefox policy created with $$(echo $$ALL_CA_CERTS | wc -w) certificates$(NC)"; \
	if [ -f /usr/lib/firefox/distribution/policies.json ]; then \
		echo "$(YELLOW)Firefox distribution policy detected$(NC)"; \
		echo "$(YELLOW)Merging with existing policy...$(NC)"; \
		jq -s '.[0] * .[1]' /usr/lib/firefox/distribution/policies.json firefox-config/policies.json > firefox-config/policies-merged.json; \
		echo "$(YELLOW)To install, run:$(NC)"; \
		echo "  sudo cp firefox-config/policies-merged.json /usr/lib/firefox/distribution/policies.json"; \
	else \
		echo "$(YELLOW)To install system-wide, run:$(NC)"; \
		echo "  sudo mkdir -p /etc/firefox/policies/"; \
		echo "  sudo cp firefox-config/policies.json /etc/firefox/policies/"; \
	fi; \
	echo ""; \
	echo "$(YELLOW)Or run 'make firefox-install-policy' to install with sudo$(NC)"

.PHONY: firefox
firefox: firefox-setup
	@echo "$(GREEN)Launching Firefox with trusted CA...$(NC)"
	@# Create fresh profile to avoid IndexedDB corruption
	@rm -rf firefox-profile
	@mkdir -p firefox-profile
	@# Extract the first DNS SAN from client config
	@CLIENT_DNS=$$(grep -A 10 "webservice:" $(CLIENT_DIR)/config.yaml | grep -A 5 "dns:" | grep "^      - " | head -1 | sed 's/^      - //'); \
	if [ -z "$$CLIENT_DNS" ]; then \
		CLIENT_DNS="localhost"; \
	fi; \
	echo "$(GREEN)Opening https://$$CLIENT_DNS:$(CLIENT_TLS_PORT)$(NC)"; \
	echo "$(YELLOW)Using fresh Firefox profile to avoid storage issues$(NC)"; \
	if command -v firefox >/dev/null 2>&1; then \
		firefox --profile firefox-profile --new-instance "https://$$CLIENT_DNS:$(CLIENT_TLS_PORT)" & \
	else \
		echo "$(RED)Firefox not found. Please install Firefox.$(NC)"; \
	fi


