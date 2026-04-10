# Makefile for Trusted Platform Internal DNS Example
# This demonstrates server/client setup using only internal DNS names
# Can run on different physical computers on the same network
#
# To use DNS on port 53:
#   make DNS_PUBLIC_PORT=53 DNS_INTERNAL_PORT=5354 all
#   make setcap
#   make run-server
# Note: Public and internal DNS must use different ports

# Configuration
APPBIN             := $(PWD)/../../../platformd
PASSWORD           ?= test
HOSTNAME           ?= $(shell hostname)
INTERNAL_DOMAIN    ?= internal
TPM_SIMULATOR      ?= true

# Server configuration
SERVER_DIR         := server
SERVER_HOSTNAME    ?= server
SERVER_FQDN        := $(SERVER_HOSTNAME).$(INTERNAL_DOMAIN)
SERVER_PORT        ?= 8443
DNS_PUBLIC_PORT    ?= 8053  # Public DNS port
DNS_INTERNAL_PORT  ?= 8054  # Internal DNS port (must be different from public)
SERVER_DNS_PORT    := $(DNS_INTERNAL_PORT)  # Server uses internal DNS port for queries
SERVER_ACME_URL    := https://$(SERVER_FQDN):$(SERVER_PORT)/api/v1/acme/directory

# Client configuration  
CLIENT_DIR         := client
CLIENT_HOSTNAME    ?= client-001
CLIENT_FQDN        := $(CLIENT_HOSTNAME).$(INTERNAL_DOMAIN)
CLIENT_PORT        ?= 8081
CLIENT_TLS_PORT    ?= 9443
CLIENT_ENROLLMENT  := enroll-$(CLIENT_PORT)
CLIENT_CHALLENGE   := http-$(CLIENT_PORT)

# Public HTML source
PUBLIC_HTML_SRC    := ../../../public_html

# Server IP (for DNS and initial connection)
SERVER_IP          ?= $(shell hostname -I | awk '{print $$1}' || echo "127.0.0.1")

# Colors for output
GREEN  := \033[0;32m
YELLOW := \033[0;33m
RED    := \033[0;31m
NC     := \033[0m

.PHONY: all
all: clean build setup
	@echo "$(GREEN)✓ Setup complete!$(NC)"
	@echo ""
	@echo "Next steps:"
	@echo "  1. make run-server   (terminal 1)"
	@echo "  2. make dns-forward  (see DNS setup options)"  
	@echo "  3. make run-client   (terminal 2)"
	@echo "  4. make firefox      (test WebAuthn)"

.PHONY: help
help:
	@echo "Trusted Platform Internal DNS Example"
	@echo "===================================="
	@echo ""
	@echo "Quick start:"
	@echo "  make all         - Build and setup everything"
	@echo "  make run-server  - Run server (terminal 1)"
	@echo "  make run-client  - Run client (terminal 2)"
	@echo "  make firefox     - Launch Firefox"
	@echo ""
	@echo "Other commands:"
	@echo "  make status      - Check status"
	@echo "  make logs        - Show logs"
	@echo "  make dns-forward - Setup DNS forwarding (requires sudo)"
	@echo "  make setcap      - Enable binding to port 53 without root"
	@echo "  make test-dns    - Test DNS resolution"
	@echo "  make stop-all    - Stop services"
	@echo "  make clean       - Clean up"
	@echo ""
	@echo "Configuration:"
	@echo "  SERVER_FQDN=$(SERVER_FQDN)"
	@echo "  CLIENT_FQDN=$(CLIENT_FQDN)"
	@echo "  SERVER_IP=$(SERVER_IP)"
	@echo "  INTERNAL_DOMAIN=$(INTERNAL_DOMAIN)"
	@echo "  DNS_PUBLIC_PORT=$(DNS_PUBLIC_PORT)"
	@echo "  DNS_INTERNAL_PORT=$(DNS_INTERNAL_PORT)"

.PHONY: build
build:
	@echo "$(GREEN)Building platform binary...$(NC)"
	@cd ../../.. && make build

.PHONY: setup
setup: setup-dirs copy-public-html init-server init-client

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
		--dns-public-port $(DNS_PUBLIC_PORT) \
		--dns-internal-port $(DNS_INTERNAL_PORT) \
		--tpm-simulator $(TPM_SIMULATOR) \
		--hostname $(SERVER_HOSTNAME) \
		--internal-domain $(INTERNAL_DOMAIN) \
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
		--internal-domain $(INTERNAL_DOMAIN) \
		--acme-directory-url "https://$(SERVER_FQDN):$(SERVER_PORT)/api/v1/acme/directory" \
		--acme-client-enrollment-challenge $(CLIENT_ENROLLMENT) \
		--acme-client-webservice-challenge $(CLIENT_CHALLENGE) \
		--webservice-port $(CLIENT_PORT) \
		--webservice-tls-port $(CLIENT_TLS_PORT) \
		--tpm-ek-cert-handle 0 \
		--hostname $(CLIENT_HOSTNAME) \
		--raw-so-pin $(PASSWORD) \
		--raw-pin $(PASSWORD)

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
	@echo "$(GREEN)Starting server on https://$(SERVER_FQDN):$(SERVER_PORT)$(NC)"
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
	@echo "$(GREEN)Starting client on https://$(CLIENT_FQDN):$(CLIENT_TLS_PORT)$(NC)"
	@cd $(CLIENT_DIR) && $(APPBIN) \
		--init \
		--raw-so-pin $(PASSWORD) \
		--raw-pin $(PASSWORD) \
		webservice

.PHONY: status
status:
	@echo "$(GREEN)=== Server Status ===$(NC)"
	@curl -sk https://$(SERVER_FQDN):$(SERVER_PORT)/api/v1/status 2>/dev/null | jq -r '.message // .' || echo "$(RED)Server not running$(NC)"
	@echo ""
	@echo "$(GREEN)=== Client Status ===$(NC)"
	@curl -sk https://$(CLIENT_FQDN):$(CLIENT_TLS_PORT)/api/v1/status 2>/dev/null | jq -r '.message // .' || echo "$(RED)Client not enrolled yet$(NC)"

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
	@rm -rf $(SERVER_DIR) $(CLIENT_DIR) firefox-config firefox-profile
	@rm -f server.log client.log server.pid client.pid
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


# Firefox support
.PHONY: firefox-setup
firefox-setup:
	@echo "$(GREEN)Setting up Firefox with trusted CA certificates...$(NC)"
	@# Find all available CA certificates (root and intermediate)
	@ROOT_CA_CERTS=$$(find $(SERVER_DIR)/trusted-data/ca/root-ca.$(INTERNAL_DOMAIN)/x509 -name "root-ca.$(INTERNAL_DOMAIN).*.cer" 2>/dev/null); \
	INTERMEDIATE_CA_CERTS=$$(find $(SERVER_DIR)/trusted-data/ca/intermediate-ca.$(INTERNAL_DOMAIN)/x509 -name "intermediate-ca.$(INTERNAL_DOMAIN).*.cer" 2>/dev/null); \
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
	echo "$(GREEN)✓ Firefox policy created with $$(echo $$ALL_CA_CERTS | wc -w) certificates$(NC)"

.PHONY: firefox
firefox: firefox-setup
	@rm -rf firefox-profile
	@mkdir -p firefox-profile
	@echo "$(GREEN)Opening https://$(CLIENT_FQDN):$(CLIENT_TLS_PORT)$(NC)"
	@firefox --profile firefox-profile --new-instance "https://$(CLIENT_FQDN):$(CLIENT_TLS_PORT)" 2>/dev/null &

.PHONY: dns-forward
dns-forward:
	@echo "$(GREEN)Setting up DNS forwarding for .internal domain...$(NC)"
	@echo ""
	@echo "Choose an option:"
	@echo "1. systemd-resolved (recommended):"
	@echo "   sudo resolvectl dns $$(ip route | grep default | awk '{print $$5}') $(SERVER_IP)"
	@echo "   sudo resolvectl domain $$(ip route | grep default | awk '{print $$5}') '~internal'"
	@echo ""
	@echo "2. Quick test with socat:"
	@echo "   sudo socat UDP4-LISTEN:53,fork,reuseaddr UDP4:$(SERVER_IP):$(DNS_INTERNAL_PORT)"
	@echo ""
	@echo "3. See dns-forwarding.md for more options"

.PHONY: test-dns
test-dns:
	@echo "$(GREEN)Testing DNS resolution...$(NC)"
	@dig @$(SERVER_IP) -p $(DNS_INTERNAL_PORT) $(SERVER_FQDN) +short || echo "Direct query to server DNS"
	@echo ""
	@dig $(SERVER_FQDN) +short || echo "System DNS query"

.PHONY: setcap
setcap:
	@echo "$(GREEN)Setting capability to bind port 53...$(NC)"
	@sudo setcap 'cap_net_bind_service=+ep' $(APPBIN)
	@echo "$(GREEN)✓ Done. platformd can now bind to port 53 as normal user$(NC)"
	@echo ""
	@echo "To use port 53, update the DNS configuration in server/config.yaml:"
	@echo "  dns:"
	@echo "    public:"
	@echo "      port: 53"
	@echo "    internal:"
	@echo "      port: 53"

