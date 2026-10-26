# Docker Trusted Platform Example Makefile
# This demonstrates a complete server/client setup using Docker containers

# Configuration
PROJECT_ROOT       := $(shell cd ../../.. && pwd)
APPBIN             := $(PROJECT_ROOT)/platformd
PUBLIC_HTML_SRC    := $(PROJECT_ROOT)/public_html
PASSWORD           ?= test
TPM_SIMULATOR      ?= true
TARGETARCH         ?= $(shell go env GOARCH 2>/dev/null || echo "amd64")

# Server configuration
SERVER_HOSTNAME    ?= server
SERVER_DOMAIN      ?= platform.local
SERVER_PORT        ?= 8443
SERVER_HTTP_PORT   ?= 8080
SERVER_DNS_PUBLIC  ?= 8053
SERVER_DNS_INTERNAL?= 8054
SERVER_ACME_URL    := https://platform.local:$(SERVER_PORT)/api/v1/acme/directory

# Client configuration  
CLIENT_HOSTNAME    ?= edge-001
CLIENT_DOMAIN      ?= edge-001.platform.local
CLIENT_PORT        ?= 8081
CLIENT_TLS_PORT    ?= 9443
CLIENT_ENROLLMENT  := enroll-01
CLIENT_CHALLENGE   := http-8081

# Docker configuration
COMPOSE_PROJECT    := trusted-platform-example
DOCKER_BUILDKIT    := 1

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
	@echo "  make up      - Start both server and client"
	@echo "  make logs    - View container logs"
	@echo "  make status  - Check service status"
	@echo ""
	@echo "The client will auto-enroll with the server."

.PHONY: help
help:
	@echo "Docker Trusted Platform Example"
	@echo "==============================="
	@echo ""
	@echo "Quick start:"
	@echo "  make all     - Build and setup everything"
	@echo "  make up      - Start containers"
	@echo "  make down    - Stop containers"
	@echo "  make logs    - View container logs"
	@echo "  make status  - Check service status"
	@echo "  make firefox - Launch Firefox with trusted CA"
	@echo ""
	@echo "Individual commands:"
	@echo "  make build-app     - Build platform binary"
	@echo "  make build-images  - Build Docker images"
	@echo "  make clean         - Remove all generated files"
	@echo ""
	@echo "Configuration:"
	@echo "  SERVER_DOMAIN=$(SERVER_DOMAIN)"
	@echo "  CLIENT_DOMAIN=$(CLIENT_DOMAIN)"
	@echo "  SERVER_PORT=$(SERVER_PORT)"
	@echo "  CLIENT_TLS_PORT=$(CLIENT_TLS_PORT)"

.PHONY: build
build: build-app copy-files generate-configs

.PHONY: build-app
build-app:
	@echo "$(GREEN)Building platform binary...$(NC)"
	@cd $(PROJECT_ROOT) && make build


.PHONY: copy-files
copy-files: copy-binary copy-public-html copy-wait-for

# The entrypoints poll swtpm's port with the harness's wait_for helper.
.PHONY: copy-wait-for
copy-wait-for:
	@cp $(PROJECT_ROOT)/build/docker/devcontainer/wait-for.sh server/wait-for.sh
	@cp $(PROJECT_ROOT)/build/docker/devcontainer/wait-for.sh client/wait-for.sh

.PHONY: copy-binary
copy-binary:
	@echo "$(GREEN)Copying platform binary...$(NC)"
	@if [ ! -f $(APPBIN) ]; then \
		echo "$(RED)Platform binary not found. Building...$(NC)"; \
		$(MAKE) build-app; \
	fi
	@cp $(APPBIN) server/platformd
	@cp $(APPBIN) client/platformd

.PHONY: copy-public-html
copy-public-html:
	@echo "$(GREEN)Copying public HTML files...$(NC)"
	@if [ ! -d $(PUBLIC_HTML_SRC) ]; then \
		cd $(PROJECT_ROOT) && make build-public-html; \
	fi
	@cp -r $(PUBLIC_HTML_SRC) server/public_html
	@cp -r $(PUBLIC_HTML_SRC) client/public_html

.PHONY: generate-configs
generate-configs: generate-server-config generate-client-config

.PHONY: update-localhost-config
update-localhost-config:
	@python3 add-localhost.py

.PHONY: generate-server-config
generate-server-config:
	@echo "$(GREEN)Generating server configuration...$(NC)"
	@cd server && $(APPBIN) config gen \
		--debug=true \
		--debug-secrets=true \
		--fips=false \
		--platform-dir trusted-data \
		--datastore-dir trusted-data/datastore \
		--dns-datastore-dir trusted-data \
		--tpm-simulator $(TPM_SIMULATOR) \
		--public-domain $(SERVER_DOMAIN) \
		--public-ip 172.20.0.10 \
		--internal-domain $(SERVER_HOSTNAME).internal \
		--acme-directory-url $(SERVER_ACME_URL) \
		--webauthn-rp-id localhost \
		--webservice-port $(SERVER_HTTP_PORT) \
		--webservice-tls-port $(SERVER_PORT) \
		--dns-public-port $(SERVER_DNS_PUBLIC) \
		--dns-internal-port $(SERVER_DNS_INTERNAL) \
		--hostname $(SERVER_HOSTNAME) \
		--raw-so-pin $(PASSWORD) \
		--raw-pin $(PASSWORD)

.PHONY: generate-client-config
generate-client-config:
	@echo "$(GREEN)Generating client configuration...$(NC)"
	@cd client && $(APPBIN) config gen \
		--type client \
		--debug=true \
		--debug-secrets=true \
		--fips=false \
		--platform-dir trusted-data \
		--tpm-simulator $(TPM_SIMULATOR) \
		--public-domain $(CLIENT_DOMAIN) \
		--public-ip 172.20.0.20 \
		--internal-domain $(CLIENT_HOSTNAME).internal \
		--acme-directory-url $(SERVER_ACME_URL) \
		--acme-client-enrollment-challenge $(CLIENT_ENROLLMENT) \
		--acme-client-webservice-challenge $(CLIENT_CHALLENGE) \
		--webservice-port $(CLIENT_PORT) \
		--webservice-tls-port $(CLIENT_TLS_PORT) \
		--webauthn-rp-id localhost \
		--hostname $(CLIENT_HOSTNAME) \
		--tpm-ek-cert-handle 0 \
		--raw-so-pin $(PASSWORD) \
		--raw-pin $(PASSWORD)

.PHONY: build-images
build-images:
	@echo "$(GREEN)Building Docker images...$(NC)"
	@DOCKER_BUILDKIT=$(DOCKER_BUILDKIT) docker compose build

.PHONY: up
up:
	@echo "$(GREEN)Starting containers...$(NC)"
	@TARGETARCH=$(TARGETARCH) docker compose up -d
	@echo "$(GREEN)✓ Containers started$(NC)"
	@echo ""
	@echo "$(YELLOW)Services:$(NC)"
	@echo "  Server HTTPS: https://localhost:$(SERVER_PORT)"
	@echo "  Server HTTP:  http://localhost:$(SERVER_HTTP_PORT)"
	@echo "  Client HTTP:  http://localhost:$(CLIENT_PORT)"
	@echo "  Client HTTPS: https://localhost:$(CLIENT_TLS_PORT)"
	@echo ""
	@echo "$(YELLOW)Use 'make logs' to view container logs$(NC)"

.PHONY: down
down:
	@echo "$(YELLOW)Stopping containers...$(NC)"
	@docker compose down
	@echo "$(GREEN)✓ Containers stopped$(NC)"

.PHONY: logs
logs:
	@docker compose logs -f

.PHONY: logs-server
logs-server:
	@docker compose logs -f server

.PHONY: logs-client
logs-client:
	@docker compose logs -f client

.PHONY: status
status:
	@echo "$(GREEN)=== Container Status ===$(NC)"
	@docker compose ps
	@echo ""
	@echo "$(GREEN)=== Server Status ===$(NC)"
	@curl -sk https://localhost:$(SERVER_PORT)/api/v1/status 2>/dev/null | jq -r '.message // .' || echo "$(RED)Server not running$(NC)"
	@echo ""
	@echo "$(GREEN)=== Client Status ===$(NC)"
	@curl -sk https://localhost:$(CLIENT_TLS_PORT)/api/v1/status 2>/dev/null | jq -r '.message // .' || echo "$(RED)Client not enrolled yet$(NC)"

.PHONY: shell-server
shell-server:
	@docker compose exec server /bin/bash

.PHONY: shell-client
shell-client:
	@docker compose exec client /bin/bash

.PHONY: firefox
firefox: firefox/policies/policy.json check-hosts import-certs
	@echo "$(GREEN)Launching Firefox with trusted CA...$(NC)"
	@echo "$(YELLOW)Opening:$(NC)"
	@echo "  - https://$(SERVER_DOMAIN):$(SERVER_PORT) (Server)"
	@echo "  - https://$(CLIENT_DOMAIN):$(CLIENT_TLS_PORT) (Client)"
	@echo ""
	@firefox --new-instance --profile firefox https://$(SERVER_DOMAIN):$(SERVER_PORT) https://$(CLIENT_DOMAIN):$(CLIENT_TLS_PORT) &

.PHONY: import-certs
import-certs: extract-ca
	@if [ -f firefox/cert9.db ]; then \
		echo "$(GREEN)Importing certificates into Firefox profile...$(NC)"; \
		certutil -A -n "Trusted Platform Root CA (RSA)" -t "C,," -i firefox/root-ca-rsa.cer -d sql:firefox 2>/dev/null || true; \
		certutil -A -n "Trusted Platform Root CA (ECDSA)" -t "C,," -i firefox/root-ca-ecdsa.cer -d sql:firefox 2>/dev/null || true; \
		certutil -A -n "Trusted Platform Root CA (Ed25519)" -t "C,," -i firefox/root-ca-ed25519.cer -d sql:firefox 2>/dev/null || true; \
		certutil -A -n "Trusted Platform Intermediate CA (RSA)" -t ",," -i firefox/intermediate-ca-rsa.cer -d sql:firefox 2>/dev/null || true; \
		certutil -A -n "Trusted Platform Intermediate CA (ECDSA)" -t ",," -i firefox/intermediate-ca-ecdsa.cer -d sql:firefox 2>/dev/null || true; \
		certutil -A -n "Trusted Platform Intermediate CA (Ed25519)" -t ",," -i firefox/intermediate-ca-ed25519.cer -d sql:firefox 2>/dev/null || true; \
		echo "$(GREEN)✓ Certificates imported$(NC)"; \
	fi

.PHONY: check-hosts
check-hosts:
	@if ! grep -q "$(SERVER_DOMAIN)" /etc/hosts; then \
		echo "$(YELLOW)Adding hosts entries for certificate validation...$(NC)"; \
		echo "127.0.0.1 $(SERVER_DOMAIN)" | sudo tee -a /etc/hosts > /dev/null; \
		echo "$(GREEN)✓ Added $(SERVER_DOMAIN) to /etc/hosts$(NC)"; \
	fi
	@if ! grep -q "$(CLIENT_DOMAIN)" /etc/hosts; then \
		echo "127.0.0.1 $(CLIENT_DOMAIN)" | sudo tee -a /etc/hosts > /dev/null; \
		echo "$(GREEN)✓ Added $(CLIENT_DOMAIN) to /etc/hosts$(NC)"; \
	fi

.PHONY: extract-ca
extract-ca:
	@echo "$(GREEN)Extracting CA certificates from server container...$(NC)"
	@mkdir -p firefox
	@echo "  - Extracting Root CA certificates..."
	@docker compose exec server cat /opt/trusted-platform/trusted-data/ca/root-ca.platform.local/x509/root-ca.platform.local.pkcs8.rsa.cer | openssl x509 -inform DER -outform PEM > firefox/root-ca-rsa.cer || \
		(echo "$(RED)Error: Server container not running. Run 'make up' first.$(NC)" && exit 1)
	@docker compose exec server cat /opt/trusted-platform/trusted-data/ca/root-ca.platform.local/x509/root-ca.platform.local.pkcs8.ecdsa.cer | openssl x509 -inform DER -outform PEM > firefox/root-ca-ecdsa.cer || true
	@docker compose exec server cat /opt/trusted-platform/trusted-data/ca/root-ca.platform.local/x509/root-ca.platform.local.pkcs8.ed25519.cer | openssl x509 -inform DER -outform PEM > firefox/root-ca-ed25519.cer || true
	@echo "  - Extracting Intermediate CA certificates..."
	@docker compose exec server cat /opt/trusted-platform/trusted-data/ca/intermediate-ca.platform.local/x509/intermediate-ca.platform.local.pkcs8.rsa.cer | openssl x509 -inform DER -outform PEM > firefox/intermediate-ca-rsa.cer || true
	@docker compose exec server cat /opt/trusted-platform/trusted-data/ca/intermediate-ca.platform.local/x509/intermediate-ca.platform.local.pkcs8.ecdsa.cer | openssl x509 -inform DER -outform PEM > firefox/intermediate-ca-ecdsa.cer || true
	@docker compose exec server cat /opt/trusted-platform/trusted-data/ca/intermediate-ca.platform.local/x509/intermediate-ca.platform.local.pkcs8.ed25519.cer | openssl x509 -inform DER -outform PEM > firefox/intermediate-ca-ed25519.cer || true
	@echo "$(GREEN)✓ CA certificates extracted$(NC)"

firefox/policies/policy.json: extract-ca
	@echo "$(GREEN)Generating Firefox policy to trust all CA certificates...$(NC)"
	@mkdir -p firefox/policies
	@echo '{' > firefox/policies/policy.json
	@echo '  "policies": {' >> firefox/policies/policy.json
	@echo '    "Certificates": {' >> firefox/policies/policy.json
	@echo '      "ImportEnterpriseRoots": true,' >> firefox/policies/policy.json
	@echo '      "Install": [' >> firefox/policies/policy.json
	@# Add all certificate files as absolute paths
	@first=true; \
	for cert in firefox/root-ca-*.cer firefox/intermediate-ca-*.cer; do \
		if [ -f "$$cert" ]; then \
			if [ "$$first" = "true" ]; then \
				first=false; \
			else \
				echo ',' >> firefox/policies/policy.json; \
			fi; \
			echo -n '        "' >> firefox/policies/policy.json; \
			echo -n "$$(cd firefox && pwd)/$$(basename $$cert)" >> firefox/policies/policy.json; \
			echo -n '"' >> firefox/policies/policy.json; \
		fi; \
	done; \
	echo '' >> firefox/policies/policy.json
	@echo '      ]' >> firefox/policies/policy.json
	@echo '    }' >> firefox/policies/policy.json
	@echo '  }' >> firefox/policies/policy.json
	@echo '}' >> firefox/policies/policy.json
	@echo "$(GREEN)✓ Firefox policy generated with all CA certificate types$(NC)"

.PHONY: clean
clean: clean-hosts
	@echo "$(YELLOW)Cleaning up...$(NC)"
	@docker compose down -v 2>/dev/null || true
	@rm -f server/platformd server/config.yaml client/platformd client/config.yaml
	@rm -f server/wait-for.sh client/wait-for.sh
	@rm -rf server/public_html client/public_html
	@rm -rf server/trusted-data client/trusted-data
	@rm -rf firefox
	@echo "$(GREEN)✓ Clean complete$(NC)"

.PHONY: clean-hosts
clean-hosts:
	@if grep -q "$(SERVER_DOMAIN)" /etc/hosts 2>/dev/null; then \
		echo "$(YELLOW)Removing $(SERVER_DOMAIN) from /etc/hosts...$(NC)"; \
		sudo sed -i "/127.0.0.1 $(SERVER_DOMAIN)/d" /etc/hosts; \
		echo "$(GREEN)✓ Removed $(SERVER_DOMAIN) from /etc/hosts$(NC)"; \
	fi
	@if grep -q "$(CLIENT_DOMAIN)" /etc/hosts 2>/dev/null; then \
		echo "$(YELLOW)Removing $(CLIENT_DOMAIN) from /etc/hosts...$(NC)"; \
		sudo sed -i "/127.0.0.1 $(CLIENT_DOMAIN)/d" /etc/hosts; \
		echo "$(GREEN)✓ Removed $(CLIENT_DOMAIN) from /etc/hosts$(NC)"; \
	fi

.PHONY: clean-all
clean-all: clean
	@echo "$(YELLOW)Removing Docker images...$(NC)"
	@docker compose down --rmi all 2>/dev/null || true
	@echo "$(GREEN)✓ All clean$(NC)"

.PHONY: test-enrollment
test-enrollment:
	@echo "$(GREEN)Testing client enrollment...$(NC)"
	@docker compose exec client curl -sk https://server.internal:$(SERVER_PORT)/api/v1/acme/directory | jq .
	@echo ""
	@echo "$(GREEN)Checking client certificate...$(NC)"
	@docker compose exec client ls -la /opt/trusted-platform/trusted-data/ca/intermediate-ca.*/x509/*.cer 2>/dev/null || echo "$(YELLOW)No certificates yet$(NC)"

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
	elif [ "$$response" = '"registered"' ]; then \
		echo "$(GREEN)✓ WebAuthn is registered and working$(NC)"; \
	else \
		echo "$(RED)✗ Error checking WebAuthn status$(NC)"; \
		echo "Response: $$response"; \
	fi

.PHONY: setup
setup: copy-files generate-configs build-images

# Development helpers
.PHONY: rebuild
rebuild: down clean build up

.PHONY: restart
restart: down up