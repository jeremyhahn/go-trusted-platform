
REPO                    ?= github.com
PACKAGE                 ?= trusted-platform-web
APPNAME                 ?= trusted-platform-webapp

BUILD_DATE              = $(shell date '+%Y-%m-%d_%H:%M:%S')

VERSION_FILE            ?= VERSION

ENV                     ?= dev

RPI_HOST                ?= rpi

GREEN=\033[0;32m
CYAN=\033[0;36m
YELLOW=\033[1;33m
NO_COLOR=\033[0m

WEB_PUBLIC_HTML         ?= ../public_html

# Web development container configuration
# Uses dedicated container to avoid conflicts with integration test devcontainer
CONTAINER_NAME          ?= trusted-platform-webdev
BACKEND_LOG_FILE        ?= /tmp/platformd.log
COMPOSE_FILE            ?= docker-compose.yml

.PHONY: build run dev dev-standalone start-backend stop-backend status

default: dev

# Build the SDK before installing dependencies
sdk-build:
	@echo "Building SDK..."
	cd ../sdk/javascript && npm install && npm run build

# Install dependencies (includes local SDK)
install: sdk-build
	npm install

# Development with devcontainer backend (recommended)
# Backend runs in devcontainer, frontend runs on host for best hot-reload experience
dev: start-backend
	@echo "$(GREEN)Starting frontend on port 3000...$(NO_COLOR)"
	@echo "$(CYAN)Backend: https://localhost:8443 (devcontainer)$(NO_COLOR)"
	@echo "$(CYAN)Frontend: http://localhost:3000 (host)$(NO_COLOR)"
	@echo ""
	NODE_TLS_REJECT_UNAUTHORIZED=0 npm run dev -- --port 3000


# Start the web development container
start-container:
	@echo "$(CYAN)Starting web development container...$(NO_COLOR)"
	@docker compose -f $(COMPOSE_FILE) up -d
	@echo "$(GREEN)Container started$(NO_COLOR)"

# Start the backend server in container
start-backend: start-container
	@echo "$(CYAN)Checking backend status...$(NO_COLOR)"
	@if docker exec $(CONTAINER_NAME) pgrep -f "platformd" > /dev/null 2>&1; then \
		echo "$(GREEN)Backend already running$(NO_COLOR)"; \
	else \
		echo "$(CYAN)Building backend (if needed)...$(NO_COLOR)"; \
		docker exec $(CONTAINER_NAME) bash -c "if [ ! -f /workspace/bin/platformd ]; then cd /workspace && CGO_ENABLED=1 go build -tags 'iam codec_msgpack codec_cbor codec_json local objstore raft' -o bin/platformd ./cmd/platformd; fi"; \
		echo "$(CYAN)Starting backend in container...$(NO_COLOR)"; \
		docker exec $(CONTAINER_NAME) bash -c "rm -rf /workspace/trusted-data 2>/dev/null; mkdir -p /workspace/trusted-data/{etc,log,quicbaas/wal,www}"; \
		docker exec -d $(CONTAINER_NAME) bash -c "cd /workspace && ./bin/platformd --config config.yaml --init > $(BACKEND_LOG_FILE) 2>&1"; \
		echo "$(CYAN)Waiting for backend to be ready...$(NO_COLOR)"; \
		for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do \
			if docker exec $(CONTAINER_NAME) curl -sk https://localhost:8443/ > /dev/null 2>&1; then \
				echo "$(GREEN)Backend is ready!$(NO_COLOR)"; \
				break; \
			fi; \
			if [ $$i -eq 15 ]; then \
				echo "$(YELLOW)Backend may still be starting. Check logs with: make backend-logs$(NO_COLOR)"; \
			else \
				echo "Waiting... ($$i/15)"; \
				sleep 2; \
			fi; \
		done; \
	fi

# Stop the backend server in devcontainer
stop-backend:
	@echo "$(CYAN)Stopping backend in devcontainer...$(NO_COLOR)"
	@-docker exec $(CONTAINER_NAME) bash -c "pkill -9 -f platformd" 2>/dev/null || true
	@echo "$(GREEN)Backend stopped$(NO_COLOR)"

# Stop everything (backend + container)
stop-all: stop-backend
	@echo "$(CYAN)Stopping web development container...$(NO_COLOR)"
	@docker compose -f $(COMPOSE_FILE) down

# View backend logs
backend-logs:
	@docker exec $(CONTAINER_NAME) tail -50 $(BACKEND_LOG_FILE)

# Follow backend logs
backend-logs-follow:
	@docker exec $(CONTAINER_NAME) tail -f $(BACKEND_LOG_FILE)

# Show status of devcontainer and backend
status:
	@echo "$(CYAN)=== Development Environment Status ===$(NO_COLOR)"
	@echo ""
	@if docker ps --format '{{.Names}}' | grep -q "^$(CONTAINER_NAME)$$"; then \
		echo "$(GREEN)✓ Devcontainer: Running$(NO_COLOR)"; \
		if docker exec $(CONTAINER_NAME) pgrep -f "platformd" > /dev/null 2>&1; then \
			echo "$(GREEN)✓ Backend: Running (https://localhost:8443)$(NO_COLOR)"; \
		else \
			echo "$(YELLOW)✗ Backend: Not running$(NO_COLOR)"; \
		fi; \
	else \
		echo "$(YELLOW)✗ Devcontainer: Not running$(NO_COLOR)"; \
		echo "$(YELLOW)✗ Backend: Not running$(NO_COLOR)"; \
	fi
	@echo ""
	@if lsof -i :3000 -sTCP:LISTEN > /dev/null 2>&1; then \
		echo "$(GREEN)✓ Frontend: Running (http://localhost:3000)$(NO_COLOR)"; \
	else \
		echo "$(YELLOW)✗ Frontend: Not running$(NO_COLOR)"; \
	fi

# Rebuild backend in devcontainer (if code changes)
rebuild-backend:
	@echo "$(CYAN)Rebuilding backend in devcontainer...$(NO_COLOR)"
	@docker exec $(CONTAINER_NAME) bash -c "cd /workspace && CGO_ENABLED=1 go build -tags 'iam codec_msgpack codec_cbor codec_json local objstore raft' -o bin/platformd ./cmd/platformd"
	@echo "$(GREEN)Backend rebuilt. Run 'make stop-backend && make start-backend' to restart.$(NO_COLOR)"

# Shell into devcontainer
shell:
	@docker exec -it $(CONTAINER_NAME) bash

build:
	npm run build

rpi-sync:
	rsync -av --progress ../$(PACKAGE) $(RPI_HOST): --exclude ./.git/

# Playwright installation
playwright-install:
	npx playwright install --with-deps chromium

# E2E Tests (local, uses ./e2e directory)
test-e2e:
	npx playwright test

test-e2e-ui:
	npx playwright test --ui

test-e2e-headed:
	npx playwright test --headed

test-e2e-debug:
	npx playwright test --debug

# Integration Tests (uses ../test/integration/web directory via playwright.integration.config.ts)
#
# These tests run against the REAL backend server.
#
# Modes:
#   test-integration        - Headless (default), results logged to playwright.log
#   test-integration-headed - With visible browser window (HEADED=1)
#   test-integration-ui     - Interactive UI mode for local development
#   test-integration-debug  - Debug mode with step-through
#
test-integration: start-backend
	@echo "Running integration tests against real backend..."
	@echo "Results will be in playwright.log"
	npx playwright test --config playwright.integration.config.ts
	@echo "Test results saved to playwright.log"

test-integration-ui: start-backend
	npx playwright test --config playwright.integration.config.ts --ui

test-integration-headed: start-backend
	HEADED=1 npx playwright test --config playwright.integration.config.ts

test-integration-debug: start-backend
	HEADED=1 npx playwright test --config playwright.integration.config.ts --debug

# Run specific test file (headless by default, add HEADED=1 for browser)
test-auth:
	npx playwright test --config playwright.integration.config.ts auth.spec.ts

test-dashboard:
	npx playwright test --config playwright.integration.config.ts dashboard.spec.ts

test-iam:
	npx playwright test --config playwright.integration.config.ts iam.spec.ts

test-tenant:
	npx playwright test --config playwright.integration.config.ts tenant.spec.ts

test-ca-kms:
	npx playwright test --config playwright.integration.config.ts ca-kms.spec.ts

test-devices:
	npx playwright test --config playwright.integration.config.ts devices.spec.ts

test-compute:
	npx playwright test --config playwright.integration.config.ts compute.spec.ts

test-api:
	npx playwright test --config playwright.integration.config.ts api-integration.spec.ts

# WebAuthn E2E tests — requires a running platform server
# Defaults to QEMU server at server.example.com:8443
# Override FRONTEND_URL for different environments
# Usage:
#   make test-webauthn                   # QEMU server (default)
#   make test-webauthn HEADED=1          # visible browser
FRONTEND_URL ?= https://server.example.com:8443
test-webauthn:
	FRONTEND_URL=$(FRONTEND_URL) BACKEND_URL=$(FRONTEND_URL) \
	npx playwright test --config playwright.integration.config.ts webauthn-e2e.spec.ts $(if $(HEADED),--headed)

# Show test reports
test-report:
	npx playwright show-report ../test/integration/web/playwright-report

# View JSON test log
test-log:
	@if [ -f playwright.log ]; then \
		echo "=== Test Results Summary ==="; \
		cat playwright.log | jq -r '.suites[] | .title + ": " + (.specs | length | tostring) + " tests"' 2>/dev/null || cat playwright.log; \
	else \
		echo "No playwright.log found. Run tests first with: make test-integration"; \
	fi

# Show failed tests from log
test-failures:
	@if [ -f playwright.log ]; then \
		echo "=== Failed Tests ==="; \
		cat playwright.log | jq -r '.suites[].specs[] | select(.ok == false) | .title' 2>/dev/null || echo "No failures or invalid log format"; \
	else \
		echo "No playwright.log found. Run tests first."; \
	fi

# Clean test artifacts
test-clean:
	rm -rf test-results playwright-report playwright.log ../test/integration/web/test-results ../test/integration/web/playwright-report

# Help
help:
	@echo "$(CYAN)Web Development Makefile$(NO_COLOR)"
	@echo ""
	@echo "$(GREEN)Development:$(NO_COLOR)"
	@echo "  make dev            - Start backend (devcontainer) + frontend (host)"
	@echo "  make dev-standalone - Start frontend only (no backend)"
	@echo "  make status         - Show status of all services"
	@echo ""
	@echo "$(GREEN)Backend Management:$(NO_COLOR)"
	@echo "  make start-backend  - Start backend in devcontainer"
	@echo "  make stop-backend   - Stop backend in devcontainer"
	@echo "  make rebuild-backend- Rebuild backend binary"
	@echo "  make backend-logs   - View backend logs"
	@echo "  make backend-logs-follow - Follow backend logs"
	@echo ""
	@echo "$(GREEN)Environment:$(NO_COLOR)"
	@echo "  make stop-all       - Stop backend + devcontainer"
	@echo "  make shell          - Shell into devcontainer"
	@echo ""
	@echo "$(GREEN)Testing:$(NO_COLOR)"
	@echo "  make test-e2e         - Run E2E tests"
	@echo "  make test-integration - Run integration tests"
	@echo "  make test-webauthn    - Run WebAuthn E2E tests"
	@echo "    FRONTEND_URL=https://server.example.com:8443  # target a specific server"
	@echo "    HEADED=1                                       # visible browser"
	@echo ""
