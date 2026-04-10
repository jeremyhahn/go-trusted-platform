# Makefile for Trusted Platform Standalone Reference Architecture
# Wraps docker-compose for easy deployment management
#
# Prerequisites:
#   make build-devcontainer   - Build the devcontainer image (first time only)
#
# Quick Start:
#   make up        - Start all services
#   make down      - Stop services
#   make help      - Show all available targets

COMPOSE := docker compose
COMPOSE_FILE := docker-compose.yaml
REPO_ROOT := ../../..

# Colors
GREEN  := \033[0;32m
YELLOW := \033[0;33m
RED    := \033[0;31m
CYAN   := \033[0;36m
NC     := \033[0m

.PHONY: help
help:
	@echo "$(CYAN)Trusted Platform Standalone Reference Architecture$(NC)"
	@echo "=================================================="
	@echo ""
	@echo "$(GREEN)Quick Start:$(NC)"
	@echo "  make up              - Start all services"
	@echo "  make down            - Stop services"
	@echo "  make restart         - Restart services"
	@echo ""
	@echo "$(GREEN)Individual Services:$(NC)"
	@echo "  make up-server       - Start server only"
	@echo "  make up-gateway      - Start gateway only"
	@echo "  make up-client       - Start client only"
	@echo ""
	@echo "$(GREEN)Monitoring:$(NC)"
	@echo "  make status          - Show container status"
	@echo "  make logs            - Follow all logs"
	@echo "  make logs-server     - Follow server logs"
	@echo "  make logs-gateway    - Follow gateway logs"
	@echo "  make logs-client     - Follow client logs"
	@echo ""
	@echo "$(GREEN)Management:$(NC)"
	@echo "  make build-devcontainer   - Build devcontainer image (first time)"
	@echo "  make rebuild-devcontainer - Force rebuild devcontainer"
	@echo "  make pull            - Pull latest images"
	@echo "  make clean           - Stop and remove volumes"
	@echo "  make shell-server    - Shell into server"

.PHONY: build-devcontainer
build-devcontainer:
	@echo "$(GREEN)Building devcontainer image...$(NC)"
	@if ! docker images | grep -q "go-trusted-platform-dev"; then \
		docker build -t go-trusted-platform-dev:latest $(REPO_ROOT)/build/docker/devcontainer/; \
	else \
		echo "$(CYAN)Devcontainer image already exists. Use 'make rebuild-devcontainer' to force rebuild.$(NC)"; \
	fi

.PHONY: rebuild-devcontainer
rebuild-devcontainer:
	@echo "$(GREEN)Rebuilding devcontainer image...$(NC)"
	docker build -t go-trusted-platform-dev:latest $(REPO_ROOT)/build/docker/devcontainer/

.PHONY: pull
pull:
	@echo "$(GREEN)Pulling latest images...$(NC)"
	$(COMPOSE) pull

# =============================================================================
# LIFECYCLE
# =============================================================================

.PHONY: up
up: build-devcontainer
	@echo "$(GREEN)Starting standalone platform...$(NC)"
	@echo "$(CYAN)Deployment order: server → gateway → client$(NC)"
	$(COMPOSE) up -d
	@echo ""
	@echo "$(GREEN)✓ Platform started!$(NC)"
	@echo ""
	@$(MAKE) status

.PHONY: down
down:
	@echo "$(YELLOW)Stopping platform...$(NC)"
	$(COMPOSE) down
	@echo "$(GREEN)✓ Platform stopped$(NC)"

.PHONY: restart
restart: down up

.PHONY: clean
clean:
	@echo "$(YELLOW)Stopping platform and removing volumes...$(NC)"
	$(COMPOSE) down -v --remove-orphans
	@echo "$(GREEN)✓ Clean complete$(NC)"

# =============================================================================
# INDIVIDUAL SERVICES
# =============================================================================

.PHONY: up-server
up-server:
	@echo "$(GREEN)Starting server...$(NC)"
	$(COMPOSE) up -d server
	@echo "$(GREEN)✓ Server started$(NC)"

.PHONY: up-gateway
up-gateway:
	@echo "$(GREEN)Starting gateway...$(NC)"
	$(COMPOSE) up -d gateway
	@echo "$(GREEN)✓ Gateway started$(NC)"

.PHONY: up-client
up-client:
	@echo "$(GREEN)Starting client...$(NC)"
	$(COMPOSE) up -d client
	@echo "$(GREEN)✓ Client started$(NC)"

# =============================================================================
# MONITORING
# =============================================================================

.PHONY: status
status:
	@echo "$(CYAN)=== Platform Status ===$(NC)"
	@echo ""
	$(COMPOSE) ps
	@echo ""
	@echo "$(CYAN)=== Health Checks ===$(NC)"
	@echo ""
	@echo "$(GREEN)Server:$(NC)"
	@curl -sk https://localhost:8443/api/v1/status 2>/dev/null | jq -r '.status // "DOWN"' | xargs -I {} echo "  server: {}" || echo "  server: $(RED)DOWN$(NC)"
	@echo ""
	@echo "$(GREEN)Gateway:$(NC)"
	@curl -s http://localhost:80/health 2>/dev/null && echo "  gateway: UP" || echo "  gateway: $(RED)DOWN$(NC)"
	@echo ""
	@echo "$(GREEN)Client:$(NC)"
	@curl -sk https://localhost:9444/api/v1/status 2>/dev/null | jq -r '.status // "DOWN"' | xargs -I {} echo "  client: {}" || echo "  client: $(RED)DOWN$(NC)"

.PHONY: logs
logs:
	$(COMPOSE) logs -f

.PHONY: logs-server
logs-server:
	$(COMPOSE) logs -f server

.PHONY: logs-gateway
logs-gateway:
	$(COMPOSE) logs -f gateway

.PHONY: logs-client
logs-client:
	$(COMPOSE) logs -f client

# =============================================================================
# DEBUGGING
# =============================================================================

.PHONY: shell-server
shell-server:
	$(COMPOSE) exec server /bin/sh

.PHONY: shell-gateway
shell-gateway:
	$(COMPOSE) exec gateway /bin/sh

.PHONY: shell-client
shell-client:
	$(COMPOSE) exec client /bin/sh

# =============================================================================
# TESTING
# =============================================================================

.PHONY: test-routing
test-routing:
	@echo "$(CYAN)=== Testing Gateway Routing ===$(NC)"
	@echo ""
	@echo "$(GREEN)Testing custom.example.com via gateway:$(NC)"
	curl -sk --resolve custom.example.com:443:127.0.0.1 https://custom.example.com/api/v1/status || echo "Failed"
	@echo ""
	@echo "$(GREEN)Testing server.example.com via gateway:$(NC)"
	curl -sk --resolve server.example.com:443:127.0.0.1 https://server.example.com/api/v1/status || echo "Failed"
