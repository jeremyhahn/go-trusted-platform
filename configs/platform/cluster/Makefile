# Makefile for Trusted Platform Cluster Reference Architecture
# Wraps docker-compose for easy cluster management
#
# Prerequisites:
#   make build-devcontainer   - Build the devcontainer image (first time only)
#
# Quick Start:
#   make up        - Start entire cluster
#   make down      - Stop cluster
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
	@echo "$(CYAN)Trusted Platform Cluster Reference Architecture$(NC)"
	@echo "================================================"
	@echo ""
	@echo "$(GREEN)Quick Start:$(NC)"
	@echo "  make up              - Start entire cluster"
	@echo "  make down            - Stop cluster"
	@echo "  make restart         - Restart cluster"
	@echo ""
	@echo "$(GREEN)Partial Deployment:$(NC)"
	@echo "  make up-servers      - Start server cluster only"
	@echo "  make up-gateways     - Start gateways only"
	@echo "  make up-clients      - Start clients only"
	@echo ""
	@echo "$(GREEN)Monitoring:$(NC)"
	@echo "  make status          - Show container status"
	@echo "  make logs            - Follow all logs"
	@echo "  make logs-server1    - Follow server1 logs"
	@echo "  make logs-gateway1   - Follow gateway1 logs"
	@echo ""
	@echo "$(GREEN)Management:$(NC)"
	@echo "  make build-devcontainer   - Build devcontainer image (first time)"
	@echo "  make rebuild-devcontainer - Force rebuild devcontainer"
	@echo "  make pull            - Pull latest images"
	@echo "  make clean           - Stop and remove volumes"
	@echo "  make shell-server1   - Shell into server1"

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
# CLUSTER LIFECYCLE
# =============================================================================

.PHONY: up
up: build-devcontainer
	@echo "$(GREEN)Starting cluster...$(NC)"
	@echo "$(CYAN)Deployment order: server1 → server2/3 → gateways → clients$(NC)"
	$(COMPOSE) up -d
	@echo ""
	@echo "$(GREEN)✓ Cluster started!$(NC)"
	@echo ""
	@$(MAKE) status

.PHONY: down
down:
	@echo "$(YELLOW)Stopping cluster...$(NC)"
	$(COMPOSE) down
	@echo "$(GREEN)✓ Cluster stopped$(NC)"

.PHONY: restart
restart: down up

.PHONY: clean
clean:
	@echo "$(YELLOW)Stopping cluster and removing volumes...$(NC)"
	$(COMPOSE) down -v --remove-orphans
	@echo "$(GREEN)✓ Clean complete$(NC)"

# =============================================================================
# PARTIAL DEPLOYMENT
# =============================================================================

.PHONY: up-servers
up-servers:
	@echo "$(GREEN)Starting server cluster...$(NC)"
	$(COMPOSE) up -d server1
	@sleep 5
	$(COMPOSE) up -d server2 server3
	@echo "$(GREEN)✓ Server cluster started$(NC)"

.PHONY: up-gateways
up-gateways:
	@echo "$(GREEN)Starting gateways...$(NC)"
	$(COMPOSE) up -d gateway1 gateway2
	@echo "$(GREEN)✓ Gateways started$(NC)"

.PHONY: up-clients
up-clients:
	@echo "$(GREEN)Starting clients...$(NC)"
	$(COMPOSE) up -d client1 client2 client3
	@echo "$(GREEN)✓ Clients started$(NC)"

# =============================================================================
# MONITORING
# =============================================================================

.PHONY: status
status:
	@echo "$(CYAN)=== Cluster Status ===$(NC)"
	@echo ""
	$(COMPOSE) ps
	@echo ""
	@echo "$(CYAN)=== Health Checks ===$(NC)"
	@echo ""
	@echo "$(GREEN)Servers:$(NC)"
	@curl -sk https://localhost:8443/api/v1/status 2>/dev/null | jq -r '.status // "DOWN"' | xargs -I {} echo "  server1: {}" || echo "  server1: $(RED)DOWN$(NC)"
	@curl -sk https://localhost:8444/api/v1/status 2>/dev/null | jq -r '.status // "DOWN"' | xargs -I {} echo "  server2: {}" || echo "  server2: $(RED)DOWN$(NC)"
	@curl -sk https://localhost:8445/api/v1/status 2>/dev/null | jq -r '.status // "DOWN"' | xargs -I {} echo "  server3: {}" || echo "  server3: $(RED)DOWN$(NC)"
	@echo ""
	@echo "$(GREEN)Gateways:$(NC)"
	@curl -s http://localhost:80/health 2>/dev/null && echo "  gateway1: UP" || echo "  gateway1: $(RED)DOWN$(NC)"
	@curl -s http://localhost:81/health 2>/dev/null && echo "  gateway2: UP" || echo "  gateway2: $(RED)DOWN$(NC)"
	@echo ""
	@echo "$(GREEN)Clients:$(NC)"
	@curl -sk https://localhost:9543/api/v1/status 2>/dev/null | jq -r '.status // "DOWN"' | xargs -I {} echo "  client1: {}" || echo "  client1: $(RED)DOWN$(NC)"
	@curl -sk https://localhost:9544/api/v1/status 2>/dev/null | jq -r '.status // "DOWN"' | xargs -I {} echo "  client2: {}" || echo "  client2: $(RED)DOWN$(NC)"
	@curl -sk https://localhost:9545/api/v1/status 2>/dev/null | jq -r '.status // "DOWN"' | xargs -I {} echo "  client3: {}" || echo "  client3: $(RED)DOWN$(NC)"

.PHONY: logs
logs:
	$(COMPOSE) logs -f

.PHONY: logs-server1
logs-server1:
	$(COMPOSE) logs -f server1

.PHONY: logs-server2
logs-server2:
	$(COMPOSE) logs -f server2

.PHONY: logs-server3
logs-server3:
	$(COMPOSE) logs -f server3

.PHONY: logs-gateway1
logs-gateway1:
	$(COMPOSE) logs -f gateway1

.PHONY: logs-gateway2
logs-gateway2:
	$(COMPOSE) logs -f gateway2

.PHONY: logs-client1
logs-client1:
	$(COMPOSE) logs -f client1

.PHONY: logs-client2
logs-client2:
	$(COMPOSE) logs -f client2

.PHONY: logs-client3
logs-client3:
	$(COMPOSE) logs -f client3

# =============================================================================
# DEBUGGING
# =============================================================================

.PHONY: shell-server1
shell-server1:
	$(COMPOSE) exec server1 /bin/sh

.PHONY: shell-server2
shell-server2:
	$(COMPOSE) exec server2 /bin/sh

.PHONY: shell-server3
shell-server3:
	$(COMPOSE) exec server3 /bin/sh

.PHONY: shell-gateway1
shell-gateway1:
	$(COMPOSE) exec gateway1 /bin/sh

.PHONY: shell-gateway2
shell-gateway2:
	$(COMPOSE) exec gateway2 /bin/sh

.PHONY: shell-client1
shell-client1:
	$(COMPOSE) exec client1 /bin/sh

# =============================================================================
# TESTING
# =============================================================================

.PHONY: test-routing
test-routing:
	@echo "$(CYAN)=== Testing Gateway Routing ===$(NC)"
	@echo ""
	@echo "$(GREEN)Testing custom.example.com via gateway1:$(NC)"
	curl -sk --resolve custom.example.com:443:127.0.0.1 https://custom.example.com/api/v1/status || echo "Failed"
	@echo ""
	@echo "$(GREEN)Testing server.example.com via gateway1:$(NC)"
	curl -sk --resolve server.example.com:443:127.0.0.1 https://server.example.com/api/v1/status || echo "Failed"

.PHONY: test-failover
test-failover:
	@echo "$(CYAN)=== Testing Server Failover ===$(NC)"
	@echo ""
	@echo "$(GREEN)Current Raft leader:$(NC)"
	curl -sk https://localhost:8443/api/v1/cluster/status 2>/dev/null | jq -r '.leader // "unknown"' || echo "Could not determine leader"
	@echo ""
	@echo "$(YELLOW)To test failover:$(NC)"
	@echo "  1. docker-compose stop server1"
	@echo "  2. Wait for leader election (~10s)"
	@echo "  3. curl -sk https://localhost:8444/api/v1/cluster/status"
