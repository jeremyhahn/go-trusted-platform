#!/bin/bash
# Entrypoint script for go-trusted-platform development container
#
# This entrypoint provides:
# - Development environment setup
# - OVS (Open vSwitch) service initialization
# - Device permissions setup for KVM, TUN/TAP
# - Kernel module loading
# - Tool verification

set -e

# shellcheck source=build/docker/devcontainer/swtpm-provision.sh
source /usr/local/lib/devcontainer/swtpm-provision.sh
# shellcheck source=build/docker/devcontainer/wait-for.sh
source /usr/local/lib/devcontainer/wait-for.sh

# =============================================================================
# Environment Setup
# =============================================================================

# Ensure Go environment
export GOPATH="${GOPATH:-/go}"
export PATH="/usr/local/go/bin:${GOPATH}/bin:${PATH}"

# =============================================================================
# OVS Service Management
# =============================================================================

start_ovs() {
    echo "=== Starting Open vSwitch Services ==="

    # Create necessary directories
    mkdir -p /var/run/openvswitch
    mkdir -p /var/log/openvswitch
    mkdir -p /etc/openvswitch

    # Initialize OVS database if it doesn't exist
    if [ ! -f /etc/openvswitch/conf.db ]; then
        echo "Initializing OVSDB..."
        ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema
    fi

    # Start ovsdb-server if not already running
    if ! pgrep -x ovsdb-server > /dev/null; then
        echo "Starting ovsdb-server..."
        ovsdb-server --remote=punix:/var/run/openvswitch/db.sock \
            --remote=ptcp:6640:127.0.0.1 \
            --pidfile=/var/run/openvswitch/ovsdb-server.pid \
            --detach \
            --log-file=/var/log/openvswitch/ovsdb-server.log

        wait_for 10 "ovsdb-server on db.sock" ovs-vsctl --no-wait --timeout=1 show || return 1

        # Initialize OVS
        echo "Initializing Open vSwitch..."
        ovs-vsctl --no-wait init || true
    else
        echo "ovsdb-server already running"
    fi

    # Start ovs-vswitchd if not already running
    if ! pgrep -x ovs-vswitchd > /dev/null; then
        echo "Starting ovs-vswitchd..."
        ovs-vswitchd --pidfile=/var/run/openvswitch/ovs-vswitchd.pid \
            --detach \
            --log-file=/var/log/openvswitch/ovs-vswitchd.log

        wait_for 10 "ovs-vswitchd control socket" ovs-appctl -t ovs-vswitchd version || return 1
    else
        echo "ovs-vswitchd already running"
    fi

    # Verify OVS is running
    echo "OVS Status:"
    ovs-vsctl show
    echo "=== OVS Services Started ==="
}

stop_ovs() {
    echo "=== Stopping Open vSwitch Services ==="
    if [ -f /var/run/openvswitch/ovs-vswitchd.pid ]; then
        kill "$(cat /var/run/openvswitch/ovs-vswitchd.pid)" 2>/dev/null || true
    fi
    if [ -f /var/run/openvswitch/ovsdb-server.pid ]; then
        kill "$(cat /var/run/openvswitch/ovsdb-server.pid)" 2>/dev/null || true
    fi
    echo "=== OVS Services Stopped ==="
}

# =============================================================================
# Device and Kernel Module Setup
# =============================================================================

setup_devices() {
    echo "=== Setting Up Devices and Kernel Modules ==="

    # Set up TUN/TAP permissions
    if [ -e /dev/net/tun ]; then
        echo "Setting permissions on /dev/net/tun..."
        chmod 666 /dev/net/tun
    else
        echo "WARNING: /dev/net/tun not available. Run container with --device /dev/net/tun:/dev/net/tun"
    fi

    # Set up KVM permissions
    if [ -e /dev/kvm ]; then
        echo "Setting permissions on /dev/kvm..."
        chmod 666 /dev/kvm
    else
        echo "INFO: /dev/kvm not available. For KVM acceleration, run with --device /dev/kvm:/dev/kvm"
    fi

    # Load kernel modules (best effort)
    echo "Loading kernel modules (best effort)..."
    modprobe tun 2>/dev/null || echo "  tun: already loaded or not available"
    modprobe kvm 2>/dev/null || echo "  kvm: already loaded or not available"
    modprobe kvm_intel 2>/dev/null || modprobe kvm_amd 2>/dev/null || echo "  kvm_intel/kvm_amd: already loaded or not available"

    # Try to load openvswitch module (may not be available in container)
    modprobe openvswitch 2>/dev/null || echo "  openvswitch: kernel module not available (userspace mode will be used)"

    echo "=== Device Setup Complete ==="
}

# =============================================================================
# Web Frontend Setup
# =============================================================================

setup_web() {
    echo "=== Setting Up Web Frontend ==="

    if [ ! -d /workspace/web ]; then
        echo "WARNING: /workspace/web directory not found, skipping web setup"
        return 1
    fi

    cd /workspace/web

    # Install npm dependencies if package.json exists and node_modules doesn't
    if [ -f package.json ]; then
        if [ ! -d node_modules ] || [ ! -f node_modules/.package-lock.json ]; then
            echo "Installing npm dependencies..."
            npm install
        else
            echo "npm dependencies already installed"
        fi

        # Install Playwright browsers if configured and not already installed
        if [ -n "${PLAYWRIGHT_BROWSERS_PATH}" ] && ! compgen -G "${PLAYWRIGHT_BROWSERS_PATH}/chromium-*" >/dev/null; then
            echo "Installing Playwright browsers to ${PLAYWRIGHT_BROWSERS_PATH}..."
            npx playwright install chromium firefox webkit
            echo "Playwright browsers installed"
        elif [ -n "${PLAYWRIGHT_BROWSERS_PATH}" ]; then
            echo "Playwright browsers already installed at ${PLAYWRIGHT_BROWSERS_PATH}"
        fi
    else
        echo "WARNING: package.json not found in /workspace/web"
        return 1
    fi

    cd /workspace
    echo "=== Web Frontend Setup Complete ==="
}

start_web_dev() {
    echo "=== Starting Next.js Development Server ==="

    if [ ! -d /workspace/web ]; then
        echo "ERROR: /workspace/web directory not found"
        return 1
    fi

    # Ensure dependencies are installed
    setup_web

    # Start Next.js dev server in background
    cd /workspace/web
    echo "Starting Next.js on port 3000..."
    npm run dev > /var/log/nextjs-dev.log 2>&1 &

    NEXTJS_PID=$!
    echo $NEXTJS_PID > /run/nextjs.pid

    # Wait for server to be ready
    echo "Waiting for Next.js dev server to be ready..."
    if wait_for 120 "Next.js dev server on http://localhost:3000" curl -s http://localhost:3000; then
        echo "Next.js dev server started successfully (PID: $NEXTJS_PID)"
        echo "=== Next.js Development Server Started ==="
        cd /workspace
        return 0
    fi

    echo "WARNING: Next.js dev server not ready after 120 seconds"
    echo "Check logs at /var/log/nextjs-dev.log"
    cd /workspace
    return 1
}

stop_web_dev() {
    echo "=== Stopping Next.js Development Server ==="
    if [ -f /run/nextjs.pid ]; then
        PID=$(cat /run/nextjs.pid)
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID" 2>/dev/null || true
            # Force kill if still running
            if ! wait_for 2 "PID $PID to exit after SIGTERM" process_gone "$PID"; then
                kill -9 "$PID" 2>/dev/null || true
            fi
        fi
        rm -f /run/nextjs.pid
    fi
    echo "=== Next.js Development Server Stopped ==="
}

# =============================================================================
# swtpm (Software TPM) Management
# =============================================================================

start_swtpm() {
    echo "=== Starting Software TPM (swtpm) ==="

    # Kill any existing swtpm
    pkill -9 -f 'swtpm socket' 2>/dev/null || true
    wait_for 5 "the old swtpm to exit" no_process_matching 'swtpm socket' || return 1

    # Setup swtpm directories
    rm -rf /tmp/swtpm
    mkdir -p /tmp/swtpm

    # Provision it like shipped hardware, with an EK and an EK certificate
    echo "Initializing swtpm state..."
    if ! provision_swtpm_state /tmp/swtpm; then
        echo "ERROR: the swtpm has no EK and EK certificate"
        return 1
    fi

    # Start swtpm daemon
    echo "Starting swtpm daemon..."
    swtpm socket --tpm2 \
        --tpmstate dir=/tmp/swtpm \
        --server type=unixio,path=/tmp/swtpm/swtpm.sock \
        --ctrl type=unixio,path=/tmp/swtpm/swtpm.sock.ctrl \
        --flags startup-clear,not-need-init \
        --log level=1,file=/tmp/swtpm/swtpm.log &

    SWTPM_PID=$!
    echo $SWTPM_PID > /run/swtpm.pid

    # Verify swtpm is running
    if wait_for 10 "swtpm socket /tmp/swtpm/swtpm.sock" test -S /tmp/swtpm/swtpm.sock; then
        echo "swtpm started successfully (PID: $SWTPM_PID)"
        echo "=== Software TPM Started ==="
        return 0
    else
        echo "ERROR: swtpm socket not found"
        return 1
    fi
}

stop_swtpm() {
    echo "=== Stopping Software TPM ==="
    pkill -9 -f 'swtpm socket' 2>/dev/null || true
    rm -f /run/swtpm.pid
    echo "=== Software TPM Stopped ==="
}

# =============================================================================
# Platform Daemon Management
# =============================================================================

start_platformd() {
    echo "=== Starting Platform Daemon ==="

    # Build platformd if not already built
    if [ ! -f /workspace/bin/platformd ]; then
        echo "Building platformd..."
        cd /workspace && go build -o bin/platformd ./cmd/platformd/
    fi

    # Create socket directory
    mkdir -p /run

    # Start platformd in background with all API servers. The transports
    # default to loopback (#552); docker-compose publishes these ports to
    # the host, which only works when platformd binds the container's
    # interfaces, so the sandbox names them explicitly (PLATFORM_BIND_HOST
    # narrows it back).
    echo "Starting platformd with multi-protocol API..."
    /workspace/bin/platformd serve \
        --socket-path="${PLATFORM_SOCKET_PATH:-/run/platformd.sock}" \
        --rest-bind-host="${PLATFORM_BIND_HOST:-0.0.0.0}" \
        --rest-port="${PLATFORM_REST_PORT:-8443}" \
        --grpc-bind-host="${PLATFORM_BIND_HOST:-0.0.0.0}" \
        --grpc-port="${PLATFORM_GRPC_PORT:-10443}" \
        --quic-bind-host="${PLATFORM_BIND_HOST:-0.0.0.0}" \
        --quic-port="${PLATFORM_QUIC_PORT:-9444}" \
        --mcp-bind-host="${PLATFORM_BIND_HOST:-0.0.0.0}" \
        --mcp-port="${PLATFORM_MCP_PORT:-9445}" \
        --enable-mtls \
        &

    PLATFORMD_PID=$!
    echo $PLATFORMD_PID > /run/platformd.pid

    # Wait for socket to be ready
    echo "Waiting for platform daemon to be ready..."
    local socket="${PLATFORM_SOCKET_PATH:-/run/platformd.sock}"
    if wait_for 30 "platformd socket ${socket}" test -S "$socket"; then
        echo "Platform daemon started successfully (PID: $PLATFORMD_PID)"
        echo "=== Platform Daemon Started ==="
        return 0
    fi

    echo "WARNING: Platform daemon socket not ready after 30 seconds"
    echo "=== Platform Daemon Start May Have Failed ==="
    return 1
}

# platformd_web_ready succeeds once the WebAuthn login endpoint answers with a
# platform error body ("invalid user", "entity not found" or any JSON error
# code): the web API is serving requests.
platformd_web_ready() {
    curl -sk -X POST -H 'Content-Type: application/json' \
        -d '{"username":"healthcheck"}' \
        https://localhost:8443/api/v1/webauthn/login/begin 2>&1 |
        grep -qE '(invalid user|entity not found|"code":)'
}

# platformd_web_ready_or_exited <pid> succeeds once the web API is ready or
# platformd (pid) has exited, so a crashed daemon ends the wait at once.
platformd_web_ready_or_exited() {
    process_gone "$1" || platformd_web_ready
}

# Start platformd with swtpm for web development
start_platformd_web() {
    echo "=== Starting Platform Daemon for Web Development ==="

    # Kill any existing platformd processes
    pkill -9 -f 'platformd' 2>/dev/null || true
    # Not fatal: an unreaped zombie still matches the pattern but holds no
    # port or socket, so startup goes on, as it did after the old fixed wait.
    wait_for 5 "the old platformd to exit" no_process_matching 'platformd' ||
        echo "WARNING: a process matching 'platformd' remains; continuing"

    # Start swtpm first
    start_swtpm || return 1

    # Build platformd-web-test if not already built
    if [ ! -f /workspace/bin/platformd-web-test ]; then
        echo "Building platformd-web-test..."
        cd /workspace || return 1
        local build_tags
        build_tags="$(make -s print-build-tags)" || return 1
        go build -tags "$build_tags" -o bin/platformd-web-test ./cmd/platformd/ || return 1
    fi

    # Setup config
    echo "Setting up web-test configuration..."
    cp /workspace/configs/platform/standalone/web-test.example.yaml /workspace/pkg/config.yaml
    rm -rf /workspace/pkg/trusted-data
    mkdir -p /workspace/pkg/trusted-data/etc

    # Start platformd in background
    echo "Starting platformd-web-test..."
    cd /workspace/pkg
    ../bin/platformd-web-test \
        --config config.yaml \
        --raw-so-pin 123456 \
        --raw-pin 123456 \
        --intermediate 0 \
        --init serve > /var/log/platformd.log 2>&1 &

    PLATFORMD_PID=$!
    echo $PLATFORMD_PID > /run/platformd.pid
    cd /workspace

    # Wait for web API to be ready
    echo "Waiting for platform web API to be ready..."
    if wait_for 120 "platform web API on https://localhost:8443" platformd_web_ready_or_exited "$PLATFORMD_PID"; then
        if process_gone "$PLATFORMD_PID"; then
            echo "ERROR: platformd process died (PID: $PLATFORMD_PID)"
            echo "Last 30 lines of log:"
            tail -30 /var/log/platformd.log
            return 1
        fi
        echo "Platform web API started successfully (PID: $PLATFORMD_PID)"
        echo "=== Platform Daemon for Web Started ==="
        return 0
    fi

    echo "WARNING: Platform web API not ready after 120 seconds"
    echo "Check logs at /var/log/platformd.log"
    tail -50 /var/log/platformd.log
    return 1
}

stop_platformd() {
    echo "=== Stopping Platform Daemon ==="
    if [ -f /run/platformd.pid ]; then
        PID=$(cat /run/platformd.pid)
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID" 2>/dev/null || true
            # Force kill if still running
            if ! wait_for 2 "PID $PID to exit after SIGTERM" process_gone "$PID"; then
                kill -9 "$PID" 2>/dev/null || true
            fi
        fi
        rm -f /run/platformd.pid
    fi
    rm -f "${PLATFORM_SOCKET_PATH:-/run/platformd.sock}"
    echo "=== Platform Daemon Stopped ==="
}

# =============================================================================
# Helper Functions
# =============================================================================

verify_tools() {
    echo "=== Development Environment Verification ==="
    echo "Go:           $(go version 2>/dev/null || echo 'NOT FOUND')"
    echo "swtpm:        $(swtpm --version 2>&1 | head -1 || echo 'NOT FOUND')"
    echo "QEMU:         $(qemu-system-x86_64 --version 2>/dev/null | head -1 || echo 'NOT FOUND')"
    echo "OVS:          $(ovs-vsctl --version 2>/dev/null | head -1 || echo 'NOT FOUND')"
    echo "xorriso:      $(xorriso --version 2>&1 | head -1 || echo 'NOT FOUND')"
    echo "Node:         $(node -v 2>/dev/null || echo 'NOT FOUND')"
    echo "npm:          $(npm -v 2>/dev/null || echo 'NOT FOUND')"
    echo ""
    echo "Playwright Status:"
    if [ -n "${PLAYWRIGHT_BROWSERS_PATH}" ] && [ -d "${PLAYWRIGHT_BROWSERS_PATH}" ]; then
        CHROMIUM_COUNT=$(find "${PLAYWRIGHT_BROWSERS_PATH}" -maxdepth 1 -type d -name "chromium-*" 2>/dev/null | wc -l)
        FIREFOX_COUNT=$(find "${PLAYWRIGHT_BROWSERS_PATH}" -maxdepth 1 -type d -name "firefox-*" 2>/dev/null | wc -l)
        WEBKIT_COUNT=$(find "${PLAYWRIGHT_BROWSERS_PATH}" -maxdepth 1 -type d -name "webkit-*" 2>/dev/null | wc -l)
        echo "Browser Path: ${PLAYWRIGHT_BROWSERS_PATH}"
        echo "  Chromium:   $([ $CHROMIUM_COUNT -gt 0 ] && echo 'installed' || echo 'NOT INSTALLED')"
        echo "  Firefox:    $([ $FIREFOX_COUNT -gt 0 ] && echo 'installed' || echo 'NOT INSTALLED')"
        echo "  WebKit:     $([ $WEBKIT_COUNT -gt 0 ] && echo 'installed' || echo 'NOT INSTALLED')"
    else
        echo "Browser Path: not configured"
    fi
    echo ""
    echo "Device Status:"
    echo "/dev/net/tun: $([ -e /dev/net/tun ] && echo 'available' || echo 'NOT AVAILABLE')"
    echo "/dev/kvm:     $([ -e /dev/kvm ] && echo 'available' || echo 'NOT AVAILABLE')"
    echo ""
    echo "OVS Status:"
    if pgrep -x ovsdb-server > /dev/null; then
        echo "ovsdb-server: running (PID: $(pgrep -x ovsdb-server))"
    else
        echo "ovsdb-server: not running"
    fi
    if pgrep -x ovs-vswitchd > /dev/null; then
        echo "ovs-vswitchd: running (PID: $(pgrep -x ovs-vswitchd))"
    else
        echo "ovs-vswitchd: not running"
    fi
    echo ""
    echo "Platform Daemon Status:"
    if [ -f /run/platformd.pid ] && kill -0 "$(cat /run/platformd.pid)" 2>/dev/null; then
        echo "platformd: running (PID: $(cat /run/platformd.pid))"
        echo "  Socket: ${PLATFORM_SOCKET_PATH:-/run/platformd.sock}"
        echo "  REST:   port ${PLATFORM_REST_PORT:-8443}"
        echo "  gRPC:   port ${PLATFORM_GRPC_PORT:-10443}"
        echo "  QUIC:   port ${PLATFORM_QUIC_PORT:-9444}"
        echo "  MCP:    port ${PLATFORM_MCP_PORT:-9445}"
    else
        echo "platformd: not running"
    fi
    echo ""
    echo "Next.js Dev Server Status:"
    if [ -f /run/nextjs.pid ] && kill -0 "$(cat /run/nextjs.pid)" 2>/dev/null; then
        echo "Next.js: running (PID: $(cat /run/nextjs.pid))"
        echo "  URL: http://localhost:3000"
        echo "  Log: /var/log/nextjs-dev.log"
    else
        echo "Next.js: not running"
    fi
    echo "============================================="
}

show_help() {
    cat << EOF
go-trusted-platform Development Container

Usage:
    docker run [OPTIONS] IMAGE [COMMAND]

Available Commands:
    verify              Verify development tools and environment
    ovs-start           Start Open vSwitch services
    ovs-stop            Stop Open vSwitch services
    ovs-shell           Start OVS services and drop to shell
    platformd-start     Start platform daemon with all API servers
    platformd-stop      Stop platform daemon
    platformd-shell     Start platform daemon with OVS and drop to shell
    web-setup           Install web dependencies and Playwright browsers
    web-start           Start Next.js development server
    web-stop            Stop Next.js development server
    e2e-shell           Start all services (platformd + Next.js) for E2E tests
    integration-shell   Start all services and drop to shell for integration tests
    bash|sh             Start interactive bash shell
    <any command>       Execute custom command

Environment Variables:
    AUTO_START_OVS        Set to "true" to automatically start OVS on container start
    AUTO_START_PLATFORMD  Set to "true" to automatically start platformd on container start
    AUTO_START_WEB        Set to "true" to automatically start Next.js dev server
    PLATFORM_REST_PORT    REST/HTTPS port (default: 8443)
    PLATFORM_GRPC_PORT    gRPC TCP port (default: 10443)
    PLATFORM_QUIC_PORT    QUIC UDP port (default: 9444)
    PLATFORM_MCP_PORT     MCP port (default: 9445)
    PLATFORM_SOCKET_PATH  Unix socket path (default: /run/platformd.sock)
    NEXT_PUBLIC_API_URL   Frontend API URL (default: https://localhost:8443)
    PLAYWRIGHT_BROWSERS_PATH  Playwright browsers location (default: /ms-playwright)

Examples:
    # Verify environment
    docker run --rm IMAGE verify

    # Start OVS and run tests
    docker run --rm --privileged --device /dev/net/tun IMAGE ovs-shell

    # Run E2E tests
    docker run --rm --privileged -p 3000:3000 -p 8443:8443 \\
        -v \$(pwd):/workspace IMAGE e2e-shell

    # Run specific test with OVS
    docker run --rm --privileged --device /dev/net/tun \\
        -e AUTO_START_OVS=true IMAGE \\
        go test -v -tags "integration \$(make -s print-build-tags)" ./test/integration/sdn/...

    # Interactive development with full capabilities
    docker run --rm -it --privileged \\
        --device /dev/net/tun --device /dev/kvm \\
        -v \$(pwd):/workspace IMAGE bash

Required Docker Options for Full Functionality:
    --privileged                Enable privileged mode for OVS and kernel modules
    --device /dev/net/tun       Enable TUN/TAP networking
    --device /dev/kvm           Enable KVM acceleration for QEMU
    --cap-add=NET_ADMIN         Network administration capability
    --cap-add=SYS_MODULE        Kernel module loading capability
    -p 3000:3000                Expose Next.js dev server port
    -p 8443:8443                Expose REST API port

EOF
}

# =============================================================================
# Cleanup Handler
# =============================================================================

cleanup() {
    echo ""
    echo "Received shutdown signal, cleaning up..."
    stop_web_dev
    stop_platformd
    stop_swtpm
    stop_ovs
    exit 0
}

trap cleanup SIGTERM SIGINT

# =============================================================================
# Main Entry Point
# =============================================================================

# Automatic setup if requested
if [ "${AUTO_START_OVS}" = "true" ]; then
    setup_devices
    start_ovs
fi

if [ "${AUTO_START_PLATFORMD}" = "true" ]; then
    start_platformd
fi

if [ "${AUTO_START_WEB}" = "true" ]; then
    setup_web
    start_web_dev
fi

case "${1:-bash}" in
    help|--help|-h)
        show_help
        ;;
    verify)
        verify_tools
        ;;
    ovs-start)
        setup_devices
        start_ovs
        ;;
    ovs-stop)
        stop_ovs
        ;;
    ovs-shell)
        setup_devices
        start_ovs
        exec /bin/bash
        ;;
    platformd-start)
        start_platformd
        ;;
    platformd-stop)
        stop_platformd
        ;;
    platformd-shell)
        setup_devices
        start_ovs
        start_platformd
        exec /bin/bash
        ;;
    web-setup)
        setup_web
        ;;
    web-start)
        setup_web
        start_web_dev
        ;;
    web-stop)
        stop_web_dev
        ;;
    web-dev)
        # Start backend with swtpm and frontend for web development
        setup_devices
        start_ovs
        start_platformd_web
        setup_web
        start_web_dev
        echo ""
        echo "=== Web Development Environment Ready ==="
        echo ""
        echo "  Frontend:    http://localhost:3000"
        echo "  Backend:     https://localhost:8443"
        echo ""
        echo "  Open in browser: http://localhost:3000/auth/webauthn"
        echo ""
        echo "  Logs:"
        echo "    Backend:  /var/log/platformd.log"
        echo "    Frontend: /var/log/nextjs-dev.log"
        echo "    swtpm:    /tmp/swtpm/swtpm.log"
        echo ""
        echo "============================================="
        # Keep container running and show logs
        tail -f /var/log/platformd.log /var/log/nextjs-dev.log
        ;;
    e2e-shell)
        # Start all services for E2E testing (backend + frontend)
        setup_devices
        start_ovs
        start_platformd_web
        setup_web
        start_web_dev
        echo ""
        echo "=== E2E Test Environment Ready ==="
        echo "All services started. Available endpoints:"
        echo "  Next.js:     http://localhost:3000"
        echo "  REST/HTTPS:  https://localhost:8443"
        echo "  gRPC TCP:    localhost:10443"
        echo "  QUIC UDP:    localhost:9444"
        echo ""
        echo "Run E2E tests with: cd web && npm run test:e2e"
        echo "============================================="
        exec /bin/bash
        ;;
    integration-shell)
        # Start all services for integration testing
        setup_devices
        start_ovs
        start_platformd
        echo ""
        echo "=== Integration Test Environment Ready ==="
        echo "All services started. Available endpoints:"
        echo "  Unix Socket: ${PLATFORM_SOCKET_PATH:-/run/platformd.sock}"
        echo "  REST/HTTPS:  https://localhost:${PLATFORM_REST_PORT:-8443}"
        echo "  gRPC TCP:    localhost:${PLATFORM_GRPC_PORT:-10443}"
        echo "  QUIC UDP:    localhost:${PLATFORM_QUIC_PORT:-9444}"
        echo "  MCP:         localhost:${PLATFORM_MCP_PORT:-9445}"
        echo ""
        echo "Run integration tests with: make integration-test"
        echo "============================================="
        exec /bin/bash
        ;;
    bash|sh)
        # Pass through any additional arguments (e.g., -c "command")
        shift
        exec /bin/bash "$@"
        ;;
    *)
        # Pass through any other command
        exec "$@"
        ;;
esac
# Cache buster: 1768847248
