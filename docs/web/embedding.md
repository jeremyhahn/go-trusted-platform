# Web Frontend Embedding

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md) §5.1 and [engineering.md](engineering.md) §8. The embed is `//go:embed all:dist` in `pkg/webserver/embed/embed_web.go` (`WITH_WEB=1`, tag `platform_web`); builds use npm, not yarn.

Documentation for embedding the web frontend into the Trusted Platform Go binary.

## Overview

The Trusted Platform Web Frontend can be deployed in two ways:

1. **Embedded in Go binary** - Single binary deployment with static assets bundled
2. **Filesystem serving** - Static files served from disk

This document covers the embedding mechanism and build process.

## Deployment Options

| Option | Pros | Cons |
|--------|------|------|
| **Embedded** | Single binary, simpler deployment | Larger binary size, rebuild for UI updates |
| **Filesystem** | Update UI without rebuild | Requires file distribution, path configuration |
| **ISO Install** | Complete system image | Fixed at install time |

## Build System

### Building public_html

The main project Makefile includes targets for building the web frontend:

```bash
# Build using devcontainer (recommended)
make build-public-html

# Build on host system (legacy)
make build-public-html-host
```

### Build Process

The `build-public-html` target:

1. **Builds Swagger documentation**
   ```bash
   swag init --dir pkg/webservice,... --output public_html/swagger
   ```

2. **Downloads Swagger UI**
   ```bash
   git clone --depth=1 https://github.com/swagger-api/swagger-ui.git
   mv swagger-ui/dist/* public_html/swagger/
   ```

3. **Builds Next.js application**
   ```bash
   cd web && yarn install && yarn build
   ```

4. **Copies build output**
   ```bash
   cp -R web/out/* public_html/
   ```

5. **Creates archive for ISO**
   ```bash
   tar czf public_html.tar.gz public_html/
   ```

### Build Output

After building:

```
project-root/
├── public_html/              # Static web assets
│   ├── index.html
│   ├── auth/
│   │   └── webauthn/
│   │       └── index.html
│   ├── admin/
│   │   └── ...
│   ├── swagger/              # API documentation
│   │   ├── index.html
│   │   ├── swagger.json
│   │   └── ...
│   └── _next/
│       └── static/           # JS/CSS bundles
└── public_html.tar.gz        # Archive for ISO builds
```

## Go Embed Mechanism

### How Go Embed Works

Go 1.16+ includes the `embed` package for embedding static files:

```go
import "embed"

//go:embed public_html/*
var staticFiles embed.FS
```

The `//go:embed` directive tells the Go compiler to include files at compile time.

### Web Service Configuration

The web service configuration specifies where to serve static files from:

```yaml
webservices:
  - name: public
    port: 8080
    tls-port: 8443
    home: public_html       # Path to static files
```

| Setting | Description |
|---------|-------------|
| `home` | Directory containing static web files |

### Embedded vs Filesystem

The platform supports both modes:

**Filesystem Mode:**
```yaml
webservices:
  - name: public
    home: /var/lib/trusted-platform/public_html
```

Files are read from disk at runtime.

**Embedded Mode:**

When building with embedded assets, the `embed.FS` is used as the file source.

## ISO Installation

### WebUI in ISO

The ISO builder includes the WebUI for installation:

```bash
# Create ISO with WebUI
platformctl iso create \
  --webui public_html.tar.gz \
  --config config.yaml
```

Or auto-detect:
```bash
# Auto-detects public_html.tar.gz or public_html/ in current directory
platformctl iso create --config config.yaml
```

### Installation Path

During installation, the WebUI is extracted to:
```
/var/lib/trusted-platform/public_html/
```

Installation logs:
```json
{"level":"INFO","msg":"[ALPINE] Installing WebUI","source":"/media/cdrom/webui.tar.gz","destination":"/mnt/var/lib/trusted-platform/public_html"}
{"level":"INFO","msg":"[ALPINE] WebUI installed successfully","path":"/mnt/var/lib/trusted-platform/public_html","dir_perms":"755","file_perms":"644","owner":"root:root"}
```

## Configuration Examples

### Development Configuration

```yaml
# config.dev.yaml
webservices:
  - name: public
    port: 8080
    tls-port: 8443
    home: public_html        # Relative path for development
```

### Production Configuration

```yaml
# config.prod.yaml
webservices:
  - name: public
    port: 80
    tls-port: 443
    home: /var/lib/trusted-platform/public_html   # Absolute path
```

### Platform Configuration

```yaml
# Platform config (e.g., qemu.server.example.com.yaml)
webservices:
  - name: internal
    home: /var/lib/trusted-platform/public_html

  - name: external
    home: /var/lib/trusted-platform/public_html
```

## Directory Structure

### Production Layout

```
/var/lib/trusted-platform/
├── public_html/
│   ├── index.html
│   ├── auth/
│   │   └── webauthn/
│   │       └── index.html
│   ├── admin/
│   │   ├── tenant/
│   │   │   └── index.html
│   │   └── invitations/
│   │       └── index.html
│   ├── protected/
│   │   └── index.html
│   ├── swagger/
│   │   ├── index.html
│   │   └── swagger.json
│   └── _next/
│       └── static/
│           ├── css/
│           └── chunks/
└── config.yaml
```

## Makefile Integration

### Main Project Makefile

Relevant targets:

```makefile
# Default public_html location
WEB_PUBLIC_HTML ?= public_html

# Build WebUI using devcontainer
build-public-html:
    @echo "Building WebUI using devcontainer..."
    docker run --rm \
        -v $(CURDIR):/workspace \
        -v $(CURDIR)/../$(WEB_PACKAGE):/web-src \
        go-trusted-platform-dev:latest \
        /bin/bash -c '...'

# Build WebUI on host
build-public-html-host:
    rm -rf $(WEB_PUBLIC_HTML)/ pkg/$(WEB_PUBLIC_HTML)/
    mkdir -p $(WEB_PUBLIC_HTML)/ pkg/$(WEB_PUBLIC_HTML)/
    make swagger
    make swagger-ui
    cd $(WEB_SRC) && yarn install && yarn build
    cp -R $(WEB_SRC)/out/* $(WEB_PUBLIC_HTML)/
    tar czf public_html.tar.gz $(WEB_PUBLIC_HTML)/
```

### Web Project Makefile

```makefile
# web/Makefile
WEB_PUBLIC_HTML ?= ../go-trusted-platform/public_html

dev:
    yarn run dev

build:
    yarn run build
```

## Docker Deployment

### Dockerfile Example

```dockerfile
# Build stage
FROM node:20-alpine AS web-builder
WORKDIR /app
COPY web/package.json web/yarn.lock ./
RUN yarn install --frozen-lockfile
COPY web/ ./
RUN yarn build

# Runtime stage
FROM golang:alpine AS builder
# ... Go build steps ...
COPY --from=web-builder /app/out /app/public_html

# Final image
FROM alpine:latest
COPY --from=builder /app/platformd /usr/local/bin/
COPY --from=builder /app/public_html /var/lib/trusted-platform/public_html
```

### Docker Compose

```yaml
services:
  platform:
    build: .
    volumes:
      # Optional: mount for development
      - ./public_html:/var/lib/trusted-platform/public_html:ro
    environment:
      - HOME=/var/lib/trusted-platform/public_html
```

## Updating the Web Frontend

### Development Workflow

1. Make changes in `web/src/`
2. Run development server: `cd web && yarn dev`
3. Test changes locally
4. Build: `make build-public-html`
5. Restart platform to pick up new files

### Production Updates

**Filesystem Mode:**
1. Build new WebUI: `make build-public-html`
2. Copy files to server: `rsync -av public_html/ server:/var/lib/trusted-platform/public_html/`
3. No restart required (files served directly)

**Embedded Mode:**
1. Build new WebUI: `make build-public-html`
2. Rebuild Go binary: `make build`
3. Deploy new binary
4. Restart service

**ISO Update:**
1. Build new WebUI: `make build-public-html`
2. Create new ISO: `platformctl iso create ...`
3. Reinstall system

## Troubleshooting

### Common Issues

**Files not found:**
```
404 Not Found: /index.html
```
- Check `home` path in configuration
- Verify files exist at specified path
- Check file permissions (should be readable by service user)

**Swagger UI not loading:**
```
Failed to load swagger.json
```
- Rebuild with `make build-public-html`
- Verify `public_html/swagger/` contains all files

**Static assets not loading:**
```
Failed to load _next/static/...
```
- Ensure Next.js build completed successfully
- Check that `out/` directory was copied correctly

### Verification Commands

```bash
# Check file permissions
ls -la /var/lib/trusted-platform/public_html/

# Verify file structure
find /var/lib/trusted-platform/public_html -type f | head -20

# Check configuration
grep -A5 "home:" /var/lib/trusted-platform/config.yaml

# Test file serving
curl -I https://localhost:8443/
curl -I https://localhost:8443/swagger/
```
