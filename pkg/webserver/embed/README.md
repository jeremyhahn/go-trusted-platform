# Web Frontend Embedding

This package provides optional embedding of the Next.js web frontend into the `platformd` binary using Go's embed directive and build tags.

## Overview

The embed package uses build tags to conditionally include the web frontend:

- **Without** `platform_web` tag: `WebFS` is nil, `IsEmbedded()` returns false
- **With** `platform_web` tag: `WebFS` contains the embedded filesystem, `IsEmbedded()` returns true

## Directory Structure

```
pkg/webserver/embed/
├── embed.go          # Stub (no web frontend)
├── embed_web.go      # Embed implementation (with web frontend)
├── embed_test.go     # Unit tests
├── README.md         # This file
└── dist/             # Next.js static export (copied during build)
    ├── index.html
    ├── _next/
    └── ...
```

## Build Process

### Standard Build (No Web Frontend)

```bash
make build
# or
go build ./cmd/platformd
```

### Build with Embedded Web Frontend

```bash
make build-web
# or manually:
# 1. Build Next.js static export
cd web && npm run build
# 2. Copy output to embed directory
cp -r web/out/* pkg/webserver/embed/dist/
# 3. Build with tag
go build -tags platform_web ./cmd/platformd
```

### Makefile Integration

The Makefile handles the complete build process:

```makefile
# Build without web frontend
build:
	go build -o bin/platformd ./cmd/platformd

# Build with embedded web frontend
build-web: web-build
	mkdir -p pkg/webserver/embed/dist
	cp -r web/out/* pkg/webserver/embed/dist/
	go build -tags platform_web -o bin/platformd ./cmd/platformd

# Build Next.js frontend
web-build:
	cd web && npm ci && npm run build

# Clean embedded files
clean-embed:
	rm -rf pkg/webserver/embed/dist
```

## Usage in Code

```go
package main

import (
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webserver/embed"
)

func setupWebServer() http.Handler {
	mux := http.NewServeMux()

	// Check if web frontend is embedded
	if embed.IsEmbedded() {
		// Serve embedded files
		mux.Handle("/", http.FileServer(http.FS(embed.WebFS)))
	} else {
		// Serve from filesystem or return 404
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Web frontend not available", http.StatusNotFound)
		})
	}

	return mux
}
```

## Next.js Configuration

Ensure `next.config.mjs` is configured for static export:

```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
	output: 'export',
	trailingSlash: true,
	images: {
		unoptimized: true,
	},
}

export default nextConfig
```

## Build Tags Explained

Go build tags control which files are included in compilation:

| File | Build Tag | Included When |
|------|-----------|---------------|
| `embed.go` | `!platform_web` | Default build (no web) |
| `embed_web.go` | `platform_web` | Build with `-tags platform_web` |

Only one of these files is compiled into the binary based on the build tags.

## Verification

Check if web frontend is embedded:

```bash
# Check binary size (embedded will be significantly larger)
ls -lh bin/platformd

# Run and check at runtime
./bin/platformd --check-web
# or in code: embed.IsEmbedded()
```

## Troubleshooting

### "pattern dist/*: no matching files found"

The `dist/` directory must exist and contain files when building with `platform_web` tag:

```bash
# Ensure Next.js build output exists
ls -la pkg/webserver/embed/dist/

# If empty, rebuild:
cd web && npm run build
cp -r out/* ../pkg/webserver/embed/dist/
```

### Binary Size

Embedding the web frontend increases binary size. For minimal deployments, use the standard build without the `platform_web` tag and serve static files from the filesystem or a CDN.
