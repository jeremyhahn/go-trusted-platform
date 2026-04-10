# Trusted Platform Web Frontend

Modern, secure web frontend for the Trusted Platform using Next.js 16, React 19, and WebAuthn passwordless authentication.

## Overview

The Trusted Platform Web Frontend provides a browser-based interface for interacting with the Trusted Platform services. Built with Next.js 16 and React 19, it features WebAuthn/FIDO2 passwordless authentication, multi-tenant workspace management, and seamless integration with the platform's REST API.

The frontend is designed to be embedded directly into the Go binary for simplified deployment, or served from the filesystem for development flexibility.

## Key Features

| Feature | Description |
|---------|-------------|
| **WebAuthn/FIDO2** | Passwordless authentication using passkeys and hardware security keys |
| **Multi-Tenant** | Complete workspace isolation with tenant-scoped JWT tokens |
| **Invitation System** | Secure workspace invitations with role-based access |
| **Static Export** | Pre-rendered HTML for embedding in Go binary |
| **Turbopack** | Fast development with Next.js Turbopack bundler |
| **Type Safety** | Full TypeScript coverage with strict mode |
| **E2E Testing** | Playwright tests with WebAuthn mocking for CI |
| **Bundle Analysis** | Built-in bundle analyzer for optimization |

## Architecture Decision

**Monorepo integration with static export** - NOT a standalone SPA.

| Aspect | Decision |
|--------|----------|
| Framework | Next.js 16 with React 19 |
| Rendering | Static export (`next export`) |
| Embedding | Go embed for single-binary deployment |
| State | Client-side JWT with React Context |
| Styling | CSS Modules with Geist font family |

**Rationale:**
- Static export enables embedding in Go binary
- Single binary simplifies deployment and distribution
- Client-side rendering works offline after initial load
- No server-side runtime required

## Quick Start

### Development

```bash
cd web

# Install dependencies
yarn install

# Start development server with Turbopack
yarn dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Production Build

```bash
# Build static export
yarn build

# Output is in web/out/
```

### Integration with Platform

Build the complete public_html directory including Swagger docs:

```bash
# From project root
make build-public-html
```

This creates:
- `public_html/` - Static web assets
- `public_html.tar.gz` - Archived for ISO builds

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Component structure and state management |
| [Configuration](configuration.md) | Environment variables and build settings |
| [Testing](testing.md) | Playwright E2E testing setup |
| [API Integration](api-integration.md) | WebAuthn flows and REST API usage |
| [Embedding](embedding.md) | Go binary embedding and deployment |

## Integration with Platform Components

| Component | Integration |
|-----------|-------------|
| **IAM** | WebAuthn registration/login, JWT validation |
| **Web Services** | REST API endpoints for all operations |
| **Multi-Tenancy** | Tenant ID extracted from JWT claims |
| **Invitations** | Token-based workspace invitations |
| **CORS** | Configured for cross-origin requests |

## Project Structure

```
web/
├── src/
│   ├── app/                    # Next.js App Router pages
│   │   ├── auth/webauthn/      # WebAuthn authentication UI
│   │   ├── admin/              # Admin pages (tenant, invitations)
│   │   ├── protected/          # Protected content
│   │   └── logout/             # Logout handler
│   ├── contexts/               # React Context providers
│   │   └── AuthContext.tsx     # Authentication state
│   └── utils/                  # Utility functions
│       ├── cookie.ts           # Cookie management
│       ├── jwt.ts              # JWT decoding
│       └── getBaseUrl.ts       # Dynamic base URL
├── e2e/                        # Playwright E2E tests
│   ├── fixtures/               # Test fixtures
│   │   └── webauthn-mock.ts    # WebAuthn mock for CI
│   └── *.spec.ts               # Test specifications
├── public/                     # Static assets
├── next.config.mjs             # Next.js configuration
├── playwright.config.ts        # Playwright configuration
├── tsconfig.json               # TypeScript configuration
└── package.json                # Dependencies and scripts
```

## Technology Stack

| Technology | Version | Purpose |
|------------|---------|---------|
| Next.js | 16.x | React framework with App Router |
| React | 19.x | UI component library |
| TypeScript | 5.x | Type-safe JavaScript |
| Playwright | 1.40+ | E2E testing framework |
| @simplewebauthn/browser | 13.x | WebAuthn client library |

## Security Model

### Authentication Security

- **Passwordless by Default** - WebAuthn/FIDO2 only, no password fallback
- **Secure Cookie Storage** - JWT stored with `Secure` and `SameSite=Strict`
- **Client-Side Decoding** - JWT claims decoded without signature verification (server verifies)
- **Session Expiration** - 7-day token lifetime with server-side validation

### Multi-Tenant Security

- **Tenant Isolation** - All operations scoped to tenant ID from JWT
- **Owner Privileges** - Invitation management restricted to tenant owners
- **Role-Based UI** - UI elements hidden based on user roles

## See Also

- [IAM Documentation](../iam/README.md)
- [Web Services Documentation](../webservices/README.md)
- [Platform Configuration](../configuration/README.md)
