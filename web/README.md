# Trusted Platform Web Frontend

A Next.js 16 web application for the go-trusted-platform, providing WebAuthn authentication, tenant management, and invitation workflows.

## Features

- **WebAuthn Authentication**: Passwordless login using FIDO2/passkeys
- **Multi-Tenant Support**: Automatic tenant creation on registration
- **Invitation System**: Invite users to join your tenant
- **Tenant Dashboard**: Manage workspace information and members
- **TypeScript**: Full type safety across the codebase

## Getting Started

### Prerequisites

- Node.js 20+
- npm or pnpm
- Backend running at `https://localhost:8443`

### Installation

```bash
npm install
```

### Development

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser.

### Build

```bash
npm run build
```

## Project Structure

```
web/
├── src/
│   ├── app/                    # Next.js App Router pages
│   │   ├── auth/webauthn/      # WebAuthn authentication
│   │   ├── admin/
│   │   │   ├── invitations/    # Invitation management
│   │   │   └── tenant/         # Tenant dashboard
│   │   ├── dashboard/          # Main dashboard
│   │   └── protected/          # Protected routes
│   ├── contexts/               # React contexts
│   │   └── AuthContext.tsx     # Authentication state
│   ├── utils/                  # Utility functions
│   └── styles/                 # Global styles
├── e2e/                        # Playwright E2E tests
│   ├── fixtures/               # Test fixtures
│   │   ├── auth-setup.ts       # JWT session mocking
│   │   ├── api-mock.ts         # API response mocking
│   │   └── webauthn-mock.ts    # WebAuthn API mocking
│   ├── auth.spec.ts            # Authentication tests
│   ├── invitations.spec.ts     # Invitation management tests
│   ├── tenant.spec.ts          # Tenant dashboard tests
│   └── tenant-isolation.spec.ts # Multi-tenant isolation tests
├── docs/
│   └── testing.md              # Testing documentation
├── playwright.config.ts        # Playwright configuration
└── package.json
```

## Testing

### E2E Tests with Playwright

The project includes comprehensive E2E tests using Playwright:

```bash
# Install Playwright browsers (first time)
npx playwright install

# Run all tests
npm run test:e2e

# Run tests with UI mode (interactive)
npm run test:e2e:ui

# Run tests in headed mode (visible browser)
npm run test:e2e:headed

# Run specific test file
npx playwright test e2e/auth.spec.ts

# View test report
npx playwright show-report
```

### Test Coverage

| Test Suite | Tests | Coverage |
|------------|-------|----------|
| auth.spec.ts | 30 | Authentication flows, registration, login |
| invitations.spec.ts | 48 | Invitation CRUD, access control |
| tenant.spec.ts | 52 | Tenant dashboard, navigation |
| tenant-isolation.spec.ts | 38 | Cross-tenant data isolation |
| webauthn-flow.spec.ts | 14 | WebAuthn API integration |
| **Total** | **182** | All critical user journeys |

### Testing Documentation

See [docs/testing.md](docs/testing.md) for:
- Detailed Playwright setup
- WebAuthn mocking strategies
- CI integration guide
- Best practices and patterns

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NEXT_PUBLIC_API_URL` | Backend API URL | `https://localhost:8443` |
| `NEXT_PUBLIC_APP_URL` | Frontend app URL | `http://localhost:3000` |

## Authentication Flow

### New User Registration
1. User visits `/auth/webauthn`
2. Enters username and initiates WebAuthn ceremony
3. Backend creates new tenant automatically
4. User becomes tenant owner
5. JWT issued with `tenant_id` and `is_tenant_owner` claims

### Invited User Registration
1. Tenant owner creates invitation at `/admin/invitations`
2. Invited user receives link: `/auth/webauthn?invitation=TOKEN`
3. User registers and joins existing tenant
4. JWT issued with existing `tenant_id`

## Using from Makefile

From the root `go-trusted-platform` directory:

```bash
# Install dependencies
make web-install

# Run development server
make web-dev

# Build for production
make web-build

# Run E2E tests
make web-test

# Run linting
make web-lint
```

## Related Documentation

- [User Registration](../docs/auth/api.md)
- [Invitation Flow](../docs/tenant/architecture.md)
- [Tenant Architecture](../docs/tenant/architecture.md)
- [Testing Guide](docs/testing.md)

## License

Copyright (c) 2025 Jeremy Hahn / Automate The Things, LLC

Dual-licensed under AGPL-3.0 and Commercial License.
