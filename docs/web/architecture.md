# Web Frontend Architecture

Technical architecture documentation for the Trusted Platform Web Frontend.

## Component Structure

The frontend follows the Next.js 16 App Router convention with a clear separation between pages, contexts, and utilities.

### Directory Layout

```
src/
├── app/                        # Next.js App Router
│   ├── layout.tsx              # Root layout with fonts
│   ├── page.tsx                # Home page
│   ├── globals.css             # Global styles
│   ├── fonts/                  # Geist font files
│   ├── auth/
│   │   └── webauthn/
│   │       ├── page.tsx        # WebAuthn auth UI
│   │       └── WebAuthnUI.module.css
│   ├── admin/
│   │   ├── layout.tsx          # Admin layout
│   │   ├── tenant/
│   │   │   └── page.tsx        # Tenant dashboard
│   │   └── invitations/
│   │       └── page.tsx        # Invitation management
│   ├── protected/
│   │   └── page.tsx            # Protected content
│   └── logout/
│       └── page.tsx            # Logout handler
├── contexts/
│   └── AuthContext.tsx         # Authentication context
└── utils/
    ├── cookie.ts               # Cookie utilities
    ├── jwt.ts                  # JWT decoding
    └── getBaseUrl.ts           # Base URL resolution
```

### App Router Pages

| Route | Component | Purpose |
|-------|-----------|---------|
| `/` | `page.tsx` | Landing page |
| `/auth/webauthn` | `auth/webauthn/page.tsx` | WebAuthn login/registration |
| `/admin/tenant` | `admin/tenant/page.tsx` | Tenant workspace dashboard |
| `/admin/invitations` | `admin/invitations/page.tsx` | Invitation management |
| `/protected` | `protected/page.tsx` | Protected content area |
| `/logout` | `logout/page.tsx` | Session logout |

## State Management

### AuthContext

The `AuthContext` provides centralized authentication state management:

```typescript
interface User {
  id: string;
  email: string;
  tenantId: string;
  isTenantOwner: boolean;
  roles: string[];
}

interface AuthContextType {
  user: User | null;
  tenantId: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (token: string) => void;
  logout: () => void;
}
```

**State Flow:**

1. On mount, `AuthProvider` reads JWT from cookie
2. JWT is decoded (client-side, no verification)
3. User data extracted from JWT claims
4. Components access state via `useAuth()` hook

```typescript
// Usage in components
const { user, isAuthenticated, login, logout } = useAuth();
```

### JWT Token Structure

The JWT contains these claims for client-side state:

| Claim | Field | Description |
|-------|-------|-------------|
| `sub` | User ID | Primary user identifier |
| `email` | Email | User email address |
| `tenant_id` | Tenant ID | Workspace identifier |
| `is_tenant_owner` | Owner Flag | Tenant ownership status |
| `roles` | Roles | User role array |

**Note:** Client-side JWT decoding does NOT verify signatures. The server must always validate tokens on API requests.

## Multi-Tenant Architecture

### Tenant Isolation

Multi-tenancy is implemented through JWT claims:

```
┌─────────────────────────────────────────────────────────┐
│                     JWT Token                            │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ {                                                   │ │
│  │   "sub": "user-123",                                │ │
│  │   "email": "alice@example.com",                     │ │
│  │   "tenant_id": "tenant-456",    ◄── Tenant Scope   │ │
│  │   "is_tenant_owner": true,                          │ │
│  │   "roles": ["admin", "member"]                      │ │
│  │ }                                                   │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                   AuthContext                           │
│  ┌─────────────────┐  ┌──────────────────────────────┐  │
│  │ User State      │  │ Tenant State                 │  │
│  │ - id            │  │ - tenantId: "tenant-456"     │  │
│  │ - email         │  │ - isTenantOwner: true        │  │
│  │ - roles         │  │                              │  │
│  └─────────────────┘  └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                    API Requests                         │
│  Authorization: Bearer <JWT with tenant_id>             │
│  All operations scoped to tenant automatically          │
└─────────────────────────────────────────────────────────┘
```

### Tenant-Specific Features

| Feature | Tenant Owner | Regular Member |
|---------|--------------|----------------|
| View workspace info | Yes | Yes |
| View members | Yes | Yes |
| Manage invitations | Yes | No |
| Create invitations | Yes | No |
| Revoke invitations | Yes | No |

## API Integration

### REST Endpoint Communication

All API requests use a centralized `apiRequest` helper:

```typescript
async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<FetchResult<T>> {
  const baseUrl = getBaseUrl();

  const response = await fetch(`${baseUrl}${endpoint}`, {
    ...options,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...options.headers,
    },
  });

  // Error handling and response parsing
  // ...
}
```

### Dynamic Base URL

The `getBaseUrl()` function handles both client and server environments:

```typescript
export function getBaseUrl(): string {
  if (typeof window !== "undefined") {
    // Client-side: use current origin
    const { protocol, hostname, port } = window.location;
    return `${protocol}//${hostname}${port ? `:${port}` : ""}`;
  }

  // Server-side: use environment variables
  const protocol = process.env.NODE_ENV === "production" ? "https:" : "http:";
  const hostname = process.env.HOSTNAME ?? "localhost";
  const port = process.env.PORT ? `:${process.env.PORT}` : "";

  return `${protocol}//${hostname}${port}`;
}
```

## Build System

### Next.js 16 Configuration

The Next.js configuration enables static export:

```javascript
// next.config.mjs
const nextConfig = {
  output: "export",           // Static HTML export
  images: {
    unoptimized: true,        // No image optimization server
  },
  trailingSlash: true,        // Generate /page/index.html
  reactStrictMode: true,      // Enable strict mode
};
```

### Build Output

Static export generates:

```
out/
├── index.html
├── auth/
│   └── webauthn/
│       └── index.html
├── admin/
│   ├── tenant/
│   │   └── index.html
│   └── invitations/
│       └── index.html
├── protected/
│   └── index.html
├── _next/
│   └── static/              # JS/CSS bundles
└── ...
```

### Turbopack Development

Development uses Turbopack for fast refresh:

```bash
yarn dev  # Runs: next dev --turbopack
```

## Component Patterns

### Client Components

All interactive pages use the `"use client"` directive:

```typescript
"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
// ...

export default function Page() {
  // Client-side hooks and state
}
```

### Protected Route Pattern

Protected pages check authentication on mount:

```typescript
export default function ProtectedPage() {
  const router = useRouter();

  useEffect(() => {
    const user = getUserFromToken();
    if (!user) {
      router.push("/auth/webauthn");
      return;
    }
    // Continue with authenticated logic
  }, [router]);

  // ...
}
```

### CSS Modules

Component styles use CSS Modules:

```css
/* Component.module.css */
.container {
  max-width: 800px;
  margin: 0 auto;
}

.card {
  background: var(--card-background);
  border-radius: 8px;
  padding: 24px;
}
```

```typescript
import styles from "./Component.module.css";

export default function Component() {
  return (
    <div className={styles.container}>
      <div className={styles.card}>
        {/* Content */}
      </div>
    </div>
  );
}
```

## Error Handling

### API Error Handling

Errors are categorized and mapped to user-friendly messages:

```typescript
type ErrorCode =
  | "USER_NOT_FOUND"
  | "USER_EXISTS"
  | "INVALID_CREDENTIALS"
  | "CREDENTIAL_NOT_FOUND"
  | "SESSION_EXPIRED"
  | "RATE_LIMITED"
  | "VALIDATION_ERROR"
  | "INTERNAL_ERROR";

// Context-aware messages
const CONTEXT_ERROR_MESSAGES: Record<ErrorCode, { login: string; register: string }> = {
  USER_NOT_FOUND: {
    login: "Account not found. Please check your username or create a new account.",
    register: "Unable to start registration. Please try again.",
  },
  // ...
};
```

### Error Pattern Detection

Fallback error detection from raw messages:

```typescript
const ERROR_PATTERNS: Array<{ pattern: RegExp; code: ErrorCode }> = [
  { pattern: /entity not found.*type=user/i, code: "USER_NOT_FOUND" },
  { pattern: /user.*not found/i, code: "USER_NOT_FOUND" },
  { pattern: /user.*exists/i, code: "USER_EXISTS" },
  // ...
];
```

## Performance Considerations

### Bundle Optimization

- Tree shaking enabled via ES modules
- Code splitting at route level
- CSS modules for minimal CSS output
- Bundle analyzer available via `ANALYZE=true yarn build`

### Runtime Performance

- Static export eliminates server-side rendering overhead
- Client-side navigation after initial load
- JWT stored in cookies for persistent sessions
- Minimal dependencies for small bundle size
