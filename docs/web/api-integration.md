# Web Frontend API Integration

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md) §5.3 and [api.md](api.md). There is no `/api/v1/tenant` route (tenants are `/api/v1/tenants`); invitation revoke is `POST /invitations/{id}/revoke`; `apiRequest` is local to `web/src/app/auth/webauthn/page.tsx`, and other pages use the SDK hooks.

API integration guide for the Trusted Platform Web Frontend, covering WebAuthn flows, invitation system, and REST API patterns.

## API Overview

The frontend communicates with the Trusted Platform REST API at the following endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/webauthn/registration/begin` | POST | Start WebAuthn registration |
| `/api/v1/webauthn/registration/finish` | POST | Complete WebAuthn registration |
| `/api/v1/webauthn/login/begin` | POST | Start WebAuthn login |
| `/api/v1/webauthn/login/finish` | POST | Complete WebAuthn login |
| `/api/v1/invitations` | GET | List pending invitations |
| `/api/v1/invitations` | POST | Create new invitation |
| `/api/v1/invitations/:id` | DELETE | Revoke invitation |
| `/api/v1/tenant` | GET | Get tenant information |

## WebAuthn Registration Flow

### Flow Diagram

```
┌─────────┐                     ┌─────────┐                     ┌─────────┐
│ Browser │                     │ Frontend│                     │ Backend │
└────┬────┘                     └────┬────┘                     └────┬────┘
     │                               │                               │
     │  1. Enter email               │                               │
     │ ───────────────────────────►  │                               │
     │                               │                               │
     │                               │  2. POST /registration/begin  │
     │                               │ ──────────────────────────►   │
     │                               │                               │
     │                               │  3. PublicKey options + userId│
     │                               │ ◄──────────────────────────   │
     │                               │                               │
     │  4. navigator.credentials.create()                            │
     │ ◄─────────────────────────────┤                               │
     │                               │                               │
     │  5. Biometric/PIN prompt      │                               │
     │ ──────────────────────────────┤                               │
     │                               │                               │
     │  6. Attestation response      │                               │
     │ ──────────────────────────────►                               │
     │                               │                               │
     │                               │  7. POST /registration/finish │
     │                               │     + X-User-Id header        │
     │                               │ ──────────────────────────►   │
     │                               │                               │
     │                               │  8. JWT token                 │
     │                               │ ◄──────────────────────────   │
     │                               │                               │
     │  9. Store JWT, redirect       │                               │
     │ ◄─────────────────────────────┤                               │
     │                               │                               │
```

### Registration Implementation

```typescript
const handleRegister = async () => {
  // Step 1: Validate input
  if (!email) {
    setErrorMessage("Please enter your email address.");
    return;
  }

  // Step 2: Begin registration
  const requestBody: { email: string; invitation_token?: string } = { email };
  if (invitationToken) {
    requestBody.invitation_token = invitationToken;
  }

  const result = await apiRequest<ApiResponse>(
    "/api/v1/webauthn/registration/begin",
    {
      method: "POST",
      body: JSON.stringify(requestBody),
    }
  );

  if (!result.ok) {
    setErrorMessage(getErrorMessage(result, "register"));
    return;
  }

  // Step 3: Extract options
  const publicKey = result.data.publicKey;
  const userId = publicKey?.user?.id;

  // Step 4: Create credential with browser API
  const attestationResponse = await startRegistration({ optionsJSON: publicKey });

  // Step 5: Finish registration
  const verifyResult = await apiRequest<ApiResponse<TokenPayload>>(
    "/api/v1/webauthn/registration/finish",
    {
      method: "POST",
      body: JSON.stringify(attestationResponse),
      headers: { "X-User-Id": userId },
    }
  );

  // Step 6: Store JWT and redirect
  if (verifyResult.data.payload?.token) {
    setCookie("jwt", verifyResult.data.payload.token, {
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      secure: true,
      sameSite: "Strict",
    });
    router.push("/protected");
  }
};
```

## WebAuthn Login Flow

### Flow Diagram

```
┌─────────┐                     ┌─────────┐                     ┌─────────┐
│ Browser │                     │ Frontend│                     │ Backend │
└────┬────┘                     └────┬────┘                     └────┬────┘
     │                               │                               │
     │  1. Enter username            │                               │
     │ ───────────────────────────►  │                               │
     │                               │                               │
     │                               │  2. POST /login/begin         │
     │                               │ ──────────────────────────►   │
     │                               │                               │
     │                               │  3. PublicKey options         │
     │                               │     + X-User-Id header        │
     │                               │ ◄──────────────────────────   │
     │                               │                               │
     │  4. navigator.credentials.get()                               │
     │ ◄─────────────────────────────┤                               │
     │                               │                               │
     │  5. Biometric/PIN prompt      │                               │
     │ ──────────────────────────────┤                               │
     │                               │                               │
     │  6. Assertion response        │                               │
     │ ──────────────────────────────►                               │
     │                               │                               │
     │                               │  7. POST /login/finish        │
     │                               │     + X-User-Id header        │
     │                               │ ──────────────────────────►   │
     │                               │                               │
     │                               │  8. JWT token                 │
     │                               │ ◄──────────────────────────   │
     │                               │                               │
     │  9. Store JWT, redirect       │                               │
     │ ◄─────────────────────────────┤                               │
     │                               │                               │
```

### Login Implementation

```typescript
const handleLogin = async () => {
  if (!username) {
    setErrorMessage("Please enter your username.");
    return;
  }

  // Step 1: Begin login
  const result = await apiRequest<ApiResponse>(
    "/api/v1/webauthn/login/begin",
    {
      method: "POST",
      body: JSON.stringify({ username }),
    }
  );

  if (!result.ok) {
    setErrorMessage(getErrorMessage(result, "login"));
    return;
  }

  // Step 2: Extract options and user ID
  const publicKey = result.data.publicKey;
  const userId = result.headers.get("x-user-id");

  // Store user ID for finish step
  setCookie("uid", userId, { secure: true, sameSite: "Strict" });

  // Step 3: Get credential with browser API
  const assertionResponse = await startAuthentication({ optionsJSON: publicKey });

  // Step 4: Finish login
  const verifyResult = await apiRequest<ApiResponse<TokenPayload>>(
    "/api/v1/webauthn/login/finish",
    {
      method: "POST",
      body: JSON.stringify(assertionResponse),
      headers: { "X-User-Id": userId },
    }
  );

  // Step 5: Store JWT and redirect
  if (verifyResult.data.success && verifyResult.data.payload?.token) {
    setCookie("jwt", verifyResult.data.payload.token, {
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      secure: true,
      sameSite: "Strict",
    });
    router.push("/protected");
  }
};
```

## Invitation System

### Create Invitation

```typescript
const handleCreateInvitation = async () => {
  const baseUrl = getBaseUrl();
  const jwt = getCookie("jwt");

  const response = await fetch(`${baseUrl}/api/v1/invitations`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${jwt}`,
    },
    body: JSON.stringify({ email, role }),
  });

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.error || "Failed to create invitation");
  }

  const data = await response.json();
  // data.invitation contains the created invitation
};
```

### List Invitations

```typescript
const fetchInvitations = async () => {
  const baseUrl = getBaseUrl();
  const jwt = getCookie("jwt");

  const response = await fetch(`${baseUrl}/api/v1/invitations`, {
    headers: {
      Authorization: `Bearer ${jwt}`,
    },
  });

  const data = await response.json();
  // data.invitations is an array of pending invitations
};
```

### Revoke Invitation

```typescript
const handleRevokeInvitation = async (id: string) => {
  const baseUrl = getBaseUrl();
  const jwt = getCookie("jwt");

  const response = await fetch(`${baseUrl}/api/v1/invitations/${id}`, {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${jwt}`,
    },
  });

  if (!response.ok) {
    throw new Error("Failed to revoke invitation");
  }
};
```

### Accept Invitation

Users accept invitations by visiting the WebAuthn page with an invitation token:

```
/auth/webauthn?invitation=<token>&tenant_name=<workspace_name>
```

The token is included in the registration request:

```typescript
const requestBody = {
  email: email,
  invitation_token: invitationToken,  // Included when accepting invitation
};

await apiRequest("/api/v1/webauthn/registration/begin", {
  method: "POST",
  body: JSON.stringify(requestBody),
});
```

## Token Handling

### JWT Storage

Tokens are stored in cookies with secure settings:

```typescript
setCookie("jwt", token, {
  expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),  // 7 days
  secure: true,           // HTTPS only
  sameSite: "Strict",     // No cross-site requests
});
```

### JWT Decoding

Client-side JWT decoding for UI state (no signature verification):

```typescript
export function decodeJWT(token: string): JWTPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return null;
    }

    const payload = parts[1];
    const decoded = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(decoded) as JWTPayload;
  } catch {
    return null;
  }
}
```

### Token Refresh

The current implementation does not include automatic token refresh. Tokens expire after 7 days, requiring re-authentication.

Future enhancement: Implement a refresh endpoint and automatic refresh before expiration.

## Error Handling Patterns

### Error Response Structure

```typescript
interface ApiErrorResult {
  ok: false;
  error: string;      // Raw error message
  code?: string;      // Semantic error code
  status: number;     // HTTP status code
}
```

### Error Code Mapping

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

const ERROR_PATTERNS: Array<{ pattern: RegExp; code: ErrorCode }> = [
  { pattern: /entity not found.*type=user/i, code: "USER_NOT_FOUND" },
  { pattern: /user.*not found/i, code: "USER_NOT_FOUND" },
  { pattern: /user.*exists/i, code: "USER_EXISTS" },
  { pattern: /already exists/i, code: "USER_EXISTS" },
  // ... more patterns
];
```

### Context-Aware Messages

Different messages for login vs registration:

```typescript
const CONTEXT_ERROR_MESSAGES: Record<ErrorCode, { login: string; register: string }> = {
  USER_NOT_FOUND: {
    login: "Account not found. Please check your username or create a new account.",
    register: "Unable to start registration. Please try again.",
  },
  USER_EXISTS: {
    login: "Please enter your passkey to log in.",
    register: "An account with this email already exists. Please log in instead.",
  },
  // ... more messages
};
```

### Using Error Messages

```typescript
function getErrorMessage(result: ApiErrorResult, context: "login" | "register"): string {
  // Network errors
  if (result.status === 0) {
    return "Unable to connect to the server. Please check your connection.";
  }

  // Detect error code from message
  const errorCode = result.code ?? detectErrorCode(result.error);

  // Use context-aware message if available
  if (errorCode && errorCode in CONTEXT_ERROR_MESSAGES) {
    return CONTEXT_ERROR_MESSAGES[errorCode][context];
  }

  // Fallback based on HTTP status
  // ...
}
```

## API Request Helper

### Centralized Request Function

```typescript
interface ApiResult<T> {
  ok: true;
  data: T;
  headers: Headers;
}

interface ApiErrorResult {
  ok: false;
  error: string;
  code?: string;
  status: number;
}

type FetchResult<T> = ApiResult<T> | ApiErrorResult;

async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<FetchResult<T>> {
  const baseUrl = getBaseUrl();

  try {
    const response = await fetch(`${baseUrl}${endpoint}`, {
      ...options,
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...options.headers,
      },
    });

    if (!response.ok) {
      // Parse error response
      let rawError = "";
      let errorCode: string | undefined;

      try {
        const text = await response.text();
        if (text) {
          const errorData = JSON.parse(text);
          rawError = errorData.error || errorData.message || "";
          errorCode = errorData.errorCode || errorData.error_code;
        }
      } catch {
        // Ignore parse errors
      }

      return {
        ok: false,
        error: rawError,
        code: errorCode,
        status: response.status,
      };
    }

    const data = await response.json();
    return { ok: true, data, headers: response.headers };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : "Network request failed",
      status: 0,
    };
  }
}
```

## Authentication Headers

### Authenticated Requests

All authenticated requests include the JWT in the Authorization header:

```typescript
const jwt = getCookie("jwt");

const response = await fetch(url, {
  headers: {
    Authorization: `Bearer ${jwt}`,
    "Content-Type": "application/json",
  },
});
```

### WebAuthn User ID Header

WebAuthn finish endpoints require the user ID:

```typescript
const response = await fetch("/api/v1/webauthn/registration/finish", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-User-Id": userId,
  },
  body: JSON.stringify(attestationResponse),
});
```

## CORS Configuration

The backend must be configured to allow frontend requests:

```yaml
cors:
  allowed-origins:
    - https://example.com
    - http://localhost:3000
  allowed-methods:
    - GET
    - POST
    - PUT
    - DELETE
    - OPTIONS
  allowed-headers:
    - "*"
  allow-credentials: true
```

Key headers exposed for WebAuthn:
- `X-User-Id` - User identifier for WebAuthn flows
