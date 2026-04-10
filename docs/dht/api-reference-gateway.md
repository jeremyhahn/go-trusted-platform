# DHT Gateway API Reference

## Overview

The Gateway API provides browser-friendly access to the DHT network for:

- Chrome/Firefox extensions
- Web applications
- External clients without native DHT connectivity

The Gateway acts as a bridge between traditional HTTP clients and the distributed DHT network, translating REST requests into DHT operations and maintaining WebSocket connections for real-time updates.

## Base URL

```
https://{gateway-node}:8443/gateway/v1
```

Gateway nodes are discoverable through:
- DNS seed nodes
- Hardcoded bootstrap list
- Local network discovery (mDNS)

## Authentication

### Public Access

No authentication required for read-only operations:

| Operation | Endpoint |
|-----------|----------|
| Service browsing | `GET /services/*` |
| Product viewing | `GET /products/*` |
| Store browsing | `GET /stores/*` |
| Search operations | `GET /search` |
| Category listing | `GET /categories` |

### Authenticated Access

Authentication required for state-modifying operations:

| Operation | Endpoint |
|-----------|----------|
| Wallet operations | `GET/POST /wallet/*` |
| Order placement | `POST /checkout` |
| Cart management | `POST/DELETE /cart/*` |
| Chat room participation | `WS /ws` (chat channels) |

### Authentication Methods

#### WebAuthn (Recommended)

WebAuthn provides passwordless authentication using platform authenticators (fingerprint, Face ID) or security keys (YubiKey).

**Benefits:**
- Phishing resistant
- No password to compromise
- Hardware-backed security
- Native browser support

#### Session Token

After successful WebAuthn authentication, a session token is issued:

```http
Authorization: Bearer <session-token>
```

Session tokens:
- Valid for 24 hours by default
- Renewable before expiration
- Bound to client fingerprint
- Revocable server-side

## REST Endpoints

### Discovery

#### Search

```http
GET /search?q={query}&type={type}&tags={tags}&page={page}&limit={limit}
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `q` | string | Yes | Search query |
| `type` | string | No | Filter by type: `service`, `product`, `store` |
| `tags` | string | No | Comma-separated tags |
| `page` | integer | No | Page number (default: 1) |
| `limit` | integer | No | Results per page (default: 20, max: 100) |
| `sort` | string | No | Sort by: `relevance`, `price`, `rating`, `date` |

**Response:**

```json
{
  "results": [
    {
      "id": "QmXyz123...",
      "type": "product",
      "title": "Example Product",
      "description": "Product description...",
      "price": {
        "amount": "0.001",
        "currency": "BTC"
      },
      "rating": 4.5,
      "store_id": "QmAbc456...",
      "tags": ["electronics", "gadgets"]
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 150,
    "pages": 8
  }
}
```

#### Get Service

```http
GET /services/{id}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Service DHT identifier |

**Response:**

```json
{
  "id": "QmXyz123...",
  "name": "Example Service",
  "description": "Service description...",
  "provider": {
    "id": "QmProvider...",
    "name": "Provider Name",
    "rating": 4.8
  },
  "endpoints": [
    {
      "protocol": "https",
      "url": "https://service.example.com/api"
    }
  ],
  "pricing": {
    "model": "per_request",
    "amount": "0.00001",
    "currency": "BTC"
  },
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-07T12:00:00Z"
}
```

#### List Categories

```http
GET /categories
```

**Response:**

```json
{
  "categories": [
    {
      "id": "electronics",
      "name": "Electronics",
      "count": 1250,
      "subcategories": [
        {
          "id": "computers",
          "name": "Computers",
          "count": 450
        }
      ]
    }
  ]
}
```

#### Popular Items

```http
GET /popular?type={type}&period={period}&limit={limit}
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `type` | string | No | Filter by type: `service`, `product`, `store` |
| `period` | string | No | Time period: `day`, `week`, `month` (default: `week`) |
| `limit` | integer | No | Number of results (default: 10, max: 50) |

**Response:**

```json
{
  "items": [
    {
      "id": "QmXyz123...",
      "type": "product",
      "title": "Popular Product",
      "views": 15420,
      "orders": 234
    }
  ],
  "period": "week"
}
```

### Stores

#### List Stores

```http
GET /stores?page={page}&limit={limit}&sort={sort}
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `page` | integer | No | Page number (default: 1) |
| `limit` | integer | No | Results per page (default: 20, max: 100) |
| `sort` | string | No | Sort by: `rating`, `products`, `date` |

**Response:**

```json
{
  "stores": [
    {
      "id": "QmStore123...",
      "name": "Example Store",
      "description": "Store description...",
      "rating": 4.7,
      "product_count": 45,
      "verified": true,
      "created_at": "2025-06-15T00:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 500,
    "pages": 25
  }
}
```

#### Get Store

```http
GET /stores/{id}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Store DHT identifier |

**Response:**

```json
{
  "id": "QmStore123...",
  "name": "Example Store",
  "description": "Full store description...",
  "owner": {
    "id": "QmOwner...",
    "reputation": 4.9
  },
  "rating": 4.7,
  "reviews_count": 234,
  "product_count": 45,
  "verified": true,
  "policies": {
    "shipping": "Ships within 3-5 business days",
    "returns": "30-day return policy",
    "escrow": "Required for orders over 0.01 BTC"
  },
  "created_at": "2025-06-15T00:00:00Z"
}
```

#### List Store Products

```http
GET /stores/{id}/products?page={page}&limit={limit}&category={category}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Store DHT identifier |

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `page` | integer | No | Page number (default: 1) |
| `limit` | integer | No | Results per page (default: 20, max: 100) |
| `category` | string | No | Filter by category |

**Response:**

```json
{
  "store_id": "QmStore123...",
  "products": [
    {
      "id": "QmProduct...",
      "title": "Product Title",
      "price": {
        "amount": "0.005",
        "currency": "BTC"
      },
      "available": true,
      "stock": 15
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 45,
    "pages": 3
  }
}
```

#### Get Product

```http
GET /products/{id}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Product DHT identifier |

**Response:**

```json
{
  "id": "QmProduct...",
  "title": "Product Title",
  "description": "Full product description...",
  "store": {
    "id": "QmStore123...",
    "name": "Example Store"
  },
  "price": {
    "amount": "0.005",
    "currency": "BTC"
  },
  "available": true,
  "stock": 15,
  "images": [
    {
      "url": "ipfs://QmImage1...",
      "alt": "Product front view"
    }
  ],
  "specifications": {
    "weight": "500g",
    "dimensions": "10x5x3 cm"
  },
  "shipping_options": [
    {
      "method": "standard",
      "price": "0.0001",
      "currency": "BTC",
      "estimated_days": "5-7"
    }
  ],
  "reviews_summary": {
    "average": 4.5,
    "count": 23
  },
  "created_at": "2025-12-01T00:00:00Z"
}
```

### Orders (Authenticated)

#### Add to Cart

```http
POST /cart/add
Authorization: Bearer <session-token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "product_id": "QmProduct...",
  "quantity": 2,
  "options": {
    "color": "blue",
    "size": "medium"
  }
}
```

**Response:**

```json
{
  "cart_id": "cart_abc123",
  "item": {
    "id": "item_xyz789",
    "product_id": "QmProduct...",
    "quantity": 2,
    "price": {
      "amount": "0.010",
      "currency": "BTC"
    }
  },
  "cart_total": {
    "amount": "0.010",
    "currency": "BTC"
  }
}
```

#### Get Cart

```http
GET /cart
Authorization: Bearer <session-token>
```

**Response:**

```json
{
  "cart_id": "cart_abc123",
  "items": [
    {
      "id": "item_xyz789",
      "product": {
        "id": "QmProduct...",
        "title": "Product Title",
        "store_id": "QmStore123..."
      },
      "quantity": 2,
      "options": {
        "color": "blue",
        "size": "medium"
      },
      "price": {
        "amount": "0.010",
        "currency": "BTC"
      }
    }
  ],
  "subtotal": {
    "amount": "0.010",
    "currency": "BTC"
  },
  "shipping": {
    "amount": "0.0002",
    "currency": "BTC"
  },
  "total": {
    "amount": "0.0102",
    "currency": "BTC"
  }
}
```

#### Remove from Cart

```http
DELETE /cart/{item-id}
Authorization: Bearer <session-token>
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `item-id` | string | Cart item identifier |

**Response:**

```json
{
  "removed": true,
  "cart_total": {
    "amount": "0.000",
    "currency": "BTC"
  }
}
```

#### Checkout

```http
POST /checkout
Authorization: Bearer <session-token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "shipping_address": {
    "encrypted": true,
    "data": "base64-encrypted-address..."
  },
  "shipping_method": "standard",
  "payment_method": "wallet",
  "use_escrow": true
}
```

**Response:**

```json
{
  "order_id": "order_def456",
  "status": "pending_payment",
  "payment": {
    "address": "bc1q...",
    "amount": "0.0102",
    "currency": "BTC",
    "expires_at": "2026-01-08T13:00:00Z"
  },
  "escrow": {
    "enabled": true,
    "release_conditions": "delivery_confirmed"
  }
}
```

#### List Orders

```http
GET /orders?status={status}&page={page}&limit={limit}
Authorization: Bearer <session-token>
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `status` | string | No | Filter: `pending`, `paid`, `shipped`, `completed`, `disputed` |
| `page` | integer | No | Page number (default: 1) |
| `limit` | integer | No | Results per page (default: 20) |

**Response:**

```json
{
  "orders": [
    {
      "id": "order_def456",
      "status": "shipped",
      "total": {
        "amount": "0.0102",
        "currency": "BTC"
      },
      "items_count": 1,
      "created_at": "2026-01-07T10:00:00Z",
      "updated_at": "2026-01-07T14:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 5,
    "pages": 1
  }
}
```

#### Get Order

```http
GET /orders/{id}
Authorization: Bearer <session-token>
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Order identifier |

**Response:**

```json
{
  "id": "order_def456",
  "status": "shipped",
  "items": [
    {
      "product_id": "QmProduct...",
      "title": "Product Title",
      "quantity": 2,
      "price": {
        "amount": "0.010",
        "currency": "BTC"
      }
    }
  ],
  "shipping": {
    "method": "standard",
    "tracking": "TRACK123456",
    "carrier": "DHL"
  },
  "payment": {
    "status": "confirmed",
    "transaction_id": "txid_abc123...",
    "confirmations": 6
  },
  "escrow": {
    "enabled": true,
    "status": "held",
    "release_at": "2026-01-14T10:00:00Z"
  },
  "timeline": [
    {
      "event": "order_placed",
      "timestamp": "2026-01-07T10:00:00Z"
    },
    {
      "event": "payment_received",
      "timestamp": "2026-01-07T10:30:00Z"
    },
    {
      "event": "shipped",
      "timestamp": "2026-01-07T14:00:00Z"
    }
  ],
  "total": {
    "amount": "0.0102",
    "currency": "BTC"
  }
}
```

### Wallet (Authenticated)

#### Get Balance

```http
GET /wallet/balance
Authorization: Bearer <session-token>
```

**Response:**

```json
{
  "balances": [
    {
      "currency": "BTC",
      "available": "0.05234",
      "pending": "0.01000",
      "total": "0.06234"
    },
    {
      "currency": "XMR",
      "available": "2.5000",
      "pending": "0.0000",
      "total": "2.5000"
    }
  ],
  "updated_at": "2026-01-07T12:00:00Z"
}
```

#### Get Deposit Address

```http
POST /wallet/deposit-address
Authorization: Bearer <session-token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "currency": "BTC"
}
```

**Response:**

```json
{
  "currency": "BTC",
  "address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
  "qr_code": "data:image/png;base64,...",
  "expires_at": null,
  "minimum_deposit": "0.00001"
}
```

#### List Transactions

```http
GET /wallet/transactions?currency={currency}&type={type}&page={page}&limit={limit}
Authorization: Bearer <session-token>
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `currency` | string | No | Filter by currency |
| `type` | string | No | Filter: `deposit`, `withdrawal`, `payment`, `refund` |
| `page` | integer | No | Page number (default: 1) |
| `limit` | integer | No | Results per page (default: 20) |

**Response:**

```json
{
  "transactions": [
    {
      "id": "tx_abc123",
      "type": "deposit",
      "currency": "BTC",
      "amount": "0.05000",
      "status": "confirmed",
      "confirmations": 6,
      "transaction_id": "blockchain_txid...",
      "created_at": "2026-01-06T08:00:00Z"
    },
    {
      "id": "tx_def456",
      "type": "payment",
      "currency": "BTC",
      "amount": "-0.0102",
      "status": "completed",
      "order_id": "order_def456",
      "created_at": "2026-01-07T10:30:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 12,
    "pages": 1
  }
}
```

### Authentication

#### WebAuthn Registration (Begin)

```http
POST /auth/webauthn/register/begin
Content-Type: application/json
```

**Request Body:**

```json
{
  "username": "user@example.com"
}
```

**Response:**

```json
{
  "publicKey": {
    "challenge": "base64-challenge...",
    "rp": {
      "name": "DHT Gateway",
      "id": "gateway.example.com"
    },
    "user": {
      "id": "base64-user-id...",
      "name": "user@example.com",
      "displayName": "user@example.com"
    },
    "pubKeyCredParams": [
      {
        "type": "public-key",
        "alg": -7
      },
      {
        "type": "public-key",
        "alg": -257
      }
    ],
    "authenticatorSelection": {
      "authenticatorAttachment": "platform",
      "userVerification": "preferred"
    },
    "timeout": 60000,
    "attestation": "none"
  },
  "session_id": "reg_session_xyz..."
}
```

#### WebAuthn Registration (Finish)

```http
POST /auth/webauthn/register/finish
Content-Type: application/json
```

**Request Body:**

```json
{
  "session_id": "reg_session_xyz...",
  "credential": {
    "id": "credential-id...",
    "rawId": "base64-raw-id...",
    "response": {
      "attestationObject": "base64-attestation...",
      "clientDataJSON": "base64-client-data..."
    },
    "type": "public-key"
  }
}
```

**Response:**

```json
{
  "registered": true,
  "user_id": "user_abc123",
  "session_token": "eyJhbGciOiJFZDI1NTE5...",
  "expires_at": "2026-01-08T12:00:00Z"
}
```

#### WebAuthn Login (Begin)

```http
POST /auth/webauthn/login/begin
Content-Type: application/json
```

**Request Body:**

```json
{
  "username": "user@example.com"
}
```

**Response:**

```json
{
  "publicKey": {
    "challenge": "base64-challenge...",
    "rpId": "gateway.example.com",
    "allowCredentials": [
      {
        "type": "public-key",
        "id": "base64-credential-id..."
      }
    ],
    "userVerification": "preferred",
    "timeout": 60000
  },
  "session_id": "login_session_abc..."
}
```

#### WebAuthn Login (Finish)

```http
POST /auth/webauthn/login/finish
Content-Type: application/json
```

**Request Body:**

```json
{
  "session_id": "login_session_abc...",
  "credential": {
    "id": "credential-id...",
    "rawId": "base64-raw-id...",
    "response": {
      "authenticatorData": "base64-auth-data...",
      "clientDataJSON": "base64-client-data...",
      "signature": "base64-signature..."
    },
    "type": "public-key"
  }
}
```

**Response:**

```json
{
  "authenticated": true,
  "user_id": "user_abc123",
  "session_token": "eyJhbGciOiJFZDI1NTE5...",
  "expires_at": "2026-01-08T12:00:00Z"
}
```

#### Logout

```http
POST /auth/logout
Authorization: Bearer <session-token>
```

**Response:**

```json
{
  "logged_out": true
}
```

## WebSocket Endpoints

### Real-time Updates

```
wss://{gateway-node}:8443/gateway/v1/ws
```

WebSocket connections enable real-time updates for search results, order status, price changes, and wallet activity.

### Connection

```javascript
const ws = new WebSocket('wss://gateway.example.com:8443/gateway/v1/ws');

// For authenticated channels
ws.onopen = () => {
  ws.send(JSON.stringify({
    type: 'auth',
    token: 'session-token...'
  }));
};
```

### Message Format

All WebSocket messages use JSON format:

```json
{
  "type": "subscribe|unsubscribe|message|error|ping|pong",
  "channel": "channel-name",
  "data": {}
}
```

### Available Channels

#### Search Results (Public)

Subscribe to live search results as new items are discovered in the DHT:

```json
{
  "type": "subscribe",
  "channel": "search:abc123def456"
}
```

Where `abc123def456` is the SHA-256 hash of your search query.

**Incoming Messages:**

```json
{
  "type": "message",
  "channel": "search:abc123def456",
  "data": {
    "event": "new_result",
    "result": {
      "id": "QmNewProduct...",
      "type": "product",
      "title": "Newly Discovered Product"
    }
  }
}
```

#### Order Status (Authenticated)

```json
{
  "type": "subscribe",
  "channel": "order:order_def456"
}
```

**Incoming Messages:**

```json
{
  "type": "message",
  "channel": "order:order_def456",
  "data": {
    "event": "status_changed",
    "previous_status": "paid",
    "new_status": "shipped",
    "tracking": "TRACK123456",
    "timestamp": "2026-01-07T14:00:00Z"
  }
}
```

#### Product Updates (Public)

```json
{
  "type": "subscribe",
  "channel": "product:QmProduct..."
}
```

**Incoming Messages:**

```json
{
  "type": "message",
  "channel": "product:QmProduct...",
  "data": {
    "event": "price_changed",
    "old_price": {"amount": "0.006", "currency": "BTC"},
    "new_price": {"amount": "0.005", "currency": "BTC"},
    "timestamp": "2026-01-07T12:00:00Z"
  }
}
```

```json
{
  "type": "message",
  "channel": "product:QmProduct...",
  "data": {
    "event": "stock_changed",
    "available": true,
    "stock": 5,
    "timestamp": "2026-01-07T12:00:00Z"
  }
}
```

#### Wallet Updates (Authenticated)

```json
{
  "type": "subscribe",
  "channel": "wallet"
}
```

**Incoming Messages:**

```json
{
  "type": "message",
  "channel": "wallet",
  "data": {
    "event": "deposit_confirmed",
    "currency": "BTC",
    "amount": "0.05000",
    "confirmations": 6,
    "balance": {
      "available": "0.10234",
      "pending": "0.00000"
    }
  }
}
```

### Heartbeat

The server sends ping messages every 30 seconds. Clients must respond with pong:

```json
// Server sends
{"type": "ping", "timestamp": 1704628800}

// Client responds
{"type": "pong", "timestamp": 1704628800}
```

Connections are terminated after 90 seconds without a pong response.

### Error Messages

```json
{
  "type": "error",
  "code": "unauthorized",
  "message": "Authentication required for this channel"
}
```

## CORS Configuration

The Gateway API implements Cross-Origin Resource Sharing (CORS) to enable browser-based access.

### Allowed Origins

```
# Browser extensions
chrome-extension://*
moz-extension://*

# Configured domains (example)
https://app.example.com
https://*.trusted-domain.com
```

### Allowed Methods

```
GET, POST, DELETE, OPTIONS
```

### Allowed Headers

```
Authorization
Content-Type
X-Request-ID
X-Gateway-Version
```

### Exposed Headers

```
X-RateLimit-Limit
X-RateLimit-Remaining
X-RateLimit-Reset
```

### Preflight Cache

```
Access-Control-Max-Age: 86400
```

## Rate Limiting

Rate limits protect the gateway from abuse while ensuring fair access for all users.

### Limits by Authentication Status

| User Type | Requests/Minute | WebSocket Messages/Minute |
|-----------|-----------------|---------------------------|
| Anonymous | 30 | N/A |
| Authenticated | 100 | 50 per connection |

### Rate Limit Headers

All responses include rate limit information:

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1704628860
```

### Rate Limit Exceeded Response

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 30
Content-Type: application/json
```

```json
{
  "error": {
    "code": "rate_limit_exceeded",
    "message": "Rate limit exceeded. Please retry after 30 seconds.",
    "retry_after": 30
  }
}
```

## Security Considerations

### Transport Security

- **HTTPS Required**: All connections must use TLS 1.3
- **Certificate Pinning**: Extensions should pin gateway certificates
- **HSTS**: Strict-Transport-Security header with 1-year max-age

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### Content Security

```http
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
```

### Session Security

- Sessions bound to client fingerprint (User-Agent, origin)
- Automatic session invalidation on suspicious activity
- Maximum 5 concurrent sessions per user
- Session tokens use Ed25519 signatures

### Input Validation

- All inputs validated and sanitized
- Maximum request body size: 1MB
- Query string length limit: 2048 characters
- JSON depth limit: 10 levels

## Browser Extension Integration

### Manifest Permissions (Chrome)

```json
{
  "manifest_version": 3,
  "permissions": [
    "storage"
  ],
  "host_permissions": [
    "https://*.gateway.example.com/*"
  ],
  "content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'none'"
  }
}
```

### Manifest Permissions (Firefox)

```json
{
  "manifest_version": 2,
  "permissions": [
    "storage",
    "https://*.gateway.example.com/*"
  ],
  "content_security_policy": "script-src 'self'; object-src 'none'"
}
```

### Connection Establishment

```javascript
class GatewayClient {
  constructor(gatewayUrl) {
    this.baseUrl = gatewayUrl;
    this.sessionToken = null;
    this.ws = null;
  }

  async connect() {
    // Test gateway health
    const response = await fetch(`${this.baseUrl}/health`);
    if (!response.ok) {
      throw new Error('Gateway unavailable');
    }

    // Restore session from storage
    const stored = await browser.storage.local.get('sessionToken');
    if (stored.sessionToken) {
      this.sessionToken = stored.sessionToken;
      await this.validateSession();
    }
  }

  async validateSession() {
    const response = await fetch(`${this.baseUrl}/auth/session`, {
      headers: {
        'Authorization': `Bearer ${this.sessionToken}`
      }
    });

    if (!response.ok) {
      this.sessionToken = null;
      await browser.storage.local.remove('sessionToken');
    }
  }

  connectWebSocket() {
    this.ws = new WebSocket(`${this.baseUrl.replace('https', 'wss')}/ws`);

    this.ws.onopen = () => {
      if (this.sessionToken) {
        this.ws.send(JSON.stringify({
          type: 'auth',
          token: this.sessionToken
        }));
      }
    };

    this.ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      this.handleMessage(message);
    };
  }
}
```

### Gateway Discovery

Extensions can discover available gateway nodes through multiple methods:

#### DNS-Based Discovery

```javascript
async function discoverGateways() {
  // Query DNS seed
  const response = await fetch('https://seeds.dht.example.com/gateways');
  const { gateways } = await response.json();

  // Test latency to each gateway
  const results = await Promise.all(
    gateways.map(async (gateway) => {
      const start = Date.now();
      try {
        await fetch(`${gateway.url}/health`, {
          signal: AbortSignal.timeout(5000)
        });
        return { ...gateway, latency: Date.now() - start };
      } catch {
        return { ...gateway, latency: Infinity };
      }
    })
  );

  // Sort by latency
  return results
    .filter(g => g.latency < Infinity)
    .sort((a, b) => a.latency - b.latency);
}
```

#### Hardcoded Bootstrap List

```javascript
const BOOTSTRAP_GATEWAYS = [
  'https://gateway1.dht.example.com:8443',
  'https://gateway2.dht.example.com:8443',
  'https://gateway3.dht.example.com:8443'
];
```

#### Local Network Discovery

For advanced setups, extensions can discover local gateway nodes via mDNS:

```javascript
// Requires native messaging host
async function discoverLocalGateways() {
  const port = browser.runtime.connectNative('dht_discovery');

  return new Promise((resolve) => {
    port.onMessage.addListener((response) => {
      resolve(response.gateways);
    });

    port.postMessage({ action: 'discover_local' });
  });
}
```

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_request` | 400 | Malformed request body or parameters |
| `unauthorized` | 401 | Missing or invalid authentication |
| `forbidden` | 403 | Insufficient permissions |
| `not_found` | 404 | Resource not found |
| `rate_limit_exceeded` | 429 | Too many requests |
| `internal_error` | 500 | Server error |
| `service_unavailable` | 503 | Gateway temporarily unavailable |
| `dht_timeout` | 504 | DHT operation timed out |

### Error Response Format

```json
{
  "error": {
    "code": "not_found",
    "message": "Product not found",
    "details": {
      "product_id": "QmInvalidId..."
    },
    "request_id": "req_abc123"
  }
}
```

---

**Document Version:** 1.0
**Last Updated:** 2026-01-07
**API Version:** v1
