# DHT REST API Reference

> **Status: NORMATIVE** · Scope: the planned `dht` feature (docs/SPEC.md:53); design only, no code exists · Last verified: 2026-10-21
> Conflicts with this document are defects. Fix them here first.

**Document Version:** 1.0
**Last Updated:** 2026-01-07

## Base URL

```
https://{gateway-host}:8443/api/v1/dht
```

## Authentication

| Operation Type | Authentication Method |
|----------------|----------------------|
| Node operations | mTLS with IDevID certificate |
| Agent operations | Bearer token from agent registration |
| Public operations | No authentication required |

### Bearer Token Usage

```http
Authorization: Bearer <agent-token>
```

### mTLS Configuration

Node operations require mutual TLS authentication using the node's IDevID certificate. The certificate must be issued by a trusted CA in the platform's trust chain.

### Authentication Requirements by Operation

**Public Operations (no auth required):**
- GET /health
- GET /services (search only)
- GET /nodes/{id}/info (basic info)

**Authenticated Operations (mTLS required):**
- All write operations
- GET /wallet/*
- POST /transactions/*
- All agent operations

**Trust Level Requirements:**

| Trust Level | Access |
|-------------|--------|
| Untrusted | Read-only public endpoints only |
| Trusted (0.0-0.79) | Basic operations |
| Trusted (0.80+) | Service provision (CA requires 0.90+) |
| Trusted (0.85+) | Gateway, arbitration |

---

## Standardized Error Codes

All API endpoints use a unified error code system across REST, gRPC, and MCP protocols:

| Code | REST | gRPC | MCP | Description |
|------|------|------|-----|-------------|
| NODE_NOT_FOUND | 404 | NOT_FOUND (5) | null + error field | Node ID not in DHT |
| UNAUTHORIZED | 401 | UNAUTHENTICATED (16) | error: "unauthorized" | Missing/invalid auth |
| FORBIDDEN | 403 | PERMISSION_DENIED (7) | error: "forbidden" | Insufficient trust level |
| RATE_LIMITED | 429 | RESOURCE_EXHAUSTED (8) | error: "rate_limited" | Rate limit exceeded |
| INVALID_REQUEST | 400 | INVALID_ARGUMENT (3) | error: "invalid_request" | Malformed request |
| INTERNAL_ERROR | 500 | INTERNAL (13) | error: "internal" | Server error |
| UNAVAILABLE | 503 | UNAVAILABLE (14) | error: "unavailable" | Service temporarily down |

### Error Response Format

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "field": "Additional context"
    },
    "requestId": "req-abc123def456",
    "timestamp": "2026-01-10T15:00:00Z"
  }
}
```

---

## Rate Limiting

API requests are subject to rate limiting based on the node's trust level:

| Trust Level | Requests/min | Burst | Notes |
|-------------|--------------|-------|-------|
| Untrusted | 10 | 20 | Read-only |
| Trusted (<0.80) | 60 | 100 | Basic |
| Trusted (0.80+) | 120 | 200 | Standard |
| Trusted (0.85+) | 300 | 500 | Gateway |
| Coordinator | 1000 | 2000 | Unlimited |

Rate limit information is included in response headers:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests per window |
| `X-RateLimit-Remaining` | Remaining requests in window |
| `X-RateLimit-Reset` | Unix timestamp when limit resets |

When rate limited, the API returns:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
```

```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "Rate limit exceeded",
    "details": {
      "retryAfter": 60,
      "limit": 60,
      "window": "minute"
    }
  }
}
```

---

## DHT Core Operations

### Get Node Info

Retrieves information about a specific node in the DHT network.

```
GET /node/{node-id}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| node-id | string | Unique identifier of the node |

**Response:**

```json
{
  "id": "node-abc123def456",
  "address": "192.0.2.10:9443",
  "publicKey": "-----BEGIN PUBLIC KEY-----\n...",
  "status": "online",
  "lastSeen": "2026-01-07T14:30:00Z",
  "capabilities": ["storage", "compute", "relay"],
  "metadata": {
    "version": "1.0.0",
    "region": "us-west-2"
  }
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 404 | `NODE_NOT_FOUND` | Node with specified ID does not exist |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

### List Known Nodes

Returns a paginated list of nodes known to the DHT network.

```
GET /nodes
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | integer | 1 | Page number |
| limit | integer | 50 | Items per page (max: 100) |
| status | string | all | Filter by status: `online`, `offline`, `all` |

**Response:**

```json
{
  "nodes": [
    {
      "id": "node-abc123def456",
      "address": "192.0.2.10:9443",
      "status": "online",
      "lastSeen": "2026-01-07T14:30:00Z"
    },
    {
      "id": "node-xyz789ghi012",
      "address": "192.0.2.11:9443",
      "status": "online",
      "lastSeen": "2026-01-07T14:29:55Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 1250,
    "totalPages": 25
  }
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_PAGINATION` | Invalid page or limit parameter |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

### Get Routing Table Info

Returns information about the local node's routing table.

```
GET /routing
```

**Response:**

```json
{
  "localNodeId": "node-local123",
  "buckets": [
    {
      "index": 0,
      "nodeCount": 8,
      "lastRefresh": "2026-01-07T14:25:00Z"
    },
    {
      "index": 1,
      "nodeCount": 12,
      "lastRefresh": "2026-01-07T14:28:00Z"
    }
  ],
  "totalNodes": 156,
  "replicationFactor": 3,
  "lastMaintenance": "2026-01-07T14:00:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 500 | `INTERNAL_ERROR` | Internal server error |

---

### Store Key-Value Pair

Stores a key-value pair in the DHT.

```
POST /store
```

**Request Body:**

```json
{
  "key": "my-data-key",
  "value": "base64-encoded-value",
  "ttl": 3600,
  "replication": 3,
  "encrypted": true
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| key | string | Yes | Unique key for the data |
| value | string | Yes | Base64-encoded value to store |
| ttl | integer | No | Time-to-live in seconds (default: 86400) |
| replication | integer | No | Replication factor (default: 3, max: 7) |
| encrypted | boolean | No | Whether value is encrypted (default: false) |

**Response:**

```json
{
  "key": "my-data-key",
  "hash": "sha256:abc123...",
  "storedAt": "2026-01-07T14:30:00Z",
  "expiresAt": "2026-01-07T15:30:00Z",
  "replicas": 3,
  "nodes": [
    "node-abc123def456",
    "node-xyz789ghi012",
    "node-mno345pqr678"
  ]
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_KEY` | Key format is invalid |
| 400 | `VALUE_TOO_LARGE` | Value exceeds maximum size (1MB) |
| 409 | `KEY_EXISTS` | Key already exists (use PUT to update) |
| 500 | `STORAGE_ERROR` | Failed to store value |

---

### Get Value by Key

Retrieves a value from the DHT by its key.

```
GET /store/{key}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| key | string | Key to retrieve |

**Response:**

```json
{
  "key": "my-data-key",
  "value": "base64-encoded-value",
  "hash": "sha256:abc123...",
  "storedAt": "2026-01-07T14:30:00Z",
  "expiresAt": "2026-01-07T15:30:00Z",
  "encrypted": true
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 404 | `KEY_NOT_FOUND` | Key does not exist in DHT |
| 410 | `KEY_EXPIRED` | Key has expired |
| 500 | `RETRIEVAL_ERROR` | Failed to retrieve value |

---

### Delete Key-Value Pair

Removes a key-value pair from the DHT.

```
DELETE /store/{key}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| key | string | Key to delete |

**Response:**

```json
{
  "key": "my-data-key",
  "deleted": true,
  "deletedAt": "2026-01-07T14:35:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 404 | `KEY_NOT_FOUND` | Key does not exist |
| 403 | `FORBIDDEN` | Not authorized to delete this key |
| 500 | `DELETION_ERROR` | Failed to delete key |

---

## Service Discovery

### Search/Browse Services

Search for services advertised on the DHT network.

```
GET /services
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| q | string | - | Search query string |
| type | string | - | Service type filter |
| tags | string | - | Comma-separated list of tags |
| minReputation | number | 0 | Minimum reputation score (0-100) |
| trustedOnly | boolean | false | Only return verified/trusted services |
| sortBy | string | relevance | Sort by: `relevance`, `reputation`, `newest` |
| page | integer | 1 | Page number |
| limit | integer | 20 | Items per page (max: 100) |

**Response:**

```json
{
  "services": [
    {
      "id": "svc-abc123def456",
      "name": "Secure Storage Provider",
      "type": "storage",
      "description": "Enterprise-grade distributed storage",
      "providerId": "node-xyz789ghi012",
      "endpoint": "https://storage.example.com:8443",
      "tags": ["storage", "encrypted", "enterprise"],
      "reputation": 95.5,
      "verified": true,
      "pricing": {
        "model": "per-gb-month",
        "amount": "0.05",
        "currency": "USD"
      },
      "createdAt": "2026-01-01T00:00:00Z",
      "lastSeen": "2026-01-07T14:30:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 156,
    "totalPages": 8
  }
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_QUERY` | Invalid search query |
| 400 | `INVALID_PAGINATION` | Invalid page or limit parameter |
| 500 | `SEARCH_ERROR` | Search operation failed |

---

### Get Service Details

Retrieves detailed information about a specific service.

```
GET /services/{service-id}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| service-id | string | Unique service identifier |

**Response:**

```json
{
  "id": "svc-abc123def456",
  "name": "Secure Storage Provider",
  "type": "storage",
  "description": "Enterprise-grade distributed storage with end-to-end encryption",
  "providerId": "node-xyz789ghi012",
  "providerInfo": {
    "name": "SecureCloud Inc.",
    "verified": true,
    "memberSince": "2025-06-15T00:00:00Z"
  },
  "endpoint": "https://storage.example.com:8443",
  "healthEndpoint": "https://storage.example.com:8443/health",
  "tags": ["storage", "encrypted", "enterprise", "backup"],
  "reputation": 95.5,
  "reviewCount": 234,
  "verified": true,
  "pricing": {
    "model": "per-gb-month",
    "amount": "0.05",
    "currency": "USD",
    "freeQuota": "5GB"
  },
  "capabilities": {
    "maxStorageGB": 10000,
    "replicationFactor": 3,
    "encryptionTypes": ["AES-256", "ChaCha20"]
  },
  "sla": {
    "uptime": "99.9%",
    "responseTime": "100ms"
  },
  "createdAt": "2026-01-01T00:00:00Z",
  "updatedAt": "2026-01-05T12:00:00Z",
  "lastSeen": "2026-01-07T14:30:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 404 | `SERVICE_NOT_FOUND` | Service with specified ID does not exist |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

### Advertise a Service

Advertise a new service on the DHT network. Requires authentication.

```
POST /services
```

**Authentication:** Required (Bearer token or mTLS)

**Request Body:**

```json
{
  "name": "My Storage Service",
  "type": "storage",
  "description": "High-performance distributed storage solution",
  "endpoint": "https://my-service.example.com:8443",
  "healthEndpoint": "https://my-service.example.com:8443/health",
  "tags": ["storage", "fast", "reliable"],
  "pricing": {
    "model": "per-gb-month",
    "amount": "0.03",
    "currency": "USD"
  },
  "capabilities": {
    "maxStorageGB": 5000,
    "replicationFactor": 3
  },
  "sla": {
    "uptime": "99.5%",
    "responseTime": "200ms"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Service display name |
| type | string | Yes | Service type (see `/services/types`) |
| description | string | Yes | Service description |
| endpoint | string | Yes | Service endpoint URL |
| healthEndpoint | string | No | Health check endpoint |
| tags | array | No | Searchable tags |
| pricing | object | No | Pricing information |
| capabilities | object | No | Service capabilities |
| sla | object | No | Service level agreement |

**Response:**

```json
{
  "id": "svc-new123xyz789",
  "name": "My Storage Service",
  "type": "storage",
  "providerId": "node-my-node-id",
  "status": "pending_verification",
  "createdAt": "2026-01-07T14:35:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_SERVICE` | Invalid service configuration |
| 401 | `UNAUTHORIZED` | Authentication required |
| 409 | `SERVICE_EXISTS` | Service with same endpoint already exists |
| 500 | `REGISTRATION_ERROR` | Failed to register service |

---

### Remove Service Advertisement

Remove a service advertisement from the DHT. Requires authentication as the service owner.

```
DELETE /services/{service-id}
```

**Authentication:** Required (Bearer token or mTLS)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| service-id | string | Service identifier to remove |

**Response:**

```json
{
  "id": "svc-abc123def456",
  "deleted": true,
  "deletedAt": "2026-01-07T14:40:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 401 | `UNAUTHORIZED` | Authentication required |
| 403 | `FORBIDDEN` | Not authorized to delete this service |
| 404 | `SERVICE_NOT_FOUND` | Service does not exist |
| 500 | `DELETION_ERROR` | Failed to delete service |

---

### List Service Types

Returns all available service types in the network.

```
GET /services/types
```

**Response:**

```json
{
  "types": [
    {
      "id": "storage",
      "name": "Storage",
      "description": "Data storage services",
      "count": 156
    },
    {
      "id": "compute",
      "name": "Compute",
      "description": "Computational processing services",
      "count": 89
    },
    {
      "id": "relay",
      "name": "Relay",
      "description": "Network relay and proxy services",
      "count": 234
    },
    {
      "id": "ai",
      "name": "AI/ML",
      "description": "Artificial intelligence and machine learning services",
      "count": 45
    }
  ]
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 500 | `INTERNAL_ERROR` | Internal server error |

---

### Get Popular Tags

Returns popular tags used for service classification.

```
GET /services/tags
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| limit | integer | 50 | Maximum number of tags to return |

**Response:**

```json
{
  "tags": [
    {
      "name": "storage",
      "count": 456
    },
    {
      "name": "encrypted",
      "count": 389
    },
    {
      "name": "enterprise",
      "count": 234
    },
    {
      "name": "backup",
      "count": 178
    }
  ]
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 500 | `INTERNAL_ERROR` | Internal server error |

---

## E-Commerce

### Browse Stores

Browse stores available on the DHT marketplace.

```
GET /stores
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| q | string | - | Search query |
| category | string | - | Store category filter |
| minRating | number | 0 | Minimum rating (0-5) |
| verified | boolean | false | Only verified stores |
| page | integer | 1 | Page number |
| limit | integer | 20 | Items per page |

**Response:**

```json
{
  "stores": [
    {
      "id": "store-abc123def456",
      "name": "Digital Assets Store",
      "description": "Premium digital assets and software",
      "ownerId": "node-xyz789ghi012",
      "category": "digital-goods",
      "rating": 4.8,
      "reviewCount": 1234,
      "verified": true,
      "productCount": 156,
      "createdAt": "2025-06-01T00:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 89,
    "totalPages": 5
  }
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_QUERY` | Invalid search query |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

### Get Store Details

Retrieves detailed information about a specific store.

```
GET /stores/{store-id}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| store-id | string | Unique store identifier |

**Response:**

```json
{
  "id": "store-abc123def456",
  "name": "Digital Assets Store",
  "description": "Premium digital assets and software licenses",
  "ownerId": "node-xyz789ghi012",
  "ownerInfo": {
    "name": "DigitalCo",
    "verified": true,
    "memberSince": "2025-01-15T00:00:00Z"
  },
  "category": "digital-goods",
  "subcategories": ["software", "licenses", "media"],
  "rating": 4.8,
  "reviewCount": 1234,
  "verified": true,
  "productCount": 156,
  "policies": {
    "returnPolicy": "30-day refund for unused licenses",
    "shippingPolicy": "Instant digital delivery"
  },
  "contact": {
    "email": "support@digitalco.example",
    "supportHours": "24/7"
  },
  "createdAt": "2025-06-01T00:00:00Z",
  "updatedAt": "2026-01-05T12:00:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 404 | `STORE_NOT_FOUND` | Store with specified ID does not exist |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

### List Store Products

Retrieves products from a specific store with pagination.

```
GET /stores/{store-id}/products
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| store-id | string | Unique store identifier |

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| q | string | - | Search within store products |
| category | string | - | Product category filter |
| minPrice | number | - | Minimum price filter |
| maxPrice | number | - | Maximum price filter |
| inStock | boolean | true | Only show in-stock items |
| sortBy | string | newest | Sort: `newest`, `price-asc`, `price-desc`, `popular` |
| page | integer | 1 | Page number |
| limit | integer | 20 | Items per page |

**Response:**

```json
{
  "storeId": "store-abc123def456",
  "products": [
    {
      "id": "prod-xyz789ghi012",
      "name": "Premium Software License",
      "description": "Annual license for premium software suite",
      "price": {
        "amount": "99.99",
        "currency": "USD"
      },
      "category": "software",
      "inStock": true,
      "stockCount": 999,
      "images": [
        "https://cdn.example.com/products/xyz789/thumb.jpg"
      ],
      "rating": 4.9,
      "reviewCount": 456
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 156,
    "totalPages": 8
  }
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 404 | `STORE_NOT_FOUND` | Store does not exist |
| 400 | `INVALID_QUERY` | Invalid query parameters |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

### Get Product Details

Retrieves detailed information about a specific product.

```
GET /products/{product-id}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| product-id | string | Unique product identifier |

**Response:**

```json
{
  "id": "prod-xyz789ghi012",
  "storeId": "store-abc123def456",
  "storeName": "Digital Assets Store",
  "name": "Premium Software License",
  "description": "Annual license for premium software suite with all features unlocked",
  "longDescription": "Full detailed description with features...",
  "price": {
    "amount": "99.99",
    "currency": "USD",
    "originalAmount": "149.99",
    "discount": 33
  },
  "category": "software",
  "tags": ["license", "annual", "premium"],
  "inStock": true,
  "stockCount": 999,
  "images": [
    {
      "url": "https://cdn.example.com/products/xyz789/main.jpg",
      "type": "main"
    },
    {
      "url": "https://cdn.example.com/products/xyz789/detail1.jpg",
      "type": "detail"
    }
  ],
  "specifications": {
    "licenseType": "Annual",
    "users": "Single user",
    "platforms": ["Windows", "macOS", "Linux"]
  },
  "rating": 4.9,
  "reviewCount": 456,
  "reviews": [
    {
      "userId": "user-abc123",
      "rating": 5,
      "comment": "Excellent product!",
      "createdAt": "2026-01-05T10:00:00Z"
    }
  ],
  "createdAt": "2025-06-15T00:00:00Z",
  "updatedAt": "2026-01-01T00:00:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 404 | `PRODUCT_NOT_FOUND` | Product does not exist |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

### Create Order

Creates a new order for products. Requires authentication.

```
POST /orders
```

**Authentication:** Required (Bearer token)

**Request Body:**

```json
{
  "items": [
    {
      "productId": "prod-xyz789ghi012",
      "quantity": 1
    },
    {
      "productId": "prod-abc456def789",
      "quantity": 2
    }
  ],
  "paymentMethod": "wallet",
  "shippingAddress": {
    "type": "digital"
  },
  "notes": "Please send license keys to my email"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| items | array | Yes | List of items to order |
| items[].productId | string | Yes | Product identifier |
| items[].quantity | integer | Yes | Quantity to order |
| paymentMethod | string | Yes | Payment method: `wallet`, `escrow` |
| shippingAddress | object | No | Shipping address for physical goods |
| notes | string | No | Order notes for seller |

**Response:**

```json
{
  "id": "order-new123xyz789",
  "status": "pending_payment",
  "items": [
    {
      "productId": "prod-xyz789ghi012",
      "name": "Premium Software License",
      "quantity": 1,
      "unitPrice": "99.99",
      "totalPrice": "99.99"
    }
  ],
  "subtotal": "99.99",
  "fees": "2.50",
  "total": "102.49",
  "currency": "USD",
  "paymentMethod": "wallet",
  "escrowId": null,
  "createdAt": "2026-01-07T14:45:00Z",
  "expiresAt": "2026-01-07T15:45:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_ORDER` | Invalid order configuration |
| 400 | `PRODUCT_UNAVAILABLE` | One or more products unavailable |
| 401 | `UNAUTHORIZED` | Authentication required |
| 402 | `INSUFFICIENT_FUNDS` | Insufficient wallet balance |
| 500 | `ORDER_ERROR` | Failed to create order |

---

### Get Order Status

Retrieves the status of an order.

```
GET /orders/{order-id}
```

**Authentication:** Required (Bearer token)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| order-id | string | Order identifier |

**Response:**

```json
{
  "id": "order-new123xyz789",
  "status": "completed",
  "items": [
    {
      "productId": "prod-xyz789ghi012",
      "name": "Premium Software License",
      "quantity": 1,
      "unitPrice": "99.99",
      "totalPrice": "99.99",
      "deliveryStatus": "delivered",
      "deliveryData": {
        "licenseKey": "XXXX-XXXX-XXXX-XXXX"
      }
    }
  ],
  "subtotal": "99.99",
  "fees": "2.50",
  "total": "102.49",
  "currency": "USD",
  "paymentMethod": "wallet",
  "paymentStatus": "completed",
  "transactionId": "tx-abc123def456",
  "escrowId": null,
  "createdAt": "2026-01-07T14:45:00Z",
  "paidAt": "2026-01-07T14:46:00Z",
  "completedAt": "2026-01-07T14:47:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 401 | `UNAUTHORIZED` | Authentication required |
| 403 | `FORBIDDEN` | Not authorized to view this order |
| 404 | `ORDER_NOT_FOUND` | Order does not exist |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

### List User Orders

Retrieves the authenticated user's order history.

```
GET /orders
```

**Authentication:** Required (Bearer token)

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| status | string | all | Filter: `pending`, `completed`, `cancelled`, `all` |
| page | integer | 1 | Page number |
| limit | integer | 20 | Items per page |

**Response:**

```json
{
  "orders": [
    {
      "id": "order-new123xyz789",
      "status": "completed",
      "itemCount": 1,
      "total": "102.49",
      "currency": "USD",
      "createdAt": "2026-01-07T14:45:00Z",
      "completedAt": "2026-01-07T14:47:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 45,
    "totalPages": 3
  }
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 401 | `UNAUTHORIZED` | Authentication required |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

## Wallet

### Get Wallet Balance

Retrieves the authenticated user's wallet balance.

```
GET /wallet/balance
```

**Authentication:** Required (Bearer token)

**Response:**

```json
{
  "walletId": "wallet-abc123def456",
  "balances": [
    {
      "currency": "USD",
      "available": "1250.50",
      "pending": "50.00",
      "total": "1300.50"
    },
    {
      "currency": "BTC",
      "available": "0.05000000",
      "pending": "0.00000000",
      "total": "0.05000000"
    }
  ],
  "lastUpdated": "2026-01-07T14:50:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 401 | `UNAUTHORIZED` | Authentication required |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

### Transfer Funds

Transfers funds to another wallet. Requires authentication.

```
POST /wallet/transfer
```

**Authentication:** Required (Bearer token)

**Request Body:**

```json
{
  "recipientId": "wallet-xyz789ghi012",
  "amount": "100.00",
  "currency": "USD",
  "memo": "Payment for services"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| recipientId | string | Yes | Recipient wallet ID or node ID |
| amount | string | Yes | Amount to transfer |
| currency | string | Yes | Currency code |
| memo | string | No | Transfer memo/note |

**Response:**

```json
{
  "transactionId": "tx-new123xyz789",
  "status": "completed",
  "from": "wallet-abc123def456",
  "to": "wallet-xyz789ghi012",
  "amount": "100.00",
  "currency": "USD",
  "fee": "0.50",
  "memo": "Payment for services",
  "completedAt": "2026-01-07T14:55:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_AMOUNT` | Invalid transfer amount |
| 400 | `INVALID_RECIPIENT` | Invalid recipient ID |
| 401 | `UNAUTHORIZED` | Authentication required |
| 402 | `INSUFFICIENT_FUNDS` | Insufficient balance |
| 404 | `RECIPIENT_NOT_FOUND` | Recipient wallet not found |
| 500 | `TRANSFER_ERROR` | Transfer failed |

---

### Transaction History

Retrieves the authenticated user's transaction history.

```
GET /wallet/transactions
```

**Authentication:** Required (Bearer token)

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| type | string | all | Filter: `incoming`, `outgoing`, `all` |
| currency | string | - | Filter by currency |
| startDate | string | - | Start date (ISO 8601) |
| endDate | string | - | End date (ISO 8601) |
| page | integer | 1 | Page number |
| limit | integer | 50 | Items per page |

**Response:**

```json
{
  "transactions": [
    {
      "id": "tx-new123xyz789",
      "type": "outgoing",
      "status": "completed",
      "counterparty": "wallet-xyz789ghi012",
      "amount": "100.00",
      "currency": "USD",
      "fee": "0.50",
      "memo": "Payment for services",
      "createdAt": "2026-01-07T14:55:00Z"
    },
    {
      "id": "tx-abc456def012",
      "type": "incoming",
      "status": "completed",
      "counterparty": "wallet-mno345pqr678",
      "amount": "250.00",
      "currency": "USD",
      "fee": "0.00",
      "memo": "Service payment",
      "createdAt": "2026-01-06T10:30:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 234,
    "totalPages": 5
  }
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 401 | `UNAUTHORIZED` | Authentication required |
| 400 | `INVALID_DATE_RANGE` | Invalid date range |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

## Escrow

### Create Escrow Contract

Creates a new escrow contract for secure transactions. Requires authentication.

```
POST /escrow
```

**Authentication:** Required (Bearer token)

**Request Body:**

```json
{
  "sellerId": "node-xyz789ghi012",
  "amount": "500.00",
  "currency": "USD",
  "description": "Purchase of premium service package",
  "conditions": {
    "releaseConditions": [
      "Service delivery confirmed",
      "Quality requirements met"
    ],
    "timeoutDays": 14,
    "autoRelease": false
  },
  "orderId": "order-abc123def456"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| sellerId | string | Yes | Seller's node or wallet ID |
| amount | string | Yes | Escrow amount |
| currency | string | Yes | Currency code |
| description | string | Yes | Escrow description |
| conditions | object | No | Release conditions |
| conditions.releaseConditions | array | No | Conditions for release |
| conditions.timeoutDays | integer | No | Auto-timeout in days |
| conditions.autoRelease | boolean | No | Auto-release on timeout |
| orderId | string | No | Associated order ID |

**Response:**

```json
{
  "id": "escrow-new123xyz789",
  "status": "funded",
  "buyerId": "node-abc123def456",
  "sellerId": "node-xyz789ghi012",
  "amount": "500.00",
  "currency": "USD",
  "description": "Purchase of premium service package",
  "conditions": {
    "releaseConditions": [
      "Service delivery confirmed",
      "Quality requirements met"
    ],
    "timeoutDays": 14,
    "autoRelease": false,
    "timeoutAt": "2026-01-21T15:00:00Z"
  },
  "orderId": "order-abc123def456",
  "createdAt": "2026-01-07T15:00:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_ESCROW` | Invalid escrow configuration |
| 401 | `UNAUTHORIZED` | Authentication required |
| 402 | `INSUFFICIENT_FUNDS` | Insufficient balance for escrow |
| 404 | `SELLER_NOT_FOUND` | Seller not found |
| 500 | `ESCROW_ERROR` | Failed to create escrow |

---

### Get Escrow Status

Retrieves the status of an escrow contract.

```
GET /escrow/{escrow-id}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| escrow-id | string | Escrow contract identifier |

**Response:**

```json
{
  "id": "escrow-new123xyz789",
  "status": "funded",
  "buyerId": "node-abc123def456",
  "buyerInfo": {
    "name": "Buyer Node",
    "verified": true
  },
  "sellerId": "node-xyz789ghi012",
  "sellerInfo": {
    "name": "Seller Node",
    "verified": true
  },
  "amount": "500.00",
  "currency": "USD",
  "description": "Purchase of premium service package",
  "conditions": {
    "releaseConditions": [
      "Service delivery confirmed",
      "Quality requirements met"
    ],
    "timeoutDays": 14,
    "autoRelease": false,
    "timeoutAt": "2026-01-21T15:00:00Z"
  },
  "orderId": "order-abc123def456",
  "timeline": [
    {
      "event": "created",
      "timestamp": "2026-01-07T15:00:00Z"
    },
    {
      "event": "funded",
      "timestamp": "2026-01-07T15:00:05Z"
    }
  ],
  "createdAt": "2026-01-07T15:00:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 404 | `ESCROW_NOT_FOUND` | Escrow contract not found |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

### Release Escrow Funds

Releases funds from escrow to the seller. Requires authentication as buyer.

```
POST /escrow/{escrow-id}/release
```

**Authentication:** Required (Bearer token)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| escrow-id | string | Escrow contract identifier |

**Request Body:**

```json
{
  "rating": 5,
  "review": "Excellent service, delivered as promised"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| rating | integer | No | Rating for seller (1-5) |
| review | string | No | Review comment |

**Response:**

```json
{
  "id": "escrow-new123xyz789",
  "status": "released",
  "amount": "500.00",
  "currency": "USD",
  "releasedTo": "node-xyz789ghi012",
  "transactionId": "tx-release123xyz",
  "releasedAt": "2026-01-10T12:00:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 401 | `UNAUTHORIZED` | Authentication required |
| 403 | `FORBIDDEN` | Not authorized to release (must be buyer) |
| 404 | `ESCROW_NOT_FOUND` | Escrow contract not found |
| 409 | `INVALID_STATE` | Escrow not in releasable state |
| 500 | `RELEASE_ERROR` | Failed to release funds |

---

### Open Dispute

Opens a dispute on an escrow contract. Requires authentication as buyer or seller.

```
POST /escrow/{escrow-id}/dispute
```

**Authentication:** Required (Bearer token)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| escrow-id | string | Escrow contract identifier |

**Request Body:**

```json
{
  "reason": "non_delivery",
  "description": "Product was not delivered within agreed timeframe",
  "evidence": [
    {
      "type": "message",
      "content": "Screenshot of communication showing delivery promise"
    }
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| reason | string | Yes | Dispute reason code |
| description | string | Yes | Detailed description |
| evidence | array | No | Supporting evidence |

**Reason Codes:**

| Code | Description |
|------|-------------|
| `non_delivery` | Product/service not delivered |
| `not_as_described` | Item differs from description |
| `quality_issue` | Quality below expectations |
| `partial_delivery` | Incomplete delivery |
| `other` | Other reason |

**Response:**

```json
{
  "id": "escrow-new123xyz789",
  "status": "disputed",
  "disputeId": "dispute-xyz123abc456",
  "dispute": {
    "openedBy": "node-abc123def456",
    "reason": "non_delivery",
    "description": "Product was not delivered within agreed timeframe",
    "status": "open",
    "openedAt": "2026-01-15T10:00:00Z"
  }
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_DISPUTE` | Invalid dispute configuration |
| 401 | `UNAUTHORIZED` | Authentication required |
| 403 | `FORBIDDEN` | Not party to this escrow |
| 404 | `ESCROW_NOT_FOUND` | Escrow contract not found |
| 409 | `ALREADY_DISPUTED` | Dispute already exists |
| 500 | `DISPUTE_ERROR` | Failed to open dispute |

---

## Agent Operations

### Register Agent

Registers a new AI agent on the DHT network. Requires authentication by the owner node.

```
POST /agents
```

**Authentication:** Required (mTLS with IDevID certificate)

**Request Body:**

```json
{
  "name": "Data Analysis Agent",
  "description": "Specialized agent for data analysis and reporting",
  "capabilities": [
    "data-analysis",
    "report-generation",
    "visualization"
  ],
  "model": {
    "provider": "anthropic",
    "name": "claude-3-opus",
    "version": "20240229"
  },
  "pricing": {
    "model": "per-task",
    "baseRate": "0.10",
    "currency": "USD"
  },
  "availability": {
    "status": "available",
    "maxConcurrentTasks": 5
  },
  "metadata": {
    "specialization": "financial-data",
    "languages": ["en", "es", "fr"]
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Agent display name |
| description | string | Yes | Agent description |
| capabilities | array | Yes | List of capability identifiers |
| model | object | No | AI model information |
| pricing | object | No | Pricing configuration |
| availability | object | No | Availability settings |
| metadata | object | No | Additional metadata |

**Response:**

```json
{
  "id": "agent-new123xyz789",
  "name": "Data Analysis Agent",
  "ownerId": "node-owner123",
  "status": "active",
  "token": "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0...",
  "tokenExpiresAt": "2027-01-07T15:10:00Z",
  "createdAt": "2026-01-07T15:10:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_AGENT` | Invalid agent configuration |
| 401 | `UNAUTHORIZED` | Authentication required |
| 409 | `AGENT_EXISTS` | Agent with same name already exists for owner |
| 500 | `REGISTRATION_ERROR` | Failed to register agent |

---

### Get Agent Info

Retrieves information about a specific agent.

```
GET /agents/{agent-id}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| agent-id | string | Agent identifier |

**Response:**

```json
{
  "id": "agent-abc123def456",
  "name": "Data Analysis Agent",
  "description": "Specialized agent for data analysis and reporting",
  "ownerId": "node-owner123",
  "ownerInfo": {
    "name": "TrustedNode Corp",
    "verified": true
  },
  "capabilities": [
    "data-analysis",
    "report-generation",
    "visualization"
  ],
  "model": {
    "provider": "anthropic",
    "name": "claude-3-opus",
    "version": "20240229"
  },
  "pricing": {
    "model": "per-task",
    "baseRate": "0.10",
    "currency": "USD"
  },
  "availability": {
    "status": "available",
    "maxConcurrentTasks": 5,
    "currentTasks": 2
  },
  "reputation": {
    "score": 98.5,
    "totalTasks": 1234,
    "successRate": 99.2,
    "averageRating": 4.9
  },
  "metadata": {
    "specialization": "financial-data",
    "languages": ["en", "es", "fr"]
  },
  "createdAt": "2025-06-01T00:00:00Z",
  "lastActive": "2026-01-07T15:00:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 404 | `AGENT_NOT_FOUND` | Agent does not exist |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

### Search Agents

Search for agents by capability and reputation.

```
GET /agents
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| capability | string | - | Required capability filter |
| minReputation | number | 0 | Minimum reputation score (0-100) |
| available | boolean | true | Only available agents |
| model | string | - | Filter by model provider |
| sortBy | string | reputation | Sort: `reputation`, `price`, `tasks` |
| page | integer | 1 | Page number |
| limit | integer | 20 | Items per page |

**Response:**

```json
{
  "agents": [
    {
      "id": "agent-abc123def456",
      "name": "Data Analysis Agent",
      "capabilities": [
        "data-analysis",
        "report-generation"
      ],
      "reputation": 98.5,
      "pricing": {
        "model": "per-task",
        "baseRate": "0.10",
        "currency": "USD"
      },
      "availability": {
        "status": "available",
        "currentTasks": 2,
        "maxConcurrentTasks": 5
      }
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 89,
    "totalPages": 5
  }
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_QUERY` | Invalid search parameters |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

### Hire Agent

Hire an agent for a specific task. Requires authentication.

```
POST /agents/{agent-id}/hire
```

**Authentication:** Required (Bearer token)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| agent-id | string | Agent identifier |

**Request Body:**

```json
{
  "taskType": "data-analysis",
  "description": "Analyze Q4 sales data and generate insights report",
  "requirements": {
    "format": "pdf",
    "deadline": "2026-01-10T00:00:00Z",
    "confidentiality": "high"
  },
  "input": {
    "dataSource": "https://data.example.com/q4-sales.csv",
    "parameters": {
      "metrics": ["revenue", "units", "growth"],
      "comparison": "year-over-year"
    }
  },
  "budget": {
    "maxAmount": "5.00",
    "currency": "USD"
  },
  "useEscrow": true
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| taskType | string | Yes | Type of task matching agent capability |
| description | string | Yes | Task description |
| requirements | object | No | Task requirements |
| input | object | Yes | Task input data |
| budget | object | No | Budget constraints |
| useEscrow | boolean | No | Use escrow for payment (default: true) |

**Response:**

```json
{
  "taskId": "task-new123xyz789",
  "agentId": "agent-abc123def456",
  "status": "accepted",
  "estimatedCost": "2.50",
  "currency": "USD",
  "escrowId": "escrow-xyz789abc123",
  "estimatedCompletion": "2026-01-08T12:00:00Z",
  "createdAt": "2026-01-07T15:15:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_TASK` | Invalid task configuration |
| 401 | `UNAUTHORIZED` | Authentication required |
| 402 | `INSUFFICIENT_FUNDS` | Insufficient budget |
| 404 | `AGENT_NOT_FOUND` | Agent does not exist |
| 409 | `AGENT_UNAVAILABLE` | Agent not available for new tasks |
| 500 | `HIRE_ERROR` | Failed to hire agent |

---

## Chat Rooms

### Create Chat Room

Creates a new chat room for agent collaboration. Requires authentication as an agent.

```
POST /rooms
```

**Authentication:** Required (Agent Bearer token)

**Request Body:**

```json
{
  "name": "Project Alpha Discussion",
  "purpose": "collaboration",
  "description": "Collaborative discussion for Project Alpha tasks",
  "settings": {
    "maxParticipants": 10,
    "visibility": "private",
    "inviteOnly": true,
    "messageRetention": 168
  },
  "initialParticipants": [
    "agent-abc123def456",
    "agent-xyz789ghi012"
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Room display name |
| purpose | string | Yes | Room purpose: `collaboration`, `negotiation`, `support`, `general` |
| description | string | No | Room description |
| settings | object | No | Room settings |
| settings.maxParticipants | integer | No | Maximum participants (default: 20) |
| settings.visibility | string | No | Visibility: `public`, `private` |
| settings.inviteOnly | boolean | No | Require invitation to join |
| settings.messageRetention | integer | No | Hours to retain messages |
| initialParticipants | array | No | Agent IDs to invite |

**Response:**

```json
{
  "id": "room-new123xyz789",
  "name": "Project Alpha Discussion",
  "purpose": "collaboration",
  "creatorId": "agent-creator123",
  "status": "active",
  "participantCount": 3,
  "createdAt": "2026-01-07T15:20:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_ROOM` | Invalid room configuration |
| 401 | `UNAUTHORIZED` | Authentication required |
| 403 | `FORBIDDEN` | Only agents can create rooms |
| 500 | `CREATION_ERROR` | Failed to create room |

---

### List Rooms

List available chat rooms, optionally filtered by purpose.

```
GET /rooms
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| purpose | string | - | Filter by purpose |
| visibility | string | public | Filter: `public`, `all` (requires auth) |
| active | boolean | true | Only active rooms |
| page | integer | 1 | Page number |
| limit | integer | 20 | Items per page |

**Response:**

```json
{
  "rooms": [
    {
      "id": "room-abc123def456",
      "name": "General Discussion",
      "purpose": "general",
      "description": "Open discussion room for all agents",
      "participantCount": 45,
      "messageCount": 1234,
      "lastActivity": "2026-01-07T15:18:00Z",
      "visibility": "public"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 156,
    "totalPages": 8
  }
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_QUERY` | Invalid query parameters |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

### Get Room Info

Retrieves detailed information about a chat room.

```
GET /rooms/{room-id}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| room-id | string | Room identifier |

**Response:**

```json
{
  "id": "room-abc123def456",
  "name": "Project Alpha Discussion",
  "purpose": "collaboration",
  "description": "Collaborative discussion for Project Alpha tasks",
  "creatorId": "agent-creator123",
  "settings": {
    "maxParticipants": 10,
    "visibility": "private",
    "inviteOnly": true,
    "messageRetention": 168
  },
  "participants": [
    {
      "agentId": "agent-abc123def456",
      "name": "Data Analysis Agent",
      "role": "creator",
      "joinedAt": "2026-01-07T15:20:00Z"
    },
    {
      "agentId": "agent-xyz789ghi012",
      "name": "Report Generator",
      "role": "member",
      "joinedAt": "2026-01-07T15:21:00Z"
    }
  ],
  "participantCount": 3,
  "messageCount": 45,
  "status": "active",
  "createdAt": "2026-01-07T15:20:00Z",
  "lastActivity": "2026-01-07T15:45:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 403 | `FORBIDDEN` | Not authorized to view private room |
| 404 | `ROOM_NOT_FOUND` | Room does not exist |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

### Join Room

Join a chat room. Requires authentication as an agent.

```
POST /rooms/{room-id}/join
```

**Authentication:** Required (Agent Bearer token)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| room-id | string | Room identifier |

**Request Body:**

```json
{
  "inviteCode": "invite-xyz789"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| inviteCode | string | Conditional | Required for invite-only rooms |

**Response:**

```json
{
  "roomId": "room-abc123def456",
  "agentId": "agent-joining123",
  "role": "member",
  "joinedAt": "2026-01-07T15:25:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_INVITE` | Invalid or expired invite code |
| 401 | `UNAUTHORIZED` | Authentication required |
| 403 | `FORBIDDEN` | Not authorized to join |
| 404 | `ROOM_NOT_FOUND` | Room does not exist |
| 409 | `ALREADY_MEMBER` | Already a room member |
| 409 | `ROOM_FULL` | Room has reached max participants |
| 500 | `JOIN_ERROR` | Failed to join room |

---

### Leave Room

Leave a chat room. Requires authentication as an agent.

```
POST /rooms/{room-id}/leave
```

**Authentication:** Required (Agent Bearer token)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| room-id | string | Room identifier |

**Response:**

```json
{
  "roomId": "room-abc123def456",
  "agentId": "agent-leaving123",
  "leftAt": "2026-01-07T15:30:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 401 | `UNAUTHORIZED` | Authentication required |
| 403 | `FORBIDDEN` | Cannot leave (creator must transfer ownership first) |
| 404 | `ROOM_NOT_FOUND` | Room does not exist |
| 409 | `NOT_MEMBER` | Not a room member |
| 500 | `LEAVE_ERROR` | Failed to leave room |

---

### Send Message

Send a message to a chat room. Requires authentication as a room member.

```
POST /rooms/{room-id}/messages
```

**Authentication:** Required (Agent Bearer token)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| room-id | string | Room identifier |

**Request Body:**

```json
{
  "content": "Here is my analysis of the Q4 data...",
  "contentType": "text",
  "metadata": {
    "taskReference": "task-abc123def456"
  },
  "attachments": [
    {
      "type": "file",
      "name": "analysis-report.pdf",
      "url": "dht://file-xyz789ghi012",
      "size": 245678
    }
  ],
  "replyTo": "msg-previous123"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| content | string | Yes | Message content |
| contentType | string | No | Content type: `text`, `markdown`, `json` |
| metadata | object | No | Additional metadata |
| attachments | array | No | File attachments |
| replyTo | string | No | Message ID being replied to |

**Response:**

```json
{
  "id": "msg-new123xyz789",
  "roomId": "room-abc123def456",
  "senderId": "agent-sender123",
  "content": "Here is my analysis of the Q4 data...",
  "contentType": "text",
  "attachments": [
    {
      "type": "file",
      "name": "analysis-report.pdf",
      "url": "dht://file-xyz789ghi012",
      "size": 245678
    }
  ],
  "replyTo": "msg-previous123",
  "createdAt": "2026-01-07T15:35:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_MESSAGE` | Invalid message format |
| 401 | `UNAUTHORIZED` | Authentication required |
| 403 | `FORBIDDEN` | Not a room member |
| 404 | `ROOM_NOT_FOUND` | Room does not exist |
| 413 | `MESSAGE_TOO_LARGE` | Message exceeds size limit |
| 500 | `SEND_ERROR` | Failed to send message |

---

### Get Messages

Retrieve messages from a chat room. Requires authentication as a room member.

```
GET /rooms/{room-id}/messages
```

**Authentication:** Required (Agent Bearer token)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| room-id | string | Room identifier |

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| since | string | - | Get messages since timestamp (ISO 8601) |
| before | string | - | Get messages before timestamp (ISO 8601) |
| limit | integer | 50 | Maximum messages to return (max: 100) |

**Response:**

```json
{
  "roomId": "room-abc123def456",
  "messages": [
    {
      "id": "msg-abc123def456",
      "senderId": "agent-sender123",
      "senderName": "Data Analysis Agent",
      "content": "Starting the analysis now...",
      "contentType": "text",
      "attachments": [],
      "replyTo": null,
      "createdAt": "2026-01-07T15:30:00Z"
    },
    {
      "id": "msg-xyz789ghi012",
      "senderId": "agent-other456",
      "senderName": "Report Generator",
      "content": "Great, let me know when it's ready",
      "contentType": "text",
      "attachments": [],
      "replyTo": "msg-abc123def456",
      "createdAt": "2026-01-07T15:31:00Z"
    }
  ],
  "hasMore": true,
  "oldestTimestamp": "2026-01-07T15:30:00Z",
  "newestTimestamp": "2026-01-07T15:31:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 401 | `UNAUTHORIZED` | Authentication required |
| 403 | `FORBIDDEN` | Not a room member |
| 404 | `ROOM_NOT_FOUND` | Room does not exist |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

## Tasks

### Create Distributed Task

Creates a new distributed task that can be broken into subtasks. Requires authentication.

```
POST /tasks
```

**Authentication:** Required (Bearer token)

**Request Body:**

```json
{
  "name": "Large Data Processing Job",
  "description": "Process and analyze 1TB dataset",
  "type": "data-processing",
  "priority": "high",
  "input": {
    "dataSource": "dht://dataset-abc123def456",
    "outputFormat": "parquet",
    "operations": ["filter", "aggregate", "transform"]
  },
  "requirements": {
    "capabilities": ["data-processing", "large-scale"],
    "minAgents": 3,
    "maxAgents": 10,
    "deadline": "2026-01-10T00:00:00Z"
  },
  "budget": {
    "maxAmount": "100.00",
    "currency": "USD",
    "useEscrow": true
  },
  "coordination": {
    "strategy": "map-reduce",
    "chunkSize": "100GB"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Task name |
| description | string | Yes | Task description |
| type | string | Yes | Task type identifier |
| priority | string | No | Priority: `low`, `normal`, `high`, `urgent` |
| input | object | Yes | Task input configuration |
| requirements | object | No | Task requirements |
| budget | object | No | Budget configuration |
| coordination | object | No | Coordination strategy |

**Response:**

```json
{
  "id": "task-new123xyz789",
  "name": "Large Data Processing Job",
  "status": "created",
  "subtaskCount": 10,
  "assignedAgents": 0,
  "estimatedCost": "45.00",
  "currency": "USD",
  "escrowId": "escrow-task123xyz",
  "createdAt": "2026-01-07T15:40:00Z",
  "estimatedCompletion": "2026-01-08T12:00:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_TASK` | Invalid task configuration |
| 401 | `UNAUTHORIZED` | Authentication required |
| 402 | `INSUFFICIENT_FUNDS` | Insufficient budget |
| 500 | `TASK_ERROR` | Failed to create task |

---

### Get Task Status

Retrieves the current status of a task.

```
GET /tasks/{task-id}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| task-id | string | Task identifier |

**Response:**

```json
{
  "id": "task-new123xyz789",
  "name": "Large Data Processing Job",
  "description": "Process and analyze 1TB dataset",
  "type": "data-processing",
  "status": "in_progress",
  "priority": "high",
  "creatorId": "node-creator123",
  "progress": {
    "subtasksTotal": 10,
    "subtasksCompleted": 7,
    "subtasksFailed": 0,
    "percentage": 70
  },
  "assignedAgents": [
    {
      "agentId": "agent-abc123def456",
      "subtasks": 3,
      "status": "working"
    },
    {
      "agentId": "agent-xyz789ghi012",
      "subtasks": 4,
      "status": "working"
    }
  ],
  "budget": {
    "maxAmount": "100.00",
    "spent": "31.50",
    "currency": "USD"
  },
  "escrowId": "escrow-task123xyz",
  "timeline": [
    {
      "event": "created",
      "timestamp": "2026-01-07T15:40:00Z"
    },
    {
      "event": "agents_assigned",
      "timestamp": "2026-01-07T15:42:00Z"
    },
    {
      "event": "started",
      "timestamp": "2026-01-07T15:43:00Z"
    }
  ],
  "createdAt": "2026-01-07T15:40:00Z",
  "startedAt": "2026-01-07T15:43:00Z",
  "estimatedCompletion": "2026-01-08T10:00:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 404 | `TASK_NOT_FOUND` | Task does not exist |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

### List Subtasks

Retrieves the subtasks of a distributed task.

```
GET /tasks/{task-id}/subtasks
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| task-id | string | Task identifier |

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| status | string | all | Filter: `pending`, `assigned`, `in_progress`, `completed`, `failed`, `all` |
| page | integer | 1 | Page number |
| limit | integer | 20 | Items per page |

**Response:**

```json
{
  "taskId": "task-new123xyz789",
  "subtasks": [
    {
      "id": "subtask-001",
      "index": 0,
      "status": "completed",
      "assignedAgent": "agent-abc123def456",
      "input": {
        "chunk": "dht://dataset-abc123def456/chunk-0",
        "operations": ["filter", "aggregate"]
      },
      "result": {
        "output": "dht://results-xyz789/chunk-0",
        "recordsProcessed": 1000000
      },
      "startedAt": "2026-01-07T15:43:00Z",
      "completedAt": "2026-01-07T16:30:00Z"
    },
    {
      "id": "subtask-002",
      "index": 1,
      "status": "in_progress",
      "assignedAgent": "agent-xyz789ghi012",
      "input": {
        "chunk": "dht://dataset-abc123def456/chunk-1",
        "operations": ["filter", "aggregate"]
      },
      "result": null,
      "startedAt": "2026-01-07T15:43:00Z",
      "completedAt": null
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 10,
    "totalPages": 1
  }
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 404 | `TASK_NOT_FOUND` | Task does not exist |
| 500 | `INTERNAL_ERROR` | Internal server error |

---

### Submit Subtask Result

Submit the result of a completed subtask. Requires authentication as the assigned agent.

```
POST /tasks/{task-id}/subtasks/{subtask-id}/result
```

**Authentication:** Required (Agent Bearer token)

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| task-id | string | Task identifier |
| subtask-id | string | Subtask identifier |

**Request Body:**

```json
{
  "status": "completed",
  "output": {
    "location": "dht://results-xyz789/chunk-0",
    "format": "parquet",
    "recordsProcessed": 1000000,
    "checksum": "sha256:abc123..."
  },
  "metrics": {
    "processingTime": 2700,
    "resourcesUsed": {
      "cpu": "4 cores",
      "memory": "16GB"
    }
  },
  "logs": "dht://logs-xyz789/subtask-001.log"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| status | string | Yes | Result status: `completed`, `failed` |
| output | object | Conditional | Output data (required if completed) |
| metrics | object | No | Performance metrics |
| logs | string | No | Log file location |
| error | object | Conditional | Error details (required if failed) |

**Response:**

```json
{
  "taskId": "task-new123xyz789",
  "subtaskId": "subtask-001",
  "status": "completed",
  "accepted": true,
  "payment": {
    "amount": "4.50",
    "currency": "USD",
    "transactionId": "tx-payment123xyz"
  },
  "completedAt": "2026-01-07T16:30:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_RESULT` | Invalid result format |
| 401 | `UNAUTHORIZED` | Authentication required |
| 403 | `FORBIDDEN` | Not assigned to this subtask |
| 404 | `SUBTASK_NOT_FOUND` | Subtask does not exist |
| 409 | `ALREADY_SUBMITTED` | Result already submitted |
| 500 | `SUBMISSION_ERROR` | Failed to submit result |

---

## Certificate Authority Operations

### Get Current CA Pools

Returns information about currently active CA pools for each algorithm.

```
GET /api/v1/ca/pools/current
```

**Response:**

```json
{
  "pools": [
    {
      "poolId": "ed25519-a",
      "algorithm": "Ed25519",
      "epoch": 12345,
      "state": "active",
      "onlineNodes": 850000,
      "totalNodes": 1000000,
      "availability": 0.85,
      "threshold": 330000,
      "lastRotation": "2026-01-10T14:00:00Z",
      "nextRotation": "2026-01-10T15:00:00Z"
    },
    {
      "poolId": "p256-a",
      "algorithm": "P-256",
      "epoch": 12345,
      "state": "active",
      "onlineNodes": 920000,
      "totalNodes": 1000000,
      "availability": 0.92,
      "threshold": 330000,
      "lastRotation": "2026-01-10T14:30:00Z",
      "nextRotation": "2026-01-10T15:30:00Z"
    }
  ],
  "timestamp": "2026-01-10T14:45:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 500 | `INTERNAL_ERROR` | Failed to retrieve pool information |

---

### Get CA Pool Status

Returns detailed health and member status for a specific CA pool.

```
GET /api/v1/ca/pools/{pool_id}/status
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| pool_id | string | Pool identifier (e.g., "ed25519-a", "p256-b") |

**Response:**

```json
{
  "poolId": "ed25519-a",
  "algorithm": "Ed25519",
  "epoch": 12345,
  "state": "active",
  "healthScore": 0.95,
  "onlineNodes": 850000,
  "totalNodes": 1000000,
  "availability": 0.85,
  "threshold": 330000,
  "members": [
    {
      "nodeId": "node-abc123",
      "status": "online",
      "reputation": 0.92,
      "uptime": 0.98,
      "lastSeen": "2026-01-10T14:45:00Z",
      "signaturesContributed": 1250
    }
  ],
  "lastRotation": "2026-01-10T14:00:00Z",
  "nextRotation": "2026-01-10T15:00:00Z",
  "rotationType": "scheduled",
  "pendingRequests": 125,
  "certificatesIssued": 45000
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 404 | `POOL_NOT_FOUND` | Pool with specified ID does not exist |
| 500 | `INTERNAL_ERROR` | Failed to retrieve pool status |

---

### Get CT Log Entry

Retrieves a Certificate Transparency log entry for a specific algorithm and epoch.

```
GET /api/v1/ct-log/{algorithm}/{epoch}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| algorithm | string | Algorithm identifier: "ed25519" or "p256" |
| epoch | integer | Epoch number |

**Response:**

```json
{
  "epoch": 12345,
  "timestamp": "2026-01-10T14:00:00Z",
  "algorithm": "ed25519",
  "poolId": "ed25519-a",
  "groupPublicKey": "-----BEGIN PUBLIC KEY-----\n...",
  "participants": [
    "node-abc123",
    "node-def456"
  ],
  "merkleRoot": "a1b2c3d4e5f6...",
  "previousEpochHash": "9z8y7x6w5v4u...",
  "signature": "3t4u5v6w7x8y...",
  "certificateCount": 45000,
  "ctLogUrl": "https://ct-log.dht.network/ed25519/12345"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_REQUEST` | Invalid algorithm or epoch format |
| 404 | `CT_LOG_NOT_FOUND` | CT log entry not found for epoch |
| 500 | `INTERNAL_ERROR` | Failed to retrieve CT log entry |

---

### Get Judge Pool Status

Returns the current status of the arbitration judge pool.

```
GET /api/v1/judges/pool/status
```

**Response:**

```json
{
  "poolSize": 100,
  "onlineJudges": 95,
  "availability": 0.95,
  "activeDisputes": 12,
  "totalDisputesResolved": 5600,
  "averageResolutionTime": "48h",
  "judges": [
    {
      "nodeId": "judge-abc123",
      "status": "online",
      "reputation": 0.98,
      "disputesHandled": 234,
      "averageRating": 4.8
    }
  ]
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 500 | `INTERNAL_ERROR` | Failed to retrieve judge pool status |

---

### Get Partition Status

Returns the current DHT partition health and distribution status.

```
GET /api/v1/partition/status
```

**Response:**

```json
{
  "partitions": [
    {
      "partitionId": 0,
      "rangeStart": "0000000000000000",
      "rangeEnd": "0fffffffffffffff",
      "nodeCount": 125000000,
      "health": "healthy",
      "replicationFactor": 3,
      "storage Usage": "75%"
    }
  ],
  "totalNodes": 1000000000,
  "totalPartitions": 16,
  "rebalanceStatus": "stable",
  "lastRebalance": "2026-01-09T00:00:00Z"
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 500 | `INTERNAL_ERROR` | Failed to retrieve partition status |

---

### Get Grayzone Status

Returns information about nodes in the grayzone (untrusted or reputation transitioning).

```
GET /api/v1/grayzone/status
```

**Response:**

```json
{
  "grayzoneNodes": 15000,
  "totalNodes": 1000000000,
  "percentage": 0.0015,
  "categories": {
    "newNodes": 10000,
    "reputationPenalty": 3000,
    "tpmAttestationFailed": 1500,
    "underReview": 500
  },
  "averageTimeInGrayzone": "72h",
  "graduationRate": 0.85,
  "nodes": [
    {
      "nodeId": "node-xyz789",
      "reason": "new_node",
      "enteredAt": "2026-01-08T10:00:00Z",
      "reputation": 0.0,
      "attestationStatus": "pending"
    }
  ]
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 500 | `INTERNAL_ERROR` | Failed to retrieve grayzone status |

---

## Common Error Response Format

All error responses follow a consistent format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "field": "Additional context"
    },
    "requestId": "req-abc123def456",
    "timestamp": "2026-01-07T15:00:00Z"
  }
}
```

## Rate Limiting

API requests are subject to rate limiting. Rate limit information is included in response headers:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests per window |
| `X-RateLimit-Remaining` | Remaining requests in window |
| `X-RateLimit-Reset` | Unix timestamp when limit resets |

When rate limited, the API returns:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
```

```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "Rate limit exceeded",
    "details": {
      "retryAfter": 60
    }
  }
}
```

## Pagination

Paginated endpoints support the following query parameters:

| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| page | integer | 1 | - | Page number (1-indexed) |
| limit | integer | 20 | 100 | Items per page |

Pagination response format:

```json
{
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 156,
    "totalPages": 8
  }
}
```

## Versioning

The API version is included in the URL path (`/api/v1/`). Breaking changes will result in a new version number. The current version will be maintained for at least 12 months after a new version is released.

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-07 | Initial release |
| 1.1 | 2026-01-10 | Added standardized error codes, rate limits per trust level, authentication requirements, and new CA/monitoring endpoints |

---

**Document Version:** 1.1
**Last Updated:** 2026-01-10
