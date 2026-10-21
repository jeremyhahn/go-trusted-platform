# Browser Extension for DHT Network Access

> **Status: NORMATIVE** · Scope: the planned `dht` feature (docs/SPEC.md:53); design only, no code exists · Last verified: 2026-10-21
> Conflicts with this document are defects. Fix them here first.
## Overview

The Browser Extension provides external users seamless access to the Trusted DHT network directly from Chrome and Firefox browsers. Users can browse DHT content, discover services, interact with e-commerce stores, and manage their DHT wallet without running a full node.

**Key Features:**

- **Gateway-Based Access**: Connect through high-reputation gateway nodes (0.85+)
- **DHT Browser**: Navigate content, services, and stores on the network
- **Service Discovery**: Search and filter services by keyword, category, and tags
- **E-Commerce Integration**: Browse stores, manage cart, checkout with DHT currency
- **Identity Management**: WebAuthn integration for trusted operations
- **Wallet Operations**: View balance, send/receive DHT currency
- **Real-Time Updates**: WebSocket streaming for orders, messages, and notifications

> **Cross-References:**
> - Gateway node requirements: See [09-defense-reputation.md](09-defense-reputation.md)
> - Network architecture: See [02-network-architecture.md](02-network-architecture.md)
> - Currency operations: See [07-currency-transactions.md](07-currency-transactions.md)

---

## Architecture

### High-Level Data Flow

```
+------------------+      HTTPS/WSS       +------------------+      P2P        +------------------+
|                  | <------------------> |                  | <-------------> |                  |
| Browser Extension|                      |   Gateway Node   |                 |   DHT Network    |
|                  |                      |   (Rep 0.85+)    |                 |                  |
+------------------+                      +------------------+                 +------------------+
        |                                         |                                    |
        |  - REST API calls                       |  - DHT queries                     |  - Full nodes
        |  - WebSocket streams                    |  - P2P routing                     |  - Leaf nodes
        |  - WebAuthn auth                        |  - Transaction relay               |  - CA pools
        |                                         |  - Rate limiting                   |  - Coordinators
        |                                         |  - DDoS protection                 |
        v                                         v                                    v
   [User Browser]                          [Gateway Cluster]                    [DHT Mesh]
```

### Three-Tier Architecture

```
+-------------------------------------------------------------------------+
|                      BROWSER EXTENSION LAYER                             |
|                                                                          |
|  +------------------+  +------------------+  +------------------+        |
|  |    Popup UI      |  |  Background      |  |   Content        |        |
|  |                  |  |  Service Worker  |  |   Scripts        |        |
|  |  - Dashboard     |  |  - Gateway mgmt  |  |  - Page inject   |        |
|  |  - Wallet        |  |  - WebSocket     |  |  - DHT links     |        |
|  |  - Browser       |  |  - Auth state    |  |  - Payment UI    |        |
|  +------------------+  +------------------+  +------------------+        |
+-------------------------------------------------------------------------+
                                  |
                                  | HTTPS/WSS (TLS 1.3)
                                  v
+-------------------------------------------------------------------------+
|                       GATEWAY NODE LAYER (Rep 0.85+)                     |
|                                                                          |
|  +------------------------------------------------------------------+   |
|  |                      Gateway API Server                          |   |
|  |                                                                   |   |
|  |  +-------------+  +-------------+  +-------------+               |   |
|  |  |  REST API   |  |  WebSocket  |  |   Auth      |               |   |
|  |  |  Endpoints  |  |  Server     |  |  Service    |               |   |
|  |  +-------------+  +-------------+  +-------------+               |   |
|  |         |               |                |                       |   |
|  |  +-------------+  +-------------+  +-------------+               |   |
|  |  | Rate Limiter|  |  DDoS       |  |  Request    |               |   |
|  |  |             |  |  Protection |  |  Validator  |               |   |
|  |  +-------------+  +-------------+  +-------------+               |   |
|  +------------------------------------------------------------------+   |
+-------------------------------------------------------------------------+
                                  |
                                  | P2P Protocol (QUIC/TCP)
                                  v
+-------------------------------------------------------------------------+
|                         DHT NETWORK LAYER                                |
|                                                                          |
|  +-------------+  +-------------+  +-------------+  +-------------+     |
|  | Full Nodes  |  | Leaf Nodes  |  |   CA Pools  |  |Coordinators |     |
|  | (Shard 0-N) |  | (DHT Routing)|  | (Signing)   |  | (Consensus) |     |
|  +-------------+  +-------------+  +-------------+  +-------------+     |
+-------------------------------------------------------------------------+
```

### Gateway Discovery and Selection

```go
// Gateway selection criteria
type GatewaySelector struct {
    MinReputation  float64       // 0.85 minimum
    MaxLatency     time.Duration // 200ms preference
    PreferRegion   string        // Geographic preference
    LoadThreshold  float64       // Max load percentage
}

func (s *GatewaySelector) SelectBestGateway(gateways []GatewayInfo) *GatewayInfo {
    var best *GatewayInfo
    bestScore := 0.0

    for _, gw := range gateways {
        if gw.Reputation < s.MinReputation {
            continue
        }

        score := calculateGatewayScore(gw, s)
        if score > bestScore {
            bestScore = score
            best = &gw
        }
    }

    return best
}

func calculateGatewayScore(gw GatewayInfo, s *GatewaySelector) float64 {
    // Higher reputation = higher score
    repScore := gw.Reputation * 0.4

    // Lower latency = higher score
    latencyScore := (1.0 - float64(gw.Latency)/float64(s.MaxLatency)) * 0.3

    // Lower load = higher score
    loadScore := (1.0 - gw.CurrentLoad) * 0.2

    // Regional preference
    regionScore := 0.0
    if gw.Region == s.PreferRegion {
        regionScore = 0.1
    }

    return repScore + latencyScore + loadScore + regionScore
}
```

---

## Gateway API

Gateway nodes expose a REST and WebSocket API for browser extension access.

### Base URL Structure

```
REST API:   https://gateway.dht.network/api/v1/
WebSocket:  wss://gateway.dht.network/ws/v1/
```

### Authentication

All API requests require authentication via signed challenge-response:

```go
type AuthRequest struct {
    PublicKey   string `json:"public_key"`   // Ed25519 public key
    Challenge   string `json:"challenge"`    // Server-provided challenge
    Signature   string `json:"signature"`    // Signed challenge
    Timestamp   int64  `json:"timestamp"`    // Request timestamp
}

type AuthResponse struct {
    Token       string    `json:"token"`       // JWT access token
    ExpiresAt   time.Time `json:"expires_at"`  // Token expiration
    GatewayID   string    `json:"gateway_id"`  // Connected gateway
}
```

### REST API Endpoints

#### Content Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/content/{hash}` | Retrieve content by hash |
| GET | `/content/manifest/{hash}` | Get content manifest |
| GET | `/content/browse` | Browse content directory |
| POST | `/content/search` | Search content by metadata |

#### Service Discovery

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/services` | List all services |
| GET | `/services/{id}` | Get service details |
| GET | `/services/category/{category}` | Filter by category |
| POST | `/services/search` | Search services |

#### E-Commerce

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/stores` | List all stores |
| GET | `/stores/{id}` | Get store details |
| GET | `/stores/{id}/products` | List store products |
| GET | `/products/{id}` | Get product details |
| POST | `/cart` | Create/update cart |
| POST | `/checkout` | Initiate checkout |
| GET | `/orders` | List user orders |
| GET | `/orders/{id}` | Get order details |

#### Wallet Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/wallet/balance` | Get wallet balance |
| GET | `/wallet/history` | Transaction history |
| POST | `/wallet/send` | Send DHT currency |
| GET | `/wallet/receive` | Get receive address |
| POST | `/wallet/estimate-fee` | Estimate transaction fee |

#### Identity

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/identity/register` | Register WebAuthn credential |
| POST | `/identity/authenticate` | WebAuthn authentication |
| GET | `/identity/profile` | Get identity profile |
| PUT | `/identity/profile` | Update profile |

### Request/Response Examples

#### Service Search

```http
POST /api/v1/services/search HTTP/1.1
Host: gateway.dht.network
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
    "query": "cloud storage",
    "category": "infrastructure",
    "tags": ["encrypted", "distributed"],
    "min_reputation": 0.7,
    "max_results": 20,
    "sort_by": "reputation",
    "sort_order": "desc"
}
```

```json
{
    "results": [
        {
            "id": "svc_abc123",
            "name": "SecureVault Storage",
            "description": "End-to-end encrypted distributed storage",
            "category": "infrastructure",
            "tags": ["encrypted", "distributed", "backup"],
            "provider": {
                "node_id": "node_xyz789",
                "reputation": 0.92,
                "verified": true
            },
            "pricing": {
                "model": "per_gb_month",
                "amount": 50,
                "currency": "DHT"
            },
            "stats": {
                "uptime": 0.9995,
                "response_time_ms": 45,
                "active_users": 1250
            }
        }
    ],
    "total": 47,
    "page": 1,
    "has_more": true
}
```

#### Product Listing

```http
GET /api/v1/stores/store_123/products?category=electronics&limit=10 HTTP/1.1
Host: gateway.dht.network
Authorization: Bearer <jwt_token>
```

```json
{
    "store": {
        "id": "store_123",
        "name": "DHT Electronics",
        "reputation": 0.89,
        "verified_merchant": true
    },
    "products": [
        {
            "id": "prod_456",
            "name": "Secure Hardware Wallet",
            "description": "TPM-backed cryptocurrency hardware wallet",
            "price": {
                "amount": 15000,
                "currency": "DHT"
            },
            "images": [
                "dht://content/img_abc123"
            ],
            "inventory": 42,
            "shipping": {
                "available": true,
                "regions": ["us", "eu", "asia"],
                "estimated_days": 5
            }
        }
    ],
    "total": 156,
    "pagination": {
        "page": 1,
        "limit": 10,
        "has_next": true
    }
}
```

#### Transaction Send

```http
POST /api/v1/wallet/send HTTP/1.1
Host: gateway.dht.network
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
    "to": "wallet_recipient_xyz",
    "amount": 1000,
    "memo": "Payment for order #12345",
    "signature": "<ed25519_signature>",
    "timestamp": 1704672000
}
```

```json
{
    "transaction_id": "tx_abc123xyz",
    "status": "pending",
    "from": "wallet_sender_abc",
    "to": "wallet_recipient_xyz",
    "amount": 1000,
    "fee": 10,
    "estimated_confirmation": "2s",
    "created_at": "2024-01-08T12:00:00Z"
}
```

---

## WebSocket Streaming

Real-time updates are delivered via WebSocket connections.

### Connection Establishment

```javascript
// Extension connects to gateway WebSocket
const ws = new WebSocket('wss://gateway.dht.network/ws/v1/');

ws.onopen = () => {
    // Authenticate
    ws.send(JSON.stringify({
        type: 'auth',
        token: jwtToken
    }));
};

ws.onmessage = (event) => {
    const message = JSON.parse(event.data);
    handleMessage(message);
};
```

### Subscription Channels

| Channel | Description | Events |
|---------|-------------|--------|
| `wallet` | Wallet updates | `balance_update`, `incoming_tx`, `tx_confirmed` |
| `orders` | Order tracking | `order_created`, `order_shipped`, `order_delivered` |
| `services` | Service notifications | `service_online`, `service_offline`, `price_update` |
| `messages` | Direct messages | `new_message`, `message_read` |

### Message Format

```go
type WSMessage struct {
    Type      string          `json:"type"`       // Message type
    Channel   string          `json:"channel"`    // Subscription channel
    Event     string          `json:"event"`      // Event name
    Payload   json.RawMessage `json:"payload"`    // Event data
    Timestamp int64           `json:"timestamp"`  // Server timestamp
    Sequence  uint64          `json:"sequence"`   // Sequence number
}
```

### Subscription Management

```javascript
// Subscribe to wallet updates
ws.send(JSON.stringify({
    type: 'subscribe',
    channel: 'wallet',
    filters: {
        wallet_id: myWalletId
    }
}));

// Subscribe to order updates
ws.send(JSON.stringify({
    type: 'subscribe',
    channel: 'orders',
    filters: {
        store_id: 'store_123'
    }
}));

// Unsubscribe
ws.send(JSON.stringify({
    type: 'unsubscribe',
    channel: 'orders'
}));
```

### Event Examples

```json
{
    "type": "event",
    "channel": "wallet",
    "event": "incoming_tx",
    "payload": {
        "transaction_id": "tx_xyz789",
        "from": "wallet_sender",
        "amount": 500,
        "memo": "Refund",
        "status": "confirmed",
        "confirmations": 12
    },
    "timestamp": 1704672100,
    "sequence": 42
}
```

```json
{
    "type": "event",
    "channel": "orders",
    "event": "order_shipped",
    "payload": {
        "order_id": "ord_123",
        "tracking_number": "DHT-TRACK-456",
        "carrier": "DHT Express",
        "estimated_delivery": "2024-01-15T12:00:00Z",
        "items": [
            {
                "product_id": "prod_456",
                "quantity": 1
            }
        ]
    },
    "timestamp": 1704672200,
    "sequence": 43
}
```

---

## Extension Features

### DHT Browser

Navigate and explore content stored on the DHT network.

```
+------------------------------------------------------------------+
|  DHT Browser                                            [_][O][X] |
+------------------------------------------------------------------+
|  Address: dht://services/cloud-storage                    [Go]   |
+------------------------------------------------------------------+
|                                                                   |
|  NAVIGATION                    CONTENT VIEW                       |
|  +--------------------+        +------------------------------+   |
|  | > Content          |        |  Cloud Storage Services       |   |
|  |   - Documents      |        |                               |   |
|  |   - Media          |        |  +---------------------------+|   |
|  |   - Software       |        |  | SecureVault Storage       ||   |
|  | > Services         |        |  | Rep: 0.92 | 99.9% Uptime  ||   |
|  |   - Cloud Storage  |        |  | 50 DHT/GB/month           ||   |
|  |   - Compute        |        |  +---------------------------+|   |
|  |   - Messaging      |        |                               |   |
|  | > Stores           |        |  +---------------------------+|   |
|  |   - Electronics    |        |  | DistribuStore             ||   |
|  |   - Digital Goods  |        |  | Rep: 0.88 | 99.5% Uptime  ||   |
|  |   - Services       |        |  | 45 DHT/GB/month           ||   |
|  +--------------------+        |  +---------------------------+|   |
|                                +------------------------------+   |
+------------------------------------------------------------------+
|  Bookmarks: SecureVault | DHT Electronics | MyFiles             |
+------------------------------------------------------------------+
```

### Service Search

```
+------------------------------------------------------------------+
|  Service Search                                                   |
+------------------------------------------------------------------+
|  Search: [cloud storage encrypted          ] [Search]             |
|                                                                   |
|  Filters:                                                         |
|  Category: [Infrastructure v] Min Rep: [0.7 v] Price: [Any   v]   |
|  Tags: [x] encrypted [x] distributed [ ] enterprise              |
+------------------------------------------------------------------+
|                                                                   |
|  RESULTS (47 found)                        Sort: [Reputation v]   |
|                                                                   |
|  +--------------------------------------------------------------+|
|  | SecureVault Storage                              Rep: 0.92   ||
|  | End-to-end encrypted distributed storage                     ||
|  | Tags: encrypted, distributed, backup                         ||
|  | 50 DHT/GB/month | 99.9% Uptime | 1,250 users                 ||
|  | [View Details] [Subscribe]                                   ||
|  +--------------------------------------------------------------+|
|                                                                   |
|  +--------------------------------------------------------------+|
|  | DistribuStore                                    Rep: 0.88   ||
|  | Decentralized file storage with redundancy                   ||
|  | Tags: encrypted, distributed, enterprise                     ||
|  | 45 DHT/GB/month | 99.5% Uptime | 890 users                   ||
|  | [View Details] [Subscribe]                                   ||
|  +--------------------------------------------------------------+|
+------------------------------------------------------------------+
```

### E-Commerce Store

```
+------------------------------------------------------------------+
|  DHT Electronics                           [Cart (2)] [Account]   |
+------------------------------------------------------------------+
|  Categories: Electronics | Hardware | Accessories | Software      |
+------------------------------------------------------------------+
|                                                                   |
|  +-------------------+  +-------------------+  +------------------+|
|  |  [Product Image]  |  |  [Product Image]  |  |  [Product Image]||
|  |                   |  |                   |  |                  ||
|  | Secure HW Wallet  |  | TPM Module 2.0    |  | Privacy Router   ||
|  | 15,000 DHT        |  | 3,500 DHT         |  | 8,000 DHT        ||
|  | [Add to Cart]     |  | [Add to Cart]     |  | [Add to Cart]    ||
|  +-------------------+  +-------------------+  +------------------+|
|                                                                   |
+------------------------------------------------------------------+
|  SHOPPING CART                                                    |
|  +--------------------------------------------------------------+|
|  | Secure Hardware Wallet (1)                       15,000 DHT  ||
|  | TPM Module 2.0 (1)                                3,500 DHT  ||
|  +--------------------------------------------------------------+|
|  | Subtotal:                                        18,500 DHT  ||
|  | Shipping (US):                                      500 DHT  ||
|  | Total:                                           19,000 DHT  ||
|  +--------------------------------------------------------------+|
|  |                                            [Checkout]         ||
|  +--------------------------------------------------------------+|
+------------------------------------------------------------------+
```

### Wallet Interface

```
+------------------------------------------------------------------+
|  DHT Wallet                                                       |
+------------------------------------------------------------------+
|                                                                   |
|  +--------------------------------------------------------------+|
|  |  BALANCE                                                     ||
|  |                                                              ||
|  |  125,450 DHT                                                 ||
|  |  ~ $1,254.50 USD                                             ||
|  |                                                              ||
|  |  Available: 120,450 DHT    Pending: 5,000 DHT                ||
|  +--------------------------------------------------------------+|
|                                                                   |
|  [Send] [Receive] [History]                                       |
|                                                                   |
|  RECENT TRANSACTIONS                                              |
|  +--------------------------------------------------------------+|
|  | [<] Received from store_123        +5,000 DHT    Pending     ||
|  |     Order refund #12345                          2 min ago   ||
|  +--------------------------------------------------------------+|
|  | [>] Sent to wallet_xyz             -19,000 DHT   Confirmed   ||
|  |     Order payment                               15 min ago   ||
|  +--------------------------------------------------------------+|
|  | [<] Received from node_abc          +1,000 DHT   Confirmed   ||
|  |     Storage reward                               2 hrs ago   ||
|  +--------------------------------------------------------------+|
+------------------------------------------------------------------+
```

### Identity (WebAuthn)

```
+------------------------------------------------------------------+
|  Identity & Security                                              |
+------------------------------------------------------------------+
|                                                                   |
|  IDENTITY STATUS                                                  |
|  +--------------------------------------------------------------+|
|  | Verified Identity                                            ||
|  | Node ID: node_abc123xyz                                      ||
|  | Reputation: 0.75                                              ||
|  | Member since: Jan 2024                                       ||
|  +--------------------------------------------------------------+|
|                                                                   |
|  WEBAUTHN CREDENTIALS                                             |
|  +--------------------------------------------------------------+|
|  | YubiKey 5 NFC                          Active     [Remove]   ||
|  | Registered: Dec 15, 2023                                     ||
|  +--------------------------------------------------------------+|
|  | MacBook Touch ID                       Active     [Remove]   ||
|  | Registered: Dec 20, 2023                                     ||
|  +--------------------------------------------------------------+|
|                                                                   |
|  [+ Add New Credential]                                           |
|                                                                   |
|  SECURITY SETTINGS                                                |
|  +--------------------------------------------------------------+|
|  | [x] Require WebAuthn for transactions over 1,000 DHT         ||
|  | [x] Require WebAuthn for profile changes                     ||
|  | [ ] Require WebAuthn for all operations                      ||
|  +--------------------------------------------------------------+|
+------------------------------------------------------------------+
```

### Bookmarks

```go
type Bookmark struct {
    ID          string    `json:"id"`
    Type        string    `json:"type"`    // "service", "store", "content", "wallet"
    Name        string    `json:"name"`
    Address     string    `json:"address"` // DHT address
    Icon        string    `json:"icon"`    // Base64 favicon
    Tags        []string  `json:"tags"`
    CreatedAt   time.Time `json:"created_at"`
    LastVisited time.Time `json:"last_visited"`
}

type BookmarkManager struct {
    bookmarks map[string]*Bookmark
    storage   browser.Storage
}

func (bm *BookmarkManager) Add(bookmark *Bookmark) error {
    bookmark.ID = generateID()
    bookmark.CreatedAt = time.Now()
    bm.bookmarks[bookmark.ID] = bookmark
    return bm.sync()
}

func (bm *BookmarkManager) GetByType(bookmarkType string) []*Bookmark {
    var result []*Bookmark
    for _, b := range bm.bookmarks {
        if b.Type == bookmarkType {
            result = append(result, b)
        }
    }
    return result
}
```

---

## Extension Package Structure

### Directory Layout

```
dht-browser-extension/
|-- manifest.json              # Extension manifest (v3)
|-- package.json               # NPM dependencies
|-- tsconfig.json              # TypeScript configuration
|
|-- background/
|   |-- service-worker.ts      # Service worker (Manifest v3)
|   |-- gateway-manager.ts     # Gateway connection management
|   |-- auth-manager.ts        # Authentication state
|   |-- websocket-client.ts    # WebSocket connection
|   `-- storage-manager.ts     # Extension storage
|
|-- popup/
|   |-- popup.html             # Main popup HTML
|   |-- popup.ts               # Popup entry point
|   |-- components/
|   |   |-- Dashboard.tsx      # Main dashboard
|   |   |-- Browser.tsx        # DHT browser
|   |   |-- Wallet.tsx         # Wallet interface
|   |   |-- ServiceSearch.tsx  # Service search
|   |   |-- Store.tsx          # E-commerce store
|   |   |-- Cart.tsx           # Shopping cart
|   |   |-- Identity.tsx       # Identity management
|   |   `-- Bookmarks.tsx      # Bookmarks list
|   `-- styles/
|       `-- popup.css          # Popup styles
|
|-- content/
|   |-- content-script.ts      # Page injection
|   |-- dht-link-handler.ts    # Handle dht:// links
|   `-- payment-widget.ts      # In-page payment UI
|
|-- lib/
|   |-- api-client.ts          # Gateway API client
|   |-- crypto.ts              # Ed25519 operations
|   |-- webauthn.ts            # WebAuthn integration
|   |-- types.ts               # TypeScript types
|   `-- constants.ts           # Configuration constants
|
|-- options/
|   |-- options.html           # Options page
|   `-- options.ts             # Options logic
|
|-- _locales/
|   |-- en/
|   |   `-- messages.json      # English translations
|   `-- es/
|       `-- messages.json      # Spanish translations
|
|-- icons/
|   |-- icon-16.png
|   |-- icon-32.png
|   |-- icon-48.png
|   `-- icon-128.png
|
|-- test/
|   |-- unit/
|   |   |-- api-client.test.ts
|   |   |-- crypto.test.ts
|   |   `-- webauthn.test.ts
|   `-- integration/
|       |-- gateway.test.ts
|       `-- wallet.test.ts
|
`-- build/
    |-- webpack.config.js      # Build configuration
    `-- scripts/
        |-- build.sh           # Build script
        `-- release.sh         # Release script
```

### Manifest.json (Manifest v3)

```json
{
    "manifest_version": 3,
    "name": "DHT Browser",
    "version": "1.0.0",
    "description": "Access the Trusted DHT Network from your browser",

    "permissions": [
        "storage",
        "alarms",
        "notifications"
    ],

    "host_permissions": [
        "https://*.dht.network/*"
    ],

    "background": {
        "service_worker": "background/service-worker.js",
        "type": "module"
    },

    "action": {
        "default_popup": "popup/popup.html",
        "default_icon": {
            "16": "icons/icon-16.png",
            "32": "icons/icon-32.png",
            "48": "icons/icon-48.png",
            "128": "icons/icon-128.png"
        },
        "default_title": "DHT Browser"
    },

    "content_scripts": [
        {
            "matches": ["<all_urls>"],
            "js": ["content/content-script.js"],
            "css": ["content/content-styles.css"],
            "run_at": "document_idle"
        }
    ],

    "options_page": "options/options.html",

    "web_accessible_resources": [
        {
            "resources": ["content/payment-widget.html"],
            "matches": ["<all_urls>"]
        }
    ],

    "icons": {
        "16": "icons/icon-16.png",
        "32": "icons/icon-32.png",
        "48": "icons/icon-48.png",
        "128": "icons/icon-128.png"
    },

    "default_locale": "en",

    "content_security_policy": {
        "extension_pages": "script-src 'self'; object-src 'self'"
    }
}
```

### Background Service Worker

```typescript
// background/service-worker.ts

import { GatewayManager } from './gateway-manager';
import { AuthManager } from './auth-manager';
import { WebSocketClient } from './websocket-client';
import { StorageManager } from './storage-manager';

class BackgroundService {
    private gatewayManager: GatewayManager;
    private authManager: AuthManager;
    private wsClient: WebSocketClient;
    private storage: StorageManager;

    constructor() {
        this.storage = new StorageManager();
        this.gatewayManager = new GatewayManager(this.storage);
        this.authManager = new AuthManager(this.storage);
        this.wsClient = new WebSocketClient();

        this.setupMessageHandlers();
        this.setupAlarms();
    }

    private setupMessageHandlers(): void {
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            this.handleMessage(request, sender, sendResponse);
            return true; // Keep channel open for async response
        });
    }

    private async handleMessage(
        request: any,
        sender: chrome.runtime.MessageSender,
        sendResponse: (response: any) => void
    ): Promise<void> {
        try {
            switch (request.action) {
                case 'connect':
                    const gateway = await this.gatewayManager.connect();
                    sendResponse({ success: true, gateway });
                    break;

                case 'authenticate':
                    const authResult = await this.authManager.authenticate(request.credential);
                    sendResponse({ success: true, ...authResult });
                    break;

                case 'apiRequest':
                    const result = await this.gatewayManager.apiRequest(
                        request.method,
                        request.endpoint,
                        request.data
                    );
                    sendResponse({ success: true, data: result });
                    break;

                case 'subscribe':
                    await this.wsClient.subscribe(request.channel, request.filters);
                    sendResponse({ success: true });
                    break;

                case 'unsubscribe':
                    await this.wsClient.unsubscribe(request.channel);
                    sendResponse({ success: true });
                    break;

                default:
                    sendResponse({ success: false, error: 'Unknown action' });
            }
        } catch (error) {
            sendResponse({ success: false, error: error.message });
        }
    }

    private setupAlarms(): void {
        // Refresh gateway connection every 5 minutes
        chrome.alarms.create('refreshGateway', { periodInMinutes: 5 });

        // Check WebSocket health every minute
        chrome.alarms.create('wsHealthCheck', { periodInMinutes: 1 });

        chrome.alarms.onAlarm.addListener((alarm) => {
            switch (alarm.name) {
                case 'refreshGateway':
                    this.gatewayManager.refreshConnection();
                    break;
                case 'wsHealthCheck':
                    this.wsClient.healthCheck();
                    break;
            }
        });
    }
}

// Initialize background service
const backgroundService = new BackgroundService();
```

### API Client

```typescript
// lib/api-client.ts

import { signRequest } from './crypto';

export interface APIClientConfig {
    baseUrl: string;
    timeout: number;
    retries: number;
}

export class APIClient {
    private config: APIClientConfig;
    private authToken: string | null = null;

    constructor(config: APIClientConfig) {
        this.config = config;
    }

    setAuthToken(token: string): void {
        this.authToken = token;
    }

    async request<T>(
        method: string,
        endpoint: string,
        data?: any
    ): Promise<T> {
        const url = `${this.config.baseUrl}${endpoint}`;

        const headers: HeadersInit = {
            'Content-Type': 'application/json',
        };

        if (this.authToken) {
            headers['Authorization'] = `Bearer ${this.authToken}`;
        }

        const options: RequestInit = {
            method,
            headers,
            body: data ? JSON.stringify(data) : undefined,
        };

        let lastError: Error | null = null;

        for (let attempt = 0; attempt <= this.config.retries; attempt++) {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(
                    () => controller.abort(),
                    this.config.timeout
                );

                const response = await fetch(url, {
                    ...options,
                    signal: controller.signal,
                });

                clearTimeout(timeoutId);

                if (!response.ok) {
                    const error = await response.json();
                    throw new APIError(error.message, response.status, error.code);
                }

                return await response.json();
            } catch (error) {
                lastError = error as Error;
                if (attempt < this.config.retries) {
                    await this.delay(Math.pow(2, attempt) * 1000);
                }
            }
        }

        throw lastError;
    }

    private delay(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // Convenience methods
    async get<T>(endpoint: string): Promise<T> {
        return this.request<T>('GET', endpoint);
    }

    async post<T>(endpoint: string, data: any): Promise<T> {
        return this.request<T>('POST', endpoint, data);
    }

    async put<T>(endpoint: string, data: any): Promise<T> {
        return this.request<T>('PUT', endpoint, data);
    }

    async delete<T>(endpoint: string): Promise<T> {
        return this.request<T>('DELETE', endpoint);
    }
}

export class APIError extends Error {
    constructor(
        message: string,
        public statusCode: number,
        public errorCode: string
    ) {
        super(message);
        this.name = 'APIError';
    }
}
```

### WebAuthn Integration

```typescript
// lib/webauthn.ts

export interface WebAuthnConfig {
    rpId: string;
    rpName: string;
    timeout: number;
}

export class WebAuthnManager {
    private config: WebAuthnConfig;

    constructor(config: WebAuthnConfig) {
        this.config = config;
    }

    async register(
        userId: string,
        userName: string,
        challenge: ArrayBuffer
    ): Promise<PublicKeyCredential> {
        const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
            challenge,
            rp: {
                id: this.config.rpId,
                name: this.config.rpName,
            },
            user: {
                id: Uint8Array.from(userId, c => c.charCodeAt(0)),
                name: userName,
                displayName: userName,
            },
            pubKeyCredParams: [
                { alg: -7, type: 'public-key' },   // ES256
                { alg: -257, type: 'public-key' }, // RS256
            ],
            authenticatorSelection: {
                authenticatorAttachment: 'cross-platform',
                userVerification: 'preferred',
                residentKey: 'preferred',
            },
            timeout: this.config.timeout,
            attestation: 'direct',
        };

        const credential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreationOptions,
        });

        if (!credential) {
            throw new Error('Failed to create credential');
        }

        return credential as PublicKeyCredential;
    }

    async authenticate(
        challenge: ArrayBuffer,
        allowCredentials?: PublicKeyCredentialDescriptor[]
    ): Promise<PublicKeyCredential> {
        const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
            challenge,
            rpId: this.config.rpId,
            timeout: this.config.timeout,
            userVerification: 'preferred',
            allowCredentials,
        };

        const assertion = await navigator.credentials.get({
            publicKey: publicKeyCredentialRequestOptions,
        });

        if (!assertion) {
            throw new Error('Failed to get assertion');
        }

        return assertion as PublicKeyCredential;
    }

    serializeCredential(credential: PublicKeyCredential): object {
        const response = credential.response as AuthenticatorAttestationResponse | AuthenticatorAssertionResponse;

        const serialized: any = {
            id: credential.id,
            rawId: this.arrayBufferToBase64(credential.rawId),
            type: credential.type,
        };

        if ('attestationObject' in response) {
            // Registration response
            serialized.response = {
                clientDataJSON: this.arrayBufferToBase64(response.clientDataJSON),
                attestationObject: this.arrayBufferToBase64(response.attestationObject),
            };
        } else if ('authenticatorData' in response) {
            // Authentication response
            serialized.response = {
                clientDataJSON: this.arrayBufferToBase64(response.clientDataJSON),
                authenticatorData: this.arrayBufferToBase64(response.authenticatorData),
                signature: this.arrayBufferToBase64(response.signature),
                userHandle: response.userHandle
                    ? this.arrayBufferToBase64(response.userHandle)
                    : null,
            };
        }

        return serialized;
    }

    private arrayBufferToBase64(buffer: ArrayBuffer): string {
        return btoa(String.fromCharCode(...new Uint8Array(buffer)));
    }
}
```

---

## Gateway Node Requirements

Gateway nodes serving browser extensions must meet strict requirements to ensure security and reliability.

### Eligibility Requirements

| Requirement | Threshold | Rationale |
|-------------|-----------|-----------|
| **Reputation** | >= 0.85 | Ensures trustworthy nodes only |
| **Uptime** | >= 99.5% | Reliable API availability |
| **Age** | >= 90 days | Proven long-term operation |
| **Bandwidth** | >= 100 Mbps | Handle external traffic |
| **TPM Attestation** | Required | Hardware-backed identity |

> **Reference:** See [09-defense-reputation.md](09-defense-reputation.md) for complete role eligibility details.

### Gateway Configuration

```go
// Gateway API server configuration
type GatewayAPIConfig struct {
    // Network
    ListenAddr     string        // ":443"
    TLSCertPath    string        // TLS certificate
    TLSKeyPath     string        // TLS private key

    // Rate Limiting
    RateLimitRPS   int           // Requests per second per IP
    RateLimitBurst int           // Burst allowance
    BanDuration    time.Duration // Temporary ban duration

    // DDoS Protection
    MaxConnections      int           // Maximum concurrent connections
    ConnectionTimeout   time.Duration // Connection timeout
    RequestSizeLimit    int64         // Maximum request body size
    SlowlorisTimeout    time.Duration // Slow client timeout

    // WebSocket
    WSPingInterval      time.Duration // WebSocket ping interval
    WSPongTimeout       time.Duration // Pong response timeout
    WSMaxMessageSize    int64         // Maximum WebSocket message size
    WSMaxSubscriptions  int           // Max subscriptions per connection

    // Security
    CORSOrigins         []string      // Allowed CORS origins
    CSPDirectives       string        // Content-Security-Policy
    HSTSMaxAge          int           // HSTS max-age seconds
}
```

### Rate Limiting

```go
// Per-IP rate limiting with reputation adjustment
type RateLimiter struct {
    baseRPS        int
    burstMultiplier int
    store          sync.Map // IP -> *rateLimitState
}

type rateLimitState struct {
    tokens    float64
    lastTime  time.Time
    banned    bool
    banExpiry time.Time
}

func (rl *RateLimiter) Allow(ip string, userRep float64) bool {
    state := rl.getOrCreate(ip)

    if state.banned && time.Now().Before(state.banExpiry) {
        return false
    }

    // Reputation-adjusted rate
    // Higher reputation = more generous limits
    repMultiplier := 1.0 + userRep // 1.0x to 2.0x
    allowedRPS := float64(rl.baseRPS) * repMultiplier

    now := time.Now()
    elapsed := now.Sub(state.lastTime).Seconds()
    state.tokens = min(
        float64(rl.burstMultiplier)*allowedRPS,
        state.tokens + elapsed*allowedRPS,
    )
    state.lastTime = now

    if state.tokens >= 1.0 {
        state.tokens--
        return true
    }

    return false
}
```

### DDoS Protection

```go
// Multi-layer DDoS protection for gateway nodes
type DDoSProtection struct {
    connectionLimiter *ConnectionLimiter
    requestValidator  *RequestValidator
    ipReputation      *IPReputationTracker
    captchaChallenger *CaptchaChallenger
}

func (ddos *DDoSProtection) HandleRequest(
    w http.ResponseWriter,
    r *http.Request,
) bool {
    ip := extractClientIP(r)

    // Layer 1: Connection limits
    if !ddos.connectionLimiter.Allow(ip) {
        http.Error(w, "Too many connections", 429)
        return false
    }

    // Layer 2: IP reputation check
    rep := ddos.ipReputation.GetScore(ip)
    if rep < 0.1 {
        http.Error(w, "Access denied", 403)
        return false
    }

    // Layer 3: Request validation
    if !ddos.requestValidator.Validate(r) {
        ddos.ipReputation.Penalize(ip, 0.05)
        http.Error(w, "Invalid request", 400)
        return false
    }

    // Layer 4: CAPTCHA for suspicious patterns
    if rep < 0.5 && ddos.captchaChallenger.ShouldChallenge(ip) {
        challenge := ddos.captchaChallenger.Generate()
        w.Header().Set("X-DHT-Challenge", challenge)
        http.Error(w, "Challenge required", 428)
        return false
    }

    return true
}

type ConnectionLimiter struct {
    maxPerIP     int
    connections  sync.Map // IP -> *int32 (atomic counter)
}

func (cl *ConnectionLimiter) Allow(ip string) bool {
    counter, _ := cl.connections.LoadOrStore(ip, new(int32))
    count := atomic.AddInt32(counter.(*int32), 1)
    if count > int32(cl.maxPerIP) {
        atomic.AddInt32(counter.(*int32), -1)
        return false
    }
    return true
}

func (cl *ConnectionLimiter) Release(ip string) {
    if counter, ok := cl.connections.Load(ip); ok {
        atomic.AddInt32(counter.(*int32), -1)
    }
}
```

---

## Security Considerations

### CORS Configuration

Gateway nodes must carefully configure CORS to allow browser extension access while preventing unauthorized origins:

```go
func corsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            origin := r.Header.Get("Origin")

            // Check if origin is allowed
            allowed := false
            for _, ao := range allowedOrigins {
                if ao == origin || ao == "*" {
                    allowed = true
                    break
                }
            }

            if allowed {
                w.Header().Set("Access-Control-Allow-Origin", origin)
                w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
                w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-DHT-Signature")
                w.Header().Set("Access-Control-Allow-Credentials", "true")
                w.Header().Set("Access-Control-Max-Age", "86400")
            }

            // Handle preflight
            if r.Method == "OPTIONS" {
                w.WriteHeader(http.StatusNoContent)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}

// Allowed origins for browser extensions
var allowedOrigins = []string{
    "chrome-extension://<extension_id>",
    "moz-extension://<extension_id>",
    "https://dht.network",
}
```

### Request Signing

All mutating operations require request signing:

```typescript
// lib/crypto.ts

import nacl from 'tweetnacl';

export async function signRequest(
    privateKey: Uint8Array,
    method: string,
    path: string,
    body: any,
    timestamp: number
): Promise<string> {
    const payload = JSON.stringify({
        method,
        path,
        body: body ? JSON.stringify(body) : '',
        timestamp,
    });

    const messageBytes = new TextEncoder().encode(payload);
    const signature = nacl.sign.detached(messageBytes, privateKey);

    return btoa(String.fromCharCode(...signature));
}

export function verifySignature(
    publicKey: Uint8Array,
    signature: string,
    message: string
): boolean {
    const signatureBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    const messageBytes = new TextEncoder().encode(message);

    return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKey);
}
```

### Secure Storage

Extension data is encrypted at rest using the user's key:

```typescript
// lib/storage-manager.ts

export class StorageManager {
    private encryptionKey: CryptoKey | null = null;

    async initialize(password: string): Promise<void> {
        const salt = await this.getOrCreateSalt();
        this.encryptionKey = await this.deriveKey(password, salt);
    }

    private async deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt,
                iterations: 100000,
                hash: 'SHA-256',
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async setSecure(key: string, value: any): Promise<void> {
        if (!this.encryptionKey) {
            throw new Error('Storage not initialized');
        }

        const plaintext = JSON.stringify(value);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this.encryptionKey,
            new TextEncoder().encode(plaintext)
        );

        const stored = {
            iv: Array.from(iv),
            data: Array.from(new Uint8Array(encrypted)),
        };

        await chrome.storage.local.set({ [key]: stored });
    }

    async getSecure<T>(key: string): Promise<T | null> {
        if (!this.encryptionKey) {
            throw new Error('Storage not initialized');
        }

        const result = await chrome.storage.local.get(key);
        if (!result[key]) {
            return null;
        }

        const { iv, data } = result[key];
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: new Uint8Array(iv) },
            this.encryptionKey,
            new Uint8Array(data)
        );

        return JSON.parse(new TextDecoder().decode(decrypted));
    }
}
```

### Content Security Policy

```json
{
    "content_security_policy": {
        "extension_pages": "script-src 'self'; object-src 'self'; connect-src https://*.dht.network wss://*.dht.network; style-src 'self' 'unsafe-inline';"
    }
}
```

---

## Chrome vs Firefox Differences

### Manifest v3 Differences

| Feature | Chrome (Manifest v3) | Firefox (Manifest v3) |
|---------|---------------------|----------------------|
| **Background Script** | Service Worker only | Service Worker or Event Page |
| **Persistent Background** | Not supported | Partial support |
| **Host Permissions** | Separate array | Same as v2 |
| **Web Request API** | Limited (declarativeNetRequest) | Full support retained |
| **Remote Code** | Prohibited | Prohibited |

### Chrome-Specific Configuration

```json
{
    "manifest_version": 3,
    "background": {
        "service_worker": "background/service-worker.js",
        "type": "module"
    },
    "action": {
        "default_popup": "popup/popup.html"
    }
}
```

### Firefox-Specific Configuration

```json
{
    "manifest_version": 3,
    "background": {
        "scripts": ["background/background.js"],
        "type": "module"
    },
    "browser_action": {
        "default_popup": "popup/popup.html"
    },
    "browser_specific_settings": {
        "gecko": {
            "id": "dht-browser@dht.network",
            "strict_min_version": "109.0"
        }
    }
}
```

### Platform Detection

```typescript
// lib/platform.ts

export type Platform = 'chrome' | 'firefox' | 'unknown';

export function detectPlatform(): Platform {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
        const manifest = chrome.runtime.getManifest();
        if (manifest.browser_specific_settings?.gecko) {
            return 'firefox';
        }
        return 'chrome';
    }
    return 'unknown';
}

export function getStorageAPI(): typeof chrome.storage {
    const platform = detectPlatform();
    if (platform === 'firefox') {
        return browser.storage;
    }
    return chrome.storage;
}

export function getRuntimeAPI(): typeof chrome.runtime {
    const platform = detectPlatform();
    if (platform === 'firefox') {
        return browser.runtime;
    }
    return chrome.runtime;
}
```

### Service Worker Lifecycle (Chrome)

```typescript
// Chrome service workers can be terminated at any time
// Must handle state restoration

chrome.runtime.onStartup.addListener(async () => {
    // Restore state from storage
    const state = await chrome.storage.session.get(['gateway', 'authToken']);
    if (state.gateway) {
        await gatewayManager.reconnect(state.gateway);
    }
});

chrome.runtime.onSuspend.addListener(() => {
    // Clean up before termination
    wsClient.disconnect();
});

// Use alarms for persistent tasks
chrome.alarms.create('heartbeat', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'heartbeat') {
        // Perform periodic tasks
        gatewayManager.healthCheck();
    }
});
```

### Firefox Event Page Considerations

```typescript
// Firefox allows longer-lived background contexts
// But should still be prepared for termination

browser.runtime.onSuspend.addListener(() => {
    // Save state before potential termination
    saveState();
});

// Firefox supports persistent connections better
// But still use alarms for reliability
browser.alarms.create('heartbeat', { periodInMinutes: 1 });
```

---

## Error Handling

### Error Types

```typescript
// lib/errors.ts

export class DHTError extends Error {
    constructor(
        message: string,
        public code: string,
        public recoverable: boolean = true
    ) {
        super(message);
        this.name = 'DHTError';
    }
}

export class GatewayError extends DHTError {
    constructor(message: string, public gatewayId: string) {
        super(message, 'GATEWAY_ERROR');
    }
}

export class AuthenticationError extends DHTError {
    constructor(message: string) {
        super(message, 'AUTH_ERROR', false);
    }
}

export class NetworkError extends DHTError {
    constructor(message: string) {
        super(message, 'NETWORK_ERROR');
    }
}

export class RateLimitError extends DHTError {
    constructor(
        message: string,
        public retryAfter: number
    ) {
        super(message, 'RATE_LIMIT');
    }
}
```

### Error Recovery

```typescript
// lib/error-handler.ts

export class ErrorHandler {
    private retryQueue: Map<string, RetryEntry> = new Map();

    async handleError(error: DHTError, context: ErrorContext): Promise<void> {
        switch (error.code) {
            case 'GATEWAY_ERROR':
                await this.handleGatewayError(error as GatewayError, context);
                break;

            case 'AUTH_ERROR':
                await this.handleAuthError(error as AuthenticationError, context);
                break;

            case 'NETWORK_ERROR':
                await this.handleNetworkError(error as NetworkError, context);
                break;

            case 'RATE_LIMIT':
                await this.handleRateLimitError(error as RateLimitError, context);
                break;

            default:
                console.error('Unhandled error:', error);
                this.notifyUser(error.message);
        }
    }

    private async handleGatewayError(
        error: GatewayError,
        context: ErrorContext
    ): Promise<void> {
        // Try alternative gateway
        const newGateway = await context.gatewayManager.selectAlternative(error.gatewayId);
        if (newGateway) {
            await context.gatewayManager.connect(newGateway);
            // Retry original request
            if (context.retryCallback) {
                await context.retryCallback();
            }
        } else {
            this.notifyUser('All gateways unavailable. Please try again later.');
        }
    }

    private async handleRateLimitError(
        error: RateLimitError,
        context: ErrorContext
    ): Promise<void> {
        // Schedule retry
        const retryId = crypto.randomUUID();
        this.retryQueue.set(retryId, {
            callback: context.retryCallback,
            scheduledFor: Date.now() + error.retryAfter * 1000,
        });

        setTimeout(() => {
            const entry = this.retryQueue.get(retryId);
            if (entry?.callback) {
                entry.callback();
                this.retryQueue.delete(retryId);
            }
        }, error.retryAfter * 1000);

        this.notifyUser(`Rate limited. Retrying in ${error.retryAfter} seconds.`);
    }

    private notifyUser(message: string): void {
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon-48.png',
            title: 'DHT Browser',
            message,
        });
    }
}
```

---

## Testing

### Unit Tests

```typescript
// test/unit/api-client.test.ts

import { APIClient, APIError } from '../../lib/api-client';

describe('APIClient', () => {
    let client: APIClient;
    let mockFetch: jest.Mock;

    beforeEach(() => {
        client = new APIClient({
            baseUrl: 'https://gateway.test',
            timeout: 5000,
            retries: 2,
        });

        mockFetch = jest.fn();
        global.fetch = mockFetch;
    });

    it('should make GET request successfully', async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            json: () => Promise.resolve({ data: 'test' }),
        });

        const result = await client.get('/test');
        expect(result).toEqual({ data: 'test' });
        expect(mockFetch).toHaveBeenCalledWith(
            'https://gateway.test/test',
            expect.objectContaining({ method: 'GET' })
        );
    });

    it('should retry on failure', async () => {
        mockFetch
            .mockRejectedValueOnce(new Error('Network error'))
            .mockResolvedValueOnce({
                ok: true,
                json: () => Promise.resolve({ data: 'success' }),
            });

        const result = await client.get('/test');
        expect(result).toEqual({ data: 'success' });
        expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should throw APIError on 4xx response', async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 401,
            json: () => Promise.resolve({ message: 'Unauthorized', code: 'AUTH_REQUIRED' }),
        });

        await expect(client.get('/protected')).rejects.toThrow(APIError);
    });
});
```

### Integration Tests

```typescript
// test/integration/gateway.test.ts

import { GatewayManager } from '../../background/gateway-manager';

describe('Gateway Integration', () => {
    let gatewayManager: GatewayManager;

    beforeAll(async () => {
        gatewayManager = new GatewayManager();
        await gatewayManager.initialize();
    });

    afterAll(async () => {
        await gatewayManager.disconnect();
    });

    it('should discover and connect to gateway', async () => {
        const gateway = await gatewayManager.connect();

        expect(gateway).toBeDefined();
        expect(gateway.reputation).toBeGreaterThanOrEqual(0.85);
        expect(gatewayManager.isConnected()).toBe(true);
    });

    it('should handle gateway failover', async () => {
        const initialGateway = gatewayManager.currentGateway;

        // Simulate gateway failure
        await gatewayManager.simulateFailure(initialGateway.id);

        // Should reconnect to different gateway
        await gatewayManager.waitForReconnection();

        expect(gatewayManager.isConnected()).toBe(true);
        expect(gatewayManager.currentGateway.id).not.toBe(initialGateway.id);
    });

    it('should maintain WebSocket connection', async () => {
        const wsClient = gatewayManager.getWebSocketClient();

        await wsClient.subscribe('wallet', { wallet_id: 'test_wallet' });

        expect(wsClient.isConnected()).toBe(true);
        expect(wsClient.getSubscriptions()).toContain('wallet');
    });
});
```

---

## Related Documents

- [02-network-architecture.md](02-network-architecture.md) - Network topology and gateway architecture
- [03-security-trust.md](03-security-trust.md) - Security constants and cryptographic requirements
- [07-currency-transactions.md](07-currency-transactions.md) - DHT currency and wallet operations
- [09-defense-reputation.md](09-defense-reputation.md) - Reputation thresholds and gateway eligibility

---

**Document Version**: 1.0
**Last Updated**: 2026-01-08
**Canonical For**: Browser extension architecture, Gateway API specification, WebSocket streaming
