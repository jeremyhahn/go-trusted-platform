# Provisioning Client

mTLS-authenticated client for device profile fetching and activation.

## Overview

The provisioning client enables devices to authenticate with the Trusted Platform using IDevID certificates, retrieve their configuration profiles, and signal activation readiness.

## Features

- **mTLS Authentication**: Client certificates for device identity
- **Profile Fetching**: Retrieve device configuration from platform
- **Device Activation**: Signal production readiness
- **Context Support**: Cancellation and timeouts
- **Typed Errors**: Distinguishes transient vs permanent failures

## API

### Client Interface

```go
type Client interface {
    // FetchProfile retrieves the device profile
    FetchProfile(ctx context.Context) (*DeviceProfile, error)

    // Activate signals the device is ready for production
    Activate(ctx context.Context) (*ActivateResponse, error)

    // FetchProfileAndActivate combines both operations
    FetchProfileAndActivate(ctx context.Context) (*DeviceProfile, *ActivateResponse, error)

    // Close releases client resources
    Close() error
}
```

### Configuration

```go
type ClientConfig struct {
    ServerURL   string              // Platform API URL
    Certificate *x509.Certificate   // IDevID certificate
    PrivateKey  crypto.PrivateKey   // IDevID private key
    CACertPool  *x509.CertPool      // CA certificates
    Timeout     time.Duration       // Request timeout
}
```

## Usage

### Basic Usage

```go
import (
    "context"
    "github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
)

// Configure client
config := &provisioning.ClientConfig{
    ServerURL:   "https://provisioning.example.com:8443",
    Certificate: idevidCert,
    PrivateKey:  idevidKey,
    CACertPool:  caPool,
    Timeout:     30 * time.Second,
}

client, err := provisioning.NewClient(config, logger)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// Fetch profile and activate
ctx := context.Background()
profile, activateResp, err := client.FetchProfileAndActivate(ctx)
if err != nil {
    log.Fatal(err)
}

// Apply production network configuration
applyNetworkConfig(profile.ProductionNetwork)
```

### With Retry Logic

```go
func provisionWithRetry(ctx context.Context, client *provisioning.Client) error {
    maxRetries := 5
    backoff := time.Second

    for attempt := 1; attempt <= maxRetries; attempt++ {
        profile, _, err := client.FetchProfileAndActivate(ctx)
        if err == nil {
            return applyConfig(profile)
        }

        // Check if error is retryable
        if !isTransientError(err) {
            return err
        }

        log.Printf("Attempt %d failed: %v, retrying in %v", attempt, err, backoff)
        time.Sleep(backoff)
        backoff *= 2
    }

    return fmt.Errorf("provisioning failed after %d attempts", maxRetries)
}
```

## API Endpoints

### GET /api/v1/device/profile

Retrieves the device profile using mTLS authentication.

**Request:**
- Method: GET
- Authentication: mTLS (IDevID certificate)
- Headers: `Accept: application/json`

**Response:**
```json
{
  "serialNumber": "DEVICE-001",
  "productionNetwork": {
    "vlan": 100,
    "useDHCP": true,
    "staticIP": "",
    "gateway": "192.168.100.1",
    "dns": ["10.99.99.2"]
  },
  "acls": [
    {
      "name": "allow-https",
      "priority": 100,
      "match": {"tcp_dst": "443"},
      "action": "allow"
    }
  ],
  "rateLimit": {
    "ingressMbps": 1000,
    "egressMbps": 1000
  }
}
```

### POST /api/v1/device/activate

Signals device activation to transition to production network.

**Request:**
- Method: POST
- Authentication: mTLS (IDevID certificate)
- Headers: `Accept: application/json`, `Content-Type: application/json`

**Response:**
```json
{
  "status": "activated",
  "vlan": 100,
  "transitionedAt": "2025-12-21T22:00:00Z"
}
```

## Data Types

### DeviceProfile

```go
type DeviceProfile struct {
    SerialNumber      string            `json:"serialNumber"`
    ProductionNetwork *NetworkConfig    `json:"productionNetwork"`
    ACLs              []ACL             `json:"acls,omitempty"`
    RateLimit         *RateLimitConfig  `json:"rateLimit,omitempty"`
}
```

### NetworkConfig

```go
type NetworkConfig struct {
    VLAN      int      `json:"vlan"`
    UseDHCP   bool     `json:"useDHCP"`
    StaticIP  string   `json:"staticIP,omitempty"`
    Gateway   string   `json:"gateway"`
    DNS       []string `json:"dns,omitempty"`
}
```

### ActivateResponse

```go
type ActivateResponse struct {
    Status         string    `json:"status"`
    VLAN           int       `json:"vlan"`
    TransitionedAt time.Time `json:"transitionedAt"`
}
```

## Error Types

| Error | Condition | Retryable |
|-------|-----------|-----------|
| `ErrCertificateRequired` | Missing client certificate | No |
| `ErrPrivateKeyRequired` | Missing private key | No |
| `ErrCABundleRequired` | Missing CA certificates | No |
| `ErrConnectionFailed` | Network unreachable | Yes |
| `ErrServerError` | Server returned 5xx | Yes |
| `ErrUnauthorized` | Certificate rejected | No |
| `ErrNotFound` | Profile not found | No |
| `ErrInvalidResponse` | Malformed JSON | No |

## Security

### Certificate Requirements

- IDevID certificate issued by platform CA
- Private key protected (TPM-backed recommended)
- CA pool contains platform trust anchors

### Security Checklist

- Certificate validation enabled by default
- Minimum TLS 1.2 enforced
- Private keys never transmitted
- TLS 1.3 required; server certificate always validated against CA pool
- Timeout prevents resource exhaustion
- Error messages don't leak sensitive info
- Context cancellation prevents leaks

## Performance

| Characteristic | Value |
|----------------|-------|
| Connection pooling | Enabled |
| Keep-alive | Enabled |
| Request timeout | Configurable (default 30s) |
| Memory | Minimal allocations |
| Concurrency | Safe for concurrent use |

## Integration Points

### Server-Side Components

| Component | Purpose |
|-----------|---------|
| Device Handler | Profile and activation endpoints |
| Profile Service | Device profile lookup |
| mTLS Middleware | Certificate authentication |
| Policy Engine | Port state transitions |

### Related Components

| Component | Integration |
|-----------|-------------|
| ACME Client | Issues IDevID certificates |
| TPM | Protects IDevID private key |
| Network Setup | Applies production config |
| OVS | VLAN transitions |
