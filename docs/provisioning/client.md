# Provisioning Client

> **Status: REFERENCE** · Last verified: 2026-10-15
> The `pkg/provisioning` client: profile fetch and activation over mTLS.

mTLS-authenticated client for device profile fetching and activation.

## Overview

The provisioning client enables devices to authenticate with the Trusted Platform using IDevID certificates, retrieve their configuration profiles, and signal activation readiness.

## Features

- **mTLS Authentication**: Client certificates for device identity
- **Profile Fetching**: Retrieve device configuration from platform
- **Device Activation**: Signal production readiness
- **Context Support**: Cancellation and timeouts
- **Sentinel Errors**: Distinguishes transport failures from server refusals

## API

### Client Methods

`provisioning.Client` (`pkg/provisioning/client.go`) is a concrete type:

```go
// FetchProfile retrieves the device profile (GET /api/v1/device/profile)
func (c *Client) FetchProfile(ctx context.Context) (*ProfileResponse, error)

// Activate signals the device is ready (POST /api/v1/device/activate)
func (c *Client) Activate(ctx context.Context) (*ActivateResponse, error)

// FetchProfileAndActivate combines both operations
func (c *Client) FetchProfileAndActivate(ctx context.Context) (*ProfileResponse, *ActivateResponse, error)

// Heartbeat reports liveness (POST /api/v1/device/heartbeat)
func (c *Client) Heartbeat(ctx context.Context) (*HeartbeatResponse, error)

// BootDelivery runs the diskless boot delivery exchange (pkg/provisioning/boot.go)
func (c *Client) BootDelivery(ctx context.Context, quote BootQuoteFunc) (*BootDeliveryResponse, error)

// Close releases client resources
func (c *Client) Close() error
```

### Configuration

```go
type ClientConfig struct {
    ServerURL      string            // Platform API URL
    Certificate    *x509.Certificate // IDevID certificate
    PrivateKey     crypto.PrivateKey // IDevID private key
    CACertPool     *x509.CertPool    // CA certificates
    TLSCertificate *tls.Certificate  // Optional full chain; presented verbatim when set
    Timeout        time.Duration     // Request timeout; 0 means 30s
}
```

`NewClient(config *ClientConfig, logger *logging.Logger)` rejects a missing
certificate, private key or CA pool.

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

// "activated" moved the port to the admitted VLAN; "quarantined" did not
if activateResp.Status == "activated" {
    applyNetworkConfig(profile.AdmittedNetwork)
}
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

        // Only transport failures are worth retrying
        if !errors.Is(err, provisioning.ErrConnectionFailed) {
            return err
        }

        log.Printf("Attempt %d failed: %v, retrying in %v", attempt, err, backoff)
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-time.After(backoff):
        }
        backoff *= 2
    }

    return errProvisioningExhausted
}
```

## API Endpoints

### GET /api/v1/device/profile

Retrieves the device profile using mTLS authentication. The serial comes from
the verified client certificate.

**Request:**
- Method: GET
- Authentication: mTLS (IDevID certificate)
- Headers: `Accept: application/json`

**Response:**
```json
{
  "serialNumber": "DEVICE-001",
  "admittedNetwork": {
    "vlan": 100,
    "useDHCP": true,
    "gateway": "198.51.100.1",
    "dns": ["10.99.99.2"]
  },
  "provisioningNetwork": {
    "vlan": 10,
    "useDHCP": true
  },
  "acls": [
    {
      "name": "acl-0",
      "priority": 100,
      "match": {"protocol": "tcp", "dst_port": "443"},
      "action": "allow"
    }
  ]
}
```

ACL names are `acl-<index>`; `match` keys are `protocol`, `src_ip`, `dst_ip`,
`src_port` and `dst_port` (`ProfileFromDeviceProfile`,
`pkg/webservice/v1/device/profile_service.go`).

### POST /api/v1/device/activate

Signals device activation to transition to the admitted network.

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

`status` is `activated` or `quarantined`; when quarantined, `vlan` is the
quarantine VLAN, never the admitted one.

## Data Types

From `pkg/provisioning/types.go`.

### ProfileResponse

```go
type ProfileResponse struct {
    SerialNumber        string           `json:"serialNumber"`
    AdmittedNetwork     NetworkConfig    `json:"admittedNetwork"`
    ProvisioningNetwork *NetworkConfig   `json:"provisioningNetwork,omitempty"`
    ACLs                []ACLConfig      `json:"acls,omitempty"`
    RateLimit           *RateLimitConfig `json:"rateLimit,omitempty"`
}
```

### NetworkConfig

```go
type NetworkConfig struct {
    VLAN     uint16   `json:"vlan"`
    UseDHCP  bool     `json:"useDHCP"`
    StaticIP string   `json:"staticIP,omitempty"`
    Gateway  string   `json:"gateway,omitempty"`
    DNS      []string `json:"dns,omitempty"`
}
```

### ActivateResponse

```go
type ActivateResponse struct {
    Status         string    `json:"status"`
    VLAN           uint16    `json:"vlan"`
    TransitionedAt time.Time `json:"transitionedAt"`
}
```

## Error Types

Sentinels from `pkg/provisioning/errors.go`; request errors wrap them, so test
with `errors.Is`.

| Error | Condition | Retryable |
|-------|-----------|-----------|
| `ErrMissingCertificate` | Missing client certificate | No |
| `ErrMissingPrivateKey` | Missing private key | No |
| `ErrMissingCABundle` | Missing CA certificates | No |
| `ErrConnectionFailed` | Request could not be sent (network, TLS, timeout) | Yes |
| `ErrServerError` | Server answered any status other than 200 | Depends on the status in the message |
| `ErrInvalidResponse` | Malformed JSON | No |
| `ErrProfileFetchFailed`, `ErrActivationFailed` | The request could not be built | No |

## Security

### Certificate Requirements

- IDevID certificate issued by platform CA
- Private key protected (TPM-backed recommended)
- CA pool contains platform trust anchors

### Security Checklist

- Server certificate always validated against the CA pool
- TLS 1.3 minimum enforced
- Private keys never transmitted
- Timeout prevents resource exhaustion
- Context cancellation prevents leaks

## Performance

| Characteristic | Value |
|----------------|-------|
| Connection pooling | `net/http` transport defaults |
| Keep-alive | `net/http` transport defaults |
| Request timeout | Configurable (default 30s) |
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
| Network Setup | Applies admitted network config |
| OVS | VLAN transitions |
