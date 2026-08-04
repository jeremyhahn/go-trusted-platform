# Device Provisioning Client

## Overview

The provisioning client provides mTLS-authenticated device enrollment and network transition capabilities. After a device completes ACME enrollment and receives its IDevID certificate, this client enables:

1. Secure profile retrieval from the provisioning server
2. Network activation signaling
3. Production VLAN transition

## Architecture

### Enrollment Flow

```
┌──────────┐         ┌─────────────┐         ┌─────────────┐
│  Device  │         │    ACME     │         │ Provisioning│
│          │         │   Server    │         │   Server    │
└────┬─────┘         └──────┬──────┘         └──────┬──────┘
     │                      │                       │
     │  1. ACME Enrollment  │                       │
     │─────────────────────>│                       │
     │     (enroll-01)      │                       │
     │                      │                       │
     │<─────────────────────│                       │
     │  IDevID Certificate  │                       │
     │                      │                       │
     │  2. Fetch Profile (mTLS with IDevID)         │
     │─────────────────────────────────────────────>│
     │                      │                       │
     │<─────────────────────────────────────────────│
     │     Device Profile (network config, ACLs)    │
     │                      │                       │
     │  3. Signal Activation (mTLS)                 │
     │─────────────────────────────────────────────>│
     │                      │                       │
     │<─────────────────────────────────────────────│
     │     Activation Confirmation                  │
     │                      │                       │
     │  4. Apply Production Network Configuration   │
     │     (VLAN transition complete)               │
     │                      │                       │
```

### Component Architecture

```
┌─────────────────────────────────────────┐
│         Provisioning Client             │
├─────────────────────────────────────────┤
│                                         │
│  ┌───────────────────────────────────┐  │
│  │  mTLS Transport                   │  │
│  │  - IDevID Certificate             │  │
│  │  - TLS 1.2+ Minimum               │  │
│  │  - Server Certificate Validation  │  │
│  └───────────────────────────────────┘  │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │  API Methods                      │  │
│  │  - FetchProfile()                 │  │
│  │  - Activate()                     │  │
│  │  - FetchProfileAndActivate()      │  │
│  └───────────────────────────────────┘  │
│                                         │
└─────────────────────────────────────────┘
```

## Usage

### Basic Usage

```go
import (
    "context"
    "crypto/x509"
    "time"

    "github.com/jeremyhahn/go-trusted-platform/pkg/logging"
    "github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
)

// Load IDevID certificate and private key
cert, err := loadIDevIDCertificate()
if err != nil {
    log.Fatal(err)
}

privateKey, err := loadIDevIDPrivateKey()
if err != nil {
    log.Fatal(err)
}

// Load CA certificate bundle
caPool, err := loadCABundle()
if err != nil {
    log.Fatal(err)
}

// Configure client
config := &provisioning.ClientConfig{
    ServerURL:   "https://provisioning.example.com:8443",
    Certificate: cert,
    PrivateKey:  privateKey,
    CACertPool:  caPool,
    Timeout:     30 * time.Second,
}

logger := logging.DefaultLogger()
client, err := provisioning.NewClient(config, logger)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// Fetch device profile
ctx := context.Background()
profile, err := client.FetchProfile(ctx)
if err != nil {
    log.Fatal(err)
}

log.Printf("Device profile: VLAN=%d, DHCP=%v",
    profile.ProductionNetwork.VLAN,
    profile.ProductionNetwork.UseDHCP)

// Signal activation readiness
activateResp, err := client.Activate(ctx)
if err != nil {
    log.Fatal(err)
}

log.Printf("Activation status: %s, VLAN=%d",
    activateResp.Status,
    activateResp.VLAN)
```

### Complete Provisioning Flow

```go
// Perform complete provisioning in one call
ctx := context.Background()
profile, activateResp, err := client.FetchProfileAndActivate(ctx)
if err != nil {
    log.Fatal(err)
}

// Profile contains network configuration
networkConfig := profile.ProductionNetwork

// Apply network configuration
if networkConfig.UseDHCP {
    configureDHCP(networkConfig.VLAN)
} else {
    configureStaticIP(
        networkConfig.StaticIP,
        networkConfig.Gateway,
        networkConfig.DNS,
    )
}

// Configure VLANs
configureVLAN(networkConfig.VLAN)

log.Printf("Device activated on VLAN %d at %s",
    activateResp.VLAN,
    activateResp.TransitionedAt)
```

### Error Handling

```go
import "errors"

profile, err := client.FetchProfile(ctx)
if err != nil {
    switch {
    case errors.Is(err, provisioning.ErrConnectionFailed):
        log.Println("Network connectivity issue")
        // Retry with backoff
    case errors.Is(err, provisioning.ErrServerError):
        log.Println("Server returned error")
        // Check server logs
    case errors.Is(err, provisioning.ErrInvalidResponse):
        log.Println("Invalid response from server")
        // Check API compatibility
    default:
        log.Printf("Unknown error: %v", err)
    }
}
```

### Context Cancellation

```go
// Set timeout for provisioning operations
ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
defer cancel()

profile, activateResp, err := client.FetchProfileAndActivate(ctx)
if err != nil {
    if ctx.Err() == context.DeadlineExceeded {
        log.Println("Provisioning timed out")
    }
}
```

## Configuration

### ClientConfig

```go
type ClientConfig struct {
    // ServerURL is the base URL of the provisioning server
    ServerURL string

    // Certificate is the client IDevID certificate for mTLS
    Certificate *x509.Certificate

    // PrivateKey is the private key for the IDevID certificate
    PrivateKey crypto.PrivateKey

    // CACertPool contains trusted CA certificates for server verification
    CACertPool *x509.CertPool

    // Timeout is the HTTP client timeout (default: 30s)
    Timeout time.Duration

    // CACertPool contains trusted CA certificates for server verification.
    // TLS 1.3 is required and server certificates are always validated.
    CACertPool *x509.CertPool
}
```

### Default Configuration

```go
config := provisioning.DefaultClientConfig()
config.ServerURL = "https://provisioning.example.com:8443"
config.Certificate = cert
config.PrivateKey = privateKey
config.CACertPool = caPool
```

## API Reference

### FetchProfile

Retrieves the device profile from the provisioning server using mTLS authentication.

```go
func (c *Client) FetchProfile(ctx context.Context) (*ProfileResponse, error)
```

**Parameters:**
- `ctx`: Context for cancellation and timeouts

**Returns:**
- `*ProfileResponse`: Device profile containing network configuration
- `error`: Error if profile fetch fails

**Response Structure:**
```go
type ProfileResponse struct {
    SerialNumber      string
    ProductionNetwork NetworkConfig
    ACLs              []ACLConfig
    RateLimit         *RateLimitConfig
}

type NetworkConfig struct {
    VLAN     uint16
    UseDHCP  bool
    StaticIP string
    Gateway  string
    DNS      []string
}
```

### Activate

Signals the server that the device is ready for network transition.

```go
func (c *Client) Activate(ctx context.Context) (*ActivateResponse, error)
```

**Parameters:**
- `ctx`: Context for cancellation and timeouts

**Returns:**
- `*ActivateResponse`: Activation confirmation
- `error`: Error if activation fails

**Response Structure:**
```go
type ActivateResponse struct {
    Status         string    // "activated"
    VLAN           uint16    // Production VLAN ID
    TransitionedAt time.Time // When transition occurred
}
```

### FetchProfileAndActivate

Performs the complete provisioning flow in one call.

```go
func (c *Client) FetchProfileAndActivate(ctx context.Context) (*ProfileResponse, *ActivateResponse, error)
```

**Parameters:**
- `ctx`: Context for cancellation and timeouts

**Returns:**
- `*ProfileResponse`: Device profile
- `*ActivateResponse`: Activation confirmation
- `error`: Error if either operation fails

**Note:** If profile fetch succeeds but activation fails, the profile is still returned.

## Error Types

### ErrMissingCertificate
Returned when IDevID certificate is not provided in configuration.

### ErrMissingPrivateKey
Returned when IDevID private key is not provided in configuration.

### ErrMissingCABundle
Returned when CA certificate pool is not provided. A CA certificate pool is always
required for server certificate verification (TLS 1.3 minimum).

### ErrConnectionFailed
Returned when network connection to the server fails.

### ErrServerError
Returned when the server responds with an error status code.

### ErrInvalidResponse
Returned when the server response cannot be parsed.

### ErrProfileFetchFailed
Returned when the profile API request fails.

### ErrActivationFailed
Returned when the activation API request fails.

## Security Considerations

### Certificate Validation

The client performs strict certificate validation:
- Verifies server certificate against CA pool
- Requires minimum TLS 1.2
- Validates certificate chain
- Checks certificate expiration

**TLS 1.3 is required.** Server certificates are always validated against the CA pool.
The `InsecureSkipVerify` option is not supported.

### IDevID Certificate

The IDevID certificate is used for mTLS authentication:
- Issued by trusted CA during ACME enrollment
- Bound to TPM (if available)
- Contains device serial number
- Used to identify device to server

### Private Key Protection

The IDevID private key should be:
- Protected by TPM (preferred)
- Encrypted at rest (if software key)
- Never transmitted over network
- Rotated according to policy

## Testing

### Unit Tests

Run unit tests with coverage:

```bash
go test -v -race -cover ./pkg/provisioning/...
```

### Integration Tests

The canonical multi-protocol integration suite lives in
`test/integration/provision/` and runs against a real platformd in the
devcontainer:

```bash
make integration-test-provision
```

### Test Coverage

Current test coverage: **94.2%**

Coverage includes:
- Client initialization with various configurations
- Successful profile fetch and activation
- Error handling for all error types
- Context cancellation and timeouts
- mTLS certificate presentation
- Invalid JSON responses
- Server error responses
- Network failures

## Best Practices

### 1. Always Use Context

```go
// Good: Use context for cancellation
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
profile, err := client.FetchProfile(ctx)

// Bad: Don't use background context without timeout
profile, err := client.FetchProfile(context.Background())
```

### 2. Implement Retry Logic

```go
import "time"

func fetchProfileWithRetry(client *provisioning.Client, maxRetries int) (*ProfileResponse, error) {
    var lastErr error
    backoff := time.Second

    for i := 0; i < maxRetries; i++ {
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        profile, err := client.FetchProfile(ctx)
        cancel()

        if err == nil {
            return profile, nil
        }

        lastErr = err
        if !errors.Is(err, provisioning.ErrConnectionFailed) {
            return nil, err // Don't retry non-transient errors
        }

        time.Sleep(backoff)
        backoff *= 2 // Exponential backoff
    }

    return nil, lastErr
}
```

### 3. Validate Configuration

```go
func validateConfig(config *provisioning.ClientConfig) error {
    if config.ServerURL == "" {
        return errors.New("server URL required")
    }
    if config.Certificate == nil {
        return errors.New("IDevID certificate required")
    }
    if config.PrivateKey == nil {
        return errors.New("private key required")
    }
    return nil
}
```

### 4. Close Client When Done

```go
client, err := provisioning.NewClient(config, logger)
if err != nil {
    return err
}
defer client.Close() // Always close to release resources
```

### 5. Log Important Events

```go
logger.Info("Starting device provisioning",
    "server", config.ServerURL)

profile, err := client.FetchProfile(ctx)
if err != nil {
    logger.Error("Profile fetch failed", "error", err)
    return err
}

logger.Info("Profile fetched successfully",
    "serial", profile.SerialNumber,
    "vlan", profile.ProductionNetwork.VLAN)
```

## Troubleshooting

### Connection Timeout

**Symptom:** `context deadline exceeded`

**Solutions:**
- Verify network connectivity to server
- Check firewall rules
- Increase timeout in configuration
- Verify server is running and accessible

### Certificate Validation Failed

**Symptom:** `x509: certificate signed by unknown authority`

**Solutions:**
- Verify CA certificate bundle is correct
- Check certificate chain completeness
- Ensure server certificate is not expired
- Verify server hostname matches certificate

### Profile Not Found

**Symptom:** `server returned status 404`

**Solutions:**
- Verify device is registered on server
- Check device serial number in IDevID
- Ensure profile exists for device model
- Review server logs for details

### Activation Failed

**Symptom:** `server returned status 500`

**Solutions:**
- Check server logs for errors
- Verify device is in correct state
- Ensure network infrastructure is ready
- Retry activation after delay

## Performance Considerations

### Connection Pooling

The HTTP client reuses connections for multiple requests:

```go
// Client automatically pools connections
client, _ := provisioning.NewClient(config, logger)

// Multiple requests use same connection
profile, _ := client.FetchProfile(ctx)
_, _ = client.Activate(ctx)
```

### Timeouts

Configure appropriate timeouts based on network conditions:

```go
// Fast local network
config.Timeout = 10 * time.Second

// Slow WAN connection
config.Timeout = 60 * time.Second

// Satellite or high-latency link
config.Timeout = 120 * time.Second
```

### Resource Cleanup

Always close the client to release resources:

```go
defer client.Close() // Closes idle connections
```

## See Also

- [ACME Enrollment](CA-ACME.md)
- [Network Setup](network-setup.md)
- [Device Management](feature/device-management.md)
- [mTLS Authentication](../iam/auth-methods.md)
