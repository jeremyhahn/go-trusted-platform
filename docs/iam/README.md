# Trusted Platform IAM

Enterprise-grade Identity and Access Management integrated with the Trusted Platform.

## Overview

Trusted Platform IAM provides complete authentication and authorization capabilities as an integrated module. It leverages QuicBaaS for distributed identity storage and supports hardware-backed credentials via TPM integration.

## Key Features

| Feature | Description |
|---------|-------------|
| **Multi-Protocol API** | REST, gRPC, QUIC, MCP (AI/LLM), Unix socket, CLI |
| **Multi-Tenancy** | Complete tenant isolation with key prefix separation |
| **ABAC Policy Engine** | Attribute-Based Access Control with sub-5us evaluation |
| **mTLS Authentication** | Certificate-based authentication with TPM attestation |
| **WebAuthn/FIDO2** | Passwordless authentication via hardware keys and passkeys |
| **OAuth2/OIDC Provider** | Issue tokens to registered applications |
| **OAuth2/OIDC Consumer** | Federate identity from external providers |
| **SSO** | Single Sign-On across registered applications |
| **Hardware Binding** | TPM-bound credentials for platform attestation |

## Protocol Support

| Protocol | Transport | Port | Use Case |
|----------|-----------|------|----------|
| REST | HTTPS | 8443 | Web clients, external integrations |
| gRPC | TCP | 9443 | High-performance service-to-service |
| QUIC | UDP | 9444 | Low-latency, mobile clients |
| MCP | stdio/HTTP | 9445 | AI/LLM tool integration |
| Unix | Socket | /run/platformd.sock | Local IPC, CLI |
| CLI | - | - | Administrative operations |

## Architecture Decision

**Single Trusted Platform binary with integrated IAM module** - NOT a separate project.

| Aspect | Decision |
|--------|----------|
| Architecture | IAM built into platformd as integrated module |
| Binary | Single `platformd` / `platformctl` binary |
| Activation | Configured via `webservices[].jwt`, `webservices[].webauthn`, `webservices[].cors` |
| Deployment | Integrated with web services |

**Rationale:**
- One binary is simpler to deploy and maintain
- IAM data gets same storage guarantees
- TPM integration shares platform resources
- Single documentation set and unified CLI

## Quick Start

### Configuration

IAM settings are configured within the `webservices` section for each web service instance:

```yaml
# config.yaml
webservices:
  - name: public
    port: 8080
    tls-port: 8443

    # JWT token configuration
    jwt:
      expiration: 60    # Token expiration in minutes (1 hour default)
      issuer: trusted-platform

    # WebAuthn/FIDO2 passwordless authentication
    webauthn:
      display-name: Trusted Platform
      id: localhost
      origins:
        - https://example.com
        - http://localhost:8080

    # CORS settings for browser-based auth
    cors:
      allowed-origins:
        - https://example.com
        - http://localhost:8080
      allowed-methods:
        - GET
        - POST
        - PUT
        - DELETE
        - OPTIONS
      allowed-headers:
        - "*"
      allow-credentials: true

# Password hashing (top-level)
argon2:
  memory: 1
  iterations: 1
  parallelism: 1
  saltLen: 16
  keyLen: 32
```

### Register an Application

```bash
platformctl iam app register \
  --name "my-app" \
  --tenant "my-tenant" \
  --redirect-uris "https://myapp.com/callback"
```

### Create a User

```bash
platformctl iam user create \
  --tenant "my-tenant" \
  --email "alice@example.com" \
  --name "Alice Smith" \
  --role developer
```

### Create a Policy

```yaml
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: basic-access
  tenant: my-tenant

spec:
  rules:
    - name: read-own-data
      effect: allow
      actions: [read]
      resources:
        - keys/users/${subject.id}/**
      subjects:
        authenticated: true
```

```bash
platformctl iam policy create -f policy.yaml
```

## Authentication Methods

| Method | Hardware | Use Case |
|--------|----------|----------|
| WebAuthn/FIDO2 | Optional | Browser-based passwordless |
| mTLS | Optional | Service-to-service, devices |
| OAuth2/OIDC | No | Federated identity, apps |
| TPM Attestation | Yes | Device identity verification |
| Password | No | Legacy fallback (discouraged) |

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | System architecture and components |
| [Configuration](configuration.md) | Complete configuration reference |
| [Authentication](authentication.md) | Authentication methods and flows |
| [User Registration](user-registration.md) | WebAuthn registration and tenant creation |
| [Authorization](authorization.md) | ABAC authorization model |
| [ABAC Policies](abac-policies.md) | Policy syntax reference |
| [API Reference](api-reference.md) | REST and gRPC API documentation |
| [Invitation API](api-reference-invitations.md) | Invitation management API |
| [CLI Usage](cli-usage.md) | Command-line interface |
| [Roadmap](ROADMAP.md) | Development roadmap and progress tracker |

## Integration with Platform Components

| Component | Integration |
|-----------|-------------|
| **KMS** | Key policies, user key ownership |
| **CA** | Certificate issuance for mTLS |
| **TPM** | Hardware-backed credentials, attestation |
| **Web Services** | Token validation, authorization |
| **DNS** | Internal/external zone access control |

## Comparison with AWS IAM/Cognito

| Aspect | AWS IAM/Cognito | Trusted Platform IAM |
|--------|-----------------|----------------------|
| Deployment | Cloud-only | Self-hosted |
| Auth Latency | Network round-trip | Local (~2-5us) |
| Policy Syntax | JSON (verbose) | YAML (clean) |
| Multi-tenancy | Via Organizations | Native |
| Hardware Auth | Limited | TPM + WebAuthn |
| Pricing | Per MAU | Free (self-hosted) |
| Vendor Lock-in | AWS only | None |

## Security Model

### Authentication Security

- **Passwordless by Default** - WebAuthn/FIDO2 for users
- **Certificate-Based** - mTLS for services and devices
- **Hardware Binding** - TPM attestation for trusted devices
- **MFA Support** - TOTP, hardware keys, platform attestation

### Authorization Security

- **Default Deny** - No access without explicit policy
- **ABAC Model** - Fine-grained attribute-based control
- **Tenant Isolation** - Complete data separation
- **Audit Logging** - All access decisions logged

## Related Documentation

- [Authentication Methods](auth-methods.md) - Platform authentication and PKCS #11 configuration

## See Also

- [QuicBaaS IAM Documentation](https://github.com/jeremyhahn/go-quicbaas/tree/main/docs/iam)
- [KMS Documentation](../kms/README.md)
- [TPM Documentation](../tpm/README.md)
