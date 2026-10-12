# Device API Reference

## Overview

The Device API provides management operations for device identity and profile management in go-trusted-platform, including device registration, profile creation, and profile matching.

## Supported Protocols

| Protocol | Transport | Port | Documentation |
|----------|-----------|------|---------------|
| REST | HTTPS | 8443 | [api-reference-rest.md](api-reference-rest.md) |
| gRPC | TCP | 9443 | [api-reference-grpc.md](api-reference-grpc.md) |
| QUIC | UDP | 9444 | [api-reference-quic.md](api-reference-quic.md) |
| MCP | stdio/HTTPS | 9445 | [api-reference-mcp.md](api-reference-mcp.md) |
| Unix Socket | Unix | /run/platformd.sock | [api-reference-unix.md](api-reference-unix.md) |

## Operations

### Device Operations

| Operation | Description |
|-----------|-------------|
| RegisterDevice | Register a new device with TPM credentials |
| GetDevice | Retrieve device by ID |
| UpdateDevice | Update device information |
| DeleteDevice | Remove device from registry |
| ListDevices | List devices with pagination |
| FindBySerial | Find device by serial number |
| AttestDevice | Perform TPM-based attestation |

### Profile Operations

| Operation | Description |
|-----------|-------------|
| CreateProfile | Create a new device profile |
| GetProfile | Retrieve profile by ID |
| UpdateProfile | Update profile configuration |
| DeleteProfile | Remove profile |
| ListProfiles | List profiles with pagination |
| FindProfileByMACAddress | Find profile by MAC prefix |
| FindProfileBySerial | Find profile by serial prefix |
| FindMatchingProfile | Find profile matching device attributes |

## Error Codes

| Code | HTTP Status | gRPC Status | Description |
|------|-------------|-------------|-------------|
| DEVICE_NOT_FOUND | 404 | NOT_FOUND | Device ID not found |
| PROFILE_NOT_FOUND | 404 | NOT_FOUND | Profile ID not found |
| INVALID_DEVICE_ID | 400 | INVALID_ARGUMENT | Device ID is 0 or invalid |
| INVALID_PROFILE_ID | 400 | INVALID_ARGUMENT | Profile ID is 0 or invalid |
| NO_MATCHING_PROFILE | 404 | NOT_FOUND | No profile matches device |
| DUPLICATE_SERIAL | 409 | ALREADY_EXISTS | Serial number already exists |
| INVALID_VLAN | 400 | INVALID_ARGUMENT | VLAN ID out of range |
| INVALID_ACL | 400 | INVALID_ARGUMENT | ACL configuration invalid |

## Authentication

All API calls require authentication via mTLS or JWT:

```bash
# mTLS
curl --cert client.crt --key client.key --cacert ca.crt \
  https://localhost:8443/api/v1/devices

# JWT
curl -H "Authorization: Bearer <token>" \
  https://localhost:8443/api/v1/devices
```

## Rate Limiting

| Operation | Rate Limit |
|-----------|------------|
| Read operations | 1000/minute |
| Write operations | 100/minute |
| Profile matching | 1000/minute |

## Related Documentation

- [CLI Usage](cli-usage.md) - Command-line interface
- [Configuration](configuration.md) - Device configuration
- [Architecture](architecture.md) - Device architecture
