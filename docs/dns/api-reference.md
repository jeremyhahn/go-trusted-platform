# DNS API Reference

Multi-protocol API documentation for the Trusted Platform DNS service.

## Supported Protocols

| Protocol | Transport | Port | Documentation |
|----------|-----------|------|---------------|
| REST | HTTPS | 8443 | [api-reference-rest.md](api-reference-rest.md) |
| gRPC | TCP | 9443 | [api-reference-grpc.md](api-reference-grpc.md) |
| QUIC | UDP | 9444 | [api-reference-quic.md](api-reference-quic.md) |
| MCP | stdio/HTTPS | 9445 | [api-reference-mcp.md](api-reference-mcp.md) |
| Unix Socket | Unix | /run/platformd.sock | [api-reference-unix.md](api-reference-unix.md) |

## Authentication

All protocols require authentication via one of:

**Bearer Token:**
```
Authorization: Bearer <access_token>
```

**mTLS Client Certificate:**
```
TLS client certificate issued by the platform CA
```

## Operations

### Zone Management

| Operation | Description |
|-----------|-------------|
| CreateZone | Create a new DNS zone |
| GetZone | Retrieve zone by name |
| UpdateZone | Update zone configuration |
| DeleteZone | Delete zone and records |
| ListZones | List all zones |

### Record Management

| Operation | Description |
|-----------|-------------|
| AddRecord | Add record to zone |
| GetRecord | Get specific record |
| UpdateRecord | Update existing record |
| DeleteRecord | Delete record |
| ListRecords | List zone records |

### TLSA/DANE

| Operation | Description |
|-----------|-------------|
| AddTLSARecord | Add TLSA record for DANE |

### Resolution

| Operation | Description |
|-----------|-------------|
| Resolve | Resolve DNS query |

## Authorization

All zone operations require tenant authorization. The caller must own the zone (matching TenantID) to perform modifications.

| Requirement | Description |
|-------------|-------------|
| Tenant Context | Service must have TenantID configured |
| Zone Ownership | Zone TenantID must match caller's TenantID |
| Auto-Assignment | New zones inherit TenantID from the service |

**Protected Operations:**

| Operation | Authorization |
|-----------|---------------|
| CreateZone | TenantID auto-assigned from caller |
| UpdateZone | Must own zone |
| DeleteZone | Must own zone |
| AddRecord | Must own zone |
| UpdateRecord | Must own zone |
| DeleteRecord | Must own zone |
| SignZone | Must own zone |

## Error Handling

All protocols return consistent error codes:

| Code | Description |
|------|-------------|
| `zone_not_found` | Zone does not exist |
| `zone_already_exists` | Zone with name exists |
| `record_not_found` | Record does not exist |
| `record_already_exists` | Record exists |
| `invalid_zone_name` | Invalid zone format |
| `invalid_ip_address` | Invalid IP format |
| `validation_error` | Request validation failed |
| `unauthorized` | Authentication required |
| `forbidden` | Permission denied |
| `unauthorized_zone_access` | Caller tenant does not own the zone |
| `missing_tenant_context` | Service TenantID not configured |

## See Also

- [DNS Overview](README.md)
- [Zones](zones.md)
- [Records](records.md)
- [DNSSEC](dnssec.md)
