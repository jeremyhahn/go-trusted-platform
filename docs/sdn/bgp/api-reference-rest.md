# BGP REST API Reference

BGP endpoints live under the gateway REST surface
(`pkg/api/rest/gateway_handlers.go`), served on HTTPS port 8443 with
mTLS / platform JWT authentication.

## Endpoints

```http
GET    /api/v1/sdn/gateway/bgp/status               # Speaker status
GET    /api/v1/sdn/gateway/bgp/peers                # List peers
GET    /api/v1/sdn/gateway/bgp/prefixes             # List announced prefixes
POST   /api/v1/sdn/gateway/bgp/prefixes             # Announce a prefix
DELETE /api/v1/sdn/gateway/bgp/prefixes/{prefix}    # Withdraw a prefix
```

### Announce a Prefix

```http
POST /api/v1/sdn/gateway/bgp/prefixes
Content-Type: application/json

{
  "prefix": "2001:db8::/36",
  "next_hop": "10.0.0.1"
}
```

`next_hop` is optional. Withdraw uses the URL-encoded prefix as the
path parameter.

Peer configuration is YAML-driven (see [Configuration](configuration.md));
there are no peer-management endpoints.

## See Also

- [Gateway REST API Reference](../gateway/api-reference-rest.md)
- [CLI Usage](cli-usage.md)
