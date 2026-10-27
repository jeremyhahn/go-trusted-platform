# DNS Unix Socket API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> How to reach the DNS service over the local socket. The cross-transport
> matrix is [api.md](api.md).

| Property | Value |
|----------|-------|
| Socket path | `/run/platformd.sock` (`platformd serve --socket-path`) |
| Protocol | gRPC over a Unix domain socket |
| Service | `platform.v1.DNSService`, as on TCP |
| Caller identity | the socket peer's credentials ([auth architecture](../auth/architecture.md)) |

The socket carries the gRPC service, not the REST routes and not HTTP/1.1.
Every RPC, message and status code is the one in
[api-reference-grpc.md](api-reference-grpc.md); only the dial differs. `platformctl
--transport unix dns ...` drives the same calls ([cli.md](cli.md)).

## Go Client

```go
import (
    platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

conn, err := grpc.NewClient("unix:///run/platformd.sock",
    grpc.WithTransportCredentials(insecure.NewCredentials()))
if err != nil {
    return err
}
defer conn.Close()

client := platformv1.NewDNSServiceClient(conn)
zones, err := client.ListZones(ctx, &platformv1.ListZonesRequest{InternalOnly: true})
```

TLS is not used on the socket; access is the socket's file permissions plus
the peer credentials.

## grpcurl

```bash
grpcurl -plaintext -unix \
  -import-path pkg/api/grpc/proto -proto platform_dns.proto \
  -d '{"fqdn": "ns1.example.internal.", "type": "RECORD_TYPE_A"}' \
  /run/platformd.sock platform.v1.DNSService/Resolve
```

The daemon registers no gRPC server reflection, so `grpcurl` needs the proto.

## Errors

As on gRPC: [api-reference-grpc.md](api-reference-grpc.md#errors) and
[api.md](api.md) §5.
