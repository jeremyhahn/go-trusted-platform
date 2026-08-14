# BGP gRPC API Reference

There is no standalone `BGPService` — BGP operations are part of
`platform.v1.GatewayService` in `pkg/api/grpc/proto/gateway.proto`,
served on TCP port 10443 (mTLS).

## BGP RPCs

```protobuf
service GatewayService {
  // BGP operations
  rpc GetBGPStatus(GetBGPStatusRequest) returns (GetBGPStatusResponse);
  rpc ListBGPPeers(ListBGPPeersRequest) returns (ListBGPPeersResponse);
  rpc AnnouncePrefix(AnnouncePrefixRequest) returns (AnnouncePrefixResponse);
  rpc WithdrawPrefix(WithdrawPrefixRequest) returns (WithdrawPrefixResponse);
  rpc ListAnnouncedPrefixes(ListAnnouncedPrefixesRequest) returns (ListAnnouncedPrefixesResponse);
}
```

- **GetBGPStatus** — local ASN, router ID, peer counts, announced
  prefix count, running state.
- **ListBGPPeers** — the configured peer set with session state.
- **AnnouncePrefix / WithdrawPrefix** — manage announced prefixes;
  announce accepts an optional next hop.
- **ListAnnouncedPrefixes** — prefixes this speaker is announcing.

Peer configuration (ASNs, addresses, timers, MD5 secrets) is
YAML-driven — see [Configuration](configuration.md). There are no
add/update/delete-peer RPCs.

## Usage Example (Go)

```go
import platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

client := platformv1.NewGatewayServiceClient(conn)

status, err := client.GetBGPStatus(ctx, &platformv1.GetBGPStatusRequest{})

_, err = client.AnnouncePrefix(ctx, &platformv1.AnnouncePrefixRequest{
    Prefix:  "2602:F5BB::/36",
    NextHop: "10.0.0.1",
})
```

## See Also

- [Gateway gRPC API Reference](../gateway/api-reference-grpc.md)
- [CLI Usage](cli-usage.md)
- [Configuration](configuration.md)
