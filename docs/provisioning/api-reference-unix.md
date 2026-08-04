# Config Delivery Unix Socket API Reference

Socket path: `/run/platformd.sock`

## Overview

The Unix transport is **gRPC over a Unix domain socket**: the daemon
registers the same `platform.v1.ConfigDeliveryService` on both the TCP gRPC
server and the UDS gRPC server, so the RPCs, messages, oneof semantics, and
error codes are exactly those documented in
[api-reference-grpc.md](api-reference-grpc.md).

The socket carries no TLS — access control is kernel-level via file
permissions (owner/group + mode `0660`) and SO_PEERCRED. This is the default
transport for local `platformctl` operation.

## Connection

```go
import (
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"

    platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

conn, err := grpc.NewClient("unix:///run/platformd.sock",
    grpc.WithTransportCredentials(insecure.NewCredentials()))
if err != nil { ... }
defer conn.Close()

client := platformv1.NewConfigDeliveryServiceClient(conn)
nonce, err := client.GetNonce(ctx, &platformv1.GetNonceRequest{})
```

Or via the SDK:

```go
client, err := platform.NewClient(ctx,
    platform.WithOnlyProtocol(platform.ProtocolUnix),
    platform.WithUnixSocket("/run/platformd.sock"))
prov := provision.NewClientFromGRPC(client.ConfigDelivery())
```

## CLI Usage

`platformctl` uses the Unix socket by default for the provisioning session
verbs:

```bash
platformctl provision session list
platformctl provision session get <session-id>
platformctl provision session fulfill <session-id> --profile-id 42
platformctl provision session poll <session-id> --output /tmp/config.json
```

See [config-delivery.md](config-delivery.md#session-management-cli) for
full CLI documentation.
