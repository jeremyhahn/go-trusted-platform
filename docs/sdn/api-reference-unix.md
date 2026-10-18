# SDN Unix Socket API Reference

Socket: `/run/platformd.sock`

The Unix transport is **gRPC over a Unix domain socket** — it serves
the same `platform.v1.SDNService` as TCP port 10443 (see
[gRPC API Reference](api-reference-grpc.md) for the service definition
and messages). The server authenticates callers with Unix peer
credentials (SO_PEERCRED); socket file permissions gate which
users/groups may connect.

`AuthenticatePort` and `RevokePortAuth` are refused here as on TCP, with
`FAILED_PRECONDITION` (`policy.ErrPortAuthNotEnforced`); see
[api.md](api.md) §4.

## CLI Usage

`platformctl` uses the Unix socket for local IPC; force it explicitly
with `--transport unix` (or `PLATFORMCTL_TRANSPORT=unix`):

```bash
# Bridge operations
platformctl --transport unix sdn bridge create --id br0 --name br0 --type ovs
platformctl --transport unix sdn bridge get br0
platformctl --transport unix sdn bridge list
platformctl --transport unix sdn bridge delete br0

# Port operations
platformctl --transport unix sdn port add --bridge br0 --id eth0 --name eth0 --type physical
platformctl --transport unix sdn port state eth0 --bridge br0
platformctl --transport unix sdn port set-state eth0 --bridge br0 --admin-state down
platformctl --transport unix sdn port stats eth0 --bridge br0
platformctl --transport unix sdn port delete eth0 --bridge br0

# Flow operations
platformctl --transport unix sdn flow add --bridge br0 --id f1 --table 0 --priority 100 \
  --in-port 1 --action output --action-port 2
platformctl --transport unix sdn flow list --bridge br0
platformctl --transport unix sdn flow delete f1 --bridge br0

# VLAN operations
platformctl --transport unix sdn vlan create --id 100 --name tenant-a --bridge br0
platformctl --transport unix sdn vlan list --bridge br0
platformctl --transport unix sdn vlan delete 100 --bridge br0

# Policy operations
platformctl --transport unix sdn policy apply --id acl-1 --name tenant-acl \
  --type acl --priority 100 --bridge br0 --enabled
platformctl --transport unix sdn policy get acl-1
platformctl --transport unix sdn policy list
```

## Go Client

Use the platform Go SDK (`sdk/go`), which dials the Unix socket with
the platform's Unix transport credentials — the same path the CLI uses.

## See Also

- [gRPC API Reference](api-reference-grpc.md) — Full service definition
- [API Reference](api-reference.md) — Overview and data types
- [CLI Usage](cli-usage.md) — Full CLI reference
