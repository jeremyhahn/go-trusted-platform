# Daemon Configuration

> **Status: REFERENCE** · Last verified: 2026-10-13
> The `daemon:` listen-address keys, the `platformd serve` flags and environment, and the keys required at load.

Configuration reference for the Trusted Platform daemon (`platformd serve`).

## Configuration Structure

The daemon reads three things, and only these:

| Source | What it sets |
|---|---|
| The `daemon:` section of the platform YAML | Where each network transport binds — `daemon.<transport>.bind-host` and `.port`, nothing else |
| `platformd serve` flags | The Unix socket path, which transports run, mTLS, the listen addresses again (they win over the file) |
| `PLATFORMD_*` environment | The listen addresses, between the flags and the file |

```yaml
daemon:
  rest: {bind-host: 127.0.0.1, port: 8443}
  grpc: {bind-host: 127.0.0.1, port: 10443}
  quic: {bind-host: 127.0.0.1, port: 9444}
  mcp:  {bind-host: 127.0.0.1, port: 9445}
```

Those eight keys are the whole `daemon:` schema: the decoder is
`pkg/config/daemon.go` (`SetDaemonListenerDefaults`, `ResolveDaemonListeners`),
and any other key under `daemon:` is not read. Everything else in the
in-process `daemon.Config` (`pkg/api/daemon/config.go`) — socket mode, shutdown
timeout, REST server timeouts and CORS, MCP server name and limits, the
per-service table — is its `DefaultConfig()` value or is derived at startup;
none of it is configurable from the file, the flags or the environment.

## Listen addresses — bind hosts and ports (#552, #93)

Where each transport binds is configuration, never a literal in code
(handbook `conventions/configuration.md` §3). The
one defaults layer is **loopback on the canonical ports**; a transport reaches
an interface only because an operator named one. `platformd serve` resolves
exactly the keys above through viper and the listeners consume the resolved
value.

| Layer | Form | Example |
|---|---|---|
| Flag (wins) | `--<transport>-bind-host`, `--<transport>-port` on `platformd serve` | `--grpc-bind-host 0.0.0.0 --grpc-port 10443` |
| Environment | `PLATFORMD_DAEMON_<TRANSPORT>_BIND_HOST`, `PLATFORMD_DAEMON_<TRANSPORT>_PORT` | `PLATFORMD_DAEMON_QUIC_BIND_HOST=::` |
| File | `daemon.<transport>.bind-host`, `daemon.<transport>.port` | above |
| Defaults | `127.0.0.1` and 8443 / 10443 / 9444 / 9445 | — |

Precedence is flag > environment > file > defaults, per field: a file that
sets only a port keeps the default host, a flag that names one transport
changes nothing else, and a flag left alone never shadows the environment or
the file. `bind-host` is a host only — empty means every interface, an IP
literal also picks the address family (`tcp4`/`tcp6`), a hostname is resolved
by the listener. A value outside `1..65535`, or a host carrying a port, stops
startup with `ErrServeStartup{Phase: "daemon listener configuration"}` naming
the field.

Both serve paths apply the resolved section in one place
(`applyDaemonListeners`). With webservices enabled, REST is the webservice's
listener on its own `webservices[].bind-host`, documented in
[`docs/web/engineering.md`](../web/engineering.md).

## `platformd serve` flags

| Flag | Default | Effect |
|---|---|---|
| `--socket-path` | `/run/platformd.sock` | Unix socket path, shared by the Unix and gRPC-over-UDS transports |
| `--enable-rest` | `true` | Daemon REST listener on `daemon.rest`; daemon-only mode, where it requires `--enable-mtls` |
| `--enable-grpc` | `true` | gRPC TCP listener on `daemon.grpc` (gRPC always serves the Unix socket) |
| `--enable-quic` | `true` | QUIC listener on `daemon.quic` |
| `--enable-mcp` | `true` | MCP listener on `daemon.mcp` |
| `--enable-mtls` | `false` | Require client certificates on the network transports |
| `--skip-iam-validation` | `false` | Testing only: every transport accepts unauthenticated requests |
| `--<transport>-bind-host`, `--<transport>-port` | see above | Listen address |

In webservices mode (the platform YAML lists at least one `webservices[]`
entry) the webservice
serves REST and the daemon's own REST listener stays off, so `--enable-rest`
and `daemon.rest` apply only in daemon-only mode. The Unix socket is created
with mode `0660` and no group change.

### gRPC TCP needs mTLS or platform tokens under embedded quicbaas

A token without scope claims is authorized on gRPC TCP by the IAM policy
enforcement point (`IAMService.PEP().Check`). The embedded quicbaas SDK does
not implement that check — every call answers `ServiceNotConfigured` — so such
a daemon would serve gRPC and fail every scoped call with `Unavailable`.
`daemon.New` refuses the combination at startup instead, with
`ErrEmbeddedPEPUnavailable`:

| Condition | Refused when all hold |
|---|---|
| `--enable-grpc` | `true` (the default) |
| `--enable-mtls` | `false` (the default) |
| Platform tokens | off: no webservice `jwt.platform-token.enabled: true` |
| `--skip-iam-validation` | `false` |
| `quicbaas.transport` | `embedded`, unset, or no `quicbaas:` section |

Any one of these makes the daemon start:

- `--enable-mtls`: gRPC authorizes by client certificate. Every shipped
  launcher (systemd and OpenRC units, the installer, the compose files and the
  devcontainer) passes it.
- `jwt.platform-token.enabled: true` on the primary webservice: platform tokens
  carry their own scope claims. This applies only in webservices mode; daemon-only
  mode bridges no platform-token config, so there mTLS is the only option.
- `--enable-grpc=false`: no gRPC TCP listener (gRPC still serves the Unix
  socket).
- A remote `quicbaas.transport` (`unix`, `grpc`, `rest`, `quic`): the remote
  SDK answers the check.

The gap is upstream, in go-quicbaas `sdk/go/transport/embedded/handlers_iam.go`
`handleIAMPEPCheck`. The platform builds no local policy engine to replace it
and never falls back to allow. See [auth architecture](../auth/architecture.md).

## TLS

The network transports carry the daemon TLS identity, provisioned at startup
from the platform CA; there is no certificate or key file setting. TLS is
mandatory: when the identity cannot be provisioned the daemon refuses to start
instead of serving plaintext — REST with `ErrRESTServerStartFailed`, gRPC TCP
and MCP with `ErrTLSConfigFailed`, QUIC with `ErrQUICServerStartFailed` (or
`ErrTransportConstructionFailed` from `New` when the QUIC config carries no
TLS at all, #444). MCP serves HTTPS, TLS 1.3 only, under the same
client-certificate policy as REST and gRPC; see [`api.md`](api.md) §5. The
Unix-domain-socket transport is the single sanctioned non-TLS carve-out — it
is filesystem-permission-scoped, not network-exposed.

## Environment Variables

The environment layer is `PLATFORMD_` + the config key with every `.` and
`-` as `_` (`tpconfig.BindDaemonListenerEnv`, installed by the root command).
Only keys viper already knows — defaults, flags or the file — are read from
the environment.

| Variable | Config Path | Description |
|----------|-------------|-------------|
| `PLATFORMD_DAEMON_REST_BIND_HOST` / `_PORT` | `daemon.rest.bind-host` / `.port` | REST bind host / port |
| `PLATFORMD_DAEMON_GRPC_BIND_HOST` / `_PORT` | `daemon.grpc.bind-host` / `.port` | gRPC bind host / port |
| `PLATFORMD_DAEMON_QUIC_BIND_HOST` / `_PORT` | `daemon.quic.bind-host` / `.port` | QUIC bind host / port |
| `PLATFORMD_DAEMON_MCP_BIND_HOST` / `_PORT` | `daemon.mcp.bind-host` / `.port` | MCP bind host / port |

## Required keys at load

These keys are in the platform YAML's `quicbaas:` section, not `daemon:`.
`platformd` checks the keys it cannot start without when it loads the config
file, before it constructs the QuicBaaS factory. A failure is a
`config.ErrInvalidConfigKey` that names the file and the dotted key:

```
config file "/etc/trusted-platform/config.yaml": key quicbaas.spiffe-trust-domain: invalid configuration: SPIFFETrustDomain: spiffe-trust-domain is required for the embedded server: ...
```

| Key | Required when | Why |
|-----|---------------|-----|
| `quicbaas.spiffe-trust-domain` | the embedded server is selected: `quicbaas.transport` is `embedded` or unset, **or the `quicbaas:` section is absent** | qrdb first boot seeds IAM (system tenant, roles, admin certificate) under this trust domain, and the `/init` admin bundle's SPIFFE SAN is issued under it. It must be a lowercase name with no scheme, port or path. |
| `quicbaas.transport` | set | It must be `embedded`, `unix`, `grpc`, `rest` or `quic`. |

The remote transports (`unix`, `grpc`, `rest`, `quic`) run no first boot, so
they do not need a trust domain. No default applies: a config that leaves the
key out is rejected, even if a code-level `App` literal carries a placeholder.
The bootstrap seeder fills the key from `platform.internal_domain` (see
[bootstrap engineering](../bootstrap/engineering.md)).

### Cluster keys

A non-empty `quicbaas.join-addresses` makes the node a member of a go-qrdb
Raft cluster: platformd passes the keys below to go-quicbaas cluster mode.
`quicbaas.Config.Validate` checks them when `App.Init` builds the store, so a
bad cluster config stops platformd before the store opens.

| Key | Rule |
|-----|------|
| `quicbaas.join-addresses` | Every member as `id=host:port`, this node included as `node-id=raft-address`. A bare `host:port`, a repeated ID or a missing self entry is refused. |
| `quicbaas.node-id`, `quicbaas.deployment-id` | Non-zero. `deployment-id` is the same on every member; left at zero, go-quicbaas would derive a different one on each. |
| `quicbaas.raft-address` | Routable: not loopback, unspecified or empty. |
| `quicbaas.raft-tls-cert-file`, `raft-tls-key-file`, `raft-tls-ca-file` | All three set. Raft between peers is always mutual TLS; a clustered config without the files is refused, never run in plaintext. |

TPM-held Raft keys are out of scope until the issuer of peer certificates is
ruled on. The [cluster user guide](../cluster/user.md#configuring-a-cluster)
has the full example.

### Values platformd copies into the embedded server

Some embedded-server settings are not `quicbaas:` keys. `App.initStores`
copies them from other sections before the store starts:

| Source | Embedded server setting | Rule |
|--------|-------------------------|------|
| `tpm.device` | `seal.tpm2.device` | Copied when `tpm.simulator` is off and the device is a concrete path, not empty and not `auto`. go-quicbaas's hardware probe and its tpm2 seal strategy then open the platform's TPM. Without the copy, they open the default `/dev/tpmrm0` while the store starts, even when the platform's TPM is a swtpm socket. On a shared CI runner, that is the runner's own TPM. |
| `barrier.seal_strategy: shamir` | `seal.strategy` and the shamir threshold and share count | The quorum is copied so the embedded barrier enforces it. |

## Example Configurations

### Development (loopback, the defaults)

No `daemon:` section is needed; every transport binds `127.0.0.1` on its
canonical port. gRPC TCP still needs mTLS under embedded quicbaas (see above):

```sh
platformd serve --enable-mtls
```

### Production (gRPC and QUIC on every interface)

```yaml
daemon:
  grpc: {bind-host: 0.0.0.0, port: 10443}
  quic: {bind-host: "::", port: 9444}
```

```sh
platformd serve --enable-mtls
```

### Minimal (Unix socket only)

```sh
platformd serve --enable-rest=false --enable-grpc=false --enable-quic=false --enable-mcp=false
```

## See Also

- [Architecture](architecture.md)
- [API](api.md)
- [User guide](user.md)
