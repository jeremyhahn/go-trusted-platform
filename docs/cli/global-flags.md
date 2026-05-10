# platformctl Global Flags

`platformctl` exposes a small set of persistent flags that control how the
CLI selects a transport, points at a `platformd` instance, and renders
output. All flags follow kubectl-style precedence:

```
flag > environment variable > config file > built-in default
```

## Connection flags

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--config`, `-c` | `PLATFORMCTL_CONFIG` | `~/.platformctl/config.yaml` | Path to the platformctl config file. |
| `--context` | `PLATFORMCTL_CONTEXT` | `current-context` from config | Named context to use; overrides the config's `current_context`. |
| `--server` | `PLATFORMCTL_SERVER` | _(empty)_ | Server address override. When set, an ad-hoc remote context is synthesized (kubectl-style). Implies `ContextTypeRemote` and defaults to gRPC TCP. |
| `--server-name` | `PLATFORMCTL_SERVER_NAME` | _(empty)_ | TLS SNI / certificate verification hostname override. |
| `--transport` | `PLATFORMCTL_TRANSPORT` | _(empty: use context default)_ | Transport protocol override: `unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded`. |

## Output flags

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--output`, `-o` | `PLATFORMCTL_OUTPUT` | `table` | Output format: `table`, `json`, `yaml`. |
| `--verbose`, `-v` | _(none)_ | `false` | Verbose output. |
| `--no-color` | `NO_COLOR` | `false` | Disable colored output. |

## Transport selection

`platformctl` supports six transports. The default is **gRPC over the local
Unix domain socket** (`/run/platformd.sock`), which is the lowest-latency
option and works without TLS configuration when running on the same host as
`platformd`.

### Default behavior

When neither `--server` nor `--transport` is provided:

- The CLI loads the `current_context` from `~/.platformctl/config.yaml`.
- If no config exists, it falls back to `AutoDetectContext()`:
  - `root` user with `/run/platformd.sock` present -> local context.
  - `PLATFORMCTL_SERVER` env set -> remote context.
- A local context selects the `unix` transport, which is gRPC carried over
  the Unix domain socket. This is functionally "gRPC over UDS".

### `--server <address>`

Setting `--server` (or `PLATFORMCTL_SERVER`) synthesizes an ad-hoc remote
context that points at the supplied address. The default protocol for
remote contexts is `grpc` (TCP), so `--server cp.example.com:10443` will
connect via gRPC TCP.

```bash
# gRPC TCP against a remote daemon (TLS via context CA cert / mTLS)
platformctl --server cp.example.com:10443 ca info
```

### `--transport <name>`

`--transport` overrides the transport regardless of how the context was
loaded:

```bash
# REST over HTTPS against a remote daemon
platformctl --server https://cp.example.com:8443 --transport rest ca info

# QUIC over UDP
platformctl --server cp.example.com:9444 --transport quic ca info

# MCP (HTTP) for AI/LLM tooling
platformctl --server http://cp.example.com:9445 --transport mcp ca info

# In-process embedded transport (used by platformd's own subcommands)
platformctl --transport embedded ca info
```

Valid protocol values: `unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded`.

## Removed flags

The following flags previously existed and have been removed in favor of
the unified `--server` / `--transport` pair:

- `--rest-endpoint`
- `--grpc-endpoint`
- `--quic-endpoint`
- `--mcp-endpoint`
- `--unix-socket`

Use `--server <address>` plus `--transport <name>` to target any specific
transport endpoint.

## Daemon-side default

`platformd` itself does **not** dial out via these transports. Its own
subcommands run in-process and use the `embedded` transport, calling the
backing services directly without crossing a network or socket boundary.
`platformctl` (and any external client) is the consumer of `--server` and
`--transport`.
