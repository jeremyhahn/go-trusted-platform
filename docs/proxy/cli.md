# Trusted Reverse Proxy — CLI

> **Status: NORMATIVE** · Scope: `platformctl proxy` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every verb and every flag below was read out of `pkg/cli/commands/proxy/` on
> 2026-08-18.

---

## 1. Command group

```
platformctl proxy              Reverse-proxy configuration management
platformctl proxy route        Proxy route operations
platformctl proxy pool         Proxy backend pool operations
```

Five direct children: `route`, `pool`, `status`, `reload`, `zone-matrix`
(`proxy.go: NewCommand`). Registered on the root command at
`pkg/cli/commands/root.go:189`.

**These verbs configure platformd, not a running gatewayd.** platformd is the
source of truth for routes and pools; gatewayd instances sync it and run the
engine. Nothing here reaches into a gateway's live engine — a change takes
effect on that gateway's next sync tick.

### Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go:129`), precedence
**flag > environment > config file > built-in default**:

| Flag | Short | Default | Environment | Meaning |
|---|---|---|---|---|
| `--config` | `-c` | platform default config path | `PLATFORMCTL_CONFIG` | Config file |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` | Named context to use |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` | `unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded` |
| `--server` | | from context | `PLATFORMCTL_SERVER` | Server address; implies a remote context |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` | TLS SNI / certificate verification hostname |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` | `table`, `json`, `yaml` |
| `--verbose` | `-v` | `false` | | Verbose output |
| `--no-color` | | `false` | `NO_COLOR` | Disable coloured output |

**Which verbs work without a server.** All of them are client verbs and need a
reachable `platformd` on the selected transport. `--transport embedded` runs
the services in-process and is the only way to use them with no daemon
listening — note that an embedded `ProxyStore` starts empty and dies with the
process.

Every proxy command uses a fixed **30-second** context deadline
(`defaultCLITimeout`); there is no flag to change it.

**Correction:** the package doc comment on `pkg/cli/commands/proxy/proxy.go`
says the client factory "honors the global `--protocol`/`--endpoint` flags".
Those flag names do not exist. The root command defines `--transport` and
`--server`; the comment is stale.

---

## 2. `platformctl proxy route`

Routes map inbound host/path pairs to a backend pool with per-route
authentication requirements. **Every mutation re-validates the full
configuration and bumps the config version.**

| Verb | Argument | Purpose |
|---|---|---|
| `add` | — (all flags) | Create a route |
| `get` | `<id>` (exactly 1) | Fetch a route |
| `update` | — (all flags) | **Replace** a route |
| `delete` | `<id>` (exactly 1) | Remove a route |
| `list` | — | List all routes |

`add` and `update` share one flag set (`routeFlags.register`):

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--id` | string | `""` | **yes** | Route identifier |
| `--host` | string slice | none | no | Exact host to match; repeatable. Empty matches any host |
| `--path-prefix` | string | `/` | no | Must start with `/` |
| `--pool` | string | `""` | **yes** | Backend pool ID |
| `--auth-mode` | string | `""` | **yes** | `public`, `mtls`, `token`, `mtls-or-token` |
| `--require-idevid` | bool | `false` | no | Require an IDevID-backed client certificate |
| `--allowed-zone` | string slice | none | no | SDN zone allowed to reach this route; repeatable |
| `--backend-zone` | string | `""` | no | SDN zone the backend pool lives in |
| `--require-attestation` | bool | `false` | no | Require fresh workload attestation |
| `--attestation-max-age` | duration | `0` | no | Maximum accepted attestation age, e.g. `5m`. `0` falls back to `defaults.attestation-max-age`, then 24h |
| `--required-role` | string slice | none | no | Role required on the caller; repeatable |
| `--required-scope` | string slice | none | no | Token scope required; repeatable. **Token modes only** |
| `--opa-policy` | string | `""` | no | OPA policy name evaluated for this route |
| `--strip-prefix` | bool | `false` | no | Strip the matched prefix before forwarding |
| `--preserve-host` | bool | `false` | no | Forward the inbound `Host` header |

**`--auth-mode` is required and has no default.** The engine is fail-closed:
`ErrRouteAuthModeRequired` rather than an implicit `public`.

**The flags are singular, the config keys are plural.** `--host`,
`--allowed-zone`, `--required-role`, `--required-scope` are repeatable flags
that map onto `hosts`, `allowed-zones`, `required-roles`, `required-scopes` in
YAML. Passing `--allowed-zones` fails.

**`update` is a replace, not a patch.** Any flag you omit is sent at its
zero value. Re-state the full route.

**There is no `--token-zone` flag.** `AuthRequirements.TokenZone` exists in the
engine, `auth.token-zone` exists in the file schema, and `token_zone` exists on
the proto — but `routeFlags` does not bind it and `toProto` does not set it. A
route whose token principals need a zone must be configured through the file,
or through another transport ([api.md](api.md)). Recorded here rather than
resolved.

```bash
# A public route
platformctl proxy route add --id web --path-prefix / --pool web-pool --auth-mode public

# An mTLS route restricted to one zone, prefix stripped
platformctl proxy route add --id api --host api.example.com --path-prefix /api \
    --pool api-pool --auth-mode mtls --allowed-zone trusted --backend-zone services \
    --strip-prefix

# An attested, policy-gated route
platformctl proxy route add --id console --host console.example.com --path-prefix / \
    --pool console-pool --auth-mode mtls --require-idevid \
    --require-attestation --attestation-max-age 5m --opa-policy proxy_authz

# A token route
platformctl proxy route add --id metrics --path-prefix /metrics --pool metrics-pool \
    --auth-mode token --required-scope proxy:read

platformctl proxy route get api
platformctl proxy route update --id api --pool api-pool-v2 --auth-mode mtls --path-prefix /api
platformctl proxy route list -o json
platformctl proxy route delete api
```

Output shapes: `add` and `update` print `{"route": …, "version": N}`; `delete`
prints `{"deleted": "<id>", "version": N}`; `list` prints
`{"routes": [...], "version": N}`; `get` prints the route.

---

## 3. `platformctl proxy pool`

A pool is a set of backends sharing one pooled transport. **A pool referenced
by any route cannot be deleted** — the store returns `ErrPoolInUse` naming the
routes.

| Verb | Argument | Purpose |
|---|---|---|
| `add` | — (all flags) | Create a pool |
| `get` | `<id>` | Fetch a pool |
| `update` | — (all flags) | **Replace** a pool |
| `delete` | `<id>` | Remove a pool |
| `list` | — | List all pools |

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--id` | string | `""` | **yes** | Pool identifier |
| `--backend` | string slice | none | **yes (≥1)** | Backend URL, optionally `URL=WEIGHT`; repeatable |
| `--balancer` | string | `""` | no | Empty defaults to `round-robin`, the only registered balancer |
| `--trust-class` | string | `""` | no | `default`, `bmc` or `internal` (`pkg/trust`). Unknown → `ErrUnknownTrustClass` |
| `--mtls-client-cert` | bool | `false` | no | Present a client certificate to backends |
| `--max-idle-conns-per-host` | int | `0` | no | `0` ⇒ engine default 128 |
| `--idle-conn-timeout` | duration | `0` | no | `0` ⇒ engine default 90s |

**`--backend` weight parsing.** `parseBackend` splits on the **last** `=` and
only treats the tail as a weight if it parses as an integer, so a URL
containing a query string still works. A negative weight is rejected. Backend
URLs must be `http` or `https` with a host.

**Weights are accepted and not used.** The round-robin balancer ignores
`Weight` — [architecture.md](architecture.md) §3. Do not plan capacity on them.

```bash
platformctl proxy pool add --id web-pool \
    --backend https://web-1.internal.example.com:8443=2 \
    --backend https://web-2.internal.example.com:8443=1

platformctl proxy pool add --id api-pool \
    --backend https://api-1.internal.example.com:8443 \
    --trust-class platform --mtls-client-cert \
    --max-idle-conns-per-host 64 --idle-conn-timeout 90s

platformctl proxy pool get web-pool
platformctl proxy pool update --id web-pool --backend https://web-3.internal.example.com:8443
platformctl proxy pool list
platformctl proxy pool delete web-pool
```

---

## 4. `platformctl proxy status`

Show the proxy configuration **store** status: config version, route and pool
counts, and the time of the last mutation. No flags beyond the globals.

```bash
platformctl proxy status
platformctl proxy status -o json
```

This reports platformd's store, **not** a gateway's engine. It cannot tell you
whether a gatewayd has picked the version up; compare its `version` against the
gateway's own health snapshot for that.

---

## 5. `platformctl proxy reload`

Bump the config version without changing state, so every syncing gatewayd
re-fetches on its next tick. No flags beyond the globals. Prints
`{"version": N}`.

```bash
platformctl proxy reload
```

Use it after an out-of-band change, or to force convergence when a gateway
logged a failed reload.

---

## 6. `platformctl proxy zone-matrix`

Show the SDN zone names and the compiled allowed `(from, to)` traffic pairs
used to validate route zone requirements. No flags beyond the globals.

```bash
platformctl proxy zone-matrix
platformctl proxy zone-matrix -o json
```

This is the same matrix that programs OVS flow rules. If a route denies with
`zone_matrix_denied`, this is the table to read. When platformd has no zone
service wired, the call returns **Unavailable / 503**
(`ErrProxyZoneMatrixUnavailable`) rather than an empty matrix.

---

## 7. What the CLI does not cover

| Capability | Reach it with |
|---|---|
| `GetProxyConfig` — the full merged route+pool config plus version | REST, gRPC, Unix, QUIC, MCP, embedded. `proxyClient.Config` exists in the CLI package's interface but no command calls it |
| Setting a route's `token-zone` | Config file, REST, gRPC, Unix, QUIC, MCP, embedded — §2 |
| Anything about a running gatewayd engine (listeners, live route table, counters) | Not exposed on any transport. `Engine.Status()` and `Engine.Metrics()` are in-process only |
| Starting or stopping the proxy service | `gatewayd serve` with `proxy.enabled` — [`docs/gateway/cli.md`](../gateway/cli.md) |

---

## 8. Exit codes and output

Verbs follow the `platformctl` conventions: `0` on success, non-zero on
failure, with the structured error rendered in the selected `--output` format.
`--output json` is the form to parse; the `table` renderer is for humans and its
columns are not a stable interface.

CLI-side failures are typed: `*MessageError` for a missing required flag
(`--id is required`, `--pool is required`, `--auth-mode is required (public,
mtls, token, mtls-or-token)`, `at least one --backend is required`) and
`*WrappedError` around a transport or service failure
(`failed to create proxy route: …`).

---

## 9. Parity

`conventions/feature-docs.md` §4 requires every verb here to have a matching
definition in the integration parity suite. For this feature that is
`ProxyCommands` in `test/integration/proxy/commands.go`, implemented by the CLI
adapter and the five SDK transport adapters and exercised by
`multiprotocol_test.go`. Route CRUD+list, pool CRUD+list, `status`, `reload`
and `zone-matrix` are all covered.

Two notes rather than a clean tick: this repository defines **no
`CommandDefinition` type** (grepped repo-wide, 2026-08-18), so the convention's
literal wording has no referent here; and `GetProxyConfig` is in neither the
CLI nor `ProxyCommands`, so it is the one capability with no parity coverage.
