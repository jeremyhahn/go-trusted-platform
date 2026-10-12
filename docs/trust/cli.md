# Trust — CLI

> **Status: NORMATIVE** · Scope: CLI verbs that exercise trust · Last verified: 2026-10-11
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

Trust has **no command group of its own**: the anchor is never configured and
the resolver is a library. Two verbs exercise it; each is documented in full in
its owning feature and summarised here.

## 1. `platformctl bootstrap trust`

Fetches the platform CA bundle through the `bootstrap` class and optionally
installs it into the system trust store. Full reference:
[`docs/bootstrap/cli.md`](../bootstrap/cli.md). It runs **without a server of
its own**: it builds a one-class `trust.Config` from its flags and resolves
directly, so it works on a node that has no CA yet. It is a bootstrap-time verb;
it does not use the SDK transport flags.

| Flag | Type | Default | Required | Purpose |
|---|---|---|---|---|
| `--server-url` | string | — | **yes** | CA bundle server URL (`ErrTrustServerURLRequired` when empty) |
| `--strategy` | string | `auto` | no | `auto` (= `dane`, `noise`, `spki`), `dane`, `noise`, `spki`, `embedded`; anything else is rejected by config validation |
| `--dns-server` | string | — | no | DANE resolver, `host` (port 53) or `host:port`; a control plane's is `:8053` |
| `--hostname` | string | — | no | DANE TLSA name when `--server-url` is an IP |
| `--noise-key` | string | — | noise | Noise_NK server static key, hex |
| `--noise-addr` | string | — | noise | Noise server `host:port` |
| `--spki-pin` | string | — | spki | hex SHA-256 of the server SPKI |
| `--bundle-path` | string | server default | no | bundle endpoint path override |
| `--install-to-system-trust` | bool | `false` | no | write the bundle to `--cert-path` and run `update-ca-certificates` |
| `--cert-path` | string | `/usr/local/share/ca-certificates/platform-ca.crt` | no | install path |
| `--per-method-timeout` | duration | `5s` | no | cap per strategy attempt |

Output: `CA bundle fetched successfully (<n> bytes)` and, with
`--install-to-system-trust`, `CA bundle installed to <path>`. With
`--strategy embedded`: `Using embedded CA bundle (no fetch needed)`.
Exit code is non-zero on `ErrTrustBootstrapFailed` or `ErrTrustInstallFailed`;
a failing `update-ca-certificates` is a warning, not a failure.

```sh
platformctl bootstrap trust \
  --server-url https://cp.example.com:8443 \
  --strategy spki --spki-pin <64-hex-sha256> \
  --install-to-system-trust
```

## 2. Standalone BMC verbs

The standalone `platformctl bmc` verbs resolve BMC TLS through the `bmc` class
with a single-strategy chain, selected by one of two mutually exclusive flags
(both together is `ErrBMCFlagConflict`; reference:
[`docs/bmc/cli.md`](../bmc/cli.md)):

| Flag | Chain | Meaning |
|---|---|---|
| `--bmc-pin <hex>` | `[spki]` | pin the BMC's SPKI |
| `--bmc-ca-file <path>` | `[ca-file]` | trust the BMC certificate chain in this PEM file |

```sh
platformctl bmc ... --bmc-pin <64-hex-sha256>
```

## 3. Not on the CLI

- Anchor inspection: there is no verb that prints or sets the platform anchor.
  `platform-ca-file:` is a gatewayd configuration key.
- `trust:` is configuration, not a command; see
  [engineering.md §4](engineering.md#4-configuration).
