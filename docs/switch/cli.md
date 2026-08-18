# Managed Switch Provisioning — CLI

> **Status: NORMATIVE** · Scope: `platformctl switch` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every verb and every flag below was read out of `pkg/cli/commands/switch/`
> on 2026-08-18.

---

## 1. Command group

```
platformctl switch    Physical switch management operations
```

Five verbs: `list-ports`, `port-status`, `set-vlan`, `enable-port`,
`disable-port`. Registered on the root command at
`pkg/cli/commands/root.go:193`.

### 1.1 This group does not use the standard transport flags

**`platformctl switch` always speaks REST**, regardless of `--transport`. Every
verb builds a `switchsdk.Client` over an `*http.Client`
(`sdk/go/services/switch/client.go`), not a `cli.BaseCommand` over a
`transport.Adapter`. Consequences:

| Standard flag | Effect on `platformctl switch` |
|---|---|
| `--transport` | **Ignored.** Validated at the root, then unused here. |
| `--server` | **Ignored.** Use `--server-url` (§1.3). |
| `--server-name` | **Ignored.** |
| `--context` | Used **only** to resolve TLS material — `Remote.CACert`, `Remote.ClientCert`, `Remote.ClientKey`. |
| `--output` / `-o` | Honoured: `table`, `json`, `yaml`. |
| `--no-color` | Honoured on table output. |
| `--config`, `--verbose` | Parsed at the root; no local effect. |

There is **no embedded mode** for this group — and none is possible, since
`ServiceRegistry` has no `Switch` field ([api.md](api.md) §2). Every verb needs
a reachable `platformd` REST endpoint.

### 1.2 TLS behaviour

`buildHTTPClient` resolves the CLI context and builds a `*tls.Config` **only**
when the remote context carries `CACert` or `ClientCert`. It sets
`MinVersion: tls.VersionTLS13` and, when both `ClientCert` and `ClientKey` are
present, an mTLS client certificate.

**If the context is missing, unresolvable, or has no remote block, the command
falls back to a bare `&http.Client{}`** — Go's default transport, system root
CAs, no client certificate. That is a silent downgrade from "pinned to your
platform CA" to "any publicly-trusted certificate". Configure a context with a
`ca-cert` before using these verbs against anything you care about.

### 1.3 Common flags

Every verb takes `--server-url`; every verb except `list-ports` also takes
`--port`.

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--server-url` | string | `""` | **yes** | `platformd` REST API URL |
| `--switch` | string | `""` | **yes** | Switch name, as configured in the platform |
| `--port` | string | `""` | yes (all but `list-ports`) | Port name, e.g. `Eth1/3` |

Validation order is fixed and happens **before any network call**:
`--switch` (`switch: --switch is required`), then `--port`
(`switch: --port is required`), then verb-specific flags, then
`--server-url` (`switch: --server-url is required`, raised while building the
client).

**Every operation has a hard 30-second deadline** — `defaultCLITimeout` in
`pkg/cli/commands/switch/switch.go`. It is not configurable. A switch that is
slow to respond over SSH will time out here before it times out anywhere else.

---

## 2. `platformctl switch list-ports`

List every physical port on a switch with its status.

| Flag | Type | Default | Required |
|---|---|---|---|
| `--server-url` | string | `""` | yes |
| `--switch` | string | `""` | yes |

Table columns: `PORT`, `MODE`, `VLAN`, `ENABLED`, `LINK UP`, `DESCRIPTION`.
The `VLAN` column shows the access VLAN for access ports and a comma-separated
trunk VLAN list for trunk ports.

```bash
platformctl switch list-ports \
    --server-url https://platform.example.com:8443 --switch core-01

platformctl switch list-ports \
    --server-url https://platform.example.com:8443 --switch core-01 --output json
```

`--output json` writes the raw `[]*PortStatus` array to stdout — it is **not**
wrapped in the platform response envelope, because the SDK client already
unwrapped it.

---

## 3. `platformctl switch port-status`

Get the full observable state of one port.

| Flag | Type | Default | Required |
|---|---|---|---|
| `--server-url` | string | `""` | yes |
| `--switch` | string | `""` | yes |
| `--port` | string | `""` | yes |

```bash
platformctl switch port-status \
    --server-url https://platform.example.com:8443 --switch core-01 --port Eth1/3
```

**`link_up` and `description` are always empty from this verb.** The
single-port parser does not populate them; `list-ports` does. If you need link
state for one port, read it out of `list-ports`
([architecture.md](architecture.md) §6).

**A nonexistent port does not error.** The parser returns a zero-valued status
rather than a not-found, so you get `mode: access, access_vlan: 0,
enabled: false` for a port that does not exist. Cross-check against
`list-ports`.

---

## 4. `platformctl switch set-vlan`

Move an access-mode port to a VLAN.

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--server-url` | string | `""` | yes | |
| `--switch` | string | `""` | yes | |
| `--port` | string | `""` | yes | |
| `--vlan` | int | `0` | **yes** | VLAN ID, 1–4094 |

`0` is rejected as missing (`switch: --vlan is required`); anything outside
1–4094 is rejected as invalid (`switch: invalid --vlan N (must be 1-4094)`).
Both checks are local.

```bash
platformctl switch set-vlan \
    --server-url https://platform.example.com:8443 \
    --switch core-01 --port Eth1/3 --vlan 200
```

Output is four lines (`Switch`, `Port`, `VLAN`, `Status: ok`) or, with
`--output json`, `{"switch":…,"port":…,"vlan_id":…,"status":"ok"}`.

Three things this verb does **not** do:

- **It does not check the port is in access mode.** It sends
  `switchport mode access` followed by `switchport access vlan N`, which
  converts a trunk port to an access port. On an uplink that is an outage.
- **It does not check the VLAN exists on the switch.** A VLAN that was never
  created will usually make the switch emit an error string, which the driver
  catches — but that depends on the switch's wording, not on a lookup.
- **It does not persist.** Runtime VLAN moves are running-config only and are
  lost on switch reload. VLAN creation during bootstrap does persist
  ([architecture.md](architecture.md) §4).

---

## 5. `platformctl switch enable-port` / `disable-port`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--server-url` | string | `""` | yes |
| `--switch` | string | `""` | yes |
| `--port` | string | `""` | yes |

`enable-port` is `no shutdown`; `disable-port` is `shutdown`.

```bash
platformctl switch enable-port \
    --server-url https://platform.example.com:8443 --switch core-01 --port Eth1/3

platformctl switch disable-port \
    --server-url https://platform.example.com:8443 --switch core-01 --port Eth1/3
```

**There is no confirmation prompt and no `--force` flag on `disable-port`.**
It takes the port down immediately. There is also no dry-run.

---

## 6. Exit codes and output

`0` on success, non-zero on failure. Failures are typed:

| Error string | Cause |
|---|---|
| `switch: --switch is required` | Missing `--switch` |
| `switch: --port is required` | Missing `--port` |
| `switch: --vlan is required` | Missing or zero `--vlan` |
| `switch: invalid --vlan N (must be 1-4094)` | Out of range |
| `switch: --server-url is required` | Missing `--server-url` |
| `switch: failed to create client: …` | Client construction failed |
| `switch: failed to build TLS config: …` | CA or client certificate could not be loaded |
| `switch: <verb> failed: …` | The operation failed on the server; wraps the SDK error, which wraps the HTTP status and body |

All five verbs set `SilenceUsage: true`, so a runtime failure prints the error
without dumping the help text.

`--output json` is the form to parse. The table renderer is for humans and its
columns are not a stable interface.

---

## 7. What the CLI does not cover

| Capability | Reach it with |
|---|---|
| Read a port's access VLAN alone (`GetPortVLAN`) | No transport exposes it — Go only ([api.md](api.md) §4) |
| Create or modify VLANs | Bootstrap configuration only ([`docs/bootstrap/`](../bootstrap/)) |
| Configure port modes declaratively | Bootstrap configuration only |
| Verify a switch against its declared config | Go only (`Configurator.Verify`) |
| List configured switches | Nothing exposes this — you must read the platform config |

---

## 8. Before this works at all

Every verb returns **503** — *"switch service not configured by daemon — REST
surface is dark"* — on a daemon that has no switch service wired, which is the
current default. See [architecture.md](architecture.md) §8 and
[user.md](user.md). Check first:

```bash
curl https://platform.example.com:8443/api/v1/platform/service-registry
```

Look for the `switch` entry and whether `configured` is true.

---

## 9. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a matching
`CommandDefinition` in the integration parity suite. **This repository defines
no `CommandDefinition` type** (grepped repo-wide, 2026-08-18), so the
requirement is unmet — repo-wide, not only for switches. It is recorded here
rather than quietly marked satisfied.

---

## 10. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/cli/global-flags.md`](../cli/global-flags.md) · [`docs/cli/platformctl.md`](../cli/platformctl.md)
- [`docs/sdn/cli.md`](../sdn/cli.md) — the virtual datapath equivalent
