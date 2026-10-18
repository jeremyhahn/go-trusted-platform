# SDN — CLI

> **Status: NORMATIVE** · Scope: `platformctl sdn`, `platformctl switch` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Read out of `pkg/cli/commands/sdn/` and `pkg/cli/commands/switch/` on
> 2026-08-18.

---

## 1. Command groups

```
platformctl sdn        Software-defined networking
platformctl switch     Physical switch management
```

`platformctl sdn` has ten subgroups. **Four of them belong to the edge gateway,
not to SDN proper**, and are documented in [`docs/gateway/cli.md`](../gateway/cli.md):

| Subgroup | Feature |
|---|---|
| `bridge`, `port`, `flow`, `vlan`, `policy`, `zone` | SDN — this document |
| `overlay` | SDN — this document (§8) |
| `gateway`, `lb`, `perf`, `ipam` | Edge gateway — [`docs/gateway/`](../gateway/) |

**There is no top-level `platformctl gateway` command.** The gateway CLI lives
under `platformctl sdn gateway`. `pkg/cli/commands/root.go` registers `sdn`,
`proxy` and `switch` as top-level groups; `gateway` is not among the 41.

### Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go:125`), precedence
**flag > environment > config file > default**:

| Flag | Short | Default | Environment |
|---|---|---|---|
| `--config` | `-c` | platform default | `PLATFORMCTL_CONFIG` |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` (`unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded`) |
| `--server` | | from context | `PLATFORMCTL_SERVER` |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` |
| `--verbose` | `-v` | `false` | |
| `--no-color` | | `false` | `NO_COLOR` |

Every verb below needs a reachable daemon. `--transport embedded` runs the
services in-process — except for `platformctl switch`, whose client
(`sdk/go/services/switch`) speaks REST only; the embedded route exists for the
SDK's `Client.Switch()` ([api.md](api.md) §7).

---

## 2. `platformctl sdn bridge`

| Verb | Positional | Purpose |
|---|---|---|
| `create` | — | Create a new bridge |
| `get` | `<bridge-id>` | Bridge details |
| `list` | — | List bridges |
| `delete` | `<bridge-id>` | Delete a bridge |

**`create`**

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--id` | string | | **yes** | Bridge ID |
| `--name` | string | | **yes** | Bridge name |
| `--type` | string | | **yes** | `ovs`, `linux`, `vxlan` |
| `--description` | string | | | Free text |
| `--datapath-id` | string | | | OpenFlow datapath ID |
| `--fail-mode` | string | | | `secure` or `standalone` |
| `--stp` | bool | `false` | | Enable STP |
| `--rstp` | bool | `false` | | Enable RSTP |
| `--mtu` | int | `0` | | MTU (0 = leave default) |

**`--fail-mode secure` is the one to choose on a trusted network.** `standalone`
makes the bridge fall back to normal L2 forwarding when the controller is
unreachable, which is exactly the moment you do not want unmanaged forwarding.

**`list`**: `--type` (`ovs`/`linux`/`vxlan`), `--status` (`up`/`down`/`error`),
`--limit` int, `--cursor` string.

**`delete`**: `--force` (delete even with ports attached), `--delete-ports`,
`--delete-flows`.

```bash
platformctl sdn bridge create --id br-tenant-a --name br-tenant-a \
    --type ovs --fail-mode secure --mtu 9000
platformctl sdn bridge list --type ovs --status up
platformctl sdn bridge delete br-tenant-a --delete-ports --delete-flows
```

---

## 3. `platformctl sdn port`

Every verb requires `--bridge <bridge-id>`.

| Verb | Positional | Purpose |
|---|---|---|
| `add` | — | Add a port to a bridge |
| `delete` | `<port-id>` | Remove a port |
| `state` | `<port-id>` | Get port state |
| `set-state` | `<port-id>` | Set port state |
| `stats` | `<port-id>` | Port statistics |

**`add`**

| Flag | Type | Required | Meaning |
|---|---|---|---|
| `--bridge` | string | **yes** | Bridge ID |
| `--id` | string | **yes** | Port ID |
| `--name` | string | **yes** | Port name |
| `--type` | string | **yes** | `internal`, `physical`, `tap`, `veth`, `vxlan`, `gre` |
| `--tag` | int | | VLAN tag for access ports |
| `--interface` | string | | Host interface to attach |
| `--mac` | string | | MAC address |
| `--mtu` | int | | MTU |
| `--admin-state` | string | | `up` or `down` |

**`set-state`**

| Flag | Type | Required | Meaning |
|---|---|---|---|
| `--bridge` | string | **yes** | Bridge ID |
| `--admin-state` | string | **yes** | `up` or `down` |
| `--ingress-rate` | uint | | Ingress policing rate in bps, a whole multiple of 1000; `0` leaves policing unchanged |
| `--ingress-burst` | uint | | Ingress policing burst in bits, a whole multiple of 1000; needs `--ingress-rate` |
| `--egress-rate` | uint | | Egress shaping rate in bps; `0` leaves shaping unchanged |
| `--egress-burst` | uint | | Egress shaping burst in bits; needs `--egress-rate` |

**Administrative state is not authentication state.** `--admin-state up|down`
controls whether the port is administratively enabled. The eight-value
authentication state machine (`unconnected`, `provisioning`, `enrolled`,
`unauthorized`, `authenticating`, `authorized`, `quarantined`, `blocked`) is a
separate axis, described in [engineering.md](engineering.md) §2, and is driven
by IDevID certificate validation rather than by this flag.

```bash
platformctl sdn port add --bridge br-tenant-a --id p-01 --name vnet0 \
    --type tap --tag 120 --admin-state up
platformctl sdn port state p-01 --bridge br-tenant-a
platformctl sdn port stats p-01 --bridge br-tenant-a --output json
```

---

## 4. `platformctl sdn flow`

| Verb | Positional | Purpose |
|---|---|---|
| `add` | — | Add a flow rule |
| `delete` | `<flow-id>` | Delete a flow rule |
| `list` | — | List flow rules |

**`add`** — `--bridge`, `--id`, `--table` and `--priority` are required.

| Flag | Type | Meaning |
|---|---|---|
| `--bridge` | string | Bridge ID (required) |
| `--id` | string | A label for the flow, recorded in its metadata (required) |
| `--table` | int | Flow table number (required) |
| `--priority` | int | Flow priority (required) |
| `--in-port` | int | Match input port |
| `--dl-src`, `--dl-dst` | string | Match source / destination MAC |
| `--dl-type` | int | Match ethertype |
| `--nw-src`, `--nw-dst` | string | Match source / destination IP |
| `--action` | string slice | Action type; repeatable |
| `--action-port` | int | Output port for the action |

**`list`**: `--bridge` (required), `--table` (default `-1`, meaning all tables),
`--limit`, `--cursor`.

**A flow's ID is its cookie.** `add` returns it as `flow-0x<cookie>` (the
platform stamps every flow it adds with a fresh cookie), `list` reports the
same ID, and `delete <flow-id>` and the flow-stats verbs act on exactly the
flow carrying that cookie. The `--id` label is not an ID: an argument that is
not `flow-<cookie>` is refused rather than handed to Open vSwitch, where it
once matched every flow on the bridge.

`--table` defaults to `-1` on `list` and `0` on `add`. On `add`, `0` is a real
table number, not "unset".

```bash
platformctl sdn flow add --bridge br-tenant-a --id f-drop-all \
    --table 0 --priority 1 --action drop
platformctl sdn flow list --bridge br-tenant-a --table 0
```

---

## 5. `platformctl sdn vlan`

| Verb | Positional | Flags |
|---|---|---|
| `create` | — | `--id` int **1–4094** (required), `--name` (required), `--description`, `--bridge` (repeatable) |
| `delete` | `<vlan-id>` | `--bridge` (required) |
| `list` | — | `--bridge` (filter), `--limit`, `--cursor` |

`--bridge` is a repeatable string slice on `create` and a single string on
`delete` and `list`.

```bash
platformctl sdn vlan create --id 120 --name tenant-a --bridge br-tenant-a
platformctl sdn vlan list --bridge br-tenant-a
```

---

## 6. `platformctl sdn policy`

| Verb | Positional | Purpose |
|---|---|---|
| `apply` | — | Apply a network policy |
| `get` | `<policy-id>` | Policy details |
| `list` | — | List policies |

**`apply`**

| Flag | Type | Required | Meaning |
|---|---|---|---|
| `--id` | string | **yes** | Policy ID |
| `--name` | string | **yes** | Policy name |
| `--type` | string | **yes** | `acl`, `qos`, `nat`, `firewall`, `routing` |
| `--priority` | int | **yes** | Policy priority |
| `--bridge` | string | **yes** | Bridge to apply to |
| `--description` | string | | Free text |
| `--enabled` | bool | | Enable immediately (default `false`) |

**`--enabled` defaults to `false`.** An applied policy does nothing until it is
enabled. That is deliberate — it lets you stage a policy set and turn it on
together — but it also means "I applied it and nothing changed" is expected, not
a bug.

**`list`**: `--type`, `--target`, `--limit`, `--cursor`.

```bash
platformctl sdn policy apply --id acl-tenant-a --name tenant-a-acl \
    --type acl --priority 100 --bridge br-tenant-a --enabled
```

---

## 7. `platformctl sdn zone`

Zones are the underlay VLANs of an environment
([reference network](../architecture/reference-network.md)): nine built-ins at
fixed offsets (transit, fabric, management, hypervisor, quarantine,
provisioning, control-plane, storage, backup) and owner-defined zones at
offsets 9–99. Overlays (`platform`, `tenant`, `public`) are not zones.

| Verb | Purpose |
|---|---|
| `list` | List zones in offset order with their derived VLAN and subnets; `--lifecycle-role` filters (`provisioning`, `quarantine`) |
| `create` | Create an owner-defined zone |
| `update` | Tune a built-in zone's policy or replace an owner-defined zone |
| `delete` | Delete an owner-defined zone, or omit an optional built-in (`--name`, required) |

**`create` / `update`** share flags:

| Flag | Type | Meaning |
|---|---|---|
| `--name` | string | Zone name (required); not `platform`, `tenant`, `public` or `trusted` |
| `--offset` | uint8 | Owner-defined zones: 9–99. A built-in's offset is fixed |
| `--port-class` | string, repeatable | Owner-defined zones: `gateway` and/or `hypervisor`. Fixed for built-ins |
| `--internet-ingress` | bool | Zone accepts internet ingress traffic |
| `--isolate-from` | string, repeatable | Zone this zone never sends to |
| `--allow-to` | string, repeatable | Allowed path: `zone` or `zone:service[,service...]` |
| `--service` | string, repeatable | Service permitted inside the zone |
| `--isolate` | bool | Deny everything except the `--allow-to` paths |
| `--oob` | bool | Built-in `management` only |
| `--lifecycle-role` | string | Built-in `provisioning` and `quarantine` only |
| `--reason`, `--approved-by` | string | `privileged_access`: required together for an `--allow-to` path into `control-plane` or `management` beyond the reference defaults; the daemon audits it |

The flags of `update` replace the zone's policy as a whole. Every accepted
change prints `restart_required`: the network plan is derived when the
daemon starts. A malformed `--allow-to` or a half-set `--reason` /
`--approved-by` is refused before the CLI connects.

There is no `assign` verb: networks are zones, one per zone, derived from the
environment.

```bash
platformctl sdn zone list --lifecycle-role quarantine
platformctl sdn zone create --name lab --offset 9 --port-class hypervisor --isolate
platformctl sdn zone create --name lab-dns --offset 10 --port-class gateway \
  --allow-to control-plane:dns --reason "lab resolver" --approved-by owner
platformctl sdn zone update --name storage --isolate --allow-to storage:nvme-tcp
platformctl sdn zone delete --name lab
```

---

## 8. `platformctl sdn overlay`

VXLAN/EVPN overlay inspection and VNI management.

| Path | Purpose |
|---|---|
| `overlay status` | Overlay controller status |
| `overlay vtep list` / `get <node-id>` | VXLAN tunnel endpoints |
| `overlay vni list` / `create` / `delete <vni>` | Virtual network identifiers |
| `overlay tunnel list` | Active tunnels |
| `overlay mac list` / `forget <mac>` | Remote MAC table |

`overlay mac forget <mac>` drops a learned remote MAC so it is relearned. Reach
for it when a workload moved hosts and traffic is still going to the old VTEP.

---

## 9. `platformctl switch`

Physical switch management — six verbs, deliberately narrow.

```bash
platformctl switch --help
```

The surface is exactly the five `SwitchService` RPCs (list ports, get port
status, set port VLAN, enable port, disable port) plus the group itself. Detail
is in [`docs/switch/`](../switch/).

---

## 10. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a
`CommandDefinition` in the integration parity suite. **No `CommandDefinition`
type exists in this repository** (grepped 2026-08-18), so the requirement is
unmet repo-wide. Raised as an owner question in the migration report.
