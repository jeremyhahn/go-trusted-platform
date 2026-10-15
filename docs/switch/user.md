# Managed Switch Provisioning — Using It

> **Status: NORMATIVE** · Scope: operator tasks for physical switches · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## Read this first

**Runtime switch management is not wired into the daemon today.** The
configuration block is parsed, the routes exist on four transports, and nothing
constructs the service behind them. Every call returns "service unavailable"
until that changes ([architecture.md](architecture.md) §8).

What **does** work today is the bootstrap path: the orchestrator can create
VLANs and set port modes on a switch as phase 1 of a platform bootstrap.

Check which situation you are in before anything else:

```bash
curl https://platform.example.com:8443/api/v1/platform/service-registry
```

Find the `switch` entry. If `configured` is `false`, the reason will read
*"switch service not configured by daemon — REST surface is dark"*, and the
rest of this page's runtime tasks will return 503.

---

## What this is

The platform can drive a physical network switch over SSH: create VLANs at
bootstrap, and at runtime move a single port between VLANs or take it up and
down. It is how a machine gets moved from the provisioning zone to the zones of
its role when the port it is plugged into belongs to a real switch
rather than a virtual bridge.

Two things it is **not**:

- It is **not** the SDN feature. Bridges, virtual ports, flows and 802.1X
  authentication are [`docs/sdn/`](../sdn/) and work on the host's own
  datapath.
- It is **not** a fabric manager. LAGs, MC-LAG and multi-switch convergence
  live in `pkg/sdn/fabric`. This feature is one switch, one port, one command.

---

## Prerequisites

1. **A switch whose CLI speaks Cisco.** The only real vendor identifier is
   `cisco-nexus`, and the driver's commands work on Cisco IOS, IOS-XE, NX-OS
   and Arista EOS. There is also `noop`, which does nothing successfully.
2. **An SSH private key** for a switch account that can enter
   `configure terminal`. **Password authentication does not work** — the field
   exists in the config and the SSH layer never reads it.
3. **A pinned host key.** This is not optional and there is no
   trust-on-first-use. You must pre-populate a pin envelope for the switch
   using the xkms tooling, and point `known_hosts_path` at it. An ordinary
   OpenSSH `known_hosts` file will not do — the store reads per-pin envelopes
   from the directory containing that path.
4. **The right port names.** They are vendor-specific and you must use what the
   switch reports. SSH in and run `show interfaces status`.

---

## Task 1 — Declare a switch

Add a `switches:` block to the platform configuration:

```yaml
switches:
  - name: core-01
    vendor: cisco-nexus
    host: switch-core-01.example.com
    port: 22
    user: automation
    ssh_key: /etc/trusted-platform/switch/core-01.key
    known_hosts_path: /etc/trusted-platform/switch/known_hosts/core-01
    vlans:
      - id: 100
        name: provisioning
        subnet: 203.0.113.0/24
        description: "Device provisioning VLAN"
      - id: 200
        name: trusted
        subnet: 198.51.100.0/24
    ports:
      - port: Eth1/1-10
        mode: access
        access_vlan: 100
        description: "Provisioning rack 1"
      - port: Eth1/48
        mode: trunk
        vlans: [100, 200]
        description: "Uplink"
```

Points that bite people:

- **`name` is load-bearing twice.** It is the key you pass as `--switch`, and
  it is the owner under which the host-key pin is stored. Renaming a switch
  invalidates its pin.
- **`port` has no default.** Set it explicitly, usually `22`.
- **`vlans` and `ports` are bootstrap-only.** They are applied once, by the
  bootstrap orchestrator. Changing them later does not reconfigure a running
  switch.
- **Port ranges expand client-side.** `Eth1/3-5` becomes three interface
  blocks. `mgmt0` and `Eth1/1` are used as-is.

To test the plumbing without touching hardware:

```yaml
switches:
  - name: test-switch
    vendor: noop
```

The no-op driver accepts everything and does nothing.

---

## Task 2 — Bootstrap a switch

Switch configuration runs as phase 1 of a platform bootstrap, straight after
discovery, and only if a switch is declared in the bootstrap configuration. The
orchestrator creates the VLANs, then configures the ports, then closes the
connection.

**This writes the switch's startup configuration.** Both the VLAN and the port
command sets end with `copy running-config startup-config`, so the result
survives a switch reload. A bootstrap run against the wrong switch is not
undone by power-cycling it.

**It is not transactional.** VLANs are applied fully before ports begin. A
failure part-way leaves the switch in a partial state with no rollback — you
fix it by hand or by re-running.

---

## Task 3 — Move a port to a VLAN

```bash
platformctl switch set-vlan \
    --server-url https://platform.example.com:8443 \
    --switch core-01 --port Eth1/3 --vlan 200
```

Three warnings, in order of how much they will cost you:

**This converts the port to access mode.** It sends `switchport mode access`
before `switchport access vlan N`. Run it against a trunk uplink and you take
the trunk down. There is no mode check and no confirmation.

**The VLAN must already exist on the switch.** Nothing verifies it. If it does
not, you are relying on the switch printing something the driver recognises as
an error.

**The change is not persisted.** Runtime VLAN moves are running-config only.
A switch reload reverts them. This is deliberate — activation state belongs to
the platform — but it means a switch that reboots drops every device back to
whatever its startup configuration says.

---

## Task 4 — Look at ports

```bash
platformctl switch list-ports \
    --server-url https://platform.example.com:8443 --switch core-01

platformctl switch port-status \
    --server-url https://platform.example.com:8443 --switch core-01 --port Eth1/3
```

**Prefer `list-ports`.** The single-port path does not report link state or
description — they come back empty every time — and it cannot tell you a port
does not exist: you get a zero-valued status instead of a not-found. The list
path parses the `show interfaces status` table and populates everything.

---

## Task 5 — Take a port up or down

```bash
platformctl switch enable-port  --server-url https://… --switch core-01 --port Eth1/3
platformctl switch disable-port --server-url https://… --switch core-01 --port Eth1/3
```

`disable-port` is `shutdown`. **There is no confirmation, no `--force` and no
dry-run.** On every transport it needs `switch:write`: gRPC
and Unix, QUIC (#767) and the `switch_disable_port` MCP tool (#304)
([api.md](api.md) §7).

---

## Task 6 — Move a port automatically during device activation

You do not call this feature directly. `POST /api/v1/device/activate` does, as
part of admitting an enrolled machine to the zones of its role
([`docs/device/`](../device/)).

The VLAN move is a **deliberate no-op** when no switch service is configured or
when the request carries no switch name and port. So a successful activation
does not by itself mean a physical port changed VLAN — check with `list-ports`
if it matters.

---

## Troubleshooting

**Everything returns 503 / "service unavailable" / "switch service not
initialized".**
The daemon has no switch service wired. This is the default today. Confirm with
`GET /api/v1/platform/service-registry` and read
[architecture.md](architecture.md) §8. This is not a configuration mistake on
your side.

**"ssh connection failed … field ssh_key: must be set".**
You configured `password` instead of `ssh_key`. Password authentication is not
implemented. Note the failure appears at the **first port operation**, not at
startup — the config validator accepts a password and the SSH layer does not.

**"ssh connection failed … field known_hosts_path: must be set; switch SSH
requires pinned host keys".**
Host-key pinning is mandatory. Provision a pin envelope with the xkms tooling
and point `known_hosts_path` at it. There is no way to skip this, by design.

**"unsupported vendor: <x>".**
Only `cisco-nexus` and `noop` exist. The value is case-sensitive.

**"manager not found for switch <name>".**
The name you passed as `--switch` does not match any `name` in the `switches:`
block. Remember the fallback: a switch with no `name` is keyed by its `host`.

**"failed to parse output for …".**
The switch's CLI output did not match what the driver expects. The error
carries the **raw output** — read it. Usually the vendor renamed a column in
`show interfaces status`, or `show interfaces <port> switchport` used different
wording for the access-VLAN line.

**A command "failed" but the switch looks fine.**
Failure detection is a substring check: any output containing `error`,
`invalid`, or `% ` is treated as failure. A port description containing the
word "error" will trip it. Over-eager on purpose — a false failure beats a
silent misconfiguration.

**The port did not actually change.**
Check you are looking at the right switch: two entries with the same `name`
silently collapse into one. Then check `list-ports` rather than `port-status`.

**Two operations at once behaved strangely.**
The SSH manager is not concurrency-safe. Serialise operations per switch.

---

## Operational notes

- **Every operation opens an SSH session on first use and reuses it.** A
  restarted daemon reconnects lazily, so the first port move after a restart is
  slower and is where a bad credential surfaces.
- **Every CLI operation has a hard 30-second timeout.** It is not
  configurable.
- **There are no retries.** One command, one result.
- **There are no metrics and no audit records** for switch operations. Debug
  logging records every CLI command sent; treat `logging.level: debug` on a
  control-plane node as sensitive, because it exposes your fabric session.
- **Nothing is cached.** Every read hits the switch, deliberately: network state
  changes outside the platform, and a stale port map would be used to decide
  where a machine gets to talk.

---

## Where to go next

- [cli.md](cli.md) — every verb and flag
- [api.md](api.md) — every capability on every transport, and the authorization gap
- [architecture.md](architecture.md) — why SSH, why pinned host keys, why two interfaces
- [`docs/sdn/`](../sdn/) — the virtual datapath
- [`docs/device/`](../device/) — the activation path that drives a VLAN move
- [`docs/bootstrap/`](../bootstrap/) — the orchestrator phase that configures a switch
