# Physical Switch Auto-Configuration

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md), [engineering.md](engineering.md), [api.md](api.md), [cli.md](cli.md) and [user.md](user.md); corrections in engineering.md §12.

Optional automated configuration of the platform's physical switch during bootstrap.

## Overview

When the `switch` section is present in `bootstrap.yaml`, the bootstrap orchestrator configures the
physical switch before deploying the PXE container, so the VLANs and port classes are in place before
any node boots.

The switch follows the [reference network](../architecture/reference-network.md): it is pure L2, it
carries the environment's underlay zone VLANs, and each port carries what its **port class** carries.
Nothing in the `switch` section is a VLAN number: every VLAN, subnet and allowed-VLAN list is derived
from the top-level `environment:` (and any owner-defined `zones:`) by the network plan
(`pkg/sdn/netplan`).

**If no `switch` section is provided**, the administrator configures the switch by hand before running
bootstrap, to the same port classes. Phase 1 is skipped.

## What the switch phase programs

| Item | Derived from |
|------|--------------|
| VLANs | One per zone of the environment, named after the zone, with the zone's IPv4 subnet. Environment 4: VLANs 400–408 (`transit` … `backup`), plus any owner-defined zone (409–499) |
| Each assigned port | Its class: mode, allowed VLANs, native VLAN and MTU 9216 |

The port classes, for environment _E_ (offsets `x00`–`x08`):

| Class | Mode | Allowed VLANs | Native |
|-------|------|---------------|--------|
| `gateway` | trunk | x00, x01, x04, x05, x06, x08 | none |
| `hypervisor` | trunk | x01, x03–x08 | x05 (`provisioning`) |
| `bmc` | access | x02 | — |
| `mgmt-uplink` | trunk | x02 | none |
| `peer-link` | trunk | every zone VLAN of the block | none |

An owner-defined zone joins the `gateway` and/or `hypervisor` trunks it lists in its `port_classes`.
Every port is set to MTU 9216 so VXLAN encapsulation never fragments.

A hypervisor port's native VLAN is `provisioning`, so a factory NIC PXE-boots into provisioning on the
same trunk that later carries the node's other zones: the port needs no move after enrollment. The
platform's own port lifecycle (provisioning → the role's zones → quarantine → down) is enforced on the
node's OVS port and, where platformd drives the switches, by `pkg/sdn/fabric`
([fabric configuration](../sdn/fabric/configuration.md)).

## Supported Vendors

### Cisco Nexus (`vendor: cisco-nexus`)

Connects via SSH and applies NX-OS configuration commands: creates VLANs with names, sets each port's
mode, allowed VLANs, native VLAN, MTU and description, and brings it up.

```yaml
environment:
  id: 4
  ula: fd12:3456:789a::/48     # example ULA; generate your own random /48

switch:
  vendor: cisco-nexus
  host: 192.0.2.10
  user: admin
  ssh_key: ~/.ssh/switch_key
  known_hosts_path: /etc/platform/switch/known_hosts
  port_assignments:
    - port: Ethernet1/3
      class: gateway
      description: "gw-01 data trunk"
    - port: Ethernet1/25-27
      class: hypervisor
      description: "cp and compute trunks"
    - port: Ethernet1/41
      class: bmc
      description: "gw-01 BMC"
    - port: Ethernet1/49-50
      class: peer-link
```

`port` accepts a single interface or a range (`Ethernet1/25-27`).

### `noop`

Accepts the configuration and does nothing. For tests and dry runs.

## Host-Key Verification (required)

Switch SSH runs on the go-xkms SSH stack (reached through the go-quicbaas SDK re-exports), the same
stack the fabric driver uses (`pkg/sdn/fabric/nexus`). Two security properties follow from this:

- **The private key is enclave-sealed.** The key at `ssh_key` is loaded into a memory-protected buffer
  and parsed inside the enclave; the plaintext private key never lingers in process memory.
- **The host key is verified against a pinned store — no trust-on-first-use.** The handshake checks the
  switch's presented host key against pinned envelopes resolved from the directory containing
  `known_hosts_path`. There is no accept-on-first-connect path.

Switch SSH is therefore **fail-closed**: if `known_hosts_path` is empty, or the directory holds no pin
for the switch, the connection is refused and Phase 1 errors out.

| Field | Required | Description |
|-------|----------|-------------|
| `ssh_key` | Yes | Path to the SSH private key file used to authenticate to the switch. |
| `known_hosts_path` | Yes (for SSH vendors) | Path whose containing directory holds the pinned host-key envelopes for the switch. |

### Provisioning the pin

Operators pre-populate the pin directory with the switch's host key before running bootstrap (the
legacy flat OpenSSH `known_hosts` file is not consumed — the store expects per-pin envelopes, so the
file cannot be hand-written). The `deployer-pin` binary is the supported way to write one, despite its
name: it writes the same `(service, owner, host)` pin the switch driver reads back, and `--owner` selects
whose pin it is. The pin is addressed by the switch's `name`, falling back to `host`, so `--owner` must be
that value — `--host` alone would key the pin by IP, and a switch with a `name` would not find it. This
mirrors the host-key-pinning workflow of the fabric driver (`docs/sdn/fabric/configuration.md`, the
`known-hosts-path` field).

**Step 1 — read the switch's fingerprints out of band.** On the switch console (not over an SSH
session you have not already verified), for NX-OS:

```
show ssh key
```

The switch's provisioning record or vendor key sheet serve the same purpose. `ssh-keyscan` does **not**:
it reads the key back over the connection you are trying to verify, so a machine-in-the-middle answers
with its own key. Convert whatever the console prints to `SHA256:` form (`ssh-keygen -lf <pubkey>`) and
collect the fingerprint of *every* host key the switch holds, since the SSH handshake decides which one is
negotiated.

**Step 2 — pin, asserting those fingerprints.**

```bash
make build-deployer-pin        # also produced by `make build`
bin/deployer-pin \
  --host 192.0.2.10 \
  --owner core-sw-1 \
  --dir /etc/platform/switch \
  --expect-fingerprint SHA256:...ed25519...,SHA256:...ecdsa...
```

- `--host` is the switch's `host` (the address bootstrap connects to); add `--port` if the switch does
  not listen on 22.
- `--owner` is the switch's `name`; omit it only when the switch has no `name`, in which case it
  defaults to `--host`, which is what `host` falls back to.
- `--dir` is the store root: the directory that *contains* `known_hosts_path` (here
  `known_hosts_path: /etc/platform/switch/known_hosts`), not the configured path itself.
- `--expect-fingerprint` is mandatory — pinning is not trust-on-first-use. A key that matches none of
  the fingerprints is not written and the command exits non-zero.

The mandatory-fingerprint, idempotence and rotation behaviour is the same as for the deployer; see
[Provisioning the pin in `deployer.md`](deployer.md#provisioning-the-pin) and
[`deployer-pin`](../daemon/cli.md#73-deployer-pin).

## Retired keys

The literal-number schema is gone. `bootstrap.yaml` refuses these keys with an error naming the line
and the replacement:

| Retired key | Use instead |
|-------------|-------------|
| `switch.vlans` | `environment` (the switch carries every zone VLAN) |
| `switch.port_assignments[].mode`, `[].vlans` | `switch.port_assignments[].class` |

## Verifying the plan

`platformctl bootstrap run --dry-run` prints the switch plan: every VLAN with its zone name and subnet,
and every port with its class, allowed VLANs, native VLAN and MTU.

## When Switch Config Is Omitted

If the `switch` section is not present:

1. Phase 1 (switch configuration) is skipped entirely.
2. The administrator must configure every platform port to its class (table above), with MTU 9216, so
   that a hypervisor port's untagged traffic lands in `provisioning` and DHCP/PXE reaches the bootstrap
   container.

## Future Vendor Support

Planned support for additional switch vendors:
- Arista EOS
- Juniper Junos
- SONiC (open networking)
