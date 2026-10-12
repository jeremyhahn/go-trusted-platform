# Fabric Configuration Reference

The `sdn.fabric` section describes the physical switches, their peer links and LAGs, and the port class
of every platform port. It carries no VLAN numbers: VLANs, allowed lists and native VLANs are derived
from `sdn.environment` by the network plan ([README](README.md)).

Both decode paths accept the same YAML: `yaml.v3` (gatewayd, bootstrap) and viper with the platform
decode hook (platformd).

## Top level

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `switches` | list | yes (≥1) | The switches |
| `peers` | list | no | vPC/MC-LAG peer pairs; their peer-link ports carry the `peer-link` class |
| `lags` | list | no | Link aggregation groups |
| `ports` | list | no | Port class of each platform port |

## `switches[]`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique switch ID |
| `vendor` | string | yes | Driver name (`cisco-nexus`) |
| `model` | string | no | Hardware model |
| `mgmt-ip` | string | yes | Management address used for SSH |
| `credentials-ref` | string | no | Reference to stored credentials (`kms://…`) |
| `ssh-port` | int | no | SSH port (default 22) |
| `ssh-user` | string | no | SSH user |
| `ssh-password` | string | no | SSH password (secret) |
| `ssh-key-path` | string | for SSH | Private key path; sealed into an enclave buffer on load |
| `known-hosts-path` | string | for SSH | Directory of pinned host-key envelopes; there is no trust-on-first-use. See [Provisioning the host-key pin](#provisioning-the-host-key-pin) |

### Provisioning the host-key pin

The driver refuses a switch whose host key is not pinned. The pin is stored as an envelope under
`(service, switch id, mgmt-ip)`, and the legacy flat OpenSSH `known_hosts` file is not consumed, so the
store cannot be hand-written. The `deployer-pin` binary is the supported way to write it, despite its
name: it writes the same pin the fabric driver reads back, and `--owner` selects whose pin it is. For a
fabric switch `--owner` is the switch `id`, not its address.

**Step 1 — read the switch's fingerprints out of band.** On the switch console (not over an SSH session
you have not already verified), for NX-OS `show ssh key`, or from the provisioning record or vendor key
sheet. `ssh-keyscan` is not a source: it reads the key back over the connection you are trying to verify,
so a machine-in-the-middle answers with its own key. Express each as `SHA256:` (`ssh-keygen -lf
<pubkey>`) and collect the fingerprint of *every* host key the switch holds, since the SSH handshake
decides which one is negotiated.

**Step 2 — pin, asserting those fingerprints.**

```bash
make build-deployer-pin        # also produced by `make build`
bin/deployer-pin \
  --host 192.0.2.11 \
  --owner leaf-1 \
  --dir /etc/platform/fabric \
  --expect-fingerprint SHA256:...ed25519...,SHA256:...ecdsa...
```

| Flag | Value for a fabric switch |
|------|---------------------------|
| `--host` | the switch's `mgmt-ip` |
| `--port` | the switch's `ssh-port`, when it is not 22 |
| `--owner` | the switch's `id` (`leaf-1` above) |
| `--dir` | the directory that *contains* `known-hosts-path` (`known-hosts-path: /etc/platform/fabric/known_hosts` above), not the configured path itself |
| `--expect-fingerprint` | mandatory; a key matching none of them is not written and the command exits non-zero |

Omitting `--owner` keys the pin by `--host`, and the driver, which looks it up by `id`, will not find it.
Idempotence, rotation and the fail-closed checks are the same as for the deployer; see
[Provisioning the pin in `bootstrap/deployer.md`](../../bootstrap/deployer.md#provisioning-the-pin) and
[`deployer-pin`](../../daemon/cli.md#73-deployer-pin). The physical-switch bootstrap path pins the same
way with `--owner` set to the switch `name`
([`bootstrap/switch-management.md`](../../bootstrap/switch-management.md#provisioning-the-pin)).

## `peers[]`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `switch-a`, `switch-b` | string | yes | Switch IDs; both must be declared |
| `peer-link-ports` | list | yes (≥1) | Ports forming the peer link, on both switches |
| `keepalive-dest` | string | no | vPC keepalive destination |

## `lags[]`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | LAG ID |
| `members` | list | yes (≥1) | `{switch-id, port}` |
| `port-channel-id` | int | yes | NX-OS port-channel number |
| `mclag` | bool | no | Multi-chassis (vPC) LAG |
| `esi` | string | no | Ethernet Segment Identifier |
| `lacp-mode`, `lacp-rate` | string | no | `active`/`passive`, `fast`/`normal` |

## `ports[]`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `switch-id` | string | yes | Declared switch |
| `port` | string | yes | Interface (`Ethernet1/25`) or port-channel |
| `lag-id` | string | no | LAG the port belongs to |
| `class` | string | yes | `gateway`, `hypervisor`, `bmc`, `mgmt-uplink` or `peer-link` |
| `description` | string | no | Interface description |

## Validation

`FabricConfig.Validate` refuses, with typed errors:

| Condition | Error |
|-----------|-------|
| No switches; duplicate switch ID; switch without `vendor` or `mgmt-ip` | `ErrInvalidFabricConfig` |
| Peer naming an undeclared switch | `ErrUnknownSwitch` |
| Peer without peer-link ports; LAG without ID, members or port-channel ID | `ErrInvalidFabricConfig` |
| Port without `switch-id` or `port` | `ErrInvalidPortRef` |
| Port on an undeclared switch | `ErrUnknownSwitch` |
| Unknown class | `ErrUnknownPortClass` |
| The same port assigned twice | `ErrDuplicatePort` |

When the manager applies a class, the plan must be able to realise it: a `bmc` port in an environment
whose `management` zone is omitted fails with `ErrPortClassPlan` (wrapping `netplan.ErrEmptyPortClass`).

## Retired fields

The reference switch is pure L2, so the switch-EVPN mode is gone: `mode`, `evpn`, `segments` and a
switch's `vtep-loopback` and `bgp-asn` no longer exist, and neither does the old `VNI = vni-base + VLAN`
rule. Overlay VNIs are `E·100000 + n`, owned by the overlay on the hosts.
