# Physical Switch Auto-Configuration

Optional automated configuration of physical network switches during bootstrap.

## Overview

When the `switch` section is present in `bootstrap.yaml`, the bootstrap orchestrator configures the physical switch before deploying the PXE container. This ensures VLANs and port assignments are in place before any nodes attempt to boot.

**If no `switch` section is provided**, the administrator is responsible for configuring the switch manually before running bootstrap. The system will skip Phase 1 and proceed directly to container deployment.

## Supported Vendors

### Cisco Nexus (`vendor: nexus`)

Connects via SSH and applies NX-OS configuration commands.

**Capabilities:**
- Create VLANs with names and subnets
- Configure port modes (access, trunk)
- Assign VLANs to ports
- Set port descriptions

```yaml
switch:
  vendor: nexus
  host: 192.168.1.254
  user: admin
  ssh_key: ~/.ssh/switch_key
  known_hosts_path: /etc/platform/switch/known_hosts
  vlans:
    provisioning:
      vlan: 998
      subnet: 10.0.100.0/24
    management:
      vlan: 100
      subnet: 10.0.1.0/24
    production:
      vlan: 200
      subnet: 10.0.2.0/24
  port_assignments:
    - port: Ethernet1/1
      mode: trunk
      vlans: [998, 100, 200]
      description: "cp-01 trunk"
    - port: Ethernet1/2
      mode: access
      vlans: [200]
      description: "worker-01 access"
```

## Host-Key Verification (required)

Switch SSH runs on the go-xkms SSH stack (reached through the go-quicbaas
SDK re-exports), the same stack the EVPN fabric driver uses
(`pkg/sdn/fabric/nexus`). Two security properties follow from this:

- **The private key is enclave-sealed.** The key at `ssh_key` is loaded into
  a memory-protected buffer and parsed inside the enclave; the plaintext
  private key never lingers in process memory.
- **The host key is verified against a pinned store — no
  trust-on-first-use.** The handshake checks the switch's presented host key
  against pinned envelopes resolved from the directory containing
  `known_hosts_path`. There is no `InsecureIgnoreHostKey` / accept-on-first-
  connect path.

Because of this, switch SSH is **fail-closed**: if `known_hosts_path` is
empty, or the directory holds no pin for the switch, the connection is
refused and Phase 1 errors out rather than trusting an unverified key. This
replaces the previous behaviour, which accepted any host key.

| Field | Required | Description |
|-------|----------|-------------|
| `ssh_key` | Yes | Path to the SSH private key file used to authenticate to the switch. |
| `known_hosts_path` | Yes (for SSH vendors) | Path whose containing directory holds the pinned host-key envelopes for the switch. |

### Provisioning the pin

Operators pre-populate the pin directory with the switch's host key using
the xkms SSH tooling before running bootstrap (the legacy flat OpenSSH
`known_hosts` file is not consumed — the store expects per-pin envelopes).
The pin is addressed by the switch's `name` (falling back to `host`), so
each switch's host key is tracked independently. This mirrors the
host-key-pinning workflow documented for the EVPN fabric driver
(`docs/sdn/fabric/configuration.md`, the `known-hosts-path` field).

## VLAN Configuration

VLANs are defined as a map of name to ID + subnet:

```yaml
vlans:
  provisioning:
    vlan: 998
    subnet: 10.0.100.0/24
```

The bootstrap system creates VLANs that do not already exist. Existing VLANs are left unchanged.

## Port Assignments

Ports can be configured in `access` or `trunk` mode:

- **access**: Port carries a single VLAN (untagged)
- **trunk**: Port carries multiple VLANs (tagged)

## When Switch Config Is Omitted

If the `switch` section is not present:

1. Phase 1 (switch configuration) is skipped entirely
2. The administrator must ensure:
   - Provisioning VLAN exists and is routable
   - Server ports are in the correct VLAN
   - DHCP/PXE traffic can reach the bootstrap container
   - Servers can reach the control plane after install

## Future Vendor Support

Planned support for additional switch vendors:
- Arista EOS
- Juniper Junos
- SONiC (open networking)
- Cloud provider virtual switches
