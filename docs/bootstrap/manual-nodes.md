# Manual Node Provisioning

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md), [engineering.md](engineering.md), [api.md](api.md), [cli.md](cli.md) and [user.md](user.md); corrections in engineering.md §12.

Provisioning nodes that do not have BMC (Baseboard Management Controller) access.

## When to Use Manual Mode

Manual mode is appropriate when:

- The server has no BMC (e.g., consumer hardware, Raspberry Pi)
- The BMC is not network-accessible
- The BMC protocol is unsupported (not Redfish or IPMI)
- The node is a virtual machine
- Testing or development environments

## How It Works

For manual nodes, you provide the NIC MAC address directly in the bootstrap config instead of a BMC address. The bootstrap system:

1. Uses the provided MAC address (skips BMC discovery)
2. Configures the PXE container to serve that MAC
3. Waits for the node to PXE boot and become healthy
4. **Does not** power on the node -- the operator must do this manually

## Finding the MAC Address

### Physical Server BIOS/UEFI

1. Enter BIOS/UEFI setup during boot (usually F2, Del, or F12)
2. Navigate to Network or NIC configuration
3. Note the MAC address of the PXE boot interface

### Linux (if OS is already installed)

```bash
ip link show | grep ether
```

### Raspberry Pi

The MAC is printed on the board's Ethernet chip label, or check via:

```bash
cat /sys/class/net/eth0/address
```

### Virtual Machine

Check the VM configuration in your hypervisor (libvirt, VMware, etc.).

## Configuring PXE Boot

For manual nodes, you must configure the BIOS/UEFI to boot from network:

1. Enter BIOS/UEFI setup
2. Enable PXE boot / Network boot
3. Set network boot as the first boot device
4. Ensure the NIC is connected to the provisioning network
5. Save and reboot

## Bootstrap Config Examples

### Single Manual Node

```yaml
nodes:
  - hostname: edge-01
    role: worker
    mac: "aa:bb:cc:dd:ee:ff"
```

### Mixed BMC + Manual Nodes

```yaml
nodes:
  # BMC-managed control plane
  - hostname: cp-01
    role: control-plane
    bmc_address: 192.168.1.10
    bmc_user: admin
    bmc_password: "kms://bmc/cp-01/password"

  # Manual worker (no BMC)
  - hostname: rpi-01
    role: worker
    mac: "dc:a6:32:xx:yy:zz"
    overrides:
      disk: /dev/mmcblk0
```

### All Manual Nodes (Lab Environment)

```yaml
nodes:
  - hostname: lab-cp-01
    role: control-plane
    mac: "52:54:00:01:01:01"

  - hostname: lab-worker-01
    role: worker
    mac: "52:54:00:02:01:01"

  - hostname: lab-worker-02
    role: worker
    mac: "52:54:00:02:01:02"
```

## Operator Responsibilities

For manual nodes, the operator must:

1. **Provide the correct MAC address** in the config
2. **Configure PXE boot** in the server's BIOS/UEFI
3. **Power on the server** when prompted or after the bootstrap container is deployed
4. **Ensure network connectivity** between the server and the provisioning network

When it provisions a manual node, the bootstrap orchestrator logs:

```
bootstrap: provisioning unmanaged node — no board management, no hardware operations; ISO self-boots via after-install=reboot
  hostname=edge-01
  boot_method=pxe
```

## Timing

Manual nodes are included in the health check wait loop. The orchestrator waits up to **25 minutes** (default) for each node to become healthy. If the operator does not PXE boot the node within this window, the bootstrap reports the node as failed.

The default was 10 minutes until 2026-09-02 and is sized to a measured
firstboot cycle, not to boot time (#134): a node completes install-reboot →
firstboot seal → platformd auto-provision → ACME enrollment → service restart
before `/api/v1/status` answers, which took ~15.5 minutes on the reference
hardware. Override per deployment with `platform.health_timeout` — a unit-suffixed
duration such as `40m` ([config-reference.md](config-reference.md#platform)).

Note the blast radius if this is set too low: a node that is merely slow fails
the run, and that failure aborts the remaining-nodes phase — in the run that
motivated the change, a healthy-but-slow gateway cancelled worker orchestration
that had already succeeded.

For large deployments with many manual nodes, consider running bootstrap in phases:

```bash
# Deploy container first
platformctl bootstrap deploy --config bootstrap.yaml

# Power on all manual nodes

# Run full bootstrap (will discover + wait for health)
platformctl bootstrap run --config bootstrap.yaml
```
