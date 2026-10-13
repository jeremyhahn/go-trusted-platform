# Day Zero Deployment Guide

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md), [engineering.md](engineering.md), [api.md](api.md), [cli.md](cli.md) and [user.md](user.md); corrections in engineering.md §12.

Step-by-step guide for the first deployment of a Trusted Platform cluster from bare metal.

## Prerequisites

- Bare metal servers racked and cabled
- BMC access configured on each server (Redfish or IPMI)
- Network connectivity between the deployment host and all BMC interfaces
- A Linux host with Docker or Podman for the bootstrap container
- SSH key access to the bootstrap container host
- Docker or Podman installed on the bootstrap container host

## Step 1: Inventory Your Hardware

Document each server:
- Hostname
- Role (`control-plane`, `gateway`, or `worker`)
- BMC IP address, username, password
- BMC protocol (`redfish`, `ipmi`, or `auto`)

For servers without BMC, note the NIC MAC address manually.

## Step 2: Create Bootstrap Configuration

Create `bootstrap.yaml`:

```yaml
deployer:
  host: deploy.example.com
  user: admin
  ssh_key: ~/.ssh/id_ed25519
  container_runtime: docker

environment:          # the reference network: every VLAN and subnet is derived
  id: 4               # provisioning is VLAN 405, 192.0.2.0/24

platform:
  domain: example.com
  internal_domain: internal.example.com
  tenant_id: tenant-001
  environment: production
  upstream_dns:
    - 8.8.8.8
    - 8.8.4.4

templates:
  control-plane: templates/control-plane.yaml
  gateway: templates/gateway.yaml
  worker: templates/worker.yaml

nodes:
  - hostname: cp-01
    role: control-plane
    bmc_address: 10.4.2.10
    bmc_user: admin
    bmc_password: "kms://bmc/cp-01/password"

  - hostname: cp-02
    role: control-plane
    bmc_address: 10.4.2.11
    bmc_user: admin
    bmc_password: "kms://bmc/cp-02/password"

  - hostname: cp-03
    role: control-plane
    bmc_address: 10.4.2.12
    bmc_user: admin
    bmc_password: "kms://bmc/cp-03/password"

  - hostname: gw-01
    role: gateway
    bmc_address: 10.4.2.20
    bmc_user: admin
    bmc_password: "kms://bmc/gw-01/password"

  - hostname: worker-01
    role: worker
    bmc_address: 10.4.2.30
    bmc_user: admin
    bmc_password: "kms://bmc/worker-01/password"
```

## Step 3: Create Device Templates

Each role needs a template file defining the device configuration (CA settings, TPM enrollment, network config). See the provisioning documentation for template format.

## Step 4: Validate the Configuration

Run discovery to verify BMC connectivity:

```bash
platformctl bootstrap discover --config bootstrap.yaml
```

Expected output:

```
Discovered Nodes (5)
  HOSTNAME             ROLE            MAC                BMC        SYSTEM INFO
  --------             ----            ---                ---        -----------
  cp-01                control-plane   aa:bb:cc:dd:ee:01  bmc        Dell PowerEdge R750
  cp-02                control-plane   aa:bb:cc:dd:ee:02  bmc        Dell PowerEdge R750
  cp-03                control-plane   aa:bb:cc:dd:ee:03  bmc        Dell PowerEdge R750
  gw-01                gateway         aa:bb:cc:dd:ee:04  bmc        Dell PowerEdge R750
  worker-01            worker          aa:bb:cc:dd:ee:05  bmc        Dell PowerEdge R750
```

## Step 5: Run Bootstrap

```bash
platformctl bootstrap run --config bootstrap.yaml
```

This executes all phases. Monitor the output for per-node status. The process typically takes 15-45 minutes depending on node count and network speed.

## Step 6: Verify Deployment

Check that all nodes are healthy:

```bash
platformctl bootstrap status --config bootstrap.yaml
```

All nodes should show `healthy` status.

## Step 7: Post-Bootstrap

After the cluster is running:

1. **Add more nodes**: Add new entries to `bootstrap.yaml` and re-run. Existing nodes are skipped.
2. **Update templates**: Modify templates and re-seed via the control plane API.
3. **Remove bootstrap container**: If auto-teardown was skipped, run:
   ```bash
   platformctl bootstrap teardown --config bootstrap.yaml
   ```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Discovery fails for a node | BMC unreachable or wrong credentials | Verify BMC IP, username, password |
| Node stuck in `provisioning` | PXE boot failed or health check timeout | Check BIOS boot order, network connectivity |
| Container deploy fails | SSH key or Docker not available | Verify SSH access and container runtime |
| Health check shows `unreachable` | Node not booted or firewall blocking | Check node power state, verify port 8443 is open |
