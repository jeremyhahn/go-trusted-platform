# Bootstrap Container Deployer

The bootstrap container provides PXE, DHCP, and TFTP services needed to network-boot bare metal servers. The deployer subsystem handles deploying this container to a target host via SSH.

## Supported Targets

### Linux (`target: linux`)

Deploys to any Linux host with Docker or Podman.

**Requirements:**
- SSH access to the target host
- Docker or Podman installed and running
- Network access to the provisioning subnet

**How it works:**
1. Connects to the host via SSH
2. Copies the bootstrap manifest and configuration files
3. Pulls and starts the bootstrap container
4. Binds the container to the provisioning network interface

```yaml
deployer:
  target: linux
  host: 192.168.1.5
  user: admin
  ssh_key: ~/.ssh/id_ed25519
  container_runtime: docker
```

### Cisco IOS-XE (`target: cisco`)

Deploys to a Cisco IOS-XE guestshell environment. Useful when a network switch doubles as the bootstrap host.

**Requirements:**
- SSH access to the switch
- Guestshell enabled and configured
- Container runtime available in guestshell

```yaml
deployer:
  target: cisco
  host: 192.168.1.254
  user: admin
  ssh_key: ~/.ssh/switch_key
```

## Container Lifecycle

### Deploy

```bash
platformctl bootstrap deploy --config bootstrap.yaml
```

Discovers node MACs, builds a manifest, and deploys the container. The container starts serving PXE, DHCP, and TFTP immediately.

### Verify

The deploy command reports container status after deployment. The `bootstrap status` command checks health of nodes that should have booted.

### Teardown

```bash
platformctl bootstrap teardown --config bootstrap.yaml
```

Stops and removes the container and its data from the target host. Automatically called at the end of `bootstrap run` (Phase 6).

## Defaults

| Setting | Default |
|---------|---------|
| SSH port | 22 |
| Container runtime | docker |
| Remote data directory | /tmp/bootstrap |
| Container name | bootstrap-pxe |
