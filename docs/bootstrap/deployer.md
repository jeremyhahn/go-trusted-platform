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
  known_hosts_path: /etc/platform/deployer/known_hosts
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

> The Cisco target drives the IOS-XE CLI through generated `expect` scripts
> (the guestshell exec model drops the connection after each command), so the
> host-key pinning below applies to the **Linux** deployer and the ISO stager,
> not the Cisco path.

## Host-Key Verification (required for `target: linux`)

The Linux deployer — and the virtual-media ISO stager that streams per-node
ISOs to the same host — run on the go-xkms SSH stack, reached through the
go-quicbaas SDK re-exports (`sdk/go/xkms/ssh/{keys,knownhosts,scope,session}`).
This is the same stack the switch driver and EVPN fabric driver use. Two
security properties follow from it:

- **The private key is enclave-sealed.** The key at `ssh_key` is loaded into a
  memory-protected buffer and parsed inside the enclave; the plaintext private
  key never lingers in process memory and is destroyed when the session
  closes.
- **The host key is verified against a pinned store — no trust-on-first-use.**
  The handshake checks the deployer host's presented host key against pinned
  envelopes resolved from the directory containing `known_hosts_path`. There is
  no `InsecureIgnoreHostKey` / accept-on-first-connect path.

Because of this, the Linux deployer is **fail-closed**: if `known_hosts_path`
is empty, or the directory holds no pin for the host, the connection is refused
and the deploy/verify/teardown/ISO-stage step errors rather than trusting an
unverified key.

Large payloads (multi-gigabyte ISO images and container image tars) are
streamed to the host over this same verified session via the SSH session's
`Upload` primitive: the bytes are piped to a `<path>.partial` temp file, chmod'd,
then atomically renamed onto the final path. Nothing is buffered in memory, and
the transfer never crosses an unverified channel.

| Field | Required | Description |
|-------|----------|-------------|
| `ssh_key` | Yes | Path to the SSH private key file used to authenticate to the deployer host. |
| `known_hosts_path` | Yes (for `target: linux`) | Path whose containing directory holds the pinned host-key envelopes for the deployer host. |

### Provisioning the pin

Operators pre-populate the pin directory with the deployer host's host key
using the xkms SSH tooling before running bootstrap (the legacy flat OpenSSH
`known_hosts` file is not consumed — the store expects per-pin envelopes). The
pin is addressed by the deployer `host` under service scope, mirroring the
host-key-pinning workflow documented for switch management
(`docs/bootstrap/switch-management.md`) and the EVPN fabric driver
(`docs/sdn/fabric/configuration.md`).

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
