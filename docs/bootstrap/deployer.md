# Bootstrap Container Deployer

The bootstrap container provides PXE, DHCP, and TFTP services needed to network-boot bare metal servers. The deployer subsystem handles deploying this container to a target host via SSH.

## Deployer Host

The bootstrap container runs on a Linux host with Docker or Podman — the
jumpbox on the provisioning network. (The Cisco IOS-XE app-hosting target was
removed: the platform's own bootstrap container and gatewayd replaced it.
Switch configuration during bootstrap is a separate phase and is unaffected;
see [switch-management.md](switch-management.md).)

**Requirements:**
- SSH access to the host, with its host key pinned (below)
- Docker or Podman installed and running
- Network access to the provisioning subnet
- A netboot media build (`deployer.netboot_media_dir`, `make netboot-media`)

**How it works:**
1. Connects to the host via SSH
2. Copies the bootstrap manifest and stages the netboot media build
3. Ships or pulls and starts the bootstrap container
4. Binds the container to the provisioning network interface

```yaml
deployer:
  host: 192.168.1.5
  user: admin
  ssh_key: ~/.ssh/id_ed25519
  known_hosts_path: /etc/platform/deployer/known_hosts
  container_runtime: docker
  container_image: platform-pxeboot:latest
  netboot_media_dir: bin/netboot-media
```

## Host-Key Verification (required)

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
| `known_hosts_path` | Yes | Path whose containing directory holds the pinned host-key envelopes for the deployer host. |

### Provisioning the pin

Operators pre-populate the pin directory with the deployer host's host key
before running bootstrap (the legacy flat OpenSSH `known_hosts` file is not
consumed — the store expects per-pin envelopes, so the file cannot be
hand-written). The `deployer-pin` binary is the supported way to write one.

**Step 1 — read the host's fingerprints out of band.** On the deployer host's
console (not over an SSH session you have not already verified):

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub
```

The host's provisioning record, install log or vendor key sheet serve the same
purpose. `ssh-keyscan -t ecdsa <host> | ssh-keygen -lf -` does **not**: it reads
the key back over the connection you are trying to verify, so it can confirm a
fingerprint you already hold from one of the channels above, but it is not
itself a source — a machine-in-the-middle answers keyscan with its own key.

**Step 2 — pin, asserting those fingerprints.**

```bash
make build-deployer-pin        # also produced by `make build`
bin/deployer-pin \
  --host 192.168.1.10 \
  --dir /path/to/known_hosts_dir \
  --expect-fingerprint SHA256:...ed25519...,SHA256:...ecdsa...
```

`--expect-fingerprint` is **mandatory** — pinning is not trust-on-first-use
either. If the key the target presents is not one of the fingerprints you
verified, nothing is written and the command exits non-zero, so a
machine-in-the-middle on the provisioning network cannot install itself as the
trusted pin. Pass the fingerprints of *all* the host's keys: which one is
negotiated is decided by the SSH handshake, not by you.

`--dir` is the store root — the directory that *contains* `known_hosts_path`,
not the configured path itself. The tool is idempotent: an identical pin is
left in place, and a differing pin is rotated only after the replacement key
has matched a fingerprint you asserted.

**Nothing is created before the key is accepted.** The comparison happens
before the store is opened, so a rejected key leaves the store exactly as it
was — including leaving `--dir` non-existent on a first run. An already-correct
pin therefore survives a later probe that something else answers: the impostor
is rejected, and the good pin is neither removed nor overwritten.

**Unreadable existing state aborts the run.** Before writing anything the tool
reads what is already pinned for the host. If that record cannot be read — a
corrupt envelope, or a storage backend that errors — the command stops and
writes nothing. "Nothing is recorded" and "what is recorded cannot be read" are
different facts, and only the first one licenses writing a pin; treating an
unreadable record as an absent one would overwrite state nobody could inspect.
Repair or remove the unreadable envelope, then re-run.

The check is scoped to the host being pinned: when that host's own record reads
cleanly, nothing else in the store affects the outcome, so a corrupt pin for one
host never blocks pinning or rotating another — even when both share an
`--owner`. The one exception is a host with *no* record of its own sharing an
owner with a host whose record is unreadable; that run aborts too, because the
store cannot be read well enough to prove the absence. Repair the unreadable
envelope, or pin under a distinct `--owner`.

**Nobody but you may write to the store root.** `--dir` is refused unless it is
a real directory (not a symlink), owned by the invoking user, and not writable
by group or others. `mkdir -p` applies its mode only to directories it creates,
so a store root that already existed keeps whatever permissions it had; anyone
who can write there chooses which host key the fleet's install path trusts, and
can do so silently after provisioning. The command refuses rather than repairing
the mode, so it never changes permissions on a directory you did not intend it
to own — the error names the offending bits and the `chmod go-w` that fixes them.

Only *write* access is refused. A host-key fingerprint is public — you read it
off the target's console — so group or other **read** and **execute** bits give
an attacker nothing, and the standard layout is exactly that: a root-owned
`0755` `/etc/platform/deployer`, holding `known_hosts`, provisioned by root.
That works unchanged. `0700` works too; what is refused is `0777`, `0770`,
`0702` and anything else with a write bit outside the owner.

The directories *above* the store are checked too, up to the filesystem root: a
locked-down store under a world-writable parent is not locked down at all,
because anyone who can write to that parent can rename your directory aside and
put their own in its place. An ancestor is refused when it is group- or
other-writable **and not sticky** — the sticky bit (as on `/tmp`, mode 1777)
restricts renames and deletes to the entry's owner, which is exactly the attack
in question, so sticky directories are fine. It is also refused when it belongs
to neither root nor you: `/home/alice` at 0755 is not "writable by others" in
the mode sense, yet alice can rename anything directly inside it, so
provisioning as root into another user's tree is refused. Ordinary paths such as
`/etc/platform/deployer/known_hosts.d` pass unchanged, since every directory
above them is root-owned and not writable by others.

The ancestor walk follows symlinks before judging each directory, so a store
under a standard symlinked path — `/var/run`, a symlink to `/run` on most Linux
systems — is accepted on the merits of the real chain. The store root itself
still may not be a symlink.

**A failed rotation restores the previous pin.** Replacing a pin is
remove-then-add, so there is a moment with no pin recorded. If writing the
replacement fails, the previous pin is put back, and the command reports the
write failure with the old pin intact. Only if the restore *also* fails is the
host left unpinned — reported as a distinct, louder error naming the host,
because a fail-closed deployer cannot reach an unpinned host at all and it must
be re-pinned before the next deploy.

Exit status:

| Code | Meaning |
|------|---------|
| 0 | Pinned, rotated, or already pinned — the store holds the verified key |
| 1 | The presented key matched none of the asserted fingerprints, the target could not be reached, or the store could not be opened, read or written |
| 2 | The command line itself is wrong — a mandatory flag missing, or an `--expect-fingerprint` value that is not a SHA-256 fingerprint. Reported before the target is contacted, and the usage text names the out-of-band channels a fingerprint may come from |

The pin is addressed by the deployer `host` under service scope, mirroring the
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
