# Bootstrap — Using It

> **Status: NORMATIVE** · Scope: operating `platformctl bootstrap`, `platformctl firstboot` and the day-zero flow · Last verified: 2026-10-19
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Turning racked hardware into a running platform, in the order you do it.
> Internals are in [engineering.md](engineering.md); the design and the reasons
> behind it are in [architecture.md](architecture.md).

---

## What this is

Bootstrap is the day the machines have nothing. It does two jobs that people
often expect to be separate products:

- **Day zero** — from an operator workstation, one command turns racked,
  powered-off servers into installed, running platform nodes. You describe the
  fleet once in `bootstrap.yaml`, and the tooling discovers each machine through
  its management controller, stands up a temporary boot server, installs the
  control plane first, seeds it with per-node configuration, installs everything
  else, and cleans up after itself.
- **First trust** — a machine with no certificates has no way to verify the
  platform it is about to join. Bootstrap gives it several independent ways to
  get the platform's certificate authority bundle and check that it is the right
  one, and it seals the machine's own disk key into the machine's own TPM so the
  disk unlocks only when the boot chain still measures the same.

If you only need to add a node to an already-running platform, you probably want
[`docs/provisioning/`](../provisioning/) instead. Bootstrap is for the first
time, or for a rebuild.

---

## Three things to keep straight

| Noun | What it is | Where it lives |
|---|---|---|
| **`bootstrap.yaml`** | The fleet description: deployer host, network, roles, nodes, credentials | On your workstation; never on a node |
| **Role template** | The device configuration each node of a role gets | Referenced from `bootstrap.yaml`'s `templates:` |
| **Bootstrap container** | The temporary DHCP/TFTP/HTTP (and SMB) server nodes boot from | On the deployer host, removed at the end |

The deployer host is a machine you already have — a jump host with network reach
to the management controllers and to the network the nodes will PXE from. It is
not part of the platform, and nothing permanent is installed on it.

---

## Prerequisites

1. **Hardware racked and cabled**, with management controllers reachable and
   their credentials known. For machines without a controller, you need each
   NIC's MAC address instead.
2. **A deployer host** you can reach over SSH, with a container runtime, and
   **its SSH host key already pinned**. This is not optional and there is no
   "accept on first use" — an unpinned deployer host is a hard error, because
   that host serves the install to every node.
3. **A role template per role** you intend to deploy.
4. **The platform ISO** on your workstation, if any node will boot from virtual
   media rather than the network.
5. **An odd number of control-plane nodes** — one, or three or more. Two is
   rejected, and so is any even number: it is a quorum, not a preference.

---

## Step 1 — Describe the fleet

Create `bootstrap.yaml`. The shape, trimmed to the parts you must get right:

```yaml
deployer:
  host: deploy.example.com
  user: operator
  ssh_key: ~/.ssh/id_ed25519
  known_hosts_path: <install-dir>/known_hosts
  container_runtime: docker
  container_image: registry.example.com/platform/bootstrap-pxe:1.0.0

environment:                # required — the reference-network environment
  id: 4                     # E: VLANs 400-499, 10.4.0.0/16, VNIs 4xxxxx
  ula: fd12:3456:789a::/48  # example; generate your own random /48

platform:
  domain: example.com
  internal_domain: internal.example.com
  tenant_id: tenant-001
  environment: production

templates:
  control-plane: templates/control-plane.yaml
  gateway:       templates/gateway.yaml
  worker:        templates/worker.yaml

backups_dir: <install-dir>/backups

nodes:
  - hostname: cp-01
    role: control-plane
    bmc_address: mgmt-cp-01.example.com
    bmc_user: admin
    bmc_password: "kms://bmc/cp-01/password"
    bmc_spki_pin: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    bmc_enroll: true

  - hostname: worker-01
    role: worker
    bmc_address: mgmt-worker-01.example.com
    bmc_user: admin
    bmc_password: "kms://bmc/worker-01/password"
    bmc_spki_pin: "5f8d3a1c9b2e4f6a8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b"
```

Four things people get wrong here:

**The network is numbered from `environment:`, not written out.** Every VLAN and
subnet, the provisioning zone included (VLAN _E_05, `10.E.5.0/24`), is derived
from the environment by the [reference network](../architecture/reference-network.md).
`bootstrap.yaml` carries no VLAN or subnet numbers: the old `subnets:`,
`platform.networks`, `fabric:` and `switch.vlans` keys are refused with an error
naming the line and the replacement. (`platform.environment` is the deployment's
name, a different setting.)

**Node identity is required.** Either a management address or at least one MAC.
A node that has neither, and is not marked `skip_install: true`, is rejected.

**Overrides must not restate what a node already declares.** Hostname, network
interfaces and the management block have first-class fields, and the tooling
injects them. Putting them in `overrides:` as well is a validation error that
names the file and the line — delete the duplicate rather than reconciling it.

**Secrets belong behind a URI.** `bmc_password` accepts a `kms://` reference. Do
not commit a plaintext password into a file you will paste into a ticket.

If your control-plane template moves its webservice off `8443`, set
`platform.control_plane_port` to the template's `tls-port`. Bootstrap reaches
the control plane on that port to capture its CA, seed it and check its health,
and `bootstrap status` probes it there; a mismatch shows up as a control plane
that never answers. A value outside 1-65535 is refused when the file loads.

Moving the control plane's internal DNS zone needs no bootstrap setting: set
`dns.internal.port` in the control-plane template (or its `overrides:`) and
every node's DNS forwarder follows it. Unset, it is `9053`.

---

## Step 2 — Check what will happen, before it happens

```bash
platformctl bootstrap discover --config ./bootstrap.yaml
```

This talks to every management controller and prints what it found. Wrong
credentials, an unreachable controller, a typo in an address — all surface here,
in seconds, with nothing powered on.

Then:

```bash
platformctl bootstrap run --config ./bootstrap.yaml --dry-run
```

Dry run validates the whole configuration, resolves each node's fully merged
device configuration and prints it, probes every controller, and prints the plan
phase by phase. **Read the resolved configuration.** It is the last chance to see
what a node will actually be installed with before it is installed with it.

Nothing is powered, mounted or written by either command.

---

## Step 3 — Run it

```bash
platformctl bootstrap run --config ./bootstrap.yaml
```

Expect 15–45 minutes depending on node count, hardware and network. What happens,
in order:

1. **Discovery** — MAC addresses and system information.
2. **Switch** — VLANs and ports, if you configured a switch.
3. **Deploy** — the temporary boot server starts on the deployer host.
4. **Control plane** — control-plane nodes install first, and must be answering
   before anything else proceeds.
5. **Seed** — role templates and per-node profiles are uploaded to the running
   control plane.
6. **Remaining nodes** — gateways and workers install.
7. **Enrollment** — management-controller enrollment for nodes that asked for it.
8. **Health gate, then teardown** — the temporary boot server is removed only
   after every control-plane node is confirmed serving. With
   `deployer.boot_node: true` this step is skipped and the boot server stays up
   (see below).

The output ends with a result block and a per-node table. If the run fails, that
block is printed anyway and the `Phase:` line tells you where it stopped.

**A boot server that stays up.** When the deployer host should keep serving a
segment's netboot after the run — a boot node such as the VLAN 405 Pi segment —
set `deployer.boot_node: true`. The container then runs with
`--restart unless-stopped`, and pxeboot's iPXE firmware cache is kept on the
host in `deployer.firmware_cache_dir` (default `<data_dir>-firmware`), so a
restart does not download it again. The run skips step 8: neither the container
nor `data_dir` is removed. Running `bootstrap run` again, when it redeploys
(see `deployer.redeploy_mode`), replaces only the container and keeps both
directories. The default, `if-stale`, does not notice a changed `BOOTSTRAP_*`
setting such as `bootstrap_no_router` or `proxy_dhcp`, so after changing one set
`redeploy_mode: always` for that run to replace the container.
`platformctl bootstrap teardown` still removes the container and `data_dir`,
and leaves the firmware cache. Because the server is
meant to outlive reboots, `data_dir` and the cache must be absolute paths outside
`/tmp`, `/run` and `/dev/shm`, and must not contain one another. The file is
refused at load otherwise. The image, its ports and volumes are described in
[`build/docker/bootstrap/README.md`](../../build/docker/bootstrap/README.md).

**A segment with no router.** On an isolated provisioning VLAN whose boot
server does not route, set `deployer.bootstrap_no_router: true`: DHCP then
advertises no gateway at all, instead of the default `192.0.2.1`. It cannot be
combined with `deployer.bootstrap_gateway`; the file is refused at load if both
are set.

**Example: tgw-01 serving the Pi rack on VLAN 405.**
[`configs/bootstrap/tgw01-vlan405.example.yaml`](../../configs/bootstrap/tgw01-vlan405.example.yaml)
puts both settings together: a boot node on `bond0.405` (`192.0.2.1`), DHCP
`192.0.2.100`–`192.0.2.200` with no router, and the rack Pis netbooted diskless
as workers from the rpi4 compute template, so the netboot media build needs a
diskless root for the Pi set. Until the CM4 control plane is proven, the control
plane is tgw-01 itself: platformd standalone at `192.0.2.1` from
[`standalone-cp.example.yaml`](../../configs/platform/templates/single-node/standalone-cp.example.yaml)
(`templates.control-plane`), listed with `skip_install: true` because this run
does not install it. The CM4 entry is kept commented out; it replaces tgw-01
when it takes over, since a deployment has one control plane or an odd number
of three or more. The Pis share
[`tgw01-vlan405-pi.overrides.yaml`](../../configs/bootstrap/tgw01-vlan405-pi.overrides.yaml),
which points the template's DNS at `192.0.2.1` and sets `install-target: disk`,
because the template is the factory SD image and its `image` target would
ignore the boot server's `platform_boot_model=diskless`. Bootstrap refuses a
diskless node (`boot_model: diskless` or `diskless-nbd`) whose merged config
still says `install-target: image`. Each Pi also has inline `overrides:`
giving it its own addresses, `.20`/`.21`/`.22` in the platform VRF
(`10.4.144.0/20`) and in each zone VLAN (fabric 401, hypervisor 403, storage
407). The template carries one Pi's set, and `vlans` is a list, so an
override repeats all three entries. The Pis hold no VLAN 405 address once
installed: the compute role addresses only its zones (see
[Host addressing](../architecture/reference-network.md#host-addressing)), so `eth0` stays
`manual`. A fourth Pi takes the next host number, `.23`, in the platform VRF
and in each zone VLAN. The Pis need no `tpm.idevid.serial` of their own: all
three keep the template's `rpi4-compute-01`, and platformd on a diskless node
replaces it at every boot with the name it derives from the Pi's TPM EK
(`ek-<32 hex>`, see [docs/tpm/architecture.md](../tpm/architecture.md)), so
each Pi's IDevID certificate names that Pi. The nodes' `serial:` field is a
different value, the Pi bootloader's `/proc/cpuinfo` serial that selects its
boot directory. The orchestrator
fetches the control plane's CA bundle from `192.0.2.1:8443`, so run
`platformctl bootstrap` on tgw-01 or a host on VLAN 405. Values marked
`PLACEHOLDER` (SSH access, DNS, APK mirror, domains, Pi serials) must be
replaced first.

**Adding nodes later is not automatic.** Adding an entry and re-running will
reprovision the existing nodes too, unless you mark them `skip_install: true`.
Marked nodes keep participating in seeding and health checks; they just are not
reinstalled.

---

## Step 4 — Confirm

```bash
platformctl bootstrap status --config ./bootstrap.yaml
```

Health is one of `healthy`, `unhealthy`, `unreachable` — or `unknown`.

**`unknown` is not a network failure.** It means the platform's certificate
authority bundle could not be fetched and verified, so the command declined to
probe over an unverified connection and report a green result it could not stand
behind. Fix the trust path first; a green result obtained by ignoring
certificates is worth nothing.

---

## Establishing trust on a machine by hand

When a machine needs the platform CA bundle outside a bootstrap run:

```bash
platformctl bootstrap trust \
    --server-url https://platform.example.com:8443 \
    --strategy auto \
    --install-to-system-trust
```

`auto` tries DNS-based verification, then the Noise channel, then certificate
pinning, and stops at the first success. Naming a single strategy makes it the
only one — which is what you want when you need to know that *that* path works.

Three practical notes:

**With DNS-based verification, give the resolver a port.** Platform control
planes answer DNS on 8053, not 53, because the daemon runs unprivileged. A bare
hostname assumes 53 and queries the wrong socket. Pass `host:8053`.

**When the server URL is an IP address, pass `--hostname` too.** The record
lookup needs a name.

**The per-strategy timeout defaults to 5 seconds.** Raise it if your resolver is
slow; several examples elsewhere in this folder assume 15.

---

## First boot on a node

You do not normally run this: a service unit does, right after the node's first
reboot into the installed system. You will meet it when it fails.

```bash
platformctl firstboot
```

It reads the disk key out of the encrypted container the installer left behind,
seals it into the machine's TPM against the boot measurements, unlocks the disk,
and copies the platform state onto it. It keeps the container. The next boot
that unlocks the disk with the TPM seal (`TPM-PCR`) proves the seal, and only
then is the container securely erased
([architecture](architecture.md#phase-3a--node-first-boot-on-the-node-concurrent-with-the-wait-above),
seal confirmation).

**There is no default set of measurements.** Without a configured or supplied
PCR list the command refuses to run rather than sealing against a guess.

**Running it again when it has nothing to do is safe.** It prints "Firstboot
sealing not needed - system already configured" and exits zero.

**A non-zero exit with `FIRSTBOOT INCOMPLETE` is the important case.** The disk
was unlocked with the plain key, but sealing did not finish. The system boots and
looks fine; the platform daemon will fail at startup. The exit code is non-zero
on purpose so the service does not mark itself started and first boot runs again
next time. The usual cause is leftover TPM ownership state from an earlier failed
attempt; the message names the fix.

---

## Choosing how a node boots

| `boot_method` | Use when | Needs |
|---|---|---|
| `pxe` (default) | The node's data NIC is on the provisioning network | Nothing extra |
| `virtual-media` | The data NIC is not cabled, is on the wrong VLAN, or network boot is unavailable | A management controller and `iso_path` |
| *(neither, no controller)* | The machine has no out-of-band management at all | You set its boot order; the tooling only watches |

A machine with no management controller gets **zero** hardware operations — no
power, no boot device, no media. Set its boot order yourself; the installer
reboots it into the installed system on its own, and the tooling watches the
install log. Asking for `virtual-media` on such a machine is a configuration
error, because there is nothing to mount the media with.

When it provisions such a machine, the orchestrator logs, at info, with the
node's `hostname` and `boot_method` (`pxe` unless set):

```
bootstrap: provisioning unmanaged node — no board management, no hardware operations; ISO self-boots via after-install=reboot
  hostname=edge-01
  boot_method=pxe
```

---

## Choosing how to trust a management controller

Controllers almost always present self-signed, frequently expired certificates.
`bmc_trust` is an ordered list, tried left to right:

| Strategy | Use when |
|---|---|
| `spki` | You obtained the certificate fingerprint out of band — put it in `bmc_spki_pin` |
| `ca-file` | Your controllers were issued certificates by a CA whose bundle you have |
| `dane` | You publish TLSA records for your controllers |
| `tofu` | Neither of the above: the controller's own certificate is pinned on first contact |

**Captured pins do not survive the run.** They live in memory for one
`bootstrap run` and are gone afterwards. That means a controller certificate that
changes between runs is invisible to you. If that matters — and on a production
fleet it does — publish TLSA records and drop `tofu` from the chain.

---

## Troubleshooting

**"missing required field: deployer.host" or "missing required field: environment".**
Configuration validation, before anything ran. Fix the file. The network comes
from the top-level `environment:` block.

**"… is retired; use …".**
The file still carries a key from the literal-number schema (`subnets`,
`platform.networks`, `fabric`, `switch.vlans`, a port's `mode` or `vlans`,
`post_enrollment`). The message names the line and what replaces it.

**"invalid control-plane node count".**
One, or an odd number three or greater. Two control-plane nodes cannot form a
quorum.

**"override key … duplicates authoritative field …".**
An override restates something the node already declares. The message names the
file, the line, the key and the field that owns it. Delete the override.

**"duplicate MAC" or "duplicate bmc_address".**
Two nodes claim the same hardware. Usually a copy-paste in the node list.

**"address … is on node … and on node …".**
Two nodes' merged configs give the same address, usually because both take it
from one role template. Give each node its own in `nodes[].overrides` (for a
list such as `network.vlans`, repeat every entry). Checked before discovery,
so nothing has been touched.

**"IDevID serial … is on node … and on node …".**
Two nodes' merged configs give the same `tpm.idevid.serial` under the same
`tpm.idevid.model`, usually the role template's, so their IDevID certificates
would name one device. Give each node its own serial in `nodes[].overrides`,
for example its `/proc/cpuinfo` or DMI serial. Two nodes of different models
may share a serial. A `boot_model: diskless` node is not checked: platformd
names it after its TPM's EK and replaces the config's serial with that name.
A `diskless-nbd`, SD or disk node keeps its config's serial. Checked before
discovery, so nothing has been touched.

**"boots diskless but its config sets install-target: image".**
A diskless node's installer runs on the node, so it needs `install-target:
disk`; set it in that node's overrides. The Raspberry Pi templates default to
`image`, the factory SD image.

**Discovery fails for one node.**
Credentials or reachability for that controller. `discover` names the host. If
you supplied MACs in the file, MAC discovery failing is only a warning — the run
continues with your values.

**A node never reports an install log.**
The installer never finished. On virtual-media installs the tooling retries a
few times; the error carries the last attempt's console transcript. Every
attempt records the machine's serial console over the controller's
Serial-over-LAN; when the console printed anything, the transcript is stored
on the deployer at `/installs/<host>/console-attempt<N>.log` and the error
quotes its last lines (a silent console stores no file, and a console that
could not be opened is reported as such in the error). Read the lines: if the
machine printed a boot loader and a kernel from its disk, fix the BIOS boot
order so the virtual CD comes before the hard disk; if the installer started
and stopped, the transcript is where it said what went wrong. If the error
says the console was **silent for the whole window**, do not read that as
"booted from disk": on this hardware the BIOS does not redirect POST to the
serial console, so silence means the firmware halted before any operating
system — a failed DIMM, for instance — or console redirection is disabled in
BIOS. Open the iKVM console for the POST screen. Run `--dry-run` first: it
reads the controller's event log and warns about memory faults and a full log
before you spend a boot on them. The error may add that **"the media watcher
also never saw the ISO opened"** — advisory context, not a diagnosis: on this
hardware the controller's ISO reads leave no trace the watcher can hold, so a
perfectly healthy install reports the same absence.

**The installer finished but the node is not healthy.**
Those are two different signals. The install log is the installer reporting on
itself; health is a separate check that the platform daemon is actually serving.
A node can complete its install and still fail to come up.

**A power command "succeeded" but the machine did not change state.**
Some controllers acknowledge power commands they do not act on. The tooling polls
to verify and reports a power-state verification failure with what it expected
and what it saw. Check the machine physically.

**Virtual media will not mount.**
Some controllers gate the media API behind a licence. Insert the ISO with vendor
tooling or the remote console, then re-run with
`--skip-virtual-media-mount` — boot device, power cycle, health wait and unmount
still run.

**The bootstrap container is still running after a successful-looking run.**
The health gate did not pass, so teardown was skipped on purpose — that container
may be the only DHCP and DNS on the provisioning network. Confirm the platform's
own services are serving, then run `bootstrap teardown`. If the file sets
`deployer.boot_node: true`, the container staying up is the point of the mode.

**Node enrollment shows failures but the run succeeded.**
Enrollment is deliberately non-fatal. The result block lists each attempt; retry
the failures with the management-controller CLI.

**`bootstrap auto`, `dane`, `noise` or `spki` returns "owned by xkms".**
Those five canonical verbs exist for cross-tool consistency, but four of them are
not wired to a backend yet. Use `platformctl bootstrap trust --strategy <name>`,
which is the working path today.

---

## Two things to be aware of

**The per-machine configuration channel is plain HTTP.** The temporary boot
server hands each machine its hostname, its merged configuration, the CA bundle
and a certificate pin over unencrypted HTTP on the provisioning network — because
the machine has no way to establish anything better yet. Treat that network as
readable by everything on it, and keep secrets out of role templates that reach
it.

**The encrypted installer container is key material.** It holds the disk key in
plaintext, protected by a well-known password whose only purpose is to stop a
discarded disk from yielding a key to a casual reader. It is not access control.
It is erased only once a later boot unlocks the disk with the TPM seal, and
kept until then, so a machine whose seal never works is a machine whose disk
key is recoverable by anyone holding the disk. Resolve a failed seal; do not
live with one.

---

## Where to go next

- [cli.md](cli.md) — every verb and every flag
- [api.md](api.md) — every capability on every transport, and why so much of it is deliberately absent
- [architecture.md](architecture.md) — the design, the alternatives rejected, the trust boundaries
- [`docs/provisioning/`](../provisioning/) — the ISO, the network boot server and the installer this drives
- [`docs/bmc/`](../bmc/) — management controllers and enrollment
- [`docs/ca/`](../ca/) · [`docs/dns/dane.md`](../dns/dane.md) — where the trust material comes from
- The older narrative files (day-zero.md, pxe-bootstrap.md, config-reference.md, manual-nodes.md, switch-management.md) are deleted. These five files hold their content; the `bootstrap.yaml` reference is [engineering.md](engineering.md) §5.
