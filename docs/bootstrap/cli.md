# Bootstrap — CLI

> **Status: NORMATIVE** · Scope: `platformctl init`, `platformctl bootstrap`, `platformctl firstboot`, `platform-initrd` · Last verified: 2026-10-19
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every verb and every flag below was read out of `pkg/cli/commands/bootstrap/`,
> `pkg/cli/commands/firstboot/` and `pkg/boot/commands/` on 2026-10-19.

---

## 1. Command groups

```
platformctl init                 Initialize a fresh platform (barrier, CA, admin bundle)
platformctl bootstrap            Platform bootstrap operations
platformctl bootstrap secrets    Manage bootstrap secrets
platformctl firstboot            First-boot TPM PCR sealing operations
platform-initrd boot             Unlock the encrypted root filesystem
platform-initrd recovery         Recovery mode with re-seal
```

`platformctl bootstrap` carries **five unrelated families** under one noun, and
mixing them up is the commonest mistake here:

| Family | Verbs | What it talks to |
|---|---|---|
| Day-zero fleet orchestration | `run`, `discover`, `deploy`, `status`, `teardown` | BMCs, the deployer host, the control plane |
| Config preview | `resolve` | Nothing: the config file and its templates only |
| Boot-server probing | `probe rpi`, `probe rpi-http` | The boot server on a segment, spoken to as a Raspberry Pi's bootloader would: DHCP and TFTP, or signed HTTP boot |
| Trust bootstrap | `trust`, plus the canonical modes `auto`, `dane`, `noise`, `spki`, `direct` | A platform server's CA bundle endpoint |
| Secret migration | `secrets migrate`, `secrets verify`, `secrets status`, `secrets resolve` | A local configuration file and the KMS |

`platform-initrd` is **not user-facing**: its own help says so. It is invoked by
initramfs hooks. It is documented here because operators read its output when a
node fails to boot.

### Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go:134`), precedence
**flag > environment > config file > built-in default**:

| Flag | Short | Default | Environment | Meaning |
|---|---|---|---|---|
| `--config` | `-c` | platform default config path | `PLATFORMCTL_CONFIG` | Config file |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` | Named context to use |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` | `unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded` |
| `--server` | | from context | `PLATFORMCTL_SERVER` | Server address; implies a remote context |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` | TLS SNI / verification hostname |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` | `table`, `json`, `yaml` |
| `--verbose` | `-v` | `false` | | Verbose output |
| `--no-color` | | `false` | `NO_COLOR` | Disable coloured output |

**`--config` at the root and `--config` on a bootstrap verb are different
files.** The root flag names the *platform* configuration; `bootstrap run
--config` names the *fleet description* (`bootstrap.yaml`). The local flag wins
inside the subcommand. Under `bootstrap secrets`, `--config` names yet a third
thing — the configuration file being rewritten.

**Which verbs need a running server.** None of the day-zero verbs talk to
`platformd` on a transport: they reach BMCs and the deployer host directly and
the control plane over plain HTTPS. `--transport` therefore has no effect on
them. `bootstrap secrets` needs a local KMS. `bootstrap trust` needs only the
target server's bundle endpoint. `platformctl firstboot` runs on the node itself
with no server at all. `platformctl init` talks to the daemon, but only to its
pre-unseal mux — see §1a.

---

## 1a. `platformctl init`

Initialize a fresh platform in one call: barrier, CA-issued admin client
certificate, SPKI pin. It runs **before** the barrier is unsealed, when none of
the six transports is bound, so it does not use `--transport`, `--server` or a
context's connection settings. It sends `POST /init` to the barrier gate
([`../barrier/api.md`](../barrier/api.md#post-init)) through
`sdk/go/services/gate`. The client accepts only a Unix socket or a literal
loopback address, uses no proxy, and **never follows a redirect**: the request
carries the PINs, so a `3xx` is returned as `ErrInitRejected` with its status
code, and nothing is resent to the `Location` it names.

| Flag | Default | Environment | Meaning |
|---|---|---|---|
| `--so-pin` | | `PLATFORMCTL_SO_PIN` | SO PIN; required unless `--barrier-strategy=none` |
| `--user-pin` | | `PLATFORMCTL_USER_PIN` | User PIN; required unless `--barrier-strategy=none`. It is the barrier secret, so platformd refuses an init without one with `400` before anything is minted |
| `--barrier-strategy` | `software` | `PLATFORMCTL_BARRIER_STRATEGY` | `software`, `shamir`, `pkcs11`, `tpm2`, `awskms`, `gcpkms`, `azurekv`, `vault`, `none`. Sent as `credential_seal_strategy`, the strategy the ceremony seals credentials with. It does **not** choose the barrier's strategy: platformd initializes the barrier with its configured `barrier.seal_strategy` ([`../barrier/api.md`](../barrier/api.md#post-init)). With `shamir` the `--shares` / `--threshold` quorum is sent too, and a platformd configured for `shamir` splits the barrier with it |
| `--shares`, `--threshold` | | `PLATFORMCTL_SHARES`, `PLATFORMCTL_THRESHOLD` | Shamir quorum; required for, and only accepted with, `shamir` |
| `--officer` | | | `username=path/to/csr.pem`, repeated once per share; required for, and only accepted with, `shamir`. Each officer's CSR file is read before `/init` is sent and sent as `officers` ([`../barrier/api.md`](../barrier/api.md#post-init)); the gate refuses a CSR that does not parse or is not self-signed. A count other than `--shares`, a malformed value, a repeated username or an unreadable file fails the command (`ErrOfficerCount`, `ErrInvalidOfficerFlag`, `ErrOfficerCSRUnreadable`) and nothing is sent |
| `--hostname` | | `PLATFORMCTL_HOSTNAME` | CN for the issued certificate |
| `--sans` | | `PLATFORMCTL_SANS` | Comma-separated extra DNS / IP SANs |
| `--admin-bundle` | `-` (stdout) | `PLATFORMCTL_ADMIN_BUNDLE` | Where the admin cert + key + SPKI pin go |
| `--force` | `false` | | Replace an existing `--admin-bundle` file |
| `--gate-endpoint` | local context socket, else `unix:///run/platformd.sock` | `PLATFORMCTL_GATE_ENDPOINT` | `unix://<socket>`, or with `--loopback-http` a literal loopback `ip:port` (`127.0.0.1:9446`, `[::1]:9446`); anything else, including the name `localhost`, is refused, because the request carries both PINs |
| `--loopback-http` | `false` | `PLATFORMCTL_LOOPBACK_HTTP` | Send `/init` over loopback HTTP: to `--gate-endpoint` if it names an `ip:port`, else `127.0.0.1:9446`. **A lost response cannot be replayed over HTTP** (see below), so the one-shot admin bundle is lost with it. Combined with a `unix://` endpoint it is refused |

**The admin bundle is returned once.** The daemon does not keep the key, so:

- A file `--admin-bundle` is created (mode `0600`, as a temporary file beside the
  target) **before** `/init` is sent. A path that is a directory (even with
  `--force`), an existing file without `--force`, or a parent directory that
  cannot be written fails the command and nothing is sent.
- After a successful `/init` the bundle is renamed into place, and the command
  prints only a summary: `ceremony_id`, `state`, `initialized_at`, `spki_pin`,
  `admin_bundle` (the path). The key is never printed.
- If the bundle was written but the rename fails, the temporary file is kept
  and the command fails with an error naming it. Move it to the target by hand:
  the platform will not issue the bundle again.
- With `--admin-bundle -`, the default, stdout carries **only** the bundle, so it
  can be redirected to a file, and the summary goes to stderr. The private key
  is written to stdout exactly once, and whatever captures that stdout (a
  terminal's scrollback, a CI job log, a `tee`) now holds the platform's root
  admin key. Unless stdout is redirected straight to a file you protect, pass a
  path instead.
- If the response is lost, repeat the identical command as the same user: while
  the daemon is still pre-unseal it replays the same bundle, but only over the
  Unix socket ([`../barrier/api.md`](../barrier/api.md#retrying-init)). That is why init
  uses a Unix socket unless you pass `--loopback-http`: an init sent to the
  loopback HTTP endpoint is never replayed, and a loopback `--gate-endpoint`
  without the flag is refused before anything is sent.
- Attempts are rate limited (5 back to back, then one every 12 seconds); past
  that the command fails with HTTP `429`.

**There is no second admin credential.** `platformd` keeps its server key in
the CA keystore and writes only the public CA bundle to `<platform-dir>/tls/`
([`../daemon/architecture.md`](../daemon/architecture.md)); it mints no admin
key. Earlier builds also wrote `client-bundle.pem`, a `CN=admin` certificate
and its private key in clear, to `/tmp/platformd-integration/tls/` on every
host with a TLS transport enabled. On a host that ran one of them, delete that
file and revoke its certificate (`platformctl ca revoke <serial>`): it carries the same authority as the `/init`
bundle and stays valid for 365 days from issue.

The devcontainer integration harness
(`build/docker/devcontainer/run-integration-tests.sh`) runs `platformd` without
a barrier, so there is no `/init` to take a bundle from. Its `platformd` is
built with the `integration` build tag, which compiles in
`pkg/daemon/commands/harness_admin_bundle_integration.go`: that binary, and
only that binary, writes a test `client-bundle.pem` beside the CA bundle.

```bash
platformctl init --so-pin "$SO_PIN" --user-pin "$USER_PIN" \
  --hostname cp-01.example.com --admin-bundle /root/admin.pem -o json
```

`platformctl ceremony init` was removed in favour of this command
([`docs/cli/ceremony.md`](../cli/ceremony.md)).

---

## 2. `platformctl bootstrap run`

Execute the complete bootstrap flow. This is the verb that powers on hardware.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | `""` | Path to `bootstrap.yaml` (**required**) |
| `--dry-run` | bool | `false` | Validate config and test BMC connectivity; change nothing |
| `--skip-virtual-media-mount` | bool | `false` | For `boot_method: virtual-media` nodes, assume the operator inserted the media out of band |

```bash
platformctl bootstrap run --config ./bootstrap.yaml --dry-run
platformctl bootstrap run --config ./bootstrap.yaml
platformctl bootstrap run --config ./bootstrap.yaml --verbose
```

**Run `--dry-run` first, every time.** It validates the configuration, resolves
and prints the merged per-node device config, probes every BMC, reads each
reachable BMC's System Event Log, and prints the execution plan. Nothing is
powered, mounted or written. A full event log or memory faults on record show up
under `Warnings:` naming the node and DIMM (`node-02: DIMMB1 has 505 memory
faults on record …`) — fix or replace the part before provisioning, because a
failed DIMM halts POST and the install never starts.

**`--skip-virtual-media-mount` is an escape hatch, not a convenience.** It skips
the ISO staging on the deployer (so `iso_path` is not required), the mount, the
re-mount on each retry and the deferred unmount (`bootNodeVirtualMedia` in
`pkg/bootstrap/virtual_media.go`). Per-MAC config staging, the one-shot CDROM
boot device, the power cycle, the install-log wait with its retries, and the
post-install unmount, disk boot and health wait still run. Use it on boards whose vendor mount API is behind
a licence the platform's BMC backends cannot drive, after inserting the ISO with
vendor tooling or the remote console.

Output on success is a result block naming the phase, the duration, per-stage
booleans, and a per-node table (hostname, role, MAC, BMC, status, error). On
failure the same block is printed **before** the error is returned, so a partial
run is still readable; the `Phase:` line names where it stopped.

---

## 3. `platformctl bootstrap discover`

Phase 0 only: query BMCs for MAC addresses and system info.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | `""` | Path to `bootstrap.yaml` (**required**) |

```bash
platformctl bootstrap discover --config ./bootstrap.yaml
```

Safe to run repeatedly — it opens BMC sessions and reads. It is the fastest way
to prove credentials and reachability before a real run, and the discovered MAC
set is the union of the ones declared in YAML and the ones the BMC reports.

---

## 4. `platformctl bootstrap deploy`

Bring the bootstrap container up and stop there.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | `""` | Path to `bootstrap.yaml` (**required**) |

```bash
platformctl bootstrap deploy --config ./bootstrap.yaml
```

It runs the first phases of `bootstrap run` through the same orchestrator
(`Orchestrator.Deploy`): discovery of every node's MACs (Phase 0), switch
configuration when `bootstrap.yaml` has a `switch:` section (Phase 1), and the
container deploy — manifest from discovery, the netboot media build staged,
host-key pins enforced — ending once both of the container's listeners are
serving (Phase 2). It needs `deployer.host` and `deployer.container_image`;
without a deployer it fails with `ErrDeployerNotConfigured` before discovery.
Prints the host, the number of nodes in the manifest, whether the switch was
configured, and the elapsed time.

---

## 5. `platformctl bootstrap status`

Health-check every node in the configuration.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | `""` | Path to `bootstrap.yaml` (**required**) |

```bash
platformctl bootstrap status --config ./bootstrap.yaml
```

Prints a table of hostname, role, MAC, BMC-managed, health. Health is one of:

| Value | Means |
|---|---|
| `healthy` | `GET /api/v1/status` returned 200 **with a JSON body** |
| `unhealthy` | It answered, but with a non-200 status or a body that is not a platform response |
| `unreachable` | No candidate port answered |
| `unknown` | **No verified CA pool was available**, so no probe was attempted |

**What `healthy` measures, precisely.** `/api/v1/status` answers whenever the
node's webservice is serving; it carries no per-component verdict. So `healthy`
means *platformd is up and answering*, which is the question `bootstrap status`
exists to answer during node bring-up. A component-level reading — which
subsystem is degraded — lives at `/api/v1/platform/health` and requires an
authenticated `admin` (see [`docs/auth/architecture.md`](../auth/architecture.md)
§6c); this command holds no credential.

**The probe tries several ports**, because the webservice port depends on the
node's role: `platform.control_plane_port` (default `8443`) for control-plane and
single-node, `9443` for compute, `443` for gateway. They are tried in that order and the first port that *answers*
decides the verdict — an unreachable port says nothing about the others, but a
port that replies is that node's answer and ends the search.

**It grades on the body, not only the status code.** A status code alone cannot
tell platformd from a proxy, a load balancer, or a static file server that
answers 200 for everything. That is not hypothetical: before the SPA fallback
was closed for API paths, this command's probe was answered by `index.html` with
a 200 and reported **every node healthy regardless of its state** (#235).

`unknown` is not a network problem. It means the control plane's CA bundle could
not be fetched and verified, so the command refused to probe over an unverified
TLS connection and produce a green result it could not stand behind. A warning
naming the cause is printed to stderr.

---

## 6. `platformctl bootstrap teardown`

Remove the bootstrap container (`Orchestrator.Teardown`, the same step
`bootstrap run` ends with). It needs a deployer, like `deploy`.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | `""` | Path to `bootstrap.yaml` (**required**) |

```bash
platformctl bootstrap teardown --config ./bootstrap.yaml
```

`bootstrap run` tears the container down itself, but only after every
control-plane node passes the health gate. When the gate fails, teardown is
skipped deliberately — the container may still be the only DHCP/DNS provider on
the provisioning network. This verb is how you tear down afterwards, once you
have confirmed the platform's own services took over.

With `deployer.boot_node: true`, `bootstrap run` never tears the container down,
and this verb is the only thing that does. It removes the container and
`data_dir` as in default mode. The firmware cache (`deployer.firmware_cache_dir`)
is left on the host.

---

## 6a. `platformctl bootstrap probe rpi`

Boot from the network the way a Raspberry Pi's bootloader does, from any
host on the boot segment, and report what a Pi with that identity would have
booted with. It is the stage no emulator can run for real — the EEPROM's
own DHCP and TFTP client — spoken by `pkg/rpinetboot` exactly as the
bootloader speaks it: the DHCP DISCOVER with vendor class
`PXEClient:Arch:00000:UNDI:002001`, architecture 0 and the option 97 client
identifier (the model's FourCC, the board revision, the low MAC bytes and
the serial); only a reply whose option 43 carries the `Raspberry Pi Boot`
match is accepted, a proxy DHCP reply included; then every file the
bootloader and the firmware fetch over TFTP, in their order, tried under
the per-device prefix (`TFTP_PREFIX`) before the root, with the
bootloader's own timeouts (45 s for DHCP, retries every 4 s; 30 s per file,
five TFTP retries five seconds apart).

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--interface` | string | `""` | Interface on the boot segment (**required**) |
| `--serial` | string | `""` | The Pi's serial number, up to eight hex digits (**required**) |
| `--mac` | string | `""` | The Pi's Ethernet address (**required**) |
| `--revision` | string | `0` | Board revision code, hex; goes into option 97 |
| `--model` | string | `rpi4` | `rpi4`, `rpi400`, `cm4`, `rpi3b+`, `rpi5` — decides the FourCC, the first-stage files and the device tree | <!-- lab-string-ok: Raspberry Pi model name, not a lab host -->
| `--prefix` | string | `serial` | The bootloader's `TFTP_PREFIX`: `serial` (`9ffefdef/`), `mac` (`dc-a6-32-01-36-c2/`) or `string` |
| `--prefix-str` | string | `""` | `TFTP_PREFIX_STR`, with `--prefix string` |
| `--option43` | string | `Raspberry Pi Boot` | The bootloader's `PXE_OPTION43` match string |
| `--timeout` | duration | `0` | Overall deadline; the bootloader's own timeouts otherwise |

```bash
sudo platformctl bootstrap probe rpi --interface eth1 --serial 9ffefdef --mac dc:a6:32:01:36:c2
sudo platformctl bootstrap probe rpi --interface eth1 --serial 1a2b3c4d --mac 2c:cf:67:00:11:22 --model rpi5 --prefix mac -o json
```

The report names the DHCP server, the TFTP server the Pi would fetch from
(siaddr, else option 66, else the server identifier), whether the offer was
a proxy's, the lease when there was one, the device prefix, and each file
with the path that served it, its size and SHA-256 — so `kernel8.img`
can be checked against the U-Boot build. A file the bootloader needs that
neither the prefix nor the root serves fails the probe with the report
so far, the same place a Pi would have stopped. `cmdline.txt` is optional:
the platform's UKI carries the command line.

**It requires root**: binding the DHCP client socket to an interface is
`SO_BINDTODEVICE`, which needs `CAP_NET_RAW`. A host DHCP client already on
port 68 is tolerated (`SO_REUSEADDR`), but a DHCP client that answers the
probe's own DISCOVER on that host is not what is being measured; run it from
a host that is not itself a DHCP client on that interface.

## 6a-1. `platformctl bootstrap probe rpi-http`

The other first stage: boot over HTTP with `SIGNED_BOOT`, the way a Raspberry
Pi's bootloader does (`pkg/rpinetboot` `HTTPBoot`). It fetches
`http://<http-host>/<http-path>/boot.img` and `boot.sig`, requires the public key
the EEPROM carries to hash to the customer key hash in OTP, verifies `boot.sig`
over `boot.img` with it (RSA-2048 PKCS#1 v1.5 over SHA-256, in the
`rpi-eeprom-digest` format), and mounts `boot.img` as the FAT ramdisk. It fails
on whatever the bootloader would refuse: a tampered image
(`DigestMismatchError`), a signature by another key (`SignatureError`), an OTP
hash of another key (`KeyHashMismatchError`), a malformed `boot.sig` (including a
`target-soc` other than 2711 or 2712, `TargetSoCError`), an image
that is not a FAT ramdisk. It needs no privilege and no DHCP: it is an HTTP
client.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--http-host` | string | `""` | The EEPROM's `HTTP_HOST`: the boot server's address, with its port unless 80 (**required**) |
| `--http-path` | string | `data/http-boot` | The EEPROM's `HTTP_PATH`; the container serves the data directory under `/data/` |
| `--pubkey` | string | `""` | The public key the EEPROM carries: a `pubkey.bin` file (**required**) |
| `--otp-key-hash` | string | `""` | The customer key hash in OTP: 64 hex digits (**required**) |
| `--timeout` | duration | `0` | Overall deadline; none otherwise |

```bash
platformctl bootstrap probe rpi-http --http-host 10.99.99.1:8080 \
    --pubkey bin/netboot-media/http-boot/pubkey.bin --otp-key-hash 3f9a…c1
platformctl bootstrap probe rpi-http --http-host 10.99.99.1:8080 --pubkey pubkey.bin --otp-key-hash 3f9a…c1 -o json
```

Give `--pubkey` and `--otp-key-hash` from the device's provisioning record,
**not** from the server being probed: a probe that takes both from the server it
checks proves only that the server agrees with itself. The report names the URL,
`boot.img`'s size and SHA-256, `boot.sig`'s `ts` and `target-soc`, and the files
in the ramdisk. The build that makes these files, and the runbook for the
EEPROM and the OTP burn (**irreversible**), are in
[docs/factory-image/](../factory-image/user.md#provision-a-fleet-signed-http-boot).

## 6b. `platformctl bootstrap resolve`

Print or write each node's resolved platform config: its role template merged
with the platform identity, the node's overrides and its node identity — the
config `bootstrap run` writes for the node (`Orchestrator.ResolveNodeConfigs`).

Nothing is contacted and no netboot media build is needed: the config is
checked with `BootstrapConfig.ValidateDefinition`, which is `Validate` without
the media check. The hardware keys a real run reads from each node's BMC are
therefore absent; `run --dry-run` shows them.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | `""` | Path to `bootstrap.yaml` (**required**) |
| `--node` | string, repeatable | all nodes | Resolve only these hostnames; an unknown one fails with `ErrUnknownNode`. Every node is still checked for a shared address or a diskless image target |
| `--dump` | string | `""` | Write `<dir>/<hostname>.yaml` (mode 0600) per node and print each path, instead of printing the configs |

Without `--dump`, the output is one YAML stream: one document per node, in
config order, each headed `# <hostname> (<role>)`.
The output is deterministic, so two runs over unchanged inputs diff clean; the
`network.dns.search-domains` list keeps configuration order (engineering.md §3
invariant 22).

```bash
# Diff a deployment's resolved configs across two template versions
platformctl bootstrap resolve --config ./bootstrap.yaml --dump /tmp/before
# ... change the templates or the overrides ...
platformctl bootstrap resolve --config ./bootstrap.yaml --dump /tmp/after
diff -ru /tmp/before /tmp/after
```

Template paths are read as the config names them, so run it on a host where
those paths resolve.

---

## 7. `platformctl bootstrap trust`

Fetch the platform CA bundle over a strategy that does not need the CA bundle,
and optionally install it into the system trust store.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--server-url` | string | `""` | Platform server URL (**required**) |
| `--strategy` | string | `auto` | `auto`, `dane`, `noise`, `spki`, `embedded` |
| `--dns-server` | string | `""` | DNS server for DANE lookups; `host` or `host:port` |
| `--hostname` | string | `""` | Server hostname for the TLSA lookup — needed when `--server-url` is an IP |
| `--noise-key` | string | `""` | Noise_NK server static key, hex |
| `--noise-addr` | string | `""` | Noise server address, `host:port` |
| `--spki-pin` | string | `""` | Hex SHA-256 of the server SubjectPublicKeyInfo |
| `--bundle-path` | string | `""` | Bundle endpoint path override; empty selects the server default |
| `--install-to-system-trust` | bool | `false` | Write the bundle into the system trust store |
| `--cert-path` | string | `/usr/local/share/ca-certificates/platform-ca.crt` | Where to write it |
| `--per-method-timeout` | duration | `5s` | Timeout for each strategy attempt |

```bash
platformctl bootstrap trust \
    --server-url https://platform.example.com:8443 \
    --strategy auto \
    --install-to-system-trust

platformctl bootstrap trust \
    --server-url https://platform.example.com:8443 \
    --strategy dane --dns-server dns.example.com:8053 \
    --hostname platform.example.com

platformctl bootstrap trust \
    --server-url https://platform.example.com:8443 \
    --strategy spki --spki-pin <64-hex-sha256>
```

**`--strategy auto` is an ordered chain, not a probe.** It expands to `dane`,
`noise`, `spki` and stops at the first success. A single named strategy makes a
chain of one — a misconfigured `--strategy dane` fails rather than quietly
falling through to something weaker.

**`--dns-server` accepts a bare host and assumes port 53.** Platform control
planes do not bind privileged port 53 (the daemon runs unprivileged); their
resolver port is 8053. Pointing `--dns-server` at a control plane without a port
silently queries the wrong socket, so pass `host:8053` explicitly.

**`--per-method-timeout` defaults to 5 seconds**, not the 15 seconds several
example configurations in this folder use. Raise it for slow DNSSEC resolution.

**`--strategy embedded` fetches nothing** and prints "Using embedded CA bundle";
`--install-to-system-trust` has no effect in that mode.

`--install-to-system-trust` runs `update-ca-certificates` afterwards. A failure
there is a warning, not an error — the certificate file is already in place.

---

## 8. Canonical trust modes — `auto`, `dane`, `noise`, `spki`, `direct`

These are the locked cross-binary bootstrap surface — the shape
`<binary> bootstrap auto | dane | noise | spki | direct` is identical across
every daemon CLI in the stack, and the locked-surface specification (`docs/11`)
is the authority for it, not this file. All five verbs exist on `platformctl`.

| Verb | Args | Flags | State |
|---|---|---|---|
| `auto` | none | — | **Stub.** Returns `PendingBootstrapBackendError` |
| `dane` | none | — | **Stub.** Returns `PendingBootstrapBackendError` |
| `noise` | none | — | **Stub.** Returns `PendingBootstrapBackendError` |
| `spki` | none | — | **Stub.** Returns `PendingBootstrapBackendError` |
| `direct` | none | `--bundle` (string, path to a CA bundle PEM), `--install-to-system-trust` (bool, default false), `--cert-path` (string, default `/usr/local/share/ca-certificates/platform-ca.crt`) | Implemented |

```bash
platformctl bootstrap direct --bundle ./platform-ca.pem
platformctl bootstrap direct --bundle ./platform-ca.pem --install-to-system-trust
```

The four stubs return an error telling you to use the key-management CLI's
`bootstrap <mode>` until the platform bridge ships. `direct` requires `--bundle`,
rejects a directory, reads the file and decodes every PEM block in it. It
rejects a file with no PEM block (`ErrDirectBundleNotPEM`), a `CERTIFICATE`
block that does not parse as X.509 (`ErrDirectBundleInvalidCert`), and a
bundle with no CA certificate (`ErrDirectBundleNoCA`); on success it prints the
path, the size and the number of CA certificates. It does not verify a chain
between the certificates. With `--install-to-system-trust` it writes the bundle
to `--cert-path` (a failure returns `ErrTrustInstallFailed`); run the OS
trust-store update (for example `update-ca-certificates`) afterwards, as with
`bootstrap trust`.

The stubs are a divergence between the locked surface and the implementation.
It is recorded here and in [engineering.md](engineering.md) §7.6 rather than
documented as if the stubs worked.

---

## 9. `platformctl bootstrap secrets`

Four verbs over a configuration file's secret URIs.

| Verb | Argument | Purpose |
|---|---|---|
| `migrate` | — | Rewrite plaintext secrets into KMS URIs |
| `verify` | — | Confirm every secret URI resolves |
| `status` | — | Report which secrets are present and how they resolve |
| `resolve` | `<uri>` | Resolve one URI |

**`migrate`**

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | `""` | Configuration file (**required**) |
| `--dry-run` | bool | `false` | Preview without modifying the file |
| `--no-backup` | bool | `false` | Skip the timestamped backup |
| `--force` | bool | `false` | Continue even when some secrets fail to resolve |
| `--key-id` | string | `config-secrets` | KMS key used to encrypt migrated secrets |

**`verify`**

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | `""` | Configuration file (**required**) |
| `--dry-run` | bool | `false` | Check resolver availability without resolving |
| `--fail-fast` | bool | `false` | Stop at the first failure |
| `--show-secrets` | bool | `false` | Print resolved values |

**`status`**

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | `""` | Configuration file (**required**) |
| `--show-uris` | bool | `false` | Print masked secret URIs |

**`resolve <uri>`** — exactly one positional argument.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--masked` | bool | `true` | Mask the resolved value |
| `--raw` | bool | `false` | Print the full value |

```bash
platformctl bootstrap secrets status  --config <install-dir>/config.yaml
platformctl bootstrap secrets verify  --config <install-dir>/config.yaml
platformctl bootstrap secrets migrate --config <install-dir>/config.yaml --dry-run
platformctl bootstrap secrets migrate --config <install-dir>/config.yaml
platformctl bootstrap secrets resolve "kms://config/db/password"
```

**`--no-backup` and `--force` are both loaded.** `migrate` rewrites the file in
place; without a backup a bad run is unrecoverable, and `--force` writes KMS
references for secrets that did not resolve, which produces a configuration that
parses and then fails at startup.

**`--show-secrets` and `--raw` print secrets to your terminal**, which means into
your scrollback and possibly your shell history file. Prefer the masked default
and read the *status*, not the value.

The platform recognises the URI schemes `kms://`, `remote-kms://`, `env://`,
`idevid://`, `file://`, `dynamic://`, `xkms://`, plus `credential://` and
`autogen://`, which the go-quicbaas registry resolves (`IsSecretURI`,
`pkg/bootstrap/secrets.go`). `secrets status`, `verify` and `migrate` count only
`kms://`, `remote-kms://`, `env://` and `idevid://` values as already migrated
(`isSecretURI` in `pkg/cli/commands/bootstrap/helpers.go`). A short `kms://`
path is expanded into `tenants/<tenant>/nodes/<node>/secrets/` when both IDs are
known (`ExpandShortKMSPath`).

---

## 10. `platformctl firstboot`

Runs on the node, after `switch_root`, to seal the LUKS key into the TPM. It is
normally invoked by a service unit, not by hand.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--luks-device` | string | `""` | LUKS device path; auto-detected when empty |
| `--tpm-auto-unseal` | bool | `true` | Seal the key to the TPM |
| `--tpm-only` | bool | `false` | Remove the password keyslot after sealing |
| `--swtpm-state-dir` | string | `/var/lib/swtpm` | Software-TPM state directory |
| `--efi-mount` | string | `/boot/efi` | EFI partition mount point |
| `--pcrs` | uint slice | `nil` | PCRs to seal against; read from configuration when unset |
| `--config` | string | `""` | Platform configuration file |
| `--fips` | bool | `false` | Parsed but not read ([FIPS mode](../fips/cli.md)) |
| `--verbose` | `-v` | `false` | Verbose logging |
| `--debug` | bool | `false` | Debug logging |
| `--platform-dir` | string | `/var/lib/trusted-platform` | Platform data directory |
| `--config-dir` | string | `/etc/trusted-platform` | Configuration directory |
| `--log-dir` | string | `/var/log/trusted-platform` | Log directory |
| `--ca-dir` | string | `""` | CA data directory; defaults to `<platform-dir>/ca` |
| `--tpm-path` | string | `/dev/tpmrm0` | TPM device |
| `--xkms-dir` | string | `/etc/trusted-platform/xkms` | Key-management storage directory |

```bash
platformctl firstboot
platformctl firstboot --luks-device /dev/sda2
platformctl firstboot --luks-device /dev/sda2 --tpm-only
platformctl firstboot --pcrs 0,1,2,3,7
```

**There is no default PCR set.** With no `--pcrs` and no `seal-pcrs` in
configuration the command refuses to run rather than sealing against a guess.
Resolution order is `--pcrs`, then `seal-pcrs` / `tpm.seal-pcrs` /
`installer.seal-pcrs` in the first configuration file found.

`secure-wipe-passes` (top level, same files) sets how many overwrite passes
destroy `installer.luks` when a `TPM-PCR` unlock has proven the seal: 1 (the
default, NIST SP 800-88: one random pass plus TRIM), 3 (DoD 5220.22-M) or 7
(DoD ECE). The wipe is done by `platform-initrd boot`
(`pkg/boot/commands/sealconfirm.go`). Firstboot reads the value too, but it never
wipes: it always preserves the container for that boot to destroy
(`pkg/firstboot/strategy.go`).

**`--tpm-only` removes the password keyslot.** After that the disk unlocks only
via the TPM. If the PCR policy stops matching — firmware update, bootloader
change — the recovery key is the only way in.

**Exit codes carry meaning.** Zero means sealed. Non-zero with a
`FIRSTBOOT INCOMPLETE` message means LUKS was unlocked with the plain key but
sealing did **not** complete: the PCR banks file was not written and the daemon
will fail at startup. That is why the exit code is non-zero — so the service
manager does not mark itself started and first boot re-runs on the next boot.
The command tells you the usual cause (stale TPM owner-hierarchy auth) and the
usual fix.

Running it when there is nothing to do is safe: it prints "Firstboot sealing not
needed - system already configured" and exits zero.

---

## 11. `platform-initrd`

Called by initramfs hooks. Listed for the operator reading a failed boot.

```
platform-initrd boot       Unlock the encrypted root filesystem
platform-initrd recovery   Unlock with fallbacks and re-seal
platform-initrd version    Print version information
```

**`boot`**

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--device` | `-d` | string | | LUKS device path (**required** unless `--diskless`) |
| `--diskless` | | bool | `false` | Mount the diskless dm-verity root described by the signed kernel command line instead of unlocking `--device` |
| `--root-mount` | | string | `/sysroot` | Where the diskless root is mounted |
| `--diskless-work-dir` | | string | `/run/platform/diskless-root` | tmpfs work directory for the diskless root |
| `--name` | `-n` | string | `cryptroot` | LUKS mapping name |
| `--timeout` | | int | `30` | Unlock timeout, seconds |
| `--pcrs` | | uint slice | `nil` | Expected PCR banks; read from the `pcr-banks` file when unset |
| `--fallback` | | bool | **`true`** | Enable fallback unlock methods |
| `--emergency` | | bool | `false` | Drop to an emergency shell on failure |
| `--tpm-path` | | string | `/dev/tpmrm0` | TPM device |
| `--efi-path` | | string | `/boot/efi` | EFI partition mount point |
| `--xkms-dir` | | string | `/etc/trusted-platform/xkms` | Key-management storage directory |
| `--verbose` | `-v` | bool | `false` | Verbose logging |
| `--debug` | | bool | `false` | Debug logging |
| `--fips` | | bool | `false` | Recorded but not read; the kernel's FIPS mode selects the keyslot KDF ([FIPS mode](../fips/cli.md)) |

**`recovery`** takes the same connection flags (`--device`, `--name`,
`--tpm-path`, `--efi-path`, `--xkms-dir`, `--verbose`, `--debug`, `--fips`) plus:

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--reseal-pcrs` | bool | **`true`** | Re-seal to the current PCRs after unlocking |
| `--fido2` | bool | **`true`** | Allow a FIDO2 authenticator to unlock |
| `--interactive` | bool | `false` | Interactive recovery menu |

```bash
platform-initrd boot --device /dev/sda2
platform-initrd boot --device /dev/sda2 --timeout 60
platform-initrd recovery --device /dev/sda2 --interactive
```

**`--fallback` defaults to true**, which enables the ordered unlock chain
TPM-PCR → TPM-Upgrade → FIDO2 (when an authenticator is present) → Password.
Disabling it registers none of them: only the first-boot `Keyfile` strategy
remains, so an enrolled node cannot unlock at all (`registerDefaultStrategies`
in `pkg/initrd/initrd.go`).

**`recovery --reseal-pcrs` defaults to true**, so a successful recovery unlock
re-seals to whatever the PCRs are *now*. That is what you want after a firmware
or kernel change and emphatically not what you want if you have not established
why the measurements changed.

PCR resolution order for `boot`: `--pcrs`, then `<efi-path>/tpm2/pcr-banks`, then
`seal-pcrs` in a configuration file found inside the mounted installer container
or on the root filesystem.

---

## 12. Exit codes and output

Verbs follow the `platformctl` conventions: `0` on success, non-zero on failure,
with the structured error rendered in the selected `--output` format.
`--output json` is the form to parse; the `table` renderer is for humans and its
columns are not a stable interface. The day-zero verbs print their own
fixed-width tables directly to stdout rather than going through the renderer, so
`--output json` does **not** change their shape.

`bootstrap run` returns non-zero when a phase fails, having already printed the
result block. A BMC-enrollment failure does not make the run non-zero. It is
logged as a warning (`bmc-enroll: enrollment failed`) and recorded in
`BootstrapResult.BMCEnrollments`, which the printed result block does not show;
read the log, then retry with `platformctl bmc enroll`.

---

## 13. What the CLI does not cover

| Capability | Reach it with |
|---|---|
| Barrier init, unseal, seal, rekey, ceremony | `platformctl barrier` — [`docs/barrier/cli.md`](../barrier/cli.md); `platformctl ceremony` |
| BMC enrollment outside a bootstrap run | `platformctl bmc` — [`docs/bmc/`](../bmc/) |
| Building or customising the ISO | `platformctl iso` — [`docs/provisioning/cli.md`](../provisioning/cli.md) |
| Device templates and profiles outside seeding | `platformctl device` — [`docs/device/`](../device/) |
| DANE TLSA record management | `platformctl dns record add --type tlsa` — [`docs/dns/cli.md`](../dns/cli.md) |
| Running bootstrap remotely | Nothing. There is no bootstrap service on any transport — [api.md](api.md) §5 |

---

## 14. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a matching
`CommandDefinition` in the integration parity suite. **This repository defines no
`CommandDefinition` type** (searched repo-wide, 2026-10-19), so that requirement
is unmet — repo-wide, not only for bootstrap.
