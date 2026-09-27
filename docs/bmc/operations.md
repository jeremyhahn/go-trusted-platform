# BMC Operations

Power control, boot device management, virtual media, sensor
monitoring, user management, serial-over-LAN console, TLS
certificate management, and trust-lifecycle enrollment.

## Enrollment

The enrollment ceremony establishes a BMC's trust relationship with the
platform: it pins the BMC's TLS certificate into the SPKI pin store, issues
a platform-signed replacement certificate via the Trust CA, registers the
host in internal DNS, and publishes DANE TLSA records. The ceremony is
also triggered automatically by the bootstrap orchestrator at phase 5a
(`bmc-enroll`) for nodes that pass PXE provisioning. See
[docs/bootstrap/pxe-bootstrap.md](../bootstrap/pxe-bootstrap.md) for
orchestrator context.

### Ceremony steps

The ceremony executes the following ordered steps. Each step is recorded
independently; a failure in any step returns the partial result so the
operator can see which steps completed.

| Step | Name in result | Default |
|---|---|---|
| Establish TLS trust via class-bmc resolver | `trust` | always runs |
| Capture the factory TLS certificate | `factory-cert` | always runs |
| Persist BMC credentials to the credential store | `credentials` | always runs |
| Issue and deploy a platform-signed TLS certificate | `replace-certificate` | on |
| Register `<hostname>-bmc.<zone>` A record in internal DNS | `dns-register` | on |
| Publish DANE TLSA records for the new certificate | `dane-publish` | on |
| Stamp `Device.BMCEnrollment` with the enrollment record | `device-stamp` | always runs |

Steps that are skipped (via config or unavailable dependencies) are
recorded with `ok: true` and a skip reason, so the result is always a
complete audit trail even for partial ceremonies.

**DANE publication failure is non-fatal.** The certificate is already
deployed to the BMC when the DANE step runs. If TLSA publishing fails
(e.g., the DNS service is temporarily unavailable), the step is recorded
but does not abort the ceremony. Operators can re-run enrollment to
publish the TLSA record once DNS is restored.

All five transports expose the enrollment operation:
`POST /api/v1/bmc/{profileID}/enroll` (REST), `EnrollBMC` (gRPC),
`OpBMCCategory`/`BMCSubEnroll` (QUIC), `platform_bmc_enroll` (MCP),
and `EnrollBMC` (Unix/gRPC-over-UDS).

### Enroll a BMC

Use the profile's stored `enrollment` config defaults:

```bash
platformctl bmc enroll --profile-id 7
```

Override specific steps at call time (tri-state flags — when omitted,
the profile default is used):

```bash
platformctl bmc enroll --profile-id 7 \
    --replace-certificate \
    --rotate-password \
    --dns-register \
    --dane-publish
```

Persist the factory certificate and full enrollment result to disk:

```bash
platformctl bmc enroll --profile-id 7 \
    --backups-dir /var/lib/platform/backups
```

`--backups-dir` may also be set via the `PLATFORMCTL_BACKUPS_DIR`
environment variable. When not set, a notice is printed to stderr and
no client-side backup is written.

### Backup layout

When `--backups-dir` (or `PLATFORMCTL_BACKUPS_DIR`) is set and the
ceremony returns a factory certificate PEM, three files are written
under `<dir>/<hostname>/bmc/` with mode `0700` (directory) / `0600`
(files):

| File | Contents |
|---|---|
| `factory-cert.pem` | PEM-encoded factory TLS certificate |
| `factory-cert.json` | Auditable metadata (subject, issuer, serial, validity, SPKI SHA-256, DER SHA-256, capture time) |
| `enrollment.json` | Full enrollment result (all fields, all steps) |

The backup exists solely for **identity evidence**: the factory
certificate proves the BMC's original identity at enrollment time.
The platform never holds the factory certificate's private key and
never re-uploads the backup.

### REST example

```bash
curl -X POST https://platform:8443/api/v1/bmc/7/enroll \
  -H "Content-Type: application/json" \
  -d '{}'
```

All four override fields (`replace_certificate`, `rotate_password`,
`dns_register`, `dane_publish`) are optional booleans in the request
body. Absent fields use the profile's stored enrollment config defaults.

---

## Factory Certificate Restore

Restoring the factory certificate reverses an enrollment: the BMC is
instructed to regenerate its built-in default self-signed certificate,
the platform SPKI pin is deleted, DANE TLSA records are removed, and the
`Device.BMCEnrollment` record is cleared.

**Restore does not re-upload the backed-up factory certificate.** The
platform never held the factory cert's private key, so it cannot
re-deploy it. Instead, the BMC's firmware regenerates a fresh self-signed
certificate. The factory backup (see backup layout above) serves as
identity evidence only.

### Restore ceremony steps

| Step | Name in result |
|---|---|
| Instruct BMC to regenerate its default self-signed cert | `restore-cert` |
| Delete the stored TOFU SPKI pin from the platform trust store | `pin-delete` |
| Remove DANE TLSA records keyed by `Device.BMCEnrollment.DNSName` | `dane-unpublish` |
| Clear `Device.BMCEnrollment` (preserve `FactoryCertSHA256` for audit) | `device-state` |

`pin-delete` failure is non-fatal: the TOFU resolver detects the new
self-signed certificate on the next connection and updates the pin
automatically. `dane-unpublish` failure is also non-fatal.

The TLSA removal is keyed by the enrolled DNS name stored in
`Device.BMCEnrollment.DNSName`, not by the raw BMC address, so the
record that was published during enrollment is exactly the one removed.
When no DNS name is recorded (enrollment never ran dns-register), the
DANE step is skipped silently.

All five transports expose the restore operation:
`POST /api/v1/bmc/{profileID}/cert/restore` (REST), `RestoreFactoryCert` (gRPC),
`OpBMCCategory`/`BMCSubRestore` (QUIC), `platform_bmc_cert_restore` (MCP),
and `RestoreFactoryCert` (Unix/gRPC-over-UDS).

### X10 hardware caveat (SMC CGI backend)

The Supermicro ATEN CGI restore path (`op=SSL_DEFAULT` via `op.cgi`)
has been tested only against httptest fakes that model the CGI wire
protocol from the SMCIPMITool manual. Before using the `smc-cgi` backend
for cert restore on real X10/X11 hardware, capture a HAR trace of the
default-SSL operation via the iKVM HTML5 UI on the target firmware and
diff it against the implementation. See
`docs/operations/x10-smc-cgi-validation.md`.

### Restore command

```bash
platformctl bmc cert restore --profile-id 7 --factory
```

The `--factory` flag is **required** and must be explicit. It exists
to prevent accidental invocation — restore removes the platform-issued
certificate from the BMC and cannot be undone without re-enrolling.

### REST example

```bash
curl -X POST https://platform:8443/api/v1/bmc/7/cert/restore
```

No request body is required.

---

## TLS Certificate Management

See `../operations/cert-lifecycle.md` for the canonical runbook.
Key operations:

### Show the current BMC cert

```bash
openssl s_client -connect <bmc-ip>:443 -showcerts </dev/null 2>/dev/null \
    | openssl x509 -subject -issuer -dates -noout
```

### Get certificate details (via platformd)

```bash
platformctl bmc cert get --profile-id 42
```

Returns subject, issuer, serial, validity period, SANs and
SHA-256 fingerprint. JSON via `--output-format json`.

### Show certificate expiry status

```bash
platformctl bmc cert status --profile-id 42
```

Same data as `cert get`, intended for renewal monitoring.

### Force a cert replacement (bypass scheduler)

```bash
platformctl bmc cert replace \
    --profile-id <id> \
    --cert <path-to-cert.pem> \
    --key  <path-to-key.pem>
```

The backend (`auto`, `redfish`, or `smc-cgi`) is determined by the
device profile's `bmc.backend` config field. Standalone mode is also
available for direct BMC access without a profile:

```bash
platformctl bmc cert replace \
    --bmc-host <bmc-ip> --bmc-user admin --bmc-pass-file /etc/bmc-pass \
    --cert <path-to-cert.pem> --key <path-to-key.pem>
```

### Inspect automatic renewal job

The scheduler CLI commands (`platformctl schedule list`,
`platformctl schedule history`, etc.) are planned but not yet
implemented. Use the platformd logs to monitor cert renewal job
outcomes until the scheduler CLI is available.

### AutoCertManager selection logs

AutoCertManager logs a single structured entry on first probe per
BMC:

```
bmc: autocert: resolved backend  vendor=supermicro  requested=auto
                                 resolved=smc-cgi  has_fallback=false
```

If the probe hits a 501 on the primary backend, a second line
records the fallback attempt:

```
bmc: autocert: primary backend unsupported, trying fallback
              primary=redfish  fallback=smc-cgi  error="HTTP 501"
```

Absence of either line means AutoCertManager was not constructed
for the target BMC — check the config has `certificate:` and
`key:` blocks populated.


### Renewal trust publication

The 90-day cert-renewal scheduler calls `issueBMCCertificateCore` on
each registered BMC target. When the scheduler reissues a certificate,
the platform performs a two-phase DANE rollover following RFC 7671 §8.1
to ensure DANE validators never observe a certificate that has no
matching TLSA record.

**Pre-publication (OnCertIssued hook).**  After the new leaf certificate
is obtained from the CA but before it is deployed to the BMC,
`DANEPublisher.PrePublishRollover` adds the new DANE-EE TLSA record
alongside the existing records. DANE validators can therefore resolve
the new fingerprint at any point during or after the DNS TTL window.
If pre-publication fails (DNS temporarily unavailable), the failure is
logged at `warn` level and the deploy continues — a transient DANE gap
is preferable to withholding the cert renewal.

**Post-deployment pin update and full re-publish (OnCertDeployed hook).**
After `ReplaceWebCertificate` succeeds, two operations run in order:

1. The stored SPKI pin for the BMC host is updated to the new
   certificate's SubjectPublicKeyInfo SHA-256. This ensures the
   class-bmc `spki` resolver trusts the new cert on the next connection.
   (This was described as a TOFU pin until #83; tofu is not available for
   the bmc class, because it fetches a CA bundle a BMC does not serve.)

2. `DANEPublisher.PublishForCertificate` re-publishes the complete TLSA
   record set: a DANE-TA record anchored at the Trust CA (when a CA cert
   is available) plus a DANE-EE record for the leaf.

If the deployed CA cert is unavailable (ACME path), the DANE-TA record
is omitted and only the DANE-EE record is published. Both operations are
non-fatal — a failure is logged at `error` level, but the renewal is
considered successful because the certificate is already deployed. The
TLSA records can be corrected by re-running enrollment once DNS is
restored.

The DNS name used for all TLSA operations is read from
`Device.BMCEnrollment.DNSName` at hook-invocation time (not at boot),
so devices enrolled after platformd starts are handled correctly. If no
DNS name is recorded (enrollment skipped `dns-register`), the DANE steps
are skipped silently but the TOFU pin is still updated.

## Power Control

### Power On

Start a powered-off server.

**CLI:**
```bash
platformctl bmc power-on --profile-id 42
```

**REST:**
```bash
curl -X POST https://platform:8443/api/v1/bmc/42/power \
  -H "Content-Type: application/json" \
  -d '{"action": "on"}'
```

### Power Off

Immediately power off a server (hard shutdown).

**CLI:**
```bash
platformctl bmc power-off --profile-id 42
```

**REST:**
```bash
curl -X POST https://platform:8443/api/v1/bmc/42/power \
  -H "Content-Type: application/json" \
  -d '{"action": "off"}'
```

### Power Reset

Hard reset (equivalent to pressing the reset button).

**CLI:**
```bash
platformctl bmc power-reset --profile-id 42
```

**REST:**
```bash
curl -X POST https://platform:8443/api/v1/bmc/42/power \
  -H "Content-Type: application/json" \
  -d '{"action": "reset"}'
```

### Power Cycle

Power off then power on (with brief delay).

**CLI:**
```bash
platformctl bmc power-cycle --profile-id 42
```

**REST:**
```bash
curl -X POST https://platform:8443/api/v1/bmc/42/power \
  -H "Content-Type: application/json" \
  -d '{"action": "cycle"}'
```

### Power Status

Query the current power state.

**CLI:**
```bash
platformctl bmc power-status --profile-id 42
```

**REST:**
```bash
curl https://platform:8443/api/v1/bmc/42/power
```

**Response:**
```json
{
  "state": "on"
}
```

Power states: `on`, `off`, `unknown`.

## Boot Device Management

### Set Boot Device

Set the next boot device. Use `persistent: true` to make it survive reboots.

**CLI:**
```bash
platformctl bmc set-boot-device --profile-id 42 --device pxe --persistent
```

**REST:**
```bash
curl -X POST https://platform:8443/api/v1/bmc/42/boot-device \
  -H "Content-Type: application/json" \
  -d '{"device": "pxe", "persistent": false}'
```

### Get Boot Device

Query the current boot device override.

**CLI:**
```bash
platformctl bmc get-boot-device --profile-id 42
```

**REST:**
```bash
curl https://platform:8443/api/v1/bmc/42/boot-device
```

**Response:**
```json
{
  "device": "pxe"
}
```

Supported boot devices:

| Device | Description |
|--------|-------------|
| `pxe` | PXE network boot |
| `disk` | Local hard disk |
| `cdrom` | CD-ROM drive |
| `virtual_media` | Virtual media (mounted ISO) |
| `none` | No boot device override |

## Virtual Media

### Mount ISO

Mount an ISO image via the BMC's virtual media interface.

**CLI:**
```bash
platformctl bmc mount-iso --profile-id 42 --iso-url https://iso.example.com/os.iso
```

**REST:**
```bash
curl -X POST https://platform:8443/api/v1/bmc/42/virtual-media \
  -H "Content-Type: application/json" \
  -d '{"iso_url": "https://iso.example.com/os.iso"}'
```

### Unmount ISO

Remove the currently mounted virtual media.

**CLI:**
```bash
platformctl bmc unmount-iso --profile-id 42
```

**REST:**
```bash
curl -X DELETE https://platform:8443/api/v1/bmc/42/virtual-media
```

### Virtual Media Status

Check what is currently mounted.

**CLI:**
```bash
platformctl bmc media-status --profile-id 42
```

**REST:**
```bash
curl https://platform:8443/api/v1/bmc/42/virtual-media
```

**Response:**
```json
{
  "mounted": true,
  "image_url": "https://iso.example.com/os.iso",
  "media_type": "iso"
}
```

## Sensors

Retrieve hardware sensor readings from the BMC.

**CLI:**
```bash
platformctl bmc sensors --profile-id 42
```

**REST:**
```bash
curl https://platform:8443/api/v1/bmc/42/sensors
```

**Response:**
```json
[
  {"name": "CPU1 Temp", "value": 42.0, "units": "C", "status": "ok"},
  {"name": "System Fan 1", "value": 3200, "units": "RPM", "status": "ok"},
  {"name": "PS1 Voltage", "value": 12.1, "units": "V", "status": "ok"}
]
```

Sensor statuses: `ok`, `warning`, `critical`.

## System Information

Retrieve system identification from the BMC.

**CLI:**
```bash
platformctl bmc system-info --profile-id 42
```

**REST:**
```bash
curl https://platform:8443/api/v1/bmc/42/system-info
```

**Response:**
```json
{
  "manufacturer": "Dell Inc.",
  "product": "PowerEdge R640",
  "serial_number": "ABC1234567",
  "firmware_version": "2.82.82.82",
  "bios_version": "2.14.0",
  "power_state": "on"
}
```

## Host MAC Discovery

Discover the host system's NIC MAC addresses out-of-band, before the
node has ever booted an OS. This is a **standalone-only** command — it
talks directly to the BMC with the same `--bmc-host` flag set as the
other standalone operations and never routes through platformd.

**CLI:**
```bash
platformctl bmc mac \
  --bmc-host 198.51.100.103 \
  --bmc-user ADMIN \
  --bmc-pass-file ~/.bmc-pass \
  --bmc-protocol ipmi
```

**Response (`--output json`):**
```json
{
  "host": "198.51.100.103",
  "macs": ["00:25:90:5e:02:aa"]
}
```

**Discovery paths:**

- **Redfish** — walks the system's `EthernetInterfaces` collection and
  returns every valid unicast MAC.
- **IPMI (Supermicro OEM)** — issues the Supermicro OEM command
  NetFn `0x30` / Cmd `0x21` ("Get LAN1 MAC Address") over the RMCP+
  session. This is the only out-of-band path on X10 ATEN firmware
  (4.0.x), whose Redfish `EthernetInterfaces` collection is
  unpopulated. The OEM command is gated to Supermicro-family BMCs via
  the IPMI Get-Device-ID IANA enterprise number — a model-independent
  check, so rebadged boards such as the VeloCloud EDGE840 (Supermicro
  X10SDV silicon with an empty SMBIOS model string) take the OEM path
  like any other X10. Non-Supermicro vendors fall through to Redfish on
  the same address.
- **IPMI → Redfish fallthrough** — the fallthrough runs no reachability
  check of its own: it walks with the configured client's trust settings
  and timeouts, so a BMC the client can reach is never written off by a
  separate probe. Because "this endpoint speaks Redfish" is an inference
  rather than the operator's instruction, the connection first reads the
  Redfish service root **without credentials** (DSP0266 §7.3 requires it
  to be readable unauthenticated). Only an endpoint that answers as a
  real service root is then given the operator's BMC password; redirects
  are refused, and the identified peer's certificate is pinned for the
  authenticated walk. Anything else surfaces
  `ErrMACDiscoveryUnsupported` and the operator supplies MACs manually.

The same dispatch backs `platformctl bootstrap discover` (Phase 0 MAC
discovery), so IPMI-only Supermicro fleets no longer require operator-
provided MACs in `bootstrap.yaml`.

## User Management

BMC user management is exposed under `platformctl bmc user`. All
subcommands accept either `--profile-id <id>` (talks to platformd
over gRPC) or the standalone `--bmc-host`/`--bmc-user`/
`--bmc-pass-file` flag set for direct BMC access.

Valid roles: `administrator`, `operator`, `user`, `callback`,
`no-access`.

### List users

```bash
platformctl bmc user list --profile-id 42
```

Prints `SLOT`, `USERNAME`, `ENABLED`, `PRIVILEGE`, `CHANNEL`.
Add `--output-format json` for machine output.

### Create user

```bash
platformctl bmc user create --profile-id 42 \
    --username operator1 --role operator
```

The new password is prompted securely on stderr. `--slot` (default
0 = auto-assign) and `--channel` (default 1) are available for
hardware that requires explicit slot/channel selection.

### Delete user

```bash
platformctl bmc user delete --profile-id 42 --username operator1
```

The slot is resolved automatically by listing accounts first.

### Update password

```bash
platformctl bmc user update-password --profile-id 42 \
    --username operator1
```

The new password is prompted securely.

### Update access level

```bash
platformctl bmc user update-access --profile-id 42 \
    --username operator1 --role administrator
```

`--channel` (default 1) targets a specific IPMI channel index.

## Serial-over-LAN Console

`platformctl bmc console` opens an interactive Serial-over-LAN
session to a BMC over IPMI 2.0 RMCP+. SOL is **standalone-only**;
there is no platformd proxy because the protocol is a long-lived
bidirectional stream.

### Interactive session

```bash
platformctl bmc console \
    --bmc-host 10.4.2.103 \
    --bmc-user admin \
    --bmc-pass-file /etc/platform/bmc.pass \
    --bmc-protocol ipmi
```

Press `Ctrl+]` to disconnect. Stdin is placed in raw mode for the
duration of the session.

### Capture to log file

```bash
platformctl bmc console \
    --bmc-host 10.4.2.103 \
    --bmc-user admin \
    --bmc-pass-file /etc/platform/bmc.pass \
    --bmc-protocol ipmi \
    --log-file /var/log/sol-r640-01.log
```

Useful when stdin is not a TTY (cron, CI, automation). Press
`Ctrl+C` to stop capture.

### Send a serial-break

```bash
platformctl bmc console --bmc-host ... --send-break
```

Sends a single break to the console and exits. Useful for kicking
a stuck firmware menu.

### Drive recoveries with --send

`--send` writes literal strings to the console before any
interactive or capture loop runs. Repeatable; the delay between
sends is `--send-delay` (default 500ms).

```bash
platformctl bmc console --bmc-host ... \
    --bmc-protocol ipmi \
    --log-file recovery.log \
    --send 'reset\r' \
    --send 'boot\r'
```

Recognized escapes: `\r`, `\n`, `\t`, `\\`, `\e` (ESC, 0x1b),
`\xNN` (arbitrary byte). Unknown escapes are rejected so typos
don't silently turn into literal sequences.

## REST API Reference

All endpoints are prefixed with `/api/v1`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/bmc/{profileID}/power` | Execute power action |
| GET | `/bmc/{profileID}/power` | Get power status |
| POST | `/bmc/{profileID}/boot-device` | Set boot device |
| GET | `/bmc/{profileID}/boot-device` | Get boot device |
| POST | `/bmc/{profileID}/virtual-media` | Mount ISO |
| DELETE | `/bmc/{profileID}/virtual-media` | Unmount ISO |
| GET | `/bmc/{profileID}/virtual-media` | Virtual media status |
| GET | `/bmc/{profileID}/sensors` | Get sensor readings |
| GET | `/bmc/{profileID}/system-info` | Get system info |
| POST | `/bmc/{profileID}/provision` | Trigger provisioning |
| GET | `/bmc/{profileID}/provision` | Get provisioning status |
| POST | `/bmc/{profileID}/enroll` | Run BMC enrollment ceremony |
| POST | `/bmc/{profileID}/cert/restore` | Restore factory certificate |

## Error Responses

All errors follow the standard platform error format:

```json
{
  "code": 400,
  "error": "bmc: invalid action: destroy",
  "success": false,
  "payload": null
}
```

| Status | Condition |
|--------|-----------|
| 400 | Invalid profile ID, missing/invalid action, missing ISO URL |
| 404 | Profile not found, provision not found |
| 409 | Provision already in progress for the profile |
| 500 | BMC communication failure, internal error |
