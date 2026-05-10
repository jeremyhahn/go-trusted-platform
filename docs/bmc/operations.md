# BMC Operations

Power control, boot device management, virtual media, sensor
monitoring, user management, serial-over-LAN console, and TLS
certificate management.

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
    --bmc-host 198.18.1.103 \
    --bmc-user admin \
    --bmc-pass-file /etc/platform/bmc.pass \
    --bmc-protocol ipmi
```

Press `Ctrl+]` to disconnect. Stdin is placed in raw mode for the
duration of the session.

### Capture to log file

```bash
platformctl bmc console \
    --bmc-host 198.18.1.103 \
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
