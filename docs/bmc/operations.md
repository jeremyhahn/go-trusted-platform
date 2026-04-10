# BMC Operations

Power control, boot device management, virtual media, and sensor monitoring.

## Power Control

### Power On

Start a powered-off server.

**CLI:**
```bash
platformctl bmc power --profile-id 42 --action on
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
platformctl bmc power --profile-id 42 --action off
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
platformctl bmc power --profile-id 42 --action reset
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
platformctl bmc power --profile-id 42 --action cycle
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
platformctl bmc virtual-media-status --profile-id 42
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
