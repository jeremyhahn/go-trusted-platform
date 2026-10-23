# Interactive Provisioning

> **Status: REFERENCE** · Last verified: 2026-10-15
> The interactive flow for a device no profile matches.

When no device profile matches a device, config delivery opens a pending
session instead of delivering a config. The device waits on the session while
an operator assigns it a profile.

## How It Works

```
Device (console)                    Operator
────────────────                    ────────
1. provision interactive
2. No matching profile:
   server opens a pending session
3. Prints the session URL ───────▶ 4. Opens the session in the dashboard
                                      (or uses the CLI)
                                   5. Creates a profile from a template, or a
                                      custom profile, and fulfills the session
6. Poll returns the config ◀──────
7. Config written to --output
```

## Session URL

The device prints the `provision_url` the server returned
(`Service.provisionURL`, `pkg/provisioning/configdelivery/service.go`):

```
https://platform.example.com:8443/api/v1/provisioning/sessions/{sessionID}
```

That is the REST session view, which needs the `provisioning:read` scope. No
QR code is rendered: `generateQRText` (`pkg/cli/commands/provision/helpers.go`)
prints the URL as plain text.

## Operator Experience

The web dashboard lists sessions at `/provisioning/sessions`; its session page
(`web/src/app/(dashboard)/provisioning/sessions/[sessionId]/`) shows the
device's EK serial and MAC address and offers two actions, each of which creates
the profile and fulfills the session:

- **Create from Template**: pick a device template and customize it
- **Create Custom Profile**: fill in the profile directly

## Device Console Output

```
========================================
  DEVICE PROVISIONING
========================================

Open this URL to provision the device:

  https://platform:8443/api/v1/provisioning/sessions/...

========================================

Device Info:
  EK Serial: ABC123DEF456789
  MAC:       52:54:00:12:34:56

Scan QR code to provision this device
Waiting for approval (timeout: 600s)...
```

The device polls every 5 seconds until the session is fulfilled or the timeout
expires.

## CLI Commands

```bash
# Device side (run explicitly; autoinstall.sh does not call it)
platformctl provision interactive \
  --server-url https://platform:8443 \
  --ek-serial <serial> \
  --mac <address> \
  --eab-kid <key-id> \
  --eab-hmac <hmac> \
  --output /tmp/platform-config.yaml \
  --timeout 600

# Operator side
platformctl provision session fulfill <session-id> --profile-id <pid>
```

`--timeout` is in seconds and defaults to 600; every other flag is required.

## Security

- Opening a session needs valid EAB credentials and a fresh nonce
- Session IDs are random UUIDs
- Sessions expire after 30 minutes (`defaultSessionTTL`)
- A session can be fulfilled once; a second fulfill is refused
- Session views and fulfillment need the `provisioning:read` /
  `provisioning:write` scopes
