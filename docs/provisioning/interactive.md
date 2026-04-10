# Interactive QR Provisioning

When no pre-existing config matches a device, the device displays a QR code that an operator scans to create a config on the fly.

## How It Works

```
Device (console)                    Operator (any device)
────────────────                    ─────────────────────
1. Boot ISO
2. No matching config found
3. Display QR code ──────────────▶ 4. Scan QR code
   (URL to web UI)                  5. Browser opens URL
                                    6. WebAuthn/FIDO2 login
                                    7. Select template
                                    8. Customize config
                                    9. Save profile ────────▶ 10. Poll returns config
                                                              11. Install continues
```

## QR Code Content

The QR code contains a standard URL:

```
https://platform.example.com:8443/provisioning/sessions/{sessionID}
```

This URL works with:
- Any phone's camera app (opens browser)
- xkey app (using FIDO2/PIV as authenticator)
- Any laptop or tablet with a camera
- Manual URL entry in any browser

## Operator Experience

1. **Scan QR code** — any device with a camera
2. **Authenticate** — standard WebAuthn/FIDO2 login if no active session (xkey works as a FIDO2 authenticator)
3. **View device info** — EK serial, MAC address, timestamp
4. **Choose action**:
   - **Create from Template** — select a template, customize fields (hostname, IP, TPM PCRs, etc.), save as profile
   - **Create New Profile** — full profile editor
5. **Save** — profile created with device identity, session fulfilled, device resumes installation

## Device Console Display

When interactive mode activates, the console shows:

```
╔══════════════════════════════════════════════════╗
║        TRUSTED PLATFORM - DEVICE PROVISIONING    ║
╠══════════════════════════════════════════════════╣
║                                                  ║
║  Scan the QR code below to provision this device ║
║                                                  ║
║  ┌──────────────────────────────────────┐       ║
║  │                                      │       ║
║  │         [QR CODE ASCII ART]          │       ║
║  │                                      │       ║
║  └──────────────────────────────────────┘       ║
║                                                  ║
║  Device Info:                                    ║
║    EK Serial: ABC123DEF456789                    ║
║    MAC:       52:54:00:12:34:56                  ║
║                                                  ║
║  Or visit:                                       ║
║  https://platform:8443/provisioning/sessions/... ║
║                                                  ║
║  Waiting for operator...  [polling every 5s]     ║
╚══════════════════════════════════════════════════╝
```

## CLI Commands

```bash
# Automatic flow (called by autoinstall.sh)
platformctl-static provision interactive \
  --server-url https://platform:8443 \
  --ek-serial <serial> \
  --mac <address> \
  --eab-kid <key-id> \
  --eab-hmac <hmac> \
  --output /tmp/platform-config.yaml \
  --timeout 600

# Manual session fulfillment (operator CLI alternative)
platformctl provision fulfill \
  --session-id <id> \
  --profile-id <pid>
```

## Security

- The QR code URL requires WebAuthn/FIDO2 authentication
- Session IDs are UUIDs — not guessable
- Sessions expire after 30 minutes
- Sessions are single-use — cannot be fulfilled twice
- The operator's tenant determines the available templates
- All communication is over TLS (trust bootstrapped via DANE/Noise/SPKI)
