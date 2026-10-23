# ACME External Account Binding — Using It

> **Status: NORMATIVE** · Scope: `pkg/eab/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## What this is

An **EAB credential** is a one-off password you hand to a machine before it
exists on your network, so the platform can tell an expected machine from an
impostor that read the same serial number off a sticker.

It is a pair:

- **Key ID** — a public-ish identifier. Naming it in a log is fine.
- **HMAC key** — the secret. Whoever has it can enroll as that device profile.

The name comes from ACME's *External Account Binding* (RFC 8555 §7.3.4), which
solves the same problem for certificate accounts. Here the pair also gates the
platform's pre-enrollment flow: fetching a machine's configuration, and asking
the control plane to sign a Secure Boot key on its behalf.

---

## Before you start

1. **The platform must be QuicBaaS-backed.** If it is not, every EAB call
   returns *service unavailable* — there is nowhere to store credentials.
2. **You need a device profile.** A credential is bound to one
   ([`docs/device/`](../device/)).
3. **You need a way to call the API.** There is **no `platformctl eab`
   command** — see [cli.md](cli.md). Use the REST API, the Go SDK, the
   JavaScript SDK, or an MCP client.

---

## Issue a credential

```bash
curl -sX POST https://platform.example.com:8443/api/v1/eab/credentials \
  -H "Authorization: Bearer $PLATFORM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "profile_id": "4242",
        "tenant_id": "platform",
        "expires_in_seconds": 86400
      }'
```

The response is the **only** time you will see the HMAC key:

```json
{
  "credential": {
    "id": "1234567890",
    "key_id": "REPLACE_WITH_KEY_ID",
    "hmac_key": "REPLACE_WITH_BASE64URL_HMAC",
    "profile_id": "4242",
    "tenant_id": "platform",
    "status": "EAB_CREDENTIAL_STATUS_ACTIVE",
    "expires_at": "2026-08-19T12:00:00Z",
    "created_at": "2026-08-18T12:00:00Z"
  }
}
```

**Capture it now.** Every later read — get, list, validate — returns the
credential *without* `hmac_key`. Losing it means issuing a new credential.

Two options worth setting explicitly:

- **`expires_in_seconds`.** Omit it or send `0` and the credential **never
  expires**. There is no built-in default. For an install window, hours is
  usually right.
- **`hmac_key_length`.** Omit it for 32 bytes. Anything from 1 to 31 is
  rejected; 32 is the floor.

---

## Get it onto the machine

Three shapes, same credential.

**QR code** — for a technician standing at a console:

```bash
curl -s https://platform.example.com:8443/api/v1/eab/credentials/1234567890/qrcode?size=512 \
  -H "Authorization: Bearer $PLATFORM_TOKEN" -o enroll.png
```

**Enrollment URL** — for a browser or a paste buffer:

```bash
curl -s https://platform.example.com:8443/api/v1/eab/credentials/1234567890/url \
  -H "Authorization: Bearer $PLATFORM_TOKEN"
```

The HMAC key travels in the query string of that URL. Query strings end up in
proxy logs, browser history and `Referer` headers — prefer the QR code or a
file where you control the channel.

**JSON** — for a script:

```json
{"kid": "...", "hmac_key": "...", "profile_id": 4242, "tenant_id": "platform"}
```

`hmac_key` is `base64url` without padding on all three.

---

## Use it during install

The installer presents the pair on every pre-enrollment call:

```bash
platformctl provision fetch-config \
    --server-url https://platform.example.com:8443 \
    --ek-serial ABC123 \
    --mac 00:11:22:33:44:55 \
    --eab-kid REPLACE_WITH_KEY_ID \
    --eab-hmac REPLACE_WITH_BASE64URL_HMAC \
    --output /tmp/platform-config.yaml
```

Exit code `2` is not a failure — it means the server has the request and is
waiting for a human to approve the device. Follow it with:

```bash
platformctl provision interactive \
    --server-url https://platform.example.com:8443 \
    --ek-serial ABC123 --mac 00:11:22:33:44:55 \
    --eab-kid REPLACE_WITH_KEY_ID \
    --eab-hmac REPLACE_WITH_BASE64URL_HMAC \
    --output /tmp/platform-config.yaml --timeout 600
```

which shows a QR code for the operator and polls every 5 seconds.

---

## Retire it when the machine is up

Nothing does this for you.

```bash
# The machine enrolled successfully — burn the credential.
curl -sX POST https://platform.example.com:8443/api/v1/eab/credentials/1234567890/used \
  -H "Authorization: Bearer $PLATFORM_TOKEN"

# The credential leaked, or the install was abandoned — kill it now.
curl -sX POST https://platform.example.com:8443/api/v1/eab/credentials/1234567890/revoke \
  -H "Authorization: Bearer $PLATFORM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"revoker_id": "98765"}'
```

Both are one-way. `used` and `revoked` are terminal; nothing reactivates a
credential.

Sweep expired ones periodically:

```bash
curl -sX POST https://platform.example.com:8443/api/v1/eab/credentials/cleanup \
  -H "Authorization: Bearer $PLATFORM_TOKEN" \
  -H "Content-Type: application/json" -d '{"tenant_id": "platform"}'
```

There is no background expiry job. Expired credentials sit in the store,
correctly refusing to validate, until something calls cleanup.

---

## Check one without using it

```bash
curl -sX POST https://platform.example.com:8443/api/v1/eab/credentials/validate \
  -H "Authorization: Bearer $PLATFORM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key_id": "REPLACE_WITH_KEY_ID", "hmac_key": "REPLACE_WITH_BASE64URL_HMAC"}'
```

**A rejection comes back as HTTP 200** with `"valid": false` and an
`error_message`. Check the `valid` field, not the status code. Validating does
**not** consume the credential — only `used` does that.

---

## Troubleshooting

**Every EAB call returns 503 / "eab service not configured".**
The platform is not QuicBaaS-backed. There is no credential store, so nothing to
serve. Fix the deployment, not the request.

**QR code and enrollment URL return 503, everything else works.**
The delivery handler has no base URL — the platform FQDN or REST port is
unset. Credentials still issue; only rendering is unavailable.

**Enrollment fails with "credential expired" and you did not set an expiry.**
Then it is not expired — re-read the error. If you *did* set
`expires_in_seconds`, note the clock is the server's.

**Enrollment fails with "credential already used".**
Something called `mark used` — usually a previous successful enrollment of the
same machine, or a re-run of an install script. Issue a fresh credential.

**Enrollment fails with "invalid credential: HMAC key mismatch".**
The KeyID exists and the key does not match. Almost always a transcription
error, or padding: the key is `base64url` **without** padding. Do not add `=`.

**Enrollment fails with "credential not found".**
The KeyID itself is wrong, or the credential was deleted (not revoked —
deleted).

**Pre-enrollment succeeds with a credential you know is revoked.**
The provisioning service was started without an EAB service wired. In that
configuration the EAB fields are required to be *present* and are never
*checked* — a fail-open path documented in [architecture.md](architecture.md)
§5 and [engineering.md](engineering.md) §4. Treat it as a misconfiguration and
fix the wiring.

**You cannot find the HMAC key anywhere.**
It was returned once. It is not readable afterwards, by anyone, through any
transport. Issue a new credential and revoke the old one.

---

## One thing to be aware of

On gRPC and Unix, issuing an EAB credential needs `eab:write`, and a create
response contains a live HMAC key, so guard that grant. MCP refuses every
`platform_eab_*` tool until they are classified. The QUIC opcode catalog
(`DefaultOpcodePermissions`) has no EAB entry, so on QUIC any valid platform
token can still issue a credential. Recorded in [api.md](api.md) §5.

---

## Where to go next

- [cli.md](cli.md) — the flags that consume a credential
- [api.md](api.md) — every capability on every transport
- [architecture.md](architecture.md) — why the pair exists and what it is trusted for
- [`docs/ca/`](../ca/) · [`docs/device/`](../device/) · [`docs/provisioning/`](../provisioning/)
