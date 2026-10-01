# X10 Supermicro CGI Cert Upload -- Hardware Validation Procedure

## Purpose

Before `bmc.AutoCertManager` is allowed to select the Supermicro ATEN
CGI backend in `auto` mode, the wire protocol implemented in
`pkg/bmc/smc/cgi_cert.go` must be validated against a real X10 BMC.
This document is the runbook an operator follows to perform that
validation and flip the `allowCGIFallback` gate on.

## Why the gate exists

`pkg/bmc/smc/` implements the five-step ATEN CGI cert upload flow
(login -> upload_ssl -> SSL_VALIDATE -> BMC_reset -> logout) based on
publicly documented behavior. The devcontainer vBMC responder
(`test/integration/bmc/vbmc`) stubs the same endpoints but is **not** a
byte-for-byte replica of ATEN firmware. Firmware revisions vary;
undocumented quirks (multipart boundary handling, cookie scope,
validate-response shape) can break the flow against specific hardware.

The gate -- a package-level `allowCGIFallback atomic.Bool`, default
`false` -- prevents auto-mode from resolving Supermicro detection to
the CGI backend until this validation clears. Explicit
`backend: smc-cgi` in config still works (operator opt-in).

## Hardware requirements

- Supermicro X10 generation board with ATEN BMC firmware
  - X10SDV-TP8F, X10SDV-4C-7TP4F, or similar
  - BMC firmware 3.x or 4.x (platform variations expected)
- Network-reachable BMC over HTTPS (port 443)
- BMC administrator credentials
- A platform CA that issues certs the BMC will accept
  - Standard RSA-2048 or ECDSA P-256 leaves with valid SANs
  - CN / SAN matching the BMC's hostname or IP

## Validation procedure

### 1. Capture the baseline

Before touching anything, record the BMC's current state so you can
restore after testing:

```bash
# Export the current BMC cert (will be overwritten during test)
openssl s_client -connect <bmc-ip>:443 -showcerts </dev/null 2>/dev/null \
    | openssl x509 -outform PEM > /tmp/bmc-orig.pem

# Note firmware version for the record
curl -sk -u ADMIN:<pwd> https://<bmc-ip>/cgi/ipmi.cgi \
    -d "GENERIC_SESSION.PROCESS=GET&GENERIC_SESSION.FLD=FWD_INFO" \
    | tee /tmp/bmc-fwinfo.txt
```

### 2. Verify the platform-issued cert is ready

```bash
# Build the vBMC harness binary (same wire protocol as production)
cd .
go build -o /tmp/vbmc ./test/integration/bmc/vbmc

# Confirm your platform CA can issue for the BMC's hostname
platformctl ca issue --cn <bmc-hostname> --san <bmc-hostname> \
    --out /tmp/bmc-new.pem --key /tmp/bmc-new.key
```

### 3. Dry-run against the vBMC first

Confirm platformd's CGI path works against the well-behaved vBMC
before pointing it at real hardware:

```bash
# Start vBMC on a local port, Supermicro flavor
VBMC_HTTPS_ADDR=:28443 VBMC_VENDOR=Supermicro /tmp/vbmc &

# Point platformctl at it with explicit backend: smc-cgi
platformctl bmc cert replace \
    --address 127.0.0.1 --port 28443 \
    --username admin --password admin \
    --backend smc-cgi \
    --cert /tmp/bmc-new.pem --key /tmp/bmc-new.key

# Verify by re-reading the vBMC's cert
curl -sk https://127.0.0.1:28443/debug/stats
# Expect: "cert_replace": 1, "reset": 1

# Confirm the vBMC now serves the new cert
openssl s_client -connect 127.0.0.1:28443 -showcerts </dev/null 2>/dev/null \
    | openssl x509 -subject -noout
# Expect: subject= CN = <bmc-hostname>
```

If this fails against the vBMC, **stop** -- fix the platform code
before touching hardware.

### 4. Capture a HAR trace of the platform's CGI flow

Record the exact wire bytes platformd sends so you can diff against
real-hardware behavior:

```bash
# Run platformctl against the vBMC again but through mitmproxy
mitmproxy --mode transparent -p 8080 --ssl-insecure &
# Redirect traffic via iptables or a socat bridge, then:
platformctl bmc cert replace --address 127.0.0.1 --port 28443 ...

# Export the captured flow for reference
mitmproxy --set dumper_filter="~u cgi" --save-flow /tmp/vbmc-baseline.har
```

Save `/tmp/vbmc-baseline.har` as the reference platform behavior.

### 5. Run against the real X10

With BMC creds in hand and a fresh cert queued:

```bash
# Explicit backend -- bypasses the allowCGIFallback gate
platformctl bmc cert replace \
    --address <real-bmc-ip> \
    --port 443 \
    --username ADMIN --password <real-pwd> \
    --backend smc-cgi \
    --cert /tmp/bmc-new.pem --key /tmp/bmc-new.key \
    --log-level debug 2>&1 | tee /tmp/real-run.log
```

### 6. Verify success

Expected outcomes:

- [ ] `platformctl` returned 0 exit code
- [ ] BMC web UI responds on HTTPS after the reset (may take 30-60s)
- [ ] New cert is served on next TLS handshake:

      ```bash
      openssl s_client -connect <bmc-ip>:443 -showcerts </dev/null 2>/dev/null \
          | openssl x509 -subject -issuer -noout
      # Expect: subject= CN = <bmc-hostname>
      #         issuer=  CN = <platform CA CN>
      ```

- [ ] Browser to `https://<bmc-ip>/` shows a valid cert chain
      anchored at the platform CA
- [ ] IPMI over LAN still works (the cert swap must not have
      disrupted IPMI users):

      ```bash
      ipmitool -H <bmc-ip> -U ADMIN -P <new-pwd> chassis status
      ```

If any check fails, capture the HAR trace of the real interaction
(via mitmproxy on the platformd host) and diff against the vBMC
baseline from step 4. The diff identifies the firmware quirk to
handle in `pkg/bmc/smc/cgi_cert.go`.

### 7. Record the firmware variant

Update `docs/operations/x10-smc-cgi-validation-results.md`
(create if absent) with:

- Board model
- Firmware version
- Validation date + operator
- Any deviations from the platform's canonical flow (even if
  tolerated -- document them so regressions are detectable)
- HAR diff attached or linked if there were any

### 8. Flip the gate

Once at least one firmware variant passes all checks, enable
auto-mode CGI selection platform-wide by setting a platform config
flag that calls `bmc.SetAllowCGIFallback(true)` at boot:

```yaml
# platform config
bmc:
  allow_cgi_fallback: true  # only set after validation per
                            # docs/operations/x10-smc-cgi-validation.md
```

Or in code (for test / non-prod contexts):

```go
bmc.SetAllowCGIFallback(true)
```

This is a one-way operator decision -- revert to `false` is safe but
will cause `auto` mode to start erroring with
`ErrAutoCertCGIGated` on Supermicro detection until re-flipped.

## Failure taxonomy

| Symptom | Likely cause | Next step |
|---|---|---|
| login.cgi returns 401 with a valid SID cookie anyway | Some ATEN firmware issues SID eagerly; check if upload_ssl still works | Fix is a successful-despite-401 tolerance in `smc/cgi_cert.go:login` |
| upload_ssl.cgi returns 500 or HTML error page | Firmware rejected the PEM format (expects DER? expects specific newline encoding?) | Capture HAR; compare multipart body byte-for-byte to vBMC baseline |
| SSL_VALIDATE returns 404 | Firmware doesn't implement this op -- already handled with tolerance in code (`ErrValidateFailed` with 404 status is swallowed) | Verify the tolerance is firing; if not, the response shape differs |
| BMC_reset.cgi returns 200 but BMC doesn't actually reset | Firmware requires a different CGI endpoint or a full IPMI cold-reset | Add a fallback via IPMI cold-reset when CGI reset doesn't produce a TLS disconnect within N seconds |
| New cert served but chain is broken | BMC stripped intermediates during validation | Send leaf-only; have platformd pre-chain at a trusted anchor the BMC already knows |
| IPMI stops working after cert swap | Firmware regenerates IPMI auth keys on cert change | Re-run `platformctl bmc user rotate` to restore known credentials |

## Revocation procedure if validation invalidates the code

If validation uncovers a protocol bug that can't be worked around
quickly:

1. Open an issue documenting the exact firmware variant + HAR
   diff
2. Do NOT flip `allow_cgi_fallback: true`
3. Document the affected firmware in
   `docs/operations/x10-smc-cgi-validation-results.md` as a
   known-broken combination
4. Fix the code, re-run the full procedure from step 3
5. Only flip the gate once the validation passes clean

## Non-goals

- This procedure does NOT cover IPMI user-management cert
  validation (different surface -- see `pkg/bmc/ipmi_user.go`)
- Does NOT cover CMM, Dell iDRAC, or HPE iLO -- those use
  Redfish `CertificateService` which has its own validation
  path (far less risky because the schema is standardized)
- Does NOT remove the `allowCGIFallback` gate -- the gate stays
  as a permanent safety net; the validation just flips it for
  the first time for validated firmware revisions

## References

- Wire protocol implementation: `pkg/bmc/smc/cgi_cert.go`
- Gate: `bmc.SetAllowCGIFallback` in `pkg/bmc/auto_cert.go`
- Test harness: `test/integration/bmc/harness.go`
- vBMC reference implementation: `test/integration/bmc/vbmc/main.go`
- Architecture overview: `docs/architecture/bmc-tls.md`
