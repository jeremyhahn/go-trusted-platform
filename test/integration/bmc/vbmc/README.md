# vBMC -- Virtual BMC responder for integration tests

A minimal Go service that impersonates a BMC for integration testing.
It serves the subset of BMC protocols and endpoints that platformd's
cert-management and power-control code exercises.

## What vBMC is

vBMC exposes three protocol surfaces:

- **Redfish HTTPS** on port 8443 -- self-signed ECDSA P-256 cert at
  startup; accepts new certs via `CertificateService.ReplaceCertificate`
  and serves them on subsequent TLS handshakes via atomic handle swap.
- **Supermicro ATEN CGI** on the same port 8443 -- `login.cgi`,
  `upload_ssl.cgi`, `op.cgi` (SSL_VALIDATE), `BMC_reset.cgi`,
  `logout.cgi`.
- **IPMI 2.0 RMCP+** on UDP port 6230 -- backed by the reusable
  simulator in [`test/integration/bmc/rmcpsim`](../rmcpsim/simulator.go).
  Handles RAKP handshake (HMAC-SHA1 / HMAC-SHA256), AES-CBC-128
  confidentiality, and canned responses for Chassis Status, Chassis
  Control, Get/Set System Boot Options, Get Device ID, Set Session
  Privilege, Set User Password, and Close Session.

## What vBMC is NOT

- **Not a production binary** -- never built for release, lives
  entirely under `test/integration/`.
- **Not a drop-in for real BMC hardware** -- no firmware simulation,
  no SEL, no persistent storage, no sensor data records.
- **Not a substitute for hardware validation** -- real X10/X11/iDRAC
  hardware testing is still required before auto-mode selects CGI
  in production.

## Vendor flavors

Controlled via the `BMC_VENDOR` (or `VBMC_VENDOR`) environment variable:

| Value        | Redfish CertificateService | ATEN CGI endpoints | IPMI RMCP+ |
|--------------|:--------------------------:|:------------------:|:----------:|
| `Supermicro` | yes                        | yes                | yes        |
| `Dell`       | yes                        | no                 | yes        |

Any other string is accepted and set as the `Vendor` field in the
Redfish root response; CGI endpoints are disabled for non-Supermicro
values.

## Endpoints

| Method | Path                                                                        | Purpose |
|--------|-----------------------------------------------------------------------------|---------|
| GET    | `/redfish/v1/`                                                              | vendor probe (sets `Vendor` + `Oem`) |
| GET    | `/redfish/v1/Managers`                                                      | collection |
| GET    | `/redfish/v1/Managers/1`                                                    | manager resource + reset action |
| POST   | `/redfish/v1/Managers/1/Actions/Manager.Reset`                              | reset ack |
| POST   | `/redfish/v1/CertificateService/Actions/CertificateService.ReplaceCertificate` | install bundle |
| POST   | `/cgi/login.cgi`                                                            | open session; sets SID cookie |
| POST   | `/cgi/upload_ssl.cgi`                                                       | multipart cert+key install |
| POST   | `/cgi/op.cgi` (op=SSL_VALIDATE)                                             | post-upload validation |
| POST   | `/cgi/BMC_reset.cgi`                                                        | reset ack |
| POST   | `/cgi/logout.cgi`                                                           | close session |
| GET    | `/healthz`                                                                  | liveness |
| GET    | `/debug/stats`                                                              | test-assertion counters |
| UDP    | `VBMC_IPMI_ADDR` (default `:6230`)                                          | IPMI 2.0 RMCP+ (RAKP handshake, Chassis + App commands) |

## Environment

| Variable             | Default                          | Purpose |
|----------------------|----------------------------------|---------|
| `VBMC_HTTPS_ADDR`    | `:8443`                          | HTTPS listen address |
| `VBMC_VENDOR`        | `Supermicro`                     | `Supermicro` \| `Dell` \| any string set as `Vendor` field |
| `VBMC_CN`            | `vbmc.trusted-platform.internal` | CN / DNS-SAN on the initial self-signed cert |
| `VBMC_LOG_LEVEL`     | `info`                           | `debug` \| `info` \| `warn` \| `error` |
| `VBMC_IPMI_ADDR`     | `:6230`                          | UDP listen address for RMCP+ (6230 avoids privileged port 623) |
| `VBMC_IPMI_USER`     | `ADMIN`                          | BMC account the simulator accepts |
| `VBMC_IPMI_PASSWORD` | `ADMIN`                          | BMC account password; updated at runtime via Set User Password |

## How to run

### Via docker-compose (devcontainer)

The devcontainer's `docker-compose.yml` starts `vbmc-supermicro` and
`vbmc-dell` services automatically. Integration tests address them by
service hostname on the compose network:

```
build/docker/devcontainer/docker-compose.yml
```

### Standalone

```bash
go run ./test/integration/bmc/vbmc/
```

Or build and run:

```bash
go build -o /tmp/vbmc ./test/integration/bmc/vbmc/
VBMC_HTTPS_ADDR=:28443 /tmp/vbmc
```

Smoke test:

```bash
curl -sk https://127.0.0.1:28443/healthz         # -> ok
curl -sk https://127.0.0.1:28443/redfish/v1/     # -> {"Vendor":"Supermicro",...}
curl -sk https://127.0.0.1:28443/debug/stats     # -> counters
```

### Docker build

From repo root:

```bash
docker build -f test/integration/bmc/vbmc/Dockerfile -t trusted-platform-vbmc:latest .
```

## Test assertions

`GET /debug/stats` returns a counter snapshot. Integration tests diff
before/after a scenario to confirm deployment paths fired:

```json
{
  "vendor":          "Supermicro",
  "cert_replace":    3,
  "reset":           3,
  "active_sessions": 0
}
```

## Refresh cadence

vBMC behavior is periodically re-synced to match observed X10/X11/iDRAC
behavior via HAR-capture procedure against real hardware. When new
endpoints or response shapes are discovered on physical BMCs, the vBMC
handlers are updated to match.
