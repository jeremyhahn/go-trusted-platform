# BMC integration testing

Integration tests for BMC cert management and power control run against
a real containerized vBMC responder -- per project rules, **never
against mocks or httptest** at the integration level.

vBMC is test infrastructure, not a production binary. It lives entirely
under `test/integration/bmc/vbmc/`. See the
[vBMC README](../../test/integration/bmc/vbmc/README.md) for the full
feature list, endpoint table, environment variables, and vendor flavor
details.

## Overview

Two flavors of vBMC run alongside the devcontainer via docker-compose:

| Service hostname  | `VBMC_VENDOR` | Protocols | Purpose |
|-------------------|---------------|-----------|---------|
| `vbmc-supermicro` | `Supermicro`  | Redfish HTTPS + ATEN CGI + IPMI RMCP+ | Exercises Supermicro CGI cert-upload path + Redfish Vendor branch + IPMI power/boot |
| `vbmc-dell`       | `Dell`        | Redfish HTTPS + IPMI RMCP+ | Exercises the non-Supermicro Vendor branch (Redfish CertificateService only, no CGI) |

Both expose HTTPS on port `8443` and IPMI RMCP+ on UDP port `6230`,
sharing the `trusted-platform-net` network with the devcontainer.

## Running the tests

From inside the devcontainer:

```bash
make integration-test-bmc
```

Or run the whole integration suite (includes BMC):

```bash
make integration-test
```

Both entry points drive
`build/docker/devcontainer/run-integration-tests.sh`, which brings up
the vBMC services as a prerequisite before exercising the cert and
power-control pipelines against them.

## Writing new tests

Use the helpers in `test/integration/bmc/` to address the vBMCs:

```go
//go:build integration

package bmc_integration_test

import (
    "context"
    "testing"
    "time"

    bmctest "github.com/jeremyhahn/go-trusted-platform/test/integration/bmc"
)

func TestBMCCertIssuanceAgainstSupermicro(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    t.Cleanup(cancel)

    if err := bmctest.WaitForReady(ctx, bmctest.VBMCFlavorSupermicro); err != nil {
        t.Fatalf("vBMC not ready: %v", err)
    }

    cfg := bmctest.WithDNSCert(
        bmctest.ConfigFor(bmctest.VBMCFlavorSupermicro),
        "vbmc-supermicro.example.internal",
    )
    cfg.Backend = "" // auto; AutoCertManager will pick SMC-CGI for Supermicro

    before, err := bmctest.GetStats(ctx, bmctest.VBMCFlavorSupermicro)
    if err != nil { t.Fatal(err) }

    // ... drive issueBMCCertificateCore or RegisterCertRenewal ...

    after, err := bmctest.GetStats(ctx, bmctest.VBMCFlavorSupermicro)
    if err != nil { t.Fatal(err) }
    if after.CertReplace != before.CertReplace + 1 {
        t.Errorf("expected one cert replacement, got %d -> %d",
            before.CertReplace, after.CertReplace)
    }
    if after.Reset != before.Reset + 1 {
        t.Errorf("expected one reset, got %d -> %d",
            before.Reset, after.Reset)
    }
}
```

## What the vBMC does NOT simulate

- Firmware operations, SEL, sensor data records, or persistent storage
- Virtual media operations (use QEMU VM + swtpm harness for those)
- Full BIOS/UEFI boot sequence simulation

vBMC is not a substitute for hardware validation. Real X10/X11/iDRAC
testing is required before auto-mode selects CGI in production.

## Debug helpers

Every vBMC exposes `GET /debug/stats` returning the counter snapshot
used by tests:

```bash
curl -sk https://vbmc-supermicro:8443/debug/stats
```

And `GET /healthz` for liveness:

```bash
curl -sk https://vbmc-supermicro:8443/healthz
# -> ok
```

## Troubleshooting

**vBMC container won't start** -- check `docker compose logs vbmc-supermicro`.
Most common cause is a port collision when another service also binds
to port 8443 on the compose network.

**WaitForReady times out** -- the vBMC is dropping connections during
TLS handshake. Verify the container is running (`docker ps`) and that
the devcontainer and vBMC share the `trusted-platform-net` network.

**Tests pass locally but fail in CI** -- verify the test has
`//go:build integration` so it only runs under `make integration-test`,
not under `make test` (which does not start vBMC).
