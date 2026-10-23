# Platform Hardware Templates

Reusable configuration templates for production deployments, organized by
deployment profile and hardware platform.

For full documentation, see [docs/device-templates.md](../../../docs/device-templates.md).

## Deployment Profiles

| Profile | Layout | Status |
|---------|--------|--------|
| [dedicated/](./dedicated/) | 3 dedicated nodes: 1 control-plane, 1 gateway, 1 compute | **Active** |
| [single-node/](./single-node/) | Control-plane + gateway + compute colocated on a single node | Default ISO template; Raspberry Pi factory image under [single-node/raspberrypi/](./single-node/raspberrypi/) |
| [high-availability/](./high-availability/) | 3 control-plane, 2 gateway, 2 compute (HA Raft cluster) | Planned |

The `dedicated/` profile is the current reference architecture being
developed. The other profiles will be added once `dedicated/` is proven
end-to-end.

## Network Model

Every template follows the reference network
([docs/architecture/reference-network.md](../../../docs/architecture/reference-network.md))
on environment 4, the reference example: `sdn.environment` numbers every
zone, `network.role` decides which zones a host holds addresses on, the
physical trunk rides `br-fabric` and workloads attach to `br-int`. The
templates carry no site values; a site sets its own environment and ULA,
and overrides single zones under `sdn.environment.overrides` only where it
cannot follow the reference.

## Directory Structure

```
configs/platform/templates/
  dedicated/            # 3-node reference architecture (active)
    supermicro/
      x10/              # Supermicro X10-family boards (X10SDV-TP8F, etc.)
        control-plane.yaml
        gateway.yaml
        compute.yaml
    dell/
      r640/             # Dell PowerEdge R640 (UNTESTED, Phase 2)
        control-plane.yaml
        gateway.yaml
        compute.yaml
    raspberrypi/        # Factory SD-card image (diskimage create --target rpi --role <role>)
      rpi4/
        compute.yaml    # compute only; gateway and control plane stay x86
  single-node/          # Colocated all-in-one: the default ISO template
    default.yaml
    raspberrypi/        # Factory SD-card image (platformctl diskimage create --target rpi)
      rpi4/
        default.yaml
  high-availability/    # HA cluster (planned)
```

## Quick Start

### Deploy directly from a template

```bash
platformctl iso create \
  --platform-config configs/platform/templates/dedicated/supermicro/x10/control-plane.yaml
```

### Deploy with site-specific overrides

```bash
platformctl iso create \
  --platform-config configs/platform/templates/dedicated/supermicro/x10/control-plane.yaml \
  --overrides /path/to/my-overrides.yaml
```

Override files use the same YAML structure but only include fields to change.

## Supported Platforms

| Vendor | Model Family | Profile | Status |
|--------|--------------|---------|--------|
| Supermicro | X10 (X10SDV-TP8F, etc.) | dedicated | Production |
| Dell | PowerEdge R640 | dedicated | Phase 2 (UNTESTED) |
| Raspberry Pi | 4 Model B (`rpi4`; SLB9670 TPM HAT on SPI0 CE1) | single-node, factory SD-card image | Boots on the QEMU virt stand-in; hardware validation per [docs/factory-image/user.md](../../../docs/factory-image/user.md) |
| Raspberry Pi | 4 Model B (`rpi4`) | dedicated, compute role only ([dedicated/raspberrypi/](./dedicated/raspberrypi/README.md)) | Template builds and validates; no hardware run yet |
| Raspberry Pi | 5 (`rpi5`) | dedicated, compute role only ([dedicated/raspberrypi/](./dedicated/raspberrypi/README.md)) | **Experimental**: template builds and validates; the TPM, console and Ethernet are unvalidated on a Pi 5 |

## Architecture Notes

All `dedicated/` templates assume:

- **CA trust**: the platform CA bundle is baked into the install ISO and
  installed to the system trust store during installation. Runtime trust
  bootstrap via DANE/Noise/SPKI is NOT required and is intentionally absent
  from these templates. For zero-trust greenfield deployments (no pre-shared
  CA), use the separate greenfield template set.

- **Datastore**: QuicBaaS runs in **standalone embedded mode** (non-HA).
  `storage-backend: file` with `node-id: 1` and no join-addresses means
  Raft consensus is not engaged. For HA, use the `high-availability/`
  profile (when available).

- **Secrets**: all secret URIs use the canonical `kms://?ensure=true&len=N&enc=ENC`
  scheme backed by the platform `SecretsService.EnsureSecret` distributed lock
  pattern. First boot generates and persists; every subsequent boot returns
  the same stable bytes.

- **TPM auth encoding**: fields whose value becomes a TPM `TPM2B_AUTH` use
  `len=32&enc=raw` (32 random bytes, exactly the SHA-256 digest cap). These are
  every `srk-auth`, `webservice(s)[*].key.password`, and
  `acme.client.account.key.password` — any key with `platform-policy: true` has
  its password sealed into a TPM keyed-hash object whose `UserAuth` is that
  value, regardless of `store:`. A `len=32&enc=base64` value is 43 characters
  and the TPM rejects it with `TPM_RC_SIZE`. Non-TPM secrets keep `enc=base64`:
  `certificate-authority.identity[*].keys[*].password` (PKCS#8 encryption) and
  `bmc.password` (IPMI/Redfish account credential, must stay printable ASCII).
  See [docs/secrets/config-secret-schemes.md](../../../docs/secrets/config-secret-schemes.md).
