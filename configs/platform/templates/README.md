# Platform Hardware Templates

Reusable configuration templates for production deployments on specific hardware.

For full documentation, see [docs/device-templates.md](../../../docs/device-templates.md).

## Directory Structure

```
configs/platform/templates/
  vendor/
    model/
      control-plane.yaml   # Control plane / server node
      gateway.yaml         # Edge gateway / reverse proxy node
      compute.yaml         # Compute / worker node
```

## Quick Start

### Deploy directly from a template

```bash
platformctl iso create \
  --platform-config configs/platform/templates/supermicro/x10sdv-tp8f/control-plane.yaml
```

### Deploy with site-specific overrides

```bash
platformctl iso create \
  --platform-config configs/platform/templates/supermicro/x10sdv-tp8f/control-plane.yaml \
  --overrides /path/to/my-overrides.yaml
```

Override files use the same YAML structure but only include fields to change.

## Supported Platforms

| Vendor | Model | Status |
|--------|-------|--------|
| Supermicro | X10SDV-TP8F | Production |
| Dell | PowerEdge R640 | Phase 2 (placeholder) |
