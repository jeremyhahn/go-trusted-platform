# Trust — User Guide

> **Status: NORMATIVE** · Scope: operating platform trust · Last verified: 2026-10-11
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## What trust gives you

- **Platform services trust each other with no setup.** Everything the platform
  issues chains to the platform CA, and every node already knows how to find it.
- **Two things you may configure:** how a new node first obtains the platform CA
  (`trust.bootstrap`), and how the platform verifies a BMC (`trust.bmc`).

## Prerequisites

- A control plane that publishes its CA bundle: see [`docs/bootstrap/`](../bootstrap/).
- For `dane`: DNSSEC-signed TLSA records and a reachable DNS server.
- For a gateway node: the CA bundle file provisioning placed on it.

## Get the platform CA onto a new node

The installer does this for you from the kernel command line. To do it by hand:

```sh
platformctl bootstrap trust \
  --server-url https://cp.example.com:8443 \
  --strategy auto \
  --dns-server 10.0.0.2:8053 \
  --install-to-system-trust
```

`auto` tries `dane`, then `noise`, then `spki`, and stops at the first that
works. Pick one strategy to be strict:

| You have | Use |
|---|---|
| DNSSEC and TLSA records | `dane` (recommended) |
| No DNS, but the server's Noise key | `noise` |
| The server certificate's SPKI hash from a trusted channel | `spki` |
| A CA bundle baked into the image | `embedded` |

## Configure it permanently

```yaml
trust:
  bootstrap:
    strategies: [dane, noise, spki]
    server-url: https://cp.example.com:8443
    per-method-timeout: 15s
    install-to-system-trust: true
```

Add `tofu` only if you accept trusting the first server that answers; it is
never tried unless you list it.

## Verify BMCs

A BMC usually has a self-signed certificate. Choose how to verify it:

```yaml
trust:
  bmc:
    strategies: [spki, ca-file, tofu]
    ca-file: /etc/trusted-platform/bmc-ca.pem
```

`tofu` pins a BMC's certificate on first contact and enforces the pin from then
on. Never turn TLS verification off; the per-template guidance is in
[`docs/device-templates.md`](../device-templates.md).

## Gateway nodes

A gateway runs no CA, so point it at the bundle provisioning delivered:

```yaml
platform-ca-file: /etc/gatewayd/cp-ca.pem
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `platform anchor unavailable` | node has not enrolled yet, or `platform-ca-file` is missing/unreadable | enroll the node, or deliver the bundle; nothing else is trusted meanwhile |
| `platform anchor source yielded no CA certificate` | the bundle holds only leaf certificates | provide the CA certificate |
| `class "bmc" is not configured` | no `trust.bmc` section | add one with a strategy chain |
| `strategy "x" is not allowed for class "y"` | strategy outside the class allowlist (`bootstrap`: dane, noise, spki, embedded, tofu; `bmc`: dane, spki, ca-file, tofu) | remove it |
| `no strategy succeeded` | every strategy failed; the message lists each attempt | fix the first listed failure, or reorder the chain |
| `tofu` rejected at start | no storage for the pin store | start with storage available, or drop `tofu` |
| Settings under `trust.default` or `trust.internal` have no effect | those keys are retired and silently ignored | move to `trust.bootstrap`; internal needs no configuration |
| `platformctl bootstrap trust` warns `update-ca-certificates failed` | the bundle was written but the OS store was not refreshed | run the OS refresh command |
