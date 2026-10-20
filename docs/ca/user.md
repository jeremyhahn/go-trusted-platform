# Certificate Authority — Using It

> **Status: REFERENCE** · Last verified: 2026-08-18
> Issuing, renewing and revoking certificates on the platform. Internals are in
> [engineering.md](engineering.md).

---

## What this is

The platform hosts a CA and a full ACME (RFC 8555) server, so every identity on
the platform — nodes, devices, workloads, services — can get a certificate
without a human in the loop.

**The platform does not implement the CA.** It hosts the stack's CA and exposes
it as the product's certificate surface. That matters when something is missing:
the fix is almost never in this repository.

---

## Prerequisites

1. A control plane with the CA wired in — otherwise every route returns 503.
2. **The CA initialised.** `platformctl ca info` tells you whether it is.
3. For ACME clients: the CA bundle, so the client can trust the ACME server
   before it has a certificate of its own.

---

## Getting trust material first

A client that has no trust cannot use a mutually authenticated transport, so
three routes serve raw trust material over plain HTTP:

```bash
curl -s https://ca.example.com/api/v1/ca/bundle        > ca-bundle.pem
curl -s https://ca.example.com/api/v1/ca/root          > root.pem
curl -s https://ca.example.com/api/v1/ca/intermediate  > intermediate.pem
curl -s https://ca.example.com/api/v1/ca/bootstrap     > bootstrap.pem
```

Or from the CLI:

```bash
platformctl ca bundle --output ./ca-bundle.pem
```

These are the only CA routes with no counterpart on the other transports, and
that is deliberate.

---

## Issuing a certificate directly

```bash
platformctl ca issue web-01.example.com kms rsa \
    --valid-days 90 \
    --sans-dns web-01.example.com,web.example.com \
    --ext-key-usage serverAuth

platformctl ca list --status valid
platformctl ca certificate 0A1B2C3D --pem
```

**Short validity is the point of having automated issuance.** 365 days is the
default; if a certificate is renewed automatically, 90 or less costs you nothing
and shrinks the window a compromised key is useful for.

---

## Issuing via ACME — the normal path

ACME is how devices and services should get certificates, because it renews
without anyone deciding to.

```bash
platformctl acme register \
    --directory https://ca.example.com/api/v1/acme/directory \
    --ca-cert ./ca-bundle.pem \
    --email ops@example.com

platformctl acme renew \
    --directory https://ca.example.com/api/v1/acme/directory \
    --cn web-01.example.com --challenge dns-01 \
    --sans-dns web-01.example.com
```

**Always pass `--directory` explicitly.** Its built-in default points at a local
development address, which is the wrong server in every real deployment.

### The challenge type is the interesting choice

| Challenge | Proves |
|---|---|
| `http-01` | Control of a web path |
| `dns-01` | Control of a DNS record ([`docs/dns/`](../dns/)) |
| `endorse-01` | The device's TPM endorsement |
| `device-01` | Device identity |
| `device-attest-01` | Device attestation |

The last three are what make this a trusted-computing CA: a device proves **what
it is**, from hardware, rather than proving it can write a file or a DNS record.
Pair them with `--authz permanent-identifier`.

Those challenge handlers are the stack's, not this repository's — see
[`docs/device/`](../device/) for the enrollment side.

### Rotating an account key

```bash
platformctl acme rotate-key
```

The account key is the credential that controls every certificate the account
has ordered. Rotate it on the same schedule you would rotate any other
long-lived credential.

---

## Renewing

```bash
platformctl ca renew 0A1B2C3D --days 90
```

Renewal revokes the old certificate, rotates its key to new material under the
same key name, and issues the new certificate on that key. Renewing the same
certificate again works the same way.

`--force` renews even when the certificate is not near expiry. That is the flag
to use after a suspected key exposure: the old key is replaced and the old
certificate is revoked in the same step.

**Renewal has no REST route.** Use the CLI, gRPC, QUIC or MCP.

---

## Revoking

```bash
platformctl ca revoke 0A1B2C3D --reason superseded
platformctl ca crl export --output ./crl.pem --entries
```

Two things to get right:

**Set `--reason` honestly.** It goes into the CRL and relying parties act on it.
`key-compromise` and `ca-compromise` are not generic values — `ca-compromise`
in particular says the CA itself is untrustworthy.

**`--delete-keys` is separate and irreversible.** Revocation marks the
certificate; deleting removes the key pair. Do not reach for it reflexively —
you may need the key to prove something about the past.

There is no unrevoke.

---

## Verifying

```bash
platformctl ca verify ./web-01.pem
```

`--crl` and `--expiry` both default to **true**. To check only the chain, pass
`--crl=false --expiry=false`, and understand that you are then checking less.

---

## Installing the CA into a system trust store

```bash
platformctl ca install-ca-certificates
platformctl ca uninstall-ca-certificates
```

These modify the host's trust store. Adding a CA to a machine's trust store
means that CA can impersonate anything to that machine — a reasonable thing to
do on a platform node, and a decision worth being deliberate about elsewhere.

---

## Troubleshooting

**Everything returns 503.**
The CA is not wired into the daemon.

**An ACME operation returns 429.**
The rate limiter. Every ACME route is rate-limited, and account registration has
its own limiter. That is a control, not a fault — back off rather than
retrying tightly.

**`ca init` says the CA already exists.**
It does. `--force` re-initialises, and **every certificate the old CA issued
becomes unverifiable**. This is not a retry flag.

**Renew or verify is not available over REST.**
Correct — neither has a REST route. Use the CLI, gRPC, QUIC or MCP.

**`ca issue` and `acme register` disagree about SAN flags.**
They do. `ca issue` takes `--sans-dns` / `--sans-ips` / `--sans-email` as
comma-separated strings; `acme register` takes `--sans-dns` / `--sans-ip` /
`--sans-email` as repeatable arrays. Singular versus plural, and different
types.

**Something is missing from the CA surface.**
It is almost certainly missing upstream, in the stack's CA, not here. This
repository contains adapters and transport frontage — no certificate logic.

---

## Two things to be aware of

Every transport asks for the same scope per operation: `certs:generate` to
issue or renew, `certs:revoke` to revoke, `certs:read` and `certs:list` to read
certificates, and `ca:read` for the CA's info, CRL and bundle, including over
MCP where their REST routes are public. Recorded in [api.md](api.md) §4.

`ca sign-csr` certifies a KMS key for code signing — the fleet key every
netbooted device's boot chain trusts. **Only the platform admin may run it**:
root on the platformd host, or a platform token granting `ca:sign-csr`, which
`certs:generate` does not include. The CSR must name the KMS key and nothing else.
See [cli.md](cli.md).

---

## Where to go next

- [cli.md](cli.md) — every verb and flag
- [api.md](api.md) — every capability on every transport, and the gaps
- [architecture.md](architecture.md) — what this repo does and does not own
- [`docs/device/`](../device/) · [`docs/eab/`](../eab/) · [`docs/dns/`](../dns/) ·
  [`docs/kms/`](../kms/)
