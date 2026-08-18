# Trusted Registry — Using It

> **Status: REFERENCE** · Last verified: 2026-08-18
> Task-oriented guide for operators and developers who publish and consume
> images from the platform's attestation-gated registry. No package names, no
> internal architecture — those are in [architecture.md](architecture.md) and
> [engineering.md](engineering.md).

---

## What this is

An OCI container registry where **the machine, not the account, is the
credential.** A node can pull an image only if its TPM can prove what the node
is running. There is no password to leak and no token to copy onto an untrusted
laptop: if the host's measurements do not match the policy, the pull fails.

On top of that, images can be stored encrypted, layer by layer, so an attacker
who reaches the storage backend gets ciphertext.

---

## Prerequisites

1. **A running `platformd` with the registry service enabled.** If it is
   disabled, every registry call returns HTTP 503 with a "not configured"
   message — that is the deliberate signal that the feature is off, not broken.
2. **A `platformctl` context** pointing at that daemon. Check with
   `platformctl context` and `platformctl status`.
3. **For pulls from a real node: a provisioned TPM.** The node must have gone
   through platform enrollment so it has an attestation key the registry will
   accept.
4. **Synchronised time.** Quotes expire and sessions expire; a node whose clock
   has drifted will be refused with what looks like an attestation failure.

---

## First run

Confirm the registry is up and see the policy it is enforcing:

```bash
platformctl registry status --attestation --encryption
```

Read three things from that output before anything else:

- **`require_attestation`** — if this is false you are talking to a development
  registry, and none of the guarantees in this document apply.
- **the golden PCR set** — the measurements a client must match.
- **quote max age** — how stale a TPM quote may be.

Then list what is already there:

```bash
platformctl registry list
```

---

## Publishing an image

Plain push:

```bash
platformctl registry push registry.example.com/apps/api:1.4.2 --input ./api-1.4.2.tar
```

Push encrypted and signed — the form to use for anything that matters:

```bash
platformctl registry push registry.example.com/apps/api:1.4.2 \
    --input ./api-1.4.2.tar \
    --encrypt --key-id apps-api-dek \
    --sign
```

`--key-id` is required whenever `--encrypt` is given; there is no default key,
deliberately, so that nothing is ever encrypted under a key you did not choose.

Pushing over an existing tag fails unless you pass `--overwrite`. Treat a
failure here as the system doing its job: overwriting a published tag makes
every deployment that referenced it unreproducible.

---

## Consuming an image

```bash
platformctl registry pull registry.example.com/apps/api:1.4.2 \
    --decrypt --verify --output ./api.tar
```

`--verify` checks the manifest signature. It is off by default; turn it on.

Standard container tooling also works, because the registry serves the OCI
distribution API:

```bash
docker pull registry.example.com/apps/api:1.4.2
```

The attestation gate still applies — an unattested host's `docker pull` is
refused the same as `platformctl registry pull` would be.

---

## Inspecting before you trust

```bash
platformctl registry inspect registry.example.com/apps/api:1.4.2 --layers --signature --encryption
```

This answers, in one command: what layers are in it, who signed it, and whether
it is encrypted and under which key. `--raw` gives you the stored manifest
document byte for byte if you need to compare digests yourself.

---

## Removing an image

Always dry-run first:

```bash
platformctl registry delete registry.example.com/apps/api:1.4.1 --dry-run
```

Then remove the tag but keep the manifest, so anything pinned by digest keeps
working:

```bash
platformctl registry delete registry.example.com/apps/api:1.4.1 --keep-untagged --force
```

Only drop `--keep-untagged` when you genuinely intend the content to become
unreachable.

---

## Troubleshooting

**Everything returns 503 with "not configured."**
The daemon started without a registry service. This is configuration, not a
crash. Enable the registry in the platform config and restart `platformd`.

**Pull is refused and the message mentions PCRs.**
The node's measurements do not match the golden set. Either the node genuinely
changed (kernel, firmware, boot chain) or the policy is stale. Compare the
node's current PCRs against the set printed by
`platformctl registry status --attestation`. Do not "fix" this by widening the
policy until you know which of the two happened.

**Pull is refused and the message mentions the quote or the nonce.**
Freshness, not integrity. The usual cause is clock drift on the node or on the
registry host. Check time synchronisation before anything else.

**Pull is refused and the AIK is named.**
The node's attestation key is not in the allowlist. Either the node was never
enrolled, or it was re-provisioned and has a new key that nobody added.

**A session that worked five minutes ago now fails.**
Sessions are cached for a configured window and then require re-attestation.
That is expected. If it happens on every request, the cache duration is set to
something too small for your workload.

**`--decrypt` fails with a key error.**
The image is encrypted under a key this client cannot unwrap. Confirm with
`inspect --encryption` which key ID it needs, then check that your identity is
permitted to use it.

**Push succeeds but the image will not pull on other nodes.**
Almost always encryption: it was pushed encrypted, and the pulling side is not
passing `--decrypt`, or cannot reach the key.

---

## Where to go next

- [cli.md](cli.md) — every verb and flag
- [api.md](api.md) — the same operations over REST, gRPC, QUIC, MCP and in-process
- [architecture.md](architecture.md) — how the gate and the encryption envelope fit together
