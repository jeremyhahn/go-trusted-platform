# Barrier — Operator Guide

> **Status: NORMATIVE** · Scope: operating the platform barrier and finding the per-tenant barrier · Last verified: 2026-10-11
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · [api.md](api.md) · user (this file).

## What the barrier is

The barrier is the encryption layer over the platform's stored secrets. While it
is **sealed**, nothing behind it can be read, and `platformd` serves only three
gate routes. Once it is **unsealed**, `platformd` starts its normal transports.
You unseal it after every restart of the store, and you can seal it again at any
time.

The model is described in [architecture.md](architecture.md).

## Before you start

- Add a `barrier:` section to the daemon configuration. **Without it, `platformd`
  does not wait for the barrier at all.**
- Choose `barrier.seal_strategy`. The default is `software`, a passphrase. For
  M-of-N officer shares, set `shamir` with `shamir_threshold` and `shamir_shares`.
  [engineering.md §3](engineering.md#3-configuration) lists every key.
- There is no automatic unseal. Plan to unseal by hand whenever the barrier is sealed.

```yaml
barrier:
  seal_strategy: shamir
  shamir_threshold: 3
  shamir_shares: 5
```

## First start on a new node

`platformd serve` starts in the barrier gate. Only the local Unix socket and
`127.0.0.1:9446` answer, and they answer only `/healthz`, `/init` and `/unseal`.

Check the state:

```sh
curl -s http://127.0.0.1:9446/healthz
# {"state":"uninitialized","ready":false}

curl -s --unix-socket /run/platformd.sock http://localhost/healthz
```

Initialize:

```sh
curl -s -X POST http://127.0.0.1:9446/init \
  -H 'Content-Type: application/json' \
  -d '{"so_pin":"<so-pin>","user_pin":"<user-pin>","hostname":"<node-fqdn>"}'
```

For an M-of-N ceremony add `"threshold": 3, "shares": 5` and the five Security
Officers who will hold the shares, each with a CSR for their own key:
`"officers": [{"username":"alice","csr_pem":"-----BEGIN CERTIFICATE REQUEST-----..."}, ...]`.
`platformctl init --officer alice=alice.csr ...` builds this for you. The full
request is in [api.md §2](api.md#2-the-barrier-gate).

**Keep the user PIN.** The gate uses it as the barrier secret, so it is what
you unseal with later.

When the barrier reports `unsealed`, the gate closes and the normal transports
start. `/init` works once: while the gate is open on an initialized node, it answers `409`.

**Do the first init yourself, from the node.** The gate routes have no
authentication. The first local caller to reach `/init` on a new node sets its
PINs.

## Unsealing after a restart

The gate opens again, in state `sealed`.

With a single secret:

```sh
curl -s -X POST http://127.0.0.1:9446/unseal \
  -H 'Content-Type: application/json' -d '{"secret":"<user-pin>"}'
```

With Shamir, each officer submits a share until the threshold is met:

```sh
curl -s -X POST http://127.0.0.1:9446/unseal \
  -H 'Content-Type: application/json' -d '{"share":"<share>"}'
# {"state":"unsealing","sealed":true,"shares_provided":1,"required":3}
```

A wrong secret or share answers `500` with the reason in `error`. A body with
neither field answers `400`.

While shares are still arriving, `/healthz` and the `/unseal` response report
`unsealing`.

The quicbaas daemon can also be unsealed directly with
`platformctl barrier unseal --passphrase <pp>` or
`platformctl barrier unseal-shares --shares-file <shares-file>`.
`platformd` notices within about a second and releases the gate.

## Checking status on a running node

```sh
platformctl barrier status
```

This asks quicbaasd. To ask `platformd`, call `BarrierService.GetStatus`
through the platform SDK (`sdk/go/services/barrier`); platformctl has no verb
for it.

## Sealing

```sh
platformctl barrier seal          # asks for confirmation
platformctl barrier seal -y       # no prompt
```

Every data-plane read and write fails until the next unseal. Sealing takes no
PIN; `--so-pin` is rejected.

## Rekeying

```sh
platformctl barrier rekey --so-pin <so-pin>                          # keep the layout
platformctl barrier rekey --so-pin <so-pin> --threshold 3 --total 7  # new M-of-N
```

New shares are sealed to the enrolled Security
Officers. Nothing is printed; each officer claims a share with
`platformctl ceremony claim-share begin` and `complete`, described in
[`docs/bootstrap/`](../bootstrap/).

## Recovery keys

Generate a separate recovery share set. Like rekey shares, recovery shares are
sealed to officers, not printed. Recovery officers claim them through the
upstream recovery share claim; platformctl has no verb for it:

```sh
platformctl barrier recovery generate --threshold 3 --total 5 --so-pin <so-pin>
```

Recover with a quorum of recovery shares:

```sh
platformctl barrier recovery recover --share <s1> --share <s2> --share <s3>
```

`platformd` has no recovery route. These verbs go to quicbaasd only.

## Pointing platformctl at quicbaasd

`platformctl barrier` talks to quicbaasd, not to `platformd`. `--transport`
does not change that. If quicbaasd is not at `/run/quicbaas.sock`, set
`quicbaas_addr` in the CLI context, or export `PLATFORMCTL_QUICBAAS_ADDR`.
[cli.md §2](cli.md#2-where-the-verbs-go) has the full rules.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `platformd` never stops at the gate | No `barrier:` section in the configuration |
| `/unseal` answers `409` with state `uninitialized` | Run `/init` first |
| `platformctl barrier ...` fails with `ErrQuicBaaSNotConfigured` | No quicbaasd address; see above |
| `platformctl barrier init` rejects `--so-pin` | The strategy is `none`, or `--user-pin` is missing; see [cli.md §4](cli.md#4-validation) |

## Tenant barriers

Each tenant has its own barrier, operated with `platformctl tenant barrier`. It
never touches the platform barrier. See
[`docs/tenant/user.md`](../tenant/user.md#per-tenant-barriers) and
[`docs/tenant/cli.md`](../tenant/cli.md#5-platformctl-tenant-barrier).
