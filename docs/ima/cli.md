# Linux IMA — CLI

> **Status: NORMATIVE** · Scope: `platformctl` verbs for IMA · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

**No CLI surface: this feature has no `platformctl` verbs at all.** `pkg/ima`
is reachable only as an embedded Go call, and IMA is configured declaratively
through the installer's `os.ima.*` block. Verified against
`pkg/cli/commands/root.go` on 2026-08-18: no `ima` command group is registered,
and no other command group carries an IMA verb.

The rest of this file exists so nobody has to re-derive that.

---

## 1. Verbs the legacy documents show that do not exist

| Legacy verb | Where it is claimed | Status |
|---|---|---|
| `platformctl ima status` | tpm-integration.md | **Does not exist** |
| `platformctl ima verify` | tpm-integration.md | **Does not exist** |
| `platformctl ima export --format json` | tpm-integration.md | **Does not exist** |
| `platformctl ima policy generate --output …` | troubleshooting.md | **Does not exist** |
| `platformctl tpm pcr read --pcr 10 --bank sha256` | tpm-integration.md | **Does not exist.** `platformctl tpm` has `extend`, `policy`, `eventlog`, `nvram`, `seal`, `unseal`, `ek`, `srk`, `idevid`, `iak`, `provision`, `clear`, `info`, `status` and others — but no `pcr` subcommand |

Each is recorded in [architecture.md](architecture.md) §9.

---

## 2. How to do it today instead

Everything IMA-related is either a config change or a plain file read.

### Turn IMA on

Not a CLI verb — an installer config change, applied at install time:

```yaml
os:
  ima:
    enabled: true
    policy: tcb
    hash-algorithm: sha256
    appraise-mode: "off"
    audit-enabled: true
```

Full key reference in [engineering.md](engineering.md) §6. The resulting kernel
parameters end up inside the signed UKI, which is what makes the setting
tamper-evident — see [`docs/firmware/`](../firmware/).

### Check IMA state

```bash
# Is IMA present at all?
ls /sys/kernel/security/ima/

# Which parameters did this kernel boot with?
grep -o 'ima[^ ]*' /proc/cmdline

# How many measurements so far?
wc -l < /sys/kernel/security/ima/ascii_runtime_measurements

# Which policy is loaded?
cat /sys/kernel/security/ima/policy

# How many integrity violations?
cat /sys/kernel/security/ima/violations
```

### Read PCR 10

```bash
cat /sys/class/tpm/tpm0/pcr-sha256/10

# Which banks does this TPM expose?
ls /sys/class/tpm/tpm0/ | grep '^pcr-'
```

`platformctl tpm eventlog` reads the **TCG firmware** event log (PCRs 0–7), not
the IMA runtime log. They are different logs measuring different things; do not
substitute one for the other.

### Verify measurements

Go only, through `pkg/ima`:

```go
reader := ima.NewReader()
verifier := ima.NewVerifier()

log, err := reader.ReadEventLog()
if err != nil {
    return err
}
if err := verifier.VerifyPCR10AgainstTPM(log, ima.PCRBankSHA256); err != nil {
    return err
}
```

Read [architecture.md](architecture.md) §7 before you act on the result of that
last call — a mismatch is inconclusive until you have checked which bank the
log's template digest is actually in.

---

## 3. Why there is no CLI

Not a decision that has been made and recorded — the surface simply has not been
built. `pkg/ima` is a complete, unit-tested library whose only caller is the
VPN agent's posture report ([architecture.md](architecture.md) §4).
`platformctl vpn posture` prints the IMA `available`, `enabled` and
`policy_loaded` flags it collects; nothing else is exposed. An `ima` CLI group
is **PLANNED**.

What a first cut would need, so the next agent does not have to work it out:

| Verb | Backed by |
|---|---|
| `ima status` | `Reader.GetStatus` + `Verifier.IsTPMAvailable` + `GetAvailablePCRBanks` + `ReadViolations` — because `GetStatus` alone leaves most of `Status` zero-valued ([engineering.md](engineering.md) §2.5) |
| `ima log` | `Reader.ReadEventLog` with `--output json` |
| `ima stats` | `Reader.GetStatistics` |
| `ima policy show` | `Reader.ReadPolicy` |
| `ima verify` | `Verifier.VerifyPCR10AgainstTPM` + `VerifyEventLog`, with a `--bank` flag and an honest "inconclusive" exit code for the bank-mismatch case |

That table is a sketch, not a specification. New features and changes to
existing features are the owner's authority; an implementing agent should get
the shape signed off rather than treating this list as approved scope.

---

## 4. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a matching
`CommandDefinition` in the integration parity suite. There are no verbs, so the
requirement is vacuously satisfied for this feature. Separately, **this
repository defines no `CommandDefinition` type at all**, so the requirement is
unmet repo-wide and is an open owner question.
