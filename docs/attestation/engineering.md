# Attestation — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/attestation/`, `pkg/ima/`, `pkg/config/attestation.go` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Design and boundaries: [architecture.md](architecture.md). Transport matrix:
> [api.md](api.md).

---

## 1. Package layout

`pkg/attestation/` is six sub-packages, each with its own `errors.go` and, for
four of them, a `doc.go`:

| Package | Holds |
|---|---|
| `pkg/attestation/manifest` | `builder.go`, `signer.go`, `verifier.go`, `types.go` — building, signing and verifying host and workload manifests |
| `pkg/attestation/vm` | `attestor.go`, `quote.go`, `verifier.go` — VM attestation against a virtual TPM |
| `pkg/attestation/workload` | `chain.go`, `hash.go`, `lifecycle.go`, `tpm.go` — the workload measurement chain and its lifecycle hooks |
| `pkg/attestation/push` | `client.go`, `scheduler.go` — pushing manifests to remote verifiers on a schedule |
| `pkg/attestation/store` | `store.go` — manifest persistence |
| `pkg/attestation/service` | `service.go`, `observer.go` — the service façade the transports call |
| `pkg/attestation/reporting` | the reporting collector, cache and the never-quote-on-request invariant (#226 slice A) |
| `pkg/attestation/calleradmission` | node-side admission of machine callers to the quote-producing routes: chain verification against configured anchors, SAN-based identity, the three strategies, audited decisions (#226) |

`pkg/ima/` is separate and smaller: `reader.go`, `verifier.go`,
`tpm_integration.go`, `types.go` — Linux IMA measurement-log reading and
verification against **PCR 10**.

## 2. Exported surface

### Interfaces — the substitution seams

| Interface | Package | Why it exists |
|---|---|---|
| `ManifestBuilder` | `manifest` | Builds a manifest from collected measurements |
| `ManifestSigner` | `manifest` | Signs a built manifest |
| `ManifestVerifier` | `manifest` | Verifies signature and contents |
| `ManifestProvider` | `manifest` | Supplies manifests to a consumer; `SimpleManifestProvider` is the trivial implementation |
| `Store` | `store` | Manifest persistence; `FileStore` is the on-disk implementation |
| `VMAttestor` / `VMVerifier` | `vm` | Produce and check VM quotes |
| `ChainManager` | `workload` | Owns the workload measurement chain |
| `LifecycleHook` | `workload` | Fires on workload start/stop so measurements track reality |
| `TPMDevice` / `VTPMDevice` / `TPMDeviceFactory` | `workload` | Abstracts the TPM; `SoftwareTPM` satisfies it for tests |
| `DeviceResolver` | `push` | Resolves a device identity for a push target |
| `AttestationObserver` | `service` | Receives attestation events |

Every one of these is a fault-injection point. `SoftwareTPM` +
`NewSoftwareTPMFactory` is how the suite runs without hardware.

### Constructors and functional options

```go
NewManifestBuilder(opts ...ManifestBuilderOption) ManifestBuilder
NewManifestSigner(opts ...ManifestSignerOption) ManifestSigner
NewManifestVerifier(opts ...ManifestVerifierOption) ManifestVerifier
NewSimpleManifestProvider(contentType string) *SimpleManifestProvider
NewFileStore(root string) (*FileStore, error)
NewVMAttestor(opts ...VMAttestorOption) VMAttestor
NewVMVerifier(opts ...VMVerifierOption) VMVerifier
NewVerifier(opts ...VerifierOption) *Verifier
NewChainManager(opts ...ChainManagerOption) ChainManager
NewLifecycleManager(chain ChainManager, cfg *config.WorkloadConfig, opts ...LifecycleManagerOption) (*LifecycleManager, error)
NewClient(config *ClientConfig, opts ...ClientOption) (*Client, error)
NewScheduler(config *SchedulerConfig, client *Client, targets []*PushTarget, opts ...SchedulerOption) (*Scheduler, error)
NewService(s store.Store) *Service
NewReader(opts ...ReaderOption) *Reader          // pkg/ima
NewSoftwareTPM() *SoftwareTPM
NewSoftwareTPMFactory(tpm *SoftwareTPM) TPMDeviceFactory
```

`NewLifecycleManager` is the one constructor that takes configuration directly
rather than through options: it needs a `*config.WorkloadConfig` because the
PCR index and bank are policy, not wiring.

### Data types

Manifests: `HostManifest`, `VMManifest`, `ContainerManifest`.
Attestations: `HostAttestation`, `VMAttestation`, `ContainerAttestation`.
Quotes and evidence: `VMQuote`, `VMIdentity`, `QuoteRequest`, `VerifyRequest`,
`VerificationResult`, `PCRValue`, `PCRMismatchDetail`.
Chain: `ChainEntry`, `ChainStatistics`, `WorkloadMeasurement`, `WorkloadEvent`,
`MerkleNode`, `MerkleProof`.
Push: `PushRequest`, `PushResult`, `PushBatchResult`, `PushTarget`,
`RetryConfig`, `SchedulerStats`.
Policy: `Policy`, `PolicyRule`.
IMA: `Event`, `EventLog`, `EventFilter`, `Status`.

## 3. Invariants

1. **Nonce freshness is the replay control.** A verifier issues a nonce, the
   attestor includes it in the quote, and the verifier checks it back. A quote
   whose nonce does not match is `ErrNonceMismatch` and is never accepted —
   there is no "close enough" comparison.
2. **A quote has an expiry.** `ErrQuoteExpired` exists and is enforced;
   signature validity alone is not sufficient.
3. **PCR comparison is exact and total.** Every PCR named by policy must match.
   A mismatch produces `ErrPCRMismatch` carrying `PCRMismatchDetail` — the
   expected and actual values per index — so an operator can tell *which*
   measurement moved.
4. **Workload measurements extend a PCR; they never overwrite one.** The chain
   is append-only and its integrity is a Merkle root
   (`ErrMerkleRootMismatch`). Rebuilding the chain from scratch and getting a
   different root means the log was tampered with, not that the code changed.
5. **The workload chain must be initialised before use.** `ErrChainNotInitialized`
   and `ErrChainAlreadyInitialized` are both real errors: initialising twice is
   as much a bug as not initialising.
6. **A host that has not attested cannot vouch for its workloads.**
   `ErrHostNotAttested` and `ErrHostBindingInvalid` enforce the ordering: host
   attestation first, then VM and container attestation bound to it.
7. **IMA verification is against PCR 10.** That is the kernel's IMA PCR and is
   not configurable; the configurable PCR (`attestation.workload.pcr`, default
   **14**) is the *platform's* workload PCR, a different thing. Conflating them
   is a recurring mistake.
8. **The scheduler is single-run.** `ErrSchedulerAlreadyRunning` and
   `ErrSchedulerStopped` mean a scheduler is not restartable; construct a new
   one.

## 4. Error semantics

Errors are typed structs in each sub-package's `errors.go`, not `fmt.Errorf`
strings. Grouped by what a caller should do about them:

**Verification failed — fail closed, always:**
`ErrAttestationFailed`, `ErrQuoteVerificationFailed`, `ErrQuoteExpired`,
`ErrNonceMismatch`, `ErrPCRMismatch`, `ErrManifestVerifyFailed`,
`ErrMerkleRootMismatch`, `ErrCertificateChainInvalid`, `ErrEKCertificateInvalid`,
`ErrHostNotAttested`, `ErrHostBindingInvalid`, `ErrManifestExpired`.

**Identity material missing:**
`ErrAKNotFound`, `ErrAIKNotFound` (both exist — `AK` and `AIK` are used in
different sub-packages for the same concept; see §8).

**Input rejected:**
`ErrInvalidManifest`, `ErrEmptyManifest`, `ErrInvalidVMIdentity`,
`ErrInvalidWorkloadID`, `ErrInvalidWorkloadType`, `ErrInvalidTarget`,
`ErrInvalidHashAlgorithm`, `ErrInvalidConfig`, `ErrInvalidResponse`.

**Operation failed:**
`ErrQuoteGenerationFailed`, `ErrPCRReadFailed`, `ErrPCRExtensionFailed`,
`ErrManifestBuildFailed`, `ErrManifestSignFailed`, `ErrSerializationFailed`,
`ErrPushFailed`, `ErrRetryExhausted`, `ErrAuthFailed`, `ErrContextCanceled`.

**Lifecycle / programming errors:**
`ErrAttestorNotInitialized`, `ErrBuilderNotInitialized`,
`ErrClientNotInitialized`, `ErrClientClosed`, `ErrLifecycleNotInitialized`,
`ErrSchedulerNotInitialized`, `ErrSchedulerAlreadyRunning`,
`ErrSchedulerStopped`, `ErrChainNotInitialized`, `ErrChainAlreadyInitialized`,
`ErrChainEmpty`, `ErrManifestNotFound`, `ErrNoTargetsConfigured`.

`pkg/ima` uses sentinel errors instead: `ErrPCRReadFailed`, `ErrPCRMismatch`,
`ErrInvalidPCRBank` are `errors.New` values compared with `errors.Is`. Two
styles coexist; do not "harmonise" one into the other without a decision.

**Fail-closed rule.** Every error in the first group denies. When you add a
branch to a verifier, the default arm denies. The configured
`attestation.policy.default-action` defaults to **`deny`**
(`DefaultPolicyAction = DefaultActionDeny`) and that default must not be
inverted.

## 5. Configuration

`config.Attestation` (`pkg/config/attestation.go:238`). YAML keys use hyphens;
JSON uses underscores — with two exceptions where the JSON tag also uses
hyphens (`allow-open-enrollment`, `quote-pcrs`). That inconsistency is in the
struct tags today; it is recorded here rather than silently normalised.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `attestation.allow-attestor-self-ca` | bool | `false` | Permit an attestor to act as its own CA |
| `attestation.allow-open-enrollment` | bool | `false` | Accept enrollment without prior authorisation |
| `attestation.allowed-verifiers` | []string | empty | Verifier allowlist |
| `attestation.insecure-port` | int | — | Plaintext attestation listener |
| `attestation.tls-port` | int | — | TLS attestation listener |
| `attestation.quote-pcrs` | []int32 | — | PCR set included in quotes |
| `attestation.workload.enabled` | bool | `false` | Workload measurement on/off |
| `attestation.workload.pcr` | int | `14` | Platform workload PCR; validated to `0..23` |
| `attestation.workload.pcr-bank` | string | `sha256` | One of `sha1`, `sha256`, `sha384`, `sha512` |
| `attestation.workload.include-image-digest` | bool | — | Include the image digest in the measurement |
| `attestation.workload.include-container-id` | bool | — | Include the container ID |
| `attestation.workload.include-workload-type` | bool | — | Include the workload type |
| `attestation.manifest.include-vms` | bool | — | Cover VMs in the manifest |
| `attestation.manifest.include-containers` | bool | — | Cover containers |
| `attestation.manifest.push-enabled` | bool | `false` | Enable scheduled push |
| `attestation.manifest.push-interval` | duration string | — | Parsed with `time.ParseDuration`; a bad value is `ErrInvalidPushInterval` |
| `attestation.manifest.push-targets` | []string | empty | Remote verifiers |
| `attestation.policy.engine` | string | `opa` | `opa` or `rego` |
| `attestation.policy.policy-dir` | path | — | **Required when `engine` is set** — otherwise `ErrEmptyPolicyDir` |
| `attestation.policy.default-action` | string | `deny` | `allow` or `deny` |
| `attestation.reporting.enabled` | bool | `false` | Run the reporting collector on this node (consumed by the collector; PR b of #226) |
| `attestation.reporting.interval` | duration | `15m` | Collector refresh cycle |
| `attestation.reporting.ttl` | duration | `2 × interval` | Freshness window; must be ≥ `interval` (`ErrInvalidReportingInterval`) |
| `attestation.reporting.collector.identity` | string | primary webservice | Name of the webservice whose key/cert the collector presents |
| `attestation.reporting.collector.port` | int | `9443` | Node quote port; `ErrInvalidCollectorPort` outside 1–65535 |
| `attestation.reporting.collector.timeout` | duration | `30s` | Bound on one collection round-trip |
| `attestation.reporting.collector.pcrs` | []int | node default | PCR selection the node is asked to quote; `ErrInvalidPCR` outside 0–23 |
| `attestation.reporting.callers.strategy` | string | `reporting-servers` | `reporting-servers`, `any-attested` or `allowlist`; anything else is `ErrInvalidCallerStrategy` at startup |
| `attestation.reporting.callers.reporting-servers` | []string | derived from the host of `acme.client.directory` | Identities (DNS SAN, else CN) admitted by `reporting-servers`. A configured list **replaces** the derived one |
| `attestation.reporting.callers.allowlist` | []string | empty | Identities admitted by `allowlist`. Empty refuses everyone; an unparseable entry invalidates the whole list and refuses everyone |
| `attestation.reporting.callers.ca-file` | path | `heartbeat.ca-file`, else the IDevID issuer root | PEM bundle of CAs a caller must chain to. A configured file that cannot be read is a startup error, not a fall-through |

**Validation is eager and typed.** `Attestation.Validate()` walks
`Workload`, `Manifest`, `Policy` and `Reporting` and returns `ErrInvalidPCR`,
`ErrInvalidPCRBank`, `ErrInvalidPolicyEngine`, `ErrInvalidDefaultAction`,
`ErrInvalidPushInterval` or `ErrEmptyPolicyDir`. A misconfigured platform fails
at startup, not on the first attestation.

**`allow-open-enrollment` and `allow-attestor-self-ca` both default to false and
both should stay false outside a lab.** Either one turns a closed enrollment
into an open one.

## 6. Persistence

`Store` (`pkg/attestation/store`) holds manifests; `FileStore` is the on-disk
implementation, rooted at a directory given to `NewFileStore`. `ListFilter`
narrows queries. Manifests are versioned by their own contents — a rebuilt
manifest with identical measurements is byte-identical, which is what makes
`ErrMerkleRootMismatch` meaningful.

## 7. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/attestation/**/*_test.go`, `pkg/ima/*_test.go` | Merkle chain, quote verification, PCR comparison, config validation, error mapping |
| Integration | `test/integration/attestation/` | End-to-end host, VM and container attestation against a daemon |

`SoftwareTPM` is the fixture that makes unit tests hardware-free. Integration
tests that need a *real* TPM run against the development cluster, not CI.

The push scheduler's `WithHandler` callback is its synchronisation seam: it
fires once per completed push batch, so `scheduler_test.go` waits on pushes that
actually happened rather than asserting how many fit inside a wall-clock window
(`pushObserver` in `sync_test.go`). The count is authoritative and its channel
is only a wakeup, so a wakeup dropped while nobody is waiting cannot lose a
push. Negative cases — no manifest provider, an unchanged manifest — call
`executePush` directly, because waiting cannot prove that something did not
happen (issue #207).

**Untested guard:** `handleChange`'s `pendingDebounce` suppression has no test
that fails when it is removed. A burst of `NotifyChange` calls is already
coalesced by the single-slot change channel before `handleChange` sees it, so
the observable push count is unchanged either way, and the suppression is not
reachable from outside the package. Closing this needs an observability hook on
the debounce window — a production change, so it is recorded here rather than
made in a test-only change.

**Known repo-wide gap:** there is no `CommandDefinition` type in this
repository (grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet. Recorded, not papered over.

## 8. Naming hazards — read before writing code

Three collisions will cost an afternoon each:

1. **`AK` vs `AIK`.** `ErrAKNotFound` and `ErrAIKNotFound` both exist, in
   different sub-packages, for the same concept. Grep for both.
2. **PCR 10 vs PCR 14.** PCR 10 is the kernel's IMA log PCR, fixed. PCR 14 is
   the platform's default *workload* PCR and is configurable. They are not
   interchangeable.
3. **`ErrPCRMismatch` and `ErrPCRReadFailed` exist twice** — as typed structs in
   `pkg/attestation`, and as sentinel `errors.New` values in `pkg/ima`. The same
   name, two different comparison idioms. Check which package you are in before
   deciding between a type assertion and `errors.Is`.

## 9. Observability

`AttestationObserver` (`pkg/attestation/service/observer.go`) is the hook for
attestation events; the REST surface exposes them at
`GET /api/v1/attestation/events`. Quotes, nonces and raw evidence are **not**
logged — a log is not an evidence store, and a logged nonce is a replay
primitive.

## 10. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- Deep dives carried over from before the migration, not re-verified in this
  pass: [host-manifest.md](host-manifest.md), [manifest.md](manifest.md),
  [policy-engine.md](policy-engine.md), [push.md](push.md),
  [vm-attestation.md](vm-attestation.md),
  [workload-attestation.md](workload-attestation.md),
  [configuration.md](configuration.md)
- Adjacent features: [`docs/vtpm/`](../vtpm/), [`docs/tpm/`](../tpm/),
  [`docs/ima/`](../ima/), [`docs/registry/`](../registry/) (attestation is the
  registry's only authentication method)
