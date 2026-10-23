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

The control plane's own device record is written outside `pkg/attestation`:
`pkg/device/registration.go` holds the one registration implementation and
`pkg/device/controlplane.go` the TPM reader that fills it, composed by
`pkg/daemon/commands/controlplane_device.go` (#472). The resolver's
`reporting.SelfEndpoint` is what connects the two.

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
| `Observer` / `ObserverRegistry` | `verdict` | Hands every recorded device verdict, failed or passed, to relying parties |

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
9. **The control plane is collected as an ordinary device (#472).** Its record
   is written by `device.ControlPlaneRegistrar` through the same
   `device.Register` the ACME finalize hook uses, and its quote is fetched
   through the same `NodeQuoteSource` past the same
   `calleradmission.Policy`. There is no self-report path and no loopback
   exemption on the caller gate; the only thing that differs is address
   provenance, `reporting.SourceControlPlaneLoopback`, which applies to
   exactly one device id and is a property of the dialling process rather
   than of a record.
10. **A collected quote is bound to the connection it was collected over,
    and both ends derive the binding (#482).** `NodeQuoteSource` sends the
    **bare** nonce. The node derives the binding of the connection the
    request arrived on and quotes `xkms.PeerQualifyingData(nonce, binding)`
    — `pkg/attestation/channelbind.QualifyingData`, called by every
    collect-host entry point (`AttestationServiceServer.CollectHostAttestation`
    for gRPC, Unix, daemon QUIC `0x72` and the REST router, which records
    `req.TLS` with `channelbind.WithConnectionTLS`; the `pkg/api/quic` `0x7E`
    and `pkg/api/rest` handlers). A request with no binding (Unix, embedded,
    plain HTTP, an exporter that refuses) is
    `channelbind.ErrChannelBindingRequired` (FailedPrecondition) before the
    TPM is touched. The collector derives the binding with
    `xkms.PeerChannelBinding` (the upstream exporter label, never a local
    one) on the connection it sends on — `dial` completes the handshake,
    `exchange` rides that connection, and `singleUseDialer` refuses a redial
    (`ErrConnectionSpent`) — and an echo other than
    `PeerQualifyingData(nonce, binding)` is `ErrQuoteNotBound`, kept in
    `ErrNodeUnreachable.Causes`. A connection that cannot export keying
    material is `ErrChannelBinding`; neither end falls back to the bare
    nonce. **Never let the caller supply the bound value**: a relay forwards
    it unchanged to a healthy node and the quote passes; the node binding to
    its own connection is what makes the relay fail
    (`TestCollectHost_RelayedQuoteIsRejected`). The reporting verifier
    requires the binding. The transport verify endpoints take an optional
    `channel_binding` only to recompute the qualifying data a bound quote
    carries; a verify that passes is **not** channel proof — a relay can
    submit its own binding just as well. Channel proof belongs to the end
    that derived the binding from its own connection.
11. **Every quote a node produces over a TLS connection is bound to that
    connection (#482).** Invariant 10 holds for every endpoint that quotes a
    caller's nonce with the node's TPM, not only collect-host: attestation
    `GetAttestationQuote` (REST `/api/v1/attestation/quote`, QUIC `0x70`,
    gRPC, MCP), TPM `Quote` (`TPMGRPCService.Quote` behind gRPC, MCP
    `platform_tpm_quote` and the webservice `/api/v1/tpm/quote`; the
    `pkg/api/rest` and `pkg/api/quic` `0x99·0x0F` handlers) and the daemon
    REST `/api/v1/tpm/certify` when it is given a nonce. Each derives the
    binding itself (`channelbind.Bind`), quotes
    `PeerQualifyingData(nonce, binding)`, returns `channel_binding`, and
    refuses a request it cannot bind with `ErrChannelBindingRequired` before
    the TPM is touched — Unix, embedded and MCP over stdio included
    (`TestGetAttestationQuote_RelayedQuoteIsRejected`,
    `unboundQuoteContexts` in `pkg/api/daemon`). Every caller in this repo
    checks the echo against its own binding, never the bare nonce: the Go SDK
    `attestation` and `tpm` clients through `sdk/go/quotebind` (a quote bound
    elsewhere is `quotebind.ErrQuoteNotBound`), and `platformctl` through the
    SDK. Over a transport with no TLS state the SDK refuses before asking
    (`transport.ErrChannelBindingUnavailable`). A browser cannot read the TLS
    exporter, so `checkQuoteBinding` in `sdk/javascript` and the web TPM quote
    page prove only that the quote is bound to the binding the node returned —
    never the bare nonce — not that it is the page's own connection. Treat
    browser output as display, never as evidence another component trusts.
12. **A quote is verified under the scheme it declares (#874).** A TPM quote
    signature is bare bytes — the TPMT_SIGNATURE that names the scheme is
    stripped — and an RSA IAK signs RSASSA or RSASSA-PSS as its
    `SignatureAlgorithm` says. So `GetAttestationQuote` returns
    `signature_algorithm` (the x509.SignatureAlgorithm name of the IAK's
    scheme) beside the signature, and `VerifyAttestationQuote` hands it to
    `vm.VerifyQuoteSignatureWithAlgorithm`, which dispatches on it: the
    PKCS#1 v1.5, PSS (either salt length) and ECDSA families over SHA-256,
    -384 and -512. A quote declaring none or any other scheme is
    `vm.ErrUnsupportedSignatureAlgorithm`; a scheme the AK's key type cannot
    carry is `vm.ErrSignatureSchemeMismatch`. Never infer the scheme from the
    key type: that is how every PSS quote failed as PKCS#1 v1.5. It is the
    only quote signature check (#482): the inferring `vm.VerifyQuoteSignature`
    is deleted, and every caller — the TPM verify handlers on each transport,
    the VM and container compute paths, and the workload verdict — passes
    the scheme the quote or its IAK declares. A producer reads that scheme
    with `vm.QuoteSignatureAlgorithm`, which is
    `vm.ErrQuoteSchemeUnavailable` when the IAK names none, so no quote
    leaves without one.
    These checks (`vm.VerifyQuoteSignatureWithAlgorithm`,
    `vm.VerifyQuoteNonce`, `vm.VerifyQuotePCRDigest`) stay local because
    every caller above holds a bare AK public key: a guest vTPM's AIK, the
    node's own IAK, or one the request carries. The go-quicbaas re-export
    `xkms.NewPeerAttestationVerifier` takes only an AK certificate chained to
    anchors (TCG DevID v1 r12 §8.2) and refuses a bare key by design, so it
    cannot stand in for them. The device quote verifier, which holds the
    certificate, is on that primitive ([architecture](architecture.md),
    "Device quote verification"). Moving the rest needs an upstream entry that checks the
    signature, nonce and PCR digest under a key the caller already trusts
    (#482).

### 3a. Signing paths that are not relay oracles

Order #482 asked for every path that quotes, certifies or signs
caller-supplied data. Those not bound above are not oracles for one reason:
nothing in this repo accepts their output as proof that the node's TPM spoke
over a given connection.

| Path | Why it is not an oracle |
|------|-------------------------|
| `pkg/vtpm` `Service.Quote` (REST, QUIC, gRPC `QuoteVTPM`, MCP `vtpm_quote` / `vtpm_bundle_quote`) and compute `AttestVM` (QEMU, AWS, GCP; Azure refuses) | Signed by the guest's vTPM, or by no key at all for the cloud EK paths — never by the node IAK. No node collector or device verifier accepts a vTPM quote as host evidence. |
| attestation `AttestVM` / `CollectVMAttestation` / `CollectContainerAttestation` | Return `ErrTPMSessionNotConfigured`; no quote is produced. |
| attestation `BuildManifest` (REST `/manifests/build`, gRPC, QUIC `0x7C`, MCP `attestation_create_manifest`) | Returns `ErrTPMSessionNotConfigured` on every node, a TPM or not. A manifest is signed with a free-form IAK signature over the caller's nonce, and the daemon's TPM session (`HostQuoter`) offers only `TPM2_Quote` under the restricted IAK, so it has no key to sign with. No manifest is built or stored. |
| container `Attest(ctx, id)`, PIV `Attest(slot)`, MCP `platform_tpm_certify` | Take no caller qualifying data. |
| daemon REST `/api/v1/tpm/certify` | Bound when a nonce is given (invariant 11). Its output is a `TPM_ST_ATTEST_CERTIFY` structure, which every quote verifier, `quotebind.QuotedData` and the JS `quotedData` refuse. |
| diskless boot quote (`app.disklessBootQuote` → `hostquote.Collect`) | Quotes the binding the node derived from the connection it dialled itself; the caller never supplies it. |
| AVR firmware `Backend.AttestCert` | Signs a device-attest-01 enrolment challenge (SHA-256 of the ACME key authorization) with the device's DICE alias key, not a TPM; no platformd endpoint exposes it. |
| `HostTPMProvider.Quote`, podman `GetContainerQuote`, NV certify | No production caller passes caller qualifying data; NV certify does not exist in production code. |

A new path that signs caller data with the node's TPM joins invariant 11 or
this table in the same change.

## 4. Error semantics

Errors are typed structs in each sub-package's `errors.go`, not `fmt.Errorf`
strings. Grouped by what a caller should do about them:

**Verification failed — fail closed, always:**
`ErrAttestationFailed`, `ErrQuoteVerificationFailed`, `ErrQuoteExpired`,
`ErrNonceMismatch`, `ErrPCRMismatch`, `ErrManifestVerifyFailed`,
`ErrMerkleRootMismatch`, `ErrCertificateChainInvalid`, `ErrEKCertificateInvalid`,
`ErrHostNotAttested`, `ErrHostBindingInvalid`, `ErrManifestExpired`,
`ErrQuoteNotBound` (a collected quote bound to another connection, §3
invariant 10; the SDK's `quotebind.ErrQuoteNotBound` is the caller-side twin,
invariant 11).

**Request cannot be bound — refuse, never quote:**
`ErrChannelBindingRequired` (a quote request whose connection carries no
channel binding; §3 invariants 10 and 11).

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

**The device quote verifier keeps causes (#482).** `DeviceQuoteVerifier`
(`pkg/api/daemon`) returns an error only when it reached no verdict, and the
error carries what stopped it: an upstream verifier error is
`ErrAttestationFailed{Err: …}`, so `errors.Is(err, context.Canceled)` /
`context.DeadlineExceeded` and the upstream typed errors still match; a
profile store error is `ErrDeviceProfileLookupFailed{Cause: …}`. Only
`device.ErrNoProfileForDevice` means "no profile" (an absence verdict); never
fold a lookup failure into it.

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
| `attestation.reporting.enabled` | bool | `false` | Run the reporting collector on this node (a control plane) |
| `attestation.reporting.interval` | duration | `15m` | Collector refresh cycle |
| `attestation.reporting.ttl` | duration | `2 × interval` | Freshness window; must be ≥ `interval` (`ErrInvalidReportingInterval`) |
| `attestation.reporting.collector.identity` | string | primary webservice | Name of the webservice whose key/cert the collector presents |
| `attestation.reporting.collector.port` | int | `9443` | Node quote port; `ErrInvalidCollectorPort` outside 1–65535 |
| `attestation.reporting.collector.timeout` | duration | `30s` | Bound on one collection round-trip |
| `attestation.reporting.collector.pcrs` | []int | node default | PCR selection the node is asked to quote; `ErrInvalidPCR` outside 0–23 |
| `attestation.reporting.collector.ca-file` | path | trust resolver `internal` class | PEM bundle the nodes' webservice certificates must chain to. Set it when nodes serve certificates from their own local CA (every node on the measured fleet does); an unusable file is a startup error, not a fall-through |
| `attestation.reporting.callers.strategy` | string | `reporting-servers` | `reporting-servers`, `any-attested` or `allowlist`; anything else is `ErrInvalidCallerStrategy` at startup |
| `attestation.reporting.callers.reporting-servers` | []string | derived from the host of `acme.client.directory` | Identities (DNS SAN, else CN) admitted by `reporting-servers`. A configured list **replaces** the derived one |
| `attestation.reporting.callers.allowlist` | []string | empty | Identities admitted by `allowlist`. Empty refuses everyone; an unparseable entry invalidates the whole list and refuses everyone |
| `attestation.reporting.callers.ca-file` | path | `heartbeat.ca-file`, else the platform anchor (the IDevID issuer root) | PEM bundle of CAs a caller must chain to. A configured file that cannot be read is a startup error, not a fall-through |

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

Device attestation reports (#226) persist beside them: `FileStore` implements
`reporting.Store` with one atomically written file per device under
`<root>/reports/<device_id>.json` (`PutReport`, `Reports`). The device id is
validated as a path segment (`ErrInvalidReportDeviceID`). A file that no longer
parses is skipped on load rather than failing every other device. The cache
warms from the store at start and keeps each report's original `CollectedAt`.

## 7. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/attestation/**/*_test.go`, `pkg/ima/*_test.go` | Merkle chain, quote verification, PCR comparison, config validation, error mapping |
| Integration | `test/integration/attestation/` | End-to-end host, VM and container attestation against a daemon; the device-report and caller-policy verbs on every transport ([CLI §7](cli.md#7-parity-gap)) |

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

**On-change debounce window (#241):** the first change arms a window; every
change the run loop hands to `handleChange` while it is armed is suppressed, so
the window ends in one push. This is the ordinary path, not a corner: arming
returns at once, so the run loop sees each later change of the window, and the
single-slot change channel only coalesces changes that arrive faster than the
loop drains it. The window is disarmed *before* its push runs, so a change that
arrives while the push is in flight — and may have missed the manifest it read —
arms a new window instead of being dropped; the provider's `HasChanged` then
decides whether that window pushes. The decision is invisible in push counts, so
the scheduler carries an unexported `withChangeObserver` seam (the `onSweep`
shape from `pkg/security/ratelimit`: fixed at construction, nil in production)
and `TestSchedulerDebounceWindow` waits on it to pin both behaviours.

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

### Device verdict events

`AttestationObserver` sees only passed verdicts and cryptographic failures, so
an absence of evidence never quarantines a device. Relying parties that deny
service on *any* failed verdict register a `verdict.Observer` instead
(`Service.RegisterDeviceVerdictObserver`). It is handed every verdict once it
is in the event log, with that event's ID and time.

platformd registers one at start-up (`streamDeviceVerdicts`,
`pkg/api/daemon/attestation_verdict_stream.go`) that records every verdict in
a `feed.Feed` (`pkg/attestation/verdict/feed`), which every transport follows
(#709). gRPC over TCP and over the Unix socket serve
`AttestationService.StreamDeviceVerdicts` as a server stream; REST, QUIC, MCP
and embedded carry no server stream, so they long-poll the same feed through
`PollDeviceVerdicts` ([api.md](api.md) §5.5), and the Go SDK turns those polls
back into the one `StreamDeviceVerdicts` call. Each `DeviceVerdictEvent` carries the event-log entry's `event_id` and
`recorded_at`, and the verdict's `device_id`, `tenant_id`, `host_id`,
`serial`, `passed`, `cryptographic` and `reason`. The verifier stamps
`tenant_id` from the device record; it is empty for a device the platform
itself owns.

When the reporting collector runs, platformd also registers its report cache
(`reporting.Cache.OnDeviceVerdict`, wired by `reportEveryVerdict` in
`pkg/daemon/commands/attestation_reporting.go`). Every recorded verdict then
becomes the device's report, whichever path verified it: the collector, or a
device submitting its own quote through `AttestDevice` on any transport. A
failed `AttestDevice` therefore replaces a collected pass in `GetDeviceReport`
and in the persisted report, instead of leaving it to be served until it
expires (#765). A verdict carries no per-check breakdown, so its report sets
every check on a pass and none on a failure, whose `message` explains it. The
cache never lets an older verification replace a newer one: the verifier
stamps the verdict with its `attested_at`, and the collector's full report of
the same verification, which carries the same time, replaces the verdict's.

Who sees which verdicts:

| Caller | Admitted | Sees |
|---|---|---|
| Platform token | holds `attestation:read` and names a tenant | its tenant's devices; the `system` tenant sees every device |
| Bearer token the daemon can only check for validity | never | — |
| mTLS certificate | always | its certificate's tenant; a certificate naming no tenant, or `system`, sees every device |
| No credential (Unix socket peer, embedded in-process caller, or a listener run without authentication) | always | every device |

That table is gRPC's. QUIC and MCP have no peer identity to fall back on, so
they admit only a platform token, by its first row, and refuse a call without
one. REST takes the tenant of the verified IAM session behind the admin-role
gate (`system` sees every device; a session naming no tenant is refused `403`).

A verdict on a device with no tenant reaches only callers that see every
device. The gRPC method catalog maps both RPCs to `attestation:read`, so the
token interceptor refuses a token without it before the handler runs; the MCP
tool carries the same permission.

The feed keeps the last 256 verdicts. A follow starts at subscription (an
empty cursor means "from now on") and does not replay. Each poll answers the
verdicts after its cursor and the cursor to pass next; it waits at most 20 s
(`feed.MaxWait`, under the 30 s request timeouts of the REST, QUIC and MCP
servers) for one to arrive. A cursor older than the ring, or from an earlier
platformd run, is refused `RESOURCE_EXHAUSTED` rather than losing a verdict
silently; one the feed never issued is `INVALID_ARGUMENT`. The feed closes when
platformd shuts down, before its graceful gRPC stop, so every stream and poll
ends `UNAVAILABLE` and the stop does not wait on followers. A consumer follows
again after either and keeps a backstop for what it missed. The overlay
gateways use the stream to withdraw a failed device's VTEPs
([overlay mode](../gateway/engineering.md#revocation-on-a-failed-verdict)).

## 10. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- Deep dives carried over from before the migration, not re-verified in this
  pass: [manifest.md](manifest.md), [push.md](push.md),
  [vm-attestation.md](vm-attestation.md),
  [workload-attestation.md](workload-attestation.md). The legacy
  host-manifest.md, policy-engine.md and configuration.md are deleted; these
  five files hold their content.
- Adjacent features: [`docs/vtpm/`](../vtpm/), [`docs/tpm/`](../tpm/),
  [`docs/ima/`](../ima/), [`docs/registry/`](../registry/) (attestation is the
  registry's only authentication method)
