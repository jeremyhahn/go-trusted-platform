// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// serve_barrier_gate.go implements milestone M6 from
// docs/08-bootstrap-auth-architecture.md: gate the remote transport
// listeners (gRPC TCP, REST, QUIC, MCP) on barrier unseal state. Only the
// Unix socket and a minimal /healthz + /init + /unseal HTTP endpoint are
// allowed before the barrier is unsealed.

package commands

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	apidaemon "github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	appbackends "github.com/jeremyhahn/go-trusted-platform/pkg/app/backends"
	"github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
)

// =============================================================================
// Typed errors
// =============================================================================

// ErrBarrierGateRequiresApp is returned when the barrier gate is invoked
// without an initialized App.
type ErrBarrierGateRequiresApp struct{}

// Error returns a human-readable description of the error.
func (ErrBarrierGateRequiresApp) Error() string {
	return "barrier gate requires an initialized app"
}

// ErrBarrierGateRequiresSDK is returned when the barrier gate is invoked
// without a quicbaas SDK client.
type ErrBarrierGateRequiresSDK struct{}

// Error returns a human-readable description of the error.
func (ErrBarrierGateRequiresSDK) Error() string {
	return "barrier gate requires a quicbaas SDK client"
}

// ErrBarrierInitFailed is returned by /init when the bootstrap ceremony
// succeeded but the barrier could not be initialized.
type ErrBarrierInitFailed struct {
	Cause error
}

// Error returns a human-readable description of the error.
func (e ErrBarrierInitFailed) Error() string {
	if e.Cause == nil {
		return "barrier initialization after the ceremony failed"
	}
	return "barrier initialization after the ceremony failed: " + e.Cause.Error()
}

// Unwrap returns the underlying barrier error.
func (e ErrBarrierInitFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Barrier seam
// =============================================================================

// barrierLifecycle is the part of *barrier.Manager POST /init drives.
type barrierLifecycle interface {
	IsInitialized() bool
	Initialize(ctx context.Context, secret string) error
	InitializeShamir(ctx context.Context, secret string, threshold, shares int) (*quicbaassdk.QRDBBarrierInitializeShamirResponse, error)
	RegisterOfficer(ctx context.Context, username string, csrPEM []byte) error
	Officers(ctx context.Context) ([]string, error)
	Status(ctx context.Context) (*quicbaassdk.QRDBBarrierStatusResponse, error)
	SyncStatus(ctx context.Context) error
}

// gateBarrier is the part of *barrier.Manager the gate services drive: the
// /init lifecycle, the /unseal operations and the state flags.
type gateBarrier interface {
	barrierLifecycle
	Unseal(ctx context.Context, secret string) error
	UnsealWithShare(ctx context.Context, share string) (*quicbaassdk.QRDBBarrierUnsealShareResponse, error)
	IsSealed() bool
	IsUnsealing() bool
}

// Compile-time assertion that the manager satisfies the gate seam.
var _ gateBarrier = (*barrier.Manager)(nil)

// gateBarrierOf returns the app's barrier manager, or nil when the app has
// none. A nil *barrier.Manager must not become a non-nil interface value.
func gateBarrierOf(a *app.App) gateBarrier {
	if a == nil {
		return nil
	}
	mgr := a.Barrier()
	if mgr == nil {
		return nil
	}
	return mgr
}

// ErrBarrierStrategyUnsupported is returned when barrier.seal_strategy names
// a strategy /init cannot initialize the platform barrier with. "none" is
// one: the SDK's system-barrier initialize seals with the node's registered
// strategies and cannot select an unencrypted barrier.
type ErrBarrierStrategyUnsupported struct {
	Strategy string
}

// Error returns a human-readable description of the error.
func (e *ErrBarrierStrategyUnsupported) Error() string {
	return fmt.Sprintf("barrier strategy %q cannot initialize the platform barrier", e.Strategy)
}

// ErrBarrierInitMissingSecret is returned when /init carries no user PIN,
// which every barrier strategy uses as the barrier secret.
type ErrBarrierInitMissingSecret struct {
	Strategy string
}

// Error returns a human-readable description of the error.
func (e *ErrBarrierInitMissingSecret) Error() string {
	return fmt.Sprintf("barrier strategy %q requires the user PIN as the barrier secret", e.Strategy)
}

// Unwrap reports the missing secret as the missing user_pin request field.
func (e *ErrBarrierInitMissingSecret) Unwrap() error {
	return rest.ErrMissingRequiredField{Field: "user_pin"}
}

// ErrBarrierShamirQuorum is returned when a shamir /init does not carry a
// quorum with 2 <= threshold <= shares.
type ErrBarrierShamirQuorum struct {
	Threshold int
	Shares    int
}

// Error returns a human-readable description of the error.
func (e *ErrBarrierShamirQuorum) Error() string {
	return fmt.Sprintf("shamir barrier requires 2 <= threshold <= shares, got threshold %d of %d shares", e.Threshold, e.Shares)
}

// ErrBarrierInitOfficers is returned when an M-of-N /init does not name one
// Security Officer per share, or names officers without a quorum. The
// ceremony seals each share to an enrolled officer, so a share without an
// officer could never be claimed.
type ErrBarrierInitOfficers struct {
	Officers int
	Shares   int
}

// Error returns a human-readable description of the error.
func (e *ErrBarrierInitOfficers) Error() string {
	return fmt.Sprintf("an M-of-N init needs one officer per share, got %d officers for %d shares", e.Officers, e.Shares)
}

// ErrBarrierInitOfficerInvalid is returned when an /init officer cannot be
// enrolled. Index is the officer's position in the request, Reason names the
// defect and Err carries the CSR parse failure, if that was the defect.
type ErrBarrierInitOfficerInvalid struct {
	Index    int
	Username string
	Reason   string
	Err      error
}

// Error returns a human-readable description of the error.
func (e *ErrBarrierInitOfficerInvalid) Error() string {
	msg := fmt.Sprintf("officer %d %q cannot be enrolled: %s", e.Index, e.Username, e.Reason)
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns the CSR parse failure, if any.
func (e *ErrBarrierInitOfficerInvalid) Unwrap() error { return e.Err }

// ErrBarrierInitOfficerCSRNotPEM is the CSR defect of an /init officer whose
// csr_pem holds no PEM block.
type ErrBarrierInitOfficerCSRNotPEM struct{}

// Error returns a human-readable description of the error.
func (e *ErrBarrierInitOfficerCSRNotPEM) Error() string {
	return "csr_pem holds no PEM block"
}

// ErrBarrierShamirUnenforceable is returned when /init asks for a shamir
// barrier but the platform barrier is not sealed by a Shamir strategy. Without
// one, the SDK's InitializeShamir falls back to credential mode: it initializes
// a single-key barrier with the user PIN and distributes shares of that PIN,
// so the initiating operator could still unseal alone. Registered is the
// strategy the barrier reports, empty when the daemon has no barrier manager.
type ErrBarrierShamirUnenforceable struct {
	Registered string
}

// Error returns a human-readable description of the error.
func (e *ErrBarrierShamirUnenforceable) Error() string {
	if e.Registered == "" {
		return "shamir barrier requested but the daemon has no barrier that can enforce the quorum"
	}
	return fmt.Sprintf("shamir barrier requested but the platform barrier seals with %q, which cannot enforce the quorum", e.Registered)
}

// ErrBarrierStatusUnavailable is returned when /init cannot read the platform
// barrier's seal strategy, so a shamir request cannot be verified.
type ErrBarrierStatusUnavailable struct {
	Err error
}

// Error returns a human-readable description of the error.
func (e *ErrBarrierStatusUnavailable) Error() string {
	return "barrier status unavailable: " + e.Err.Error()
}

// Unwrap returns the status read failure.
func (e *ErrBarrierStatusUnavailable) Unwrap() error {
	return e.Err
}

// =============================================================================
// State provider
// =============================================================================

// barrierStateProvider implements rest.PlatformStateProvider by reading the
// platform's barrier manager. The state machine has four observable values:
//   - uninitialized: barrier never initialized
//   - sealed:        initialized but locked
//   - unsealing:     sealed, with at least one Shamir share accepted
//   - unsealed:      operational
//
// The provider is safe for concurrent use; the underlying barrier.Manager
// uses atomics for its cached flags.
type barrierStateProvider struct {
	barrier gateBarrier
}

// State returns the current platform state.
func (p *barrierStateProvider) State(_ context.Context) rest.PlatformState {
	if p == nil || p.barrier == nil {
		return rest.PlatformStateUninitialized
	}
	if !p.barrier.IsInitialized() {
		return rest.PlatformStateUninitialized
	}
	if p.barrier.IsUnsealing() {
		return rest.PlatformStateUnsealing
	}
	if p.barrier.IsSealed() {
		return rest.PlatformStateSealed
	}
	return rest.PlatformStateUnsealed
}

// =============================================================================
// Init service (POST /init)
// =============================================================================

// barrierInitFunc initializes the platform barrier for one strategy.
type barrierInitFunc func(ctx context.Context, mgr barrierLifecycle, req *rest.BarrierInitRequest) error

// barrierInitStrategies maps each strategy /init accepts to the barrier
// lifecycle operation that honours it. Shamir splits the barrier key M-of-N;
// every other strategy initializes it with the user PIN, and the node seals
// it with its registered strategy (TPM, PKCS#11, cloud KMS or software).
var barrierInitStrategies = map[string]barrierInitFunc{
	barrier.SealStrategyShamir:     initShamirBarrier,
	barrier.SealStrategySoftware:   initSingleKeyBarrier,
	barrier.SealStrategyPassphrase: initSingleKeyBarrier,
	barrier.SealStrategyTPM2:       initSingleKeyBarrier,
	barrier.SealStrategyPKCS11:     initSingleKeyBarrier,
	"awskms":                       initSingleKeyBarrier,
	"gcpkms":                       initSingleKeyBarrier,
	"azurekv":                      initSingleKeyBarrier,
	"vault":                        initSingleKeyBarrier,
}

// initSingleKeyBarrier initializes the barrier with the user PIN.
func initSingleKeyBarrier(ctx context.Context, mgr barrierLifecycle, req *rest.BarrierInitRequest) error {
	return mgr.Initialize(ctx, req.UserPIN)
}

// initShamirBarrier initializes the barrier with Shamir secret sharing. The
// shares go to enrolled Security Officers, who claim them through the
// share-claim flow; none comes back here.
func initShamirBarrier(ctx context.Context, mgr barrierLifecycle, req *rest.BarrierInitRequest) error {
	if err := enrollBarrierOfficers(ctx, mgr, req.Officers); err != nil {
		return err
	}
	_, err := mgr.InitializeShamir(ctx, req.UserPIN, req.Threshold, req.Shares)
	return err
}

// enrollBarrierOfficers registers every /init officer with the barrier's
// share ceremony through the SDK; InitializeShamir seals one share to each
// enrolled officer and refuses a set smaller than the share count. Officers an
// earlier, failed attempt already enrolled are skipped, so an identical retry
// completes the set instead of failing on a duplicate username.
func enrollBarrierOfficers(ctx context.Context, mgr barrierLifecycle, officers []rest.BarrierInitOfficer) error {
	enrolled, err := mgr.Officers(ctx)
	if err != nil {
		return err
	}
	known := make(map[string]struct{}, len(enrolled))
	for _, username := range enrolled {
		known[username] = struct{}{}
	}
	for _, officer := range officers {
		if _, ok := known[officer.Username]; ok {
			continue
		}
		if err := mgr.RegisterOfficer(ctx, officer.Username, []byte(officer.CSRPEM)); err != nil {
			return err
		}
	}
	return nil
}

// firstNonEmpty returns the first non-empty value.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// barrierInitService implements rest.BarrierInitService by delegating to the
// QuicBaaS ceremony backend (which terminates at go-qrdb's CeremonyService).
// On success the backend response is rendered into a rest.BarrierInitResponse
// and the barrier is initialized; a barrier failure fails the request. The
// platform state then moves to sealed (passphrase/shamir) or unsealed
// (software with auto-unseal) depending on the strategy.
//
// The service is retry-safe for the operator who ran it. The first
// successful init is held in memory while the gate is up, keyed by a digest
// of the request (PINs included), with the admin key in a memguard enclave.
// An identical retry from the same uid over the Unix socket receives the
// same admin bundle and re-attempts the barrier initialization if it failed.
// Every other request — a different one, or an identical one from loopback
// HTTP or another uid — is rejected the same way, so the gate never confirms
// the PINs to anyone but the operator. The key is destroyed as soon as the
// barrier unseals or the gate shuts down; nothing is persisted.
type barrierInitService struct {
	logger  *logging.Logger
	backend apidaemon.CeremonyBackend
	state   rest.PlatformStateProvider

	// barrier is the platform barrier /init initializes after the ceremony;
	// nil when the daemon has no barrier manager.
	barrier barrierLifecycle
	// defaultStrategy is the daemon's configured barrier seal strategy
	// (barrier.seal_strategy); empty selects barrier.DefaultSealStrategy.
	// The request cannot override it.
	defaultStrategy string

	// mu serializes Initialize so concurrent requests cannot run the
	// ceremony (and mint an admin key) twice.
	mu     sync.Mutex
	issued *issuedInit
}

// issuedInit is the response of the init this gate completed.
type issuedInit struct {
	digest [sha256.Size]byte
	// resp is the issued response without the admin key; key holds it.
	resp rest.BarrierInitResponse
	key  *memguard.MemoryEnclave
	// caller is the Unix peer that was issued the bundle. callerKnown is
	// false when it was issued over loopback HTTP, which has no peer
	// identity, so that bundle is never replayed.
	caller      peercred.UnixCredentials
	callerKnown bool
}

// newIssuedInit moves the admin key of resp into locked memory. The string
// the backend returned cannot be wiped, but it is not retained either.
func newIssuedInit(ctx context.Context, digest [sha256.Size]byte, resp rest.BarrierInitResponse) *issuedInit {
	caller, known := peercred.UnixCredentialsFromContext(ctx)
	key := memguard.NewMemoryEnclaveFromString(resp.AdminKeyPEM)
	resp.AdminKeyPEM = ""
	return &issuedInit{digest: digest, resp: resp, key: key, caller: caller, callerKnown: known}
}

// replay returns the issued response, admin key included, when the caller
// in ctx is the Unix peer it was issued to and digest matches the issued
// request. It returns false once the key has been destroyed.
func (i *issuedInit) replay(ctx context.Context, digest [sha256.Size]byte) (rest.BarrierInitResponse, bool) {
	caller, ok := peercred.UnixCredentialsFromContext(ctx)
	if !ok || !i.callerKnown || caller.UID != i.caller.UID {
		return rest.BarrierInitResponse{}, false
	}
	if subtle.ConstantTimeCompare(i.digest[:], digest[:]) != 1 {
		return rest.BarrierInitResponse{}, false
	}
	resp := i.resp
	err := i.key.Open(func(key []byte) error {
		resp.AdminKeyPEM = string(key)
		return nil
	})
	return resp, err == nil
}

// initRequestDigest hashes every request field, each length-prefixed so no
// two different requests share an encoding.
func initRequestDigest(req *rest.BarrierInitRequest) [sha256.Size]byte {
	fields := []string{
		req.SOPIN, req.UserPIN,
		strconv.Itoa(req.Shares), strconv.Itoa(req.Threshold),
		req.Hostname, req.CredentialSealStrategy,
		strconv.Itoa(len(req.Officers)),
	}
	for _, officer := range req.Officers {
		fields = append(fields, officer.Username, officer.CSRPEM)
	}
	fields = append(fields, req.SANs...)
	var buf []byte
	for _, field := range fields {
		buf = binary.AppendUvarint(buf, uint64(len(field)))
		buf = append(buf, field...)
	}
	return sha256.Sum256(buf)
}

// ceremonyOfficers maps the /init officers onto the ceremony request, which
// signs each officer's CSR. It returns nil for none.
func ceremonyOfficers(officers []rest.BarrierInitOfficer) []apidaemon.CeremonyOfficer {
	if len(officers) == 0 {
		return nil
	}
	out := make([]apidaemon.CeremonyOfficer, 0, len(officers))
	for _, officer := range officers {
		out = append(out, apidaemon.CeremonyOfficer{Username: officer.Username, CSRPEM: officer.CSRPEM})
	}
	return out
}

// Initialize delegates the canonical ceremony bootstrap to the configured
// backend, then initializes the barrier, or replays the issued response for an
// identical retry. The state in the response reflects the barrier state after
// both steps.
func (s *barrierInitService) Initialize(ctx context.Context, req *rest.BarrierInitRequest) (*rest.BarrierInitResponse, error) {
	if s == nil || s.backend == nil {
		return nil, &rest.ErrBarrierInitServiceUnavailable{}
	}
	if req == nil {
		req = &rest.BarrierInitRequest{}
	}
	// Refuse a request the barrier cannot honour before the ceremony mints
	// the one-shot admin bundle, so it leaves nothing half done.
	strategy := s.resolveBarrierStrategy()
	initBarrier, err := planBarrierInit(strategy, req)
	if err != nil {
		return nil, err
	}
	if err := s.requireQuorumBarrier(ctx, strategy); err != nil {
		var unenforceable *ErrBarrierShamirUnenforceable
		if errors.As(err, &unenforceable) {
			return nil, &rest.ErrInitBarrierConflict{Err: err}
		}
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	digest := initRequestDigest(req)
	if s.issued != nil {
		resp, ok := s.issued.replay(ctx, digest)
		if !ok {
			return nil, &rest.ErrInitAlreadyIssued{}
		}
		if err := s.initializeBarrier(ctx, initBarrier, req, &resp); err != nil {
			return nil, err
		}
		s.destroyKeyIfUnsealed(resp.State)
		return &resp, nil
	}

	thresholdSpec := ""
	if req.Shares > 0 || req.Threshold > 0 {
		thresholdSpec = formatThreshold(req.Threshold, req.Shares)
	}
	// The qrdb embedded ceremony transport threads the per-request
	// SOPin/UserPin from the ceremony-initialize request directly into the
	// service layer, so the PINs are supplied on the call itself below.
	out, err := s.backend.Initialize(ctx, &apidaemon.CeremonyInitRequest{
		SOPIN:                  req.SOPIN,
		UserPIN:                req.UserPIN,
		Threshold:              thresholdSpec,
		Hostname:               req.Hostname,
		SANs:                   req.SANs,
		CredentialSealStrategy: req.CredentialSealStrategy,
		Officers:               ceremonyOfficers(req.Officers),
	})
	if err != nil {
		return nil, err
	}
	resp := rest.BarrierInitResponse{}
	if out != nil {
		resp.CeremonyID = out.CeremonyID
		resp.InitializedAt = out.InitializedAt
		resp.SPKIPin = out.SPKIPin
		resp.AdminCertPEM = out.AdminCertPEM
		resp.AdminKeyPEM = out.AdminKeyPEM
	}
	// The bundle is retained before the barrier step: when that step fails,
	// an identical retry from the issuing uid receives the bundle and
	// re-attempts it.
	s.issued = newIssuedInit(ctx, digest, resp)
	if err := s.initializeBarrier(ctx, initBarrier, req, &resp); err != nil {
		return nil, err
	}
	s.destroyKeyIfUnsealed(resp.State)
	return &resp, nil
}

// destroyKeyIfUnsealed wipes the retained admin key once the barrier is
// unsealed: the gate is closing and no replay can follow. The caller holds
// s.mu.
func (s *barrierInitService) destroyKeyIfUnsealed(state rest.PlatformState) {
	if state == rest.PlatformStateUnsealed {
		s.issued.key.Destroy()
	}
}

// Replay implements rest.BarrierInitReplayer: the issued response for a
// request identical to the one that was issued, to the Unix peer it was
// issued to, while the barrier is still sealed.
func (s *barrierInitService) Replay(ctx context.Context, req *rest.BarrierInitRequest) (*rest.BarrierInitResponse, bool) {
	if s == nil || req == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.issued == nil {
		return nil, false
	}
	state := rest.PlatformStateSealed
	if s.state != nil {
		state = s.state.State(ctx)
	}
	if state == rest.PlatformStateUnsealed {
		s.issued.key.Destroy()
		return nil, false
	}
	resp, ok := s.issued.replay(ctx, initRequestDigest(req))
	if !ok {
		return nil, false
	}
	resp.State = state
	return &resp, true
}

// release destroys the retained admin key when the gate shuts down.
// Initialize and Replay already destroy it as soon as they see the barrier
// unsealed. Safe to call more than once.
func (s *barrierInitService) release() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.issued != nil {
		s.issued.key.Destroy()
	}
}

// initializeBarrier drives the data-plane barrier after the ceremony and
// records the resulting state in resp.
//
// The qrdb ceremony service does not initialize the StorageBarrier as a side
// effect — it only stores PINs in the credential service and transitions its
// own state machine. The barrier must be initialized explicitly so the
// BarrierServicer (which the waitForUnseal loop polls) reports initialized +
// unsealed and the gate releases. A barrier failure is returned as
// ErrBarrierInitFailed; the issued bundle stays retained, so an identical
// retry from the issuing uid re-attempts it.
func (s *barrierInitService) initializeBarrier(ctx context.Context, initBarrier barrierInitFunc, req *rest.BarrierInitRequest, resp *rest.BarrierInitResponse) error {
	if s.barrier != nil {
		if !s.barrier.IsInitialized() {
			if err := initBarrier(ctx, s.barrier, req); err != nil {
				return ErrBarrierInitFailed{Cause: err}
			}
		}
		// Refresh the cached flags from the backend. Initialize has already
		// set them, so a failed refresh leaves a correct state to report.
		if err := s.barrier.SyncStatus(ctx); err != nil {
			s.warn("barrier status refresh after init failed; reporting the cached state", err)
		}
	}
	if s.state != nil {
		resp.State = s.state.State(ctx)
	}
	return nil
}

// planBarrierInit returns the barrier operation for strategy and checks that
// req can drive it. A strategy the platform barrier cannot be initialized
// with is a configuration fault and is returned as is; a request that cannot
// drive the operation is refused as rest.ErrInitInvalidRequest.
func planBarrierInit(strategy string, req *rest.BarrierInitRequest) (barrierInitFunc, error) {
	initBarrier, ok := barrierInitStrategies[strategy]
	if !ok {
		return nil, &ErrBarrierStrategyUnsupported{Strategy: strategy}
	}
	if req.UserPIN == "" {
		return nil, &rest.ErrInitInvalidRequest{Err: &ErrBarrierInitMissingSecret{Strategy: strategy}}
	}
	if strategy == barrier.SealStrategyShamir && (req.Threshold < 2 || req.Threshold > req.Shares) {
		return nil, &rest.ErrInitInvalidRequest{Err: &ErrBarrierShamirQuorum{Threshold: req.Threshold, Shares: req.Shares}}
	}
	if err := validateInitOfficers(req); err != nil {
		return nil, &rest.ErrInitInvalidRequest{Err: err}
	}
	return initBarrier, nil
}

// validateInitOfficers checks the officers an /init enrolls before the
// ceremony mints anything. They accompany exactly the M-of-N threshold the
// ceremony receives: one per share, each with a unique username and a CSR
// that parses and verifies, and none when the request carries no threshold.
func validateInitOfficers(req *rest.BarrierInitRequest) error {
	shares := 0
	if formatThreshold(req.Threshold, req.Shares) != "" {
		shares = req.Shares
	}
	if len(req.Officers) != shares {
		return &ErrBarrierInitOfficers{Officers: len(req.Officers), Shares: shares}
	}
	seen := make(map[string]struct{}, len(req.Officers))
	for i, officer := range req.Officers {
		if officer.Username == "" {
			return &ErrBarrierInitOfficerInvalid{Index: i, Reason: "missing username"}
		}
		if _, duplicate := seen[officer.Username]; duplicate {
			return &ErrBarrierInitOfficerInvalid{Index: i, Username: officer.Username, Reason: "duplicate username"}
		}
		seen[officer.Username] = struct{}{}
		if err := verifyOfficerCSR(officer.CSRPEM); err != nil {
			return &ErrBarrierInitOfficerInvalid{Index: i, Username: officer.Username, Reason: "unusable csr_pem", Err: err}
		}
	}
	return nil
}

// verifyOfficerCSR reports whether csrPEM holds a certificate signing request
// whose signature verifies, the precondition the ceremony checks before it
// signs the officer's certificate.
func verifyOfficerCSR(csrPEM string) error {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return &ErrBarrierInitOfficerCSRNotPEM{}
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return err
	}
	return csr.CheckSignature()
}

// resolveBarrierStrategy returns the barrier strategy /init initializes: the
// configured barrier.seal_strategy, else barrier.DefaultSealStrategy.
func (s *barrierInitService) resolveBarrierStrategy() string {
	return firstNonEmpty(s.defaultStrategy, barrier.DefaultSealStrategy)
}

// requireQuorumBarrier refuses a shamir request unless the platform barrier,
// as reported by the SDK's barrier status, is sealed by the Shamir strategy.
// Any other barrier would run InitializeShamir in credential mode and let one
// operator unseal with the user PIN alone. A status that cannot be read
// refuses too: the quorum is never assumed.
func (s *barrierInitService) requireQuorumBarrier(ctx context.Context, strategy string) error {
	if strategy != barrier.SealStrategyShamir {
		return nil
	}
	if s.barrier == nil {
		return &ErrBarrierShamirUnenforceable{}
	}
	status, err := s.barrier.Status(ctx)
	if err != nil {
		return &ErrBarrierStatusUnavailable{Err: err}
	}
	if status == nil || status.Strategy != barrier.SealStrategyShamir {
		registered := ""
		if status != nil {
			registered = status.Strategy
		}
		return &ErrBarrierShamirUnenforceable{Registered: registered}
	}
	return nil
}

func (s *barrierInitService) warn(msg string, err error) {
	if s.logger != nil {
		s.logger.Warn(msg, "error", err.Error())
	}
}

// =============================================================================
// Unseal service (POST /unseal)
// =============================================================================

// barrierUnsealService implements rest.BarrierUnsealService by delegating to
// the platform's barrier.Manager. Either Secret (single-key) or Share
// (Shamir, multi-step) must be provided; the manager tracks quorum progress
// internally.
type barrierUnsealService struct {
	barrier gateBarrier
	state   rest.PlatformStateProvider
}

// Unseal submits a single secret or share toward the unseal threshold.
func (s *barrierUnsealService) Unseal(ctx context.Context, req *rest.BarrierUnsealRequest) (*rest.BarrierUnsealResponse, error) {
	if s == nil || s.barrier == nil {
		return nil, &rest.ErrBarrierUnsealServiceUnavailable{}
	}
	if req == nil || (req.Secret == "" && req.Share == "") {
		return nil, rest.ErrMissingRequiredField{Field: "secret or share"}
	}
	resp := &rest.BarrierUnsealResponse{}
	switch {
	case req.Secret != "":
		if err := s.barrier.Unseal(ctx, req.Secret); err != nil {
			return nil, err
		}
		resp.Sealed = false
	case req.Share != "":
		shareResp, err := s.barrier.UnsealWithShare(ctx, req.Share)
		if err != nil {
			return nil, err
		}
		if shareResp != nil {
			resp.Sealed = !shareResp.Complete
			resp.SharesProvided = shareResp.Submitted
			resp.Required = shareResp.Required
		}
	}
	if s.state != nil {
		resp.State = s.state.State(ctx)
	}
	return resp, nil
}

// =============================================================================
// Init-only mode runner
// =============================================================================

// barrierGateConfig captures the dependencies required to run the
// init-only mode listener and the unseal-wait loop.
type barrierGateConfig struct {
	socketPath string
	httpAddr   string
	pollEvery  time.Duration
}

// defaultBarrierGateConfig returns sensible defaults aligned with the
// canonical port assignments documented in CLAUDE.md.
func defaultBarrierGateConfig() barrierGateConfig {
	return barrierGateConfig{
		socketPath: "/run/platformd.sock",
		httpAddr:   apidaemon.DefaultInitOnlyHTTPAddr,
		pollEvery:  time.Second,
	}
}

// initOnlyGate is the function invoked by the daemon entry points to run
// the M6 barrier-unseal gate. Production code points it at
// runInitOnlyMode; tests substitute a fake to assert the gate is invoked
// in both runWithWebservices and runDaemonOnly without standing up an
// actual listener.
var initOnlyGate = runInitOnlyMode

// invokeBarrierGate is the single call site used by both runWithWebservices
// and runDaemonOnly to run the M6 init-only mode gate. It builds the gate
// config from the package-level CLI flags (so the gate binds the same
// Unix socket path the production daemon will reuse) and dispatches via
// the initOnlyGate hook. Returning early from the caller on a non-nil
// error keeps production listeners gated until the barrier is unsealed.
func invokeBarrierGate(ctx context.Context, a *app.App, logger *logging.Logger) error {
	gateCfg := defaultBarrierGateConfig()
	gateCfg.socketPath = serveSocketPath
	return initOnlyGate(ctx, a, logger, gateCfg)
}

// runInitOnlyMode binds the Unix socket and a 127.0.0.1 loopback HTTP
// listener that serves only /healthz + /init + /unseal. The function
// blocks until the barrier transitions to unsealed (state machine reports
// sealed=false, initialized=true) or ctx is cancelled. Once the barrier
// is unsealed the listeners are torn down so the caller can bind the
// production transports.
//
// This is the M6 gate: remote transports are NOT bound while this runs.
func runInitOnlyMode(ctx context.Context, a *app.App, logger *logging.Logger, gateCfg barrierGateConfig) error {
	if a == nil {
		return ErrBarrierGateRequiresApp{}
	}

	gate := gateBarrierOf(a)
	stateProvider := &barrierStateProvider{barrier: gate}

	// Wire init service when the SDK client is available. When the SDK
	// client is missing we still start the listener so /healthz works,
	// but /init returns 503 ErrBarrierInitServiceUnavailable.
	var initSvc rest.BarrierInitService
	if sdk := a.QuicBaaSSDKClient(); sdk != nil {
		admin := appbackends.NewAdminBundleIssuer(appbackends.PlatformCertIssuer(a.CA, sdk), appbackends.PlatformAdminIdentity(a))
		backend := appbackends.NewCeremonyBackend(logger, sdk, admin)
		issuer := &barrierInitService{
			logger:  logger,
			backend: backend,
			barrier: gate,
			state:   stateProvider,
		}
		if a.BarrierConfig != nil {
			issuer.defaultStrategy = a.BarrierConfig.SealStrategy
		}
		// The admin key must not outlive the gate, whichever way it exits.
		defer issuer.release()
		initSvc = issuer
	}

	// Wire unseal service when the barrier manager is available. The
	// manager is always present once App.initBarrier() returned ok, but
	// we tolerate its absence so the gate can also surface a useful
	// /healthz when the platform is misconfigured.
	var unsealSvc rest.BarrierUnsealService
	if gate != nil {
		unsealSvc = &barrierUnsealService{
			barrier: gate,
			state:   stateProvider,
		}
	}

	srv, err := apidaemon.NewInitOnlyServer(apidaemon.InitOnlyConfig{
		SocketPath:     gateCfg.socketPath,
		HTTPListenAddr: gateCfg.httpAddr,
		State:          stateProvider,
		Init:           initSvc,
		Unseal:         unsealSvc,
		Logger:         logger,
	})
	if err != nil {
		return err
	}
	if err := srv.Start(ctx); err != nil {
		return err
	}
	logger.Info("init-only mode bound; remote transports gated until barrier unseal",
		"unix_socket", gateCfg.socketPath,
		"http_loopback", srv.HTTPListenAddr())

	// Block until the barrier reaches the unsealed state, the context is
	// cancelled, or the initial state was already unsealed.
	waitErr := waitForUnseal(ctx, a, logger, gateCfg.pollEvery)

	// Always tear down the init-only listeners regardless of the wait
	// outcome; the caller will either return (on cancel/error) or bind
	// the production transports next.
	if stopErr := srv.Stop(ctx); stopErr != nil {
		logger.Warn("init-only mode shutdown returned error", "error", stopErr.Error())
	}
	if waitErr != nil {
		return waitErr
	}
	logger.Info("barrier unsealed; init-only mode released, production transports may bind now")
	return nil
}

// waitForUnseal blocks until the barrier reports unsealed (initialized=true,
// sealed=false), or ctx is cancelled. It races the manager's WaitReady
// signal (instant for local unseals) against a polling ticker (catches
// /init transitioning us from uninitialized to sealed, plus external
// unseals from peer nodes that the local manager only learns about via
// SyncStatus). No time.Sleep is used.
func waitForUnseal(ctx context.Context, a *app.App, logger *logging.Logger, pollEvery time.Duration) error {
	if a == nil {
		return ErrBarrierGateRequiresApp{}
	}
	mgr := a.Barrier()
	if mgr == nil {
		// No manager: nothing to wait for. Treat as ready.
		return nil
	}
	if !mgr.IsSealed() && mgr.IsInitialized() {
		// Already unsealed.
		return nil
	}

	if pollEvery <= 0 {
		pollEvery = time.Second
	}

	// Run WaitReady in a goroutine so we can multiplex its completion
	// with the polling ticker via select. WaitReady's own context guards
	// goroutine lifetime so cancellation propagates correctly.
	readyCtx, cancelReady := context.WithCancel(ctx)
	defer cancelReady()
	readyCh := make(chan struct{}, 1)
	go func() {
		if err := mgr.WaitReady(readyCtx); err == nil {
			select {
			case readyCh <- struct{}{}:
			default:
			}
		}
	}()

	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-readyCh:
			// Successful local unseal — manager closed its ready channel.
			return nil
		case <-ticker.C:
			if syncErr := mgr.SyncStatus(ctx); syncErr != nil {
				logger.Debug("waitForUnseal: SyncStatus failed; will retry",
					"error", syncErr.Error())
				continue
			}
			if mgr.IsInitialized() && !mgr.IsSealed() {
				return nil
			}
		}
	}
}

// =============================================================================
// helpers
// =============================================================================

// formatThreshold renders a Shamir threshold pair into the "M-of-N" string
// expected by the CeremonyService Threshold field.
func formatThreshold(threshold, shares int) string {
	if threshold <= 0 || shares <= 0 {
		return ""
	}
	return formatInt(threshold) + "-of-" + formatInt(shares)
}

// formatInt is a small allocation-free integer formatter for the
// Shamir threshold rendering. Avoids pulling in fmt for a hot path
// that runs once per /init.
func formatInt(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
