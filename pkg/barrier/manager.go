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

package barrier

import (
	"context"
	"log/slog"
	"sync/atomic"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/secure"
)

// Manager provides barrier lifecycle operations for the platform.
// It wraps the go-quicbaas SDK client and tracks barrier state locally
// using atomic booleans for lock-free concurrent reads.
type Manager struct {
	sdk         quicbaassdk.Client
	config      *Config
	logger      *slog.Logger
	initialized atomic.Bool
	sealed      atomic.Bool
	// unsealing records that at least one Shamir share has been accepted
	// toward the threshold since the barrier was last sealed.
	unsealing atomic.Bool
	// ready holds the current ready generation. Seal swaps in a new one;
	// every unseal path opens whichever generation is current.
	ready atomic.Pointer[readyGate]
}

// readyGate is one generation of the ready signal. Its channel is closed
// when the barrier is unsealed, and the CompareAndSwap on opened makes the
// close happen exactly once however many unseal paths signal together.
type readyGate struct {
	ch     chan struct{}
	opened atomic.Bool
}

// newReadyGate returns a generation that has not been opened.
func newReadyGate() *readyGate {
	return &readyGate{ch: make(chan struct{})}
}

// open closes the gate's channel on the first call and does nothing after.
func (g *readyGate) open() {
	if g.opened.CompareAndSwap(false, true) {
		close(g.ch)
	}
}

// NewManager creates a new barrier Manager backed by the given SDK client.
// It queries the barrier status to set the initial sealed/initialized state.
func NewManager(sdk quicbaassdk.Client, config *Config, logger *slog.Logger) (*Manager, error) {
	if sdk == nil {
		return nil, ErrNilSDKClient
	}
	if config == nil {
		return nil, ErrNilConfig
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}

	m := &Manager{
		sdk:    sdk,
		config: config,
		logger: logger,
	}
	m.ready.Store(newReadyGate())

	// Default to sealed until status is checked.
	m.sealed.Store(true)

	return m, nil
}

// SyncStatus queries the SDK for the current barrier status and updates
// the local atomic state. This should be called after the QRDB client
// is available.
func (m *Manager) SyncStatus(ctx context.Context) error {
	if ctx == nil {
		return ErrNilContext
	}

	status, err := m.barrierStatus(ctx)
	if err != nil {
		return &ManagerError{Op: "SyncStatus", Err: err}
	}

	// A non-empty InitializedAt is the canonical signal the underlying
	// StorageBarrier has been initialized. A fresh barrier returns
	// Sealed=true with an empty InitializedAt; without this distinction
	// the M6 gate misreports the platform state as "sealed" instead of
	// "uninitialized" right after boot.
	m.initialized.Store(status.InitializedAt != "")
	m.sealed.Store(status.Sealed)

	if !status.Sealed {
		m.unsealing.Store(false)
		m.signalReady()
	}

	m.logger.Info("Barrier status synced",
		slog.Bool("sealed", status.Sealed),
		slog.String("strategy", status.Strategy),
		slog.Bool("hardware_backed", status.HardwareBacked))

	return nil
}

// Initialize initializes the barrier with a single master key.
func (m *Manager) Initialize(ctx context.Context, secret string) error {
	if ctx == nil {
		return ErrNilContext
	}
	if secret == "" {
		return ErrEmptySecret
	}
	if m.initialized.Load() {
		return ErrAlreadyInitialized
	}

	barrierClient, err := m.barrierClient()
	if err != nil {
		return &ManagerError{Op: "Initialize", Err: err}
	}

	req := &quicbaassdk.QRDBBarrierInitializeRequest{
		Secret: secretBytes(secret),
	}
	defer secure.Wipe(req.Secret)
	if err := barrierClient.BarrierInitialize(ctx, req); err != nil {
		return &ManagerError{Op: "Initialize", Err: err}
	}

	m.initialized.Store(true)
	m.sealed.Store(false)
	m.signalReady()

	m.logger.Info("Barrier initialized",
		slog.String("strategy", m.config.SealStrategy))

	return nil
}

// InitializeShamir initializes the barrier using Shamir secret sharing.
// It returns the generated key shares that must be distributed to custodians.
func (m *Manager) InitializeShamir(ctx context.Context, secret string, threshold, shares int) (*quicbaassdk.QRDBBarrierInitializeShamirResponse, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if secret == "" {
		return nil, ErrEmptySecret
	}
	if err := ValidateShamirSplit(threshold, shares); err != nil {
		return nil, err
	}
	if m.initialized.Load() {
		return nil, ErrAlreadyInitialized
	}

	barrierClient, err := m.barrierClient()
	if err != nil {
		return nil, &ManagerError{Op: "InitializeShamir", Err: err}
	}

	req := &quicbaassdk.QRDBBarrierInitializeShamirRequest{
		Secret:      secretBytes(secret),
		Threshold:   threshold,
		TotalShares: shares,
	}
	defer secure.Wipe(req.Secret)
	resp, err := barrierClient.BarrierInitializeShamir(ctx, req)
	if err != nil {
		return nil, &ManagerError{Op: "InitializeShamir", Err: err}
	}

	m.initialized.Store(true)
	m.sealed.Store(false)
	m.signalReady()

	m.logger.Info("Barrier initialized with Shamir secret sharing",
		slog.Int("threshold", threshold),
		slog.Int("shares", shares))

	return resp, nil
}

// Unseal unseals the barrier using the master key.
func (m *Manager) Unseal(ctx context.Context, secret string) error {
	if ctx == nil {
		return ErrNilContext
	}
	if secret == "" {
		return ErrEmptySecret
	}
	if !m.sealed.Load() {
		return ErrNotSealed
	}

	barrierClient, err := m.barrierClient()
	if err != nil {
		return &ManagerError{Op: "Unseal", Err: err}
	}

	req := &quicbaassdk.QRDBBarrierUnsealRequest{
		Secret: secretBytes(secret),
	}
	defer secure.Wipe(req.Secret)
	if err := barrierClient.BarrierUnseal(ctx, req); err != nil {
		return &ManagerError{Op: "Unseal", Err: err}
	}

	m.sealed.Store(false)
	m.signalReady()

	m.logger.Info("Barrier unsealed")

	return nil
}

// UnsealWithShare submits a single Shamir share toward the unseal threshold.
// It returns the current progress toward the required threshold.
func (m *Manager) UnsealWithShare(ctx context.Context, share string) (*quicbaassdk.QRDBBarrierUnsealShareResponse, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if share == "" {
		return nil, ErrEmptyShare
	}

	barrierClient, err := m.barrierClient()
	if err != nil {
		return nil, &ManagerError{Op: "UnsealWithShare", Err: err}
	}

	req := &quicbaassdk.QRDBBarrierUnsealShareRequest{
		Share: share,
	}
	resp, err := barrierClient.BarrierUnsealWithShare(ctx, req)
	if err != nil {
		return nil, &ManagerError{Op: "UnsealWithShare", Err: err}
	}

	if resp.Complete {
		m.sealed.Store(false)
		m.unsealing.Store(false)
		m.signalReady()
		m.logger.Info("Barrier unsealed via Shamir shares")
	} else {
		m.unsealing.Store(resp.Submitted > 0)
		m.logger.Info("Barrier unseal share submitted",
			slog.Int("submitted", resp.Submitted),
			slog.Int("required", resp.Required))
	}

	return resp, nil
}

// Seal seals the barrier, preventing further data access until it is
// unsealed again.
func (m *Manager) Seal(ctx context.Context) error {
	if ctx == nil {
		return ErrNilContext
	}
	if m.sealed.Load() {
		return ErrSealed
	}

	barrierClient, err := m.barrierClient()
	if err != nil {
		return &ManagerError{Op: "Seal", Err: err}
	}

	if err := barrierClient.BarrierSeal(ctx); err != nil {
		return &ManagerError{Op: "Seal", Err: err}
	}

	// Mark the barrier sealed before starting the new ready generation. If an
	// unseal lands between the two, the manager reports unsealed with an
	// unopened gate, so a waiter blocks until the next signal; the other order would
	// let a waiter through while the barrier reports sealed.
	m.sealed.Store(true)
	m.unsealing.Store(false)
	m.ready.Store(newReadyGate())

	m.logger.Info("Barrier sealed")

	return nil
}

// Status returns the current barrier status from the SDK.
func (m *Manager) Status(ctx context.Context) (*quicbaassdk.QRDBBarrierStatusResponse, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	status, err := m.barrierStatus(ctx)
	if err != nil {
		return nil, &ManagerError{Op: "Status", Err: err}
	}

	return status, nil
}

// Rekey generates new Shamir shares with the specified threshold and total
// count, replacing the existing shares.
func (m *Manager) Rekey(ctx context.Context, threshold, total int) (*quicbaassdk.QRDBBarrierRekeyResponse, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if err := ValidateShamirSplit(threshold, total); err != nil {
		return nil, err
	}
	if m.sealed.Load() {
		return nil, ErrSealed
	}

	barrierClient, err := m.barrierClient()
	if err != nil {
		return nil, &ManagerError{Op: "Rekey", Err: err}
	}

	req := &quicbaassdk.QRDBBarrierRekeyRequest{
		Threshold: threshold,
		Total:     total,
	}
	resp, err := barrierClient.BarrierRekey(ctx, req)
	if err != nil {
		return nil, &ManagerError{Op: "Rekey", Err: err}
	}

	m.logger.Info("Barrier rekeyed",
		slog.Int("threshold", threshold),
		slog.Int("total", total))

	return resp, nil
}

// CeremonyInitialize starts the M-of-N officer enrollment ceremony. It
// delegates to the go-quicbaas SDK ceremony client and maps the response
// to platform-level types.
func (m *Manager) CeremonyInitialize(ctx context.Context, config *CeremonyConfig) (*CeremonyInitResult, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if config == nil {
		return nil, ErrNilConfig
	}
	if !m.config.RequiresCeremony() {
		return nil, ErrCeremonyNotSupported
	}

	ceremonyClient, err := m.ceremonyClient()
	if err != nil {
		return nil, &ManagerError{Op: "CeremonyInitialize", Err: err}
	}

	officers := make([]quicbaassdk.QRDBCeremonyOfficerRequest, len(config.Officers))
	for i, o := range config.Officers {
		officers[i] = quicbaassdk.QRDBCeremonyOfficerRequest{
			Username: o.Username,
			CSRPEM:   string(o.CSRPEM),
		}
	}

	req := &quicbaassdk.QRDBCeremonyInitializeRequest{
		SOPin:     config.SOPin,
		UserPin:   config.UserPin,
		Threshold: config.Threshold,
		Officers:  officers,
	}
	resp, err := ceremonyClient.CeremonyInitialize(ctx, req)
	if err != nil {
		return nil, &ManagerError{Op: "CeremonyInitialize", Err: err}
	}

	m.logger.Info("Barrier ceremony initialized",
		slog.Int("threshold", config.Threshold),
		slog.Int("officers", len(config.Officers)),
		slog.String("state", resp.State))

	return &CeremonyInitResult{
		SPKIPin:    resp.SPKIPin,
		CACertPEM:  resp.CACertPEM,
		TLSCertPEM: resp.TLSCertPEM,
		State:      resp.State,
		ShareCount: resp.ShareCount,
	}, nil
}

// CeremonyStatus returns the current ceremony state.
func (m *Manager) CeremonyStatus(ctx context.Context) (*CeremonyStatusInfo, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	ceremonyClient, err := m.ceremonyClient()
	if err != nil {
		return nil, &ManagerError{Op: "CeremonyStatus", Err: err}
	}

	resp, err := ceremonyClient.CeremonyStatus(ctx)
	if err != nil {
		return nil, &ManagerError{Op: "CeremonyStatus", Err: err}
	}

	return &CeremonyStatusInfo{
		State:   resp.State,
		SPKIPin: resp.SPKIPin,
	}, nil
}

// BeginClaimCert initiates the challenge-response for a named officer.
// The returned nonce must be signed by the officer's CSR private key and
// submitted to CompleteClaimCert.
func (m *Manager) BeginClaimCert(ctx context.Context, username string) (*CeremonyChallenge, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if username == "" {
		return nil, ErrEmptyUsername
	}

	ceremonyClient, err := m.ceremonyClient()
	if err != nil {
		return nil, &ManagerError{Op: "BeginClaimCert", Err: err}
	}

	req := &quicbaassdk.QRDBClaimCertBeginRequest{Username: username}
	resp, err := ceremonyClient.CeremonyClaimCertBegin(ctx, req)
	if err != nil {
		return nil, &ManagerError{Op: "BeginClaimCert", Err: err}
	}

	m.logger.Info("Ceremony claim cert challenge issued",
		slog.String("username", username),
		slog.String("expires_at", resp.ExpiresAt))

	return &CeremonyChallenge{
		NonceHex:  resp.NonceHex,
		ExpiresAt: resp.ExpiresAt,
	}, nil
}

// CompleteClaimCert verifies the officer's signed nonce and issues their
// certificate. The signature must be produced over the nonce bytes using
// the private key corresponding to the CSR submitted during initialization.
func (m *Manager) CompleteClaimCert(ctx context.Context, username, nonceHex string, signature []byte) (*CeremonyClaimCertResult, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if username == "" {
		return nil, ErrEmptyUsername
	}
	if nonceHex == "" {
		return nil, ErrEmptyNonce
	}
	if len(signature) == 0 {
		return nil, ErrEmptySignature
	}

	ceremonyClient, err := m.ceremonyClient()
	if err != nil {
		return nil, &ManagerError{Op: "CompleteClaimCert", Err: err}
	}

	req := &quicbaassdk.QRDBClaimCertCompleteRequest{
		Username:  username,
		NonceHex:  nonceHex,
		Signature: string(signature),
	}
	resp, err := ceremonyClient.CeremonyClaimCertComplete(ctx, req)
	if err != nil {
		return nil, &ManagerError{Op: "CompleteClaimCert", Err: err}
	}

	m.logger.Info("Ceremony cert claimed",
		slog.String("username", username))

	return &CeremonyClaimCertResult{
		CertPEM:   resp.CertPEM,
		CACertPEM: resp.CACertPEM,
	}, nil
}

// BeginClaimShare initiates the challenge-response for a named officer's
// Shamir share claim. The returned nonce must be signed by the private key
// matching the officer's claimed certificate and submitted to
// CompleteClaimShare.
func (m *Manager) BeginClaimShare(ctx context.Context, username string) (*CeremonyChallenge, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if username == "" {
		return nil, ErrEmptyUsername
	}

	ceremonyClient, err := m.ceremonyClient()
	if err != nil {
		return nil, &ManagerError{Op: "BeginClaimShare", Err: err}
	}

	req := &quicbaassdk.QRDBBeginClaimShareRequest{Username: username}
	resp, err := ceremonyClient.CeremonyBeginClaimShare(ctx, req)
	if err != nil {
		return nil, &ManagerError{Op: "BeginClaimShare", Err: err}
	}

	m.logger.Info("Ceremony claim share challenge issued",
		slog.String("username", username),
		slog.String("expires_at", resp.ExpiresAt))

	return &CeremonyChallenge{
		NonceHex:  resp.NonceHex,
		ExpiresAt: resp.ExpiresAt,
	}, nil
}

// CompleteClaimShare verifies the officer's signed nonce and returns the
// officer's Shamir share JSON. The signature must be produced over the nonce
// bytes using the private key matching the officer's claimed certificate.
// The share is destroyed on the server after retrieval and must be securely
// stored by the officer.
func (m *Manager) CompleteClaimShare(ctx context.Context, username, nonceHex string, signature []byte) ([]byte, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if username == "" {
		return nil, ErrEmptyUsername
	}
	if nonceHex == "" {
		return nil, ErrEmptyNonce
	}
	if len(signature) == 0 {
		return nil, ErrEmptySignature
	}

	ceremonyClient, err := m.ceremonyClient()
	if err != nil {
		return nil, &ManagerError{Op: "CompleteClaimShare", Err: err}
	}

	req := &quicbaassdk.QRDBCompleteClaimShareRequest{
		Username:  username,
		NonceHex:  nonceHex,
		Signature: signature,
	}
	resp, err := ceremonyClient.CeremonyCompleteClaimShare(ctx, req)
	if err != nil {
		return nil, &ManagerError{Op: "CompleteClaimShare", Err: err}
	}

	m.logger.Info("Ceremony share claimed",
		slog.String("username", username))

	return []byte(resp.ShareJSON), nil
}

// ceremonyClient returns the QRDB CeremonyClient from the SDK.
func (m *Manager) ceremonyClient() (quicbaassdk.QRDBCeremonyClient, error) {
	return m.sdk.Security().Ceremony()
}

// WaitReady blocks until the barrier is unsealed or the context is cancelled.
func (m *Manager) WaitReady(ctx context.Context) error {
	if ctx == nil {
		return ErrNilContext
	}
	select {
	case <-m.ready.Load().ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// IsSealed returns true if the barrier is currently sealed.
func (m *Manager) IsSealed() bool {
	return m.sealed.Load()
}

// IsUnsealing returns true while the barrier is sealed and at least one
// Shamir share has been accepted toward the unseal threshold.
func (m *Manager) IsUnsealing() bool {
	return m.sealed.Load() && m.unsealing.Load()
}

// IsInitialized returns true if the barrier has been initialized.
func (m *Manager) IsInitialized() bool {
	return m.initialized.Load()
}

// Config returns the barrier configuration.
func (m *Manager) Config() *Config {
	return m.config
}

// barrierClient returns the QRDB BarrierClient from the SDK.
func (m *Manager) barrierClient() (quicbaassdk.QRDBBarrierClient, error) {
	return m.sdk.Security().Barrier()
}

// barrierStatus queries the barrier status via the SDK.
func (m *Manager) barrierStatus(ctx context.Context) (*quicbaassdk.QRDBBarrierStatusResponse, error) {
	barrierClient, err := m.barrierClient()
	if err != nil {
		return nil, err
	}
	return barrierClient.BarrierStatus(ctx)
}

// signalReady opens the current ready generation. It is safe to call from
// any number of goroutines at once.
func (m *Manager) signalReady() {
	m.ready.Load().open()
}

// secretBytes copies a credential into a slice the request can carry and the
// caller can wipe. go-qrdb#184 typed these request fields []byte precisely so
// the copy is destroyable; the Manager's own parameter is still a string,
// because the secret reaches it from a decoded request DTO and is therefore
// already an unwipeable Go string by then. Converting here bounds what this
// package adds rather than claiming the residue is gone.
func secretBytes(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
}
