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
	ready       chan struct{}
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
		ready:  make(chan struct{}),
	}

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

	m.initialized.Store(true)
	m.sealed.Store(status.Sealed)

	if !status.Sealed {
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
		Secret: secret,
	}
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
	if threshold < 1 || shares < 1 || threshold > shares {
		return nil, ErrInvalidThreshold
	}
	if m.initialized.Load() {
		return nil, ErrAlreadyInitialized
	}

	barrierClient, err := m.barrierClient()
	if err != nil {
		return nil, &ManagerError{Op: "InitializeShamir", Err: err}
	}

	req := &quicbaassdk.QRDBBarrierInitializeShamirRequest{
		Secret:      secret,
		Threshold:   threshold,
		TotalShares: shares,
	}
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
		Secret: secret,
	}
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
		m.signalReady()
		m.logger.Info("Barrier unsealed via Shamir shares")
	} else {
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

	m.sealed.Store(true)

	// Reset the ready channel so WaitReady blocks again.
	m.ready = make(chan struct{})

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
	if threshold < 1 || total < 1 || threshold > total {
		return nil, ErrInvalidThreshold
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
		SOCertPEM:  resp.SOCertPEM,
		SOKeyPEM:   resp.SOKeyPEM,
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

// ClaimShare returns the officer's Shamir share. The share is destroyed on
// the server after retrieval and must be securely stored by the officer.
func (m *Manager) ClaimShare(ctx context.Context, username string) ([]byte, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if username == "" {
		return nil, ErrEmptyUsername
	}

	ceremonyClient, err := m.ceremonyClient()
	if err != nil {
		return nil, &ManagerError{Op: "ClaimShare", Err: err}
	}

	req := &quicbaassdk.QRDBClaimShareRequest{Username: username}
	resp, err := ceremonyClient.CeremonyClaimShare(ctx, req)
	if err != nil {
		return nil, &ManagerError{Op: "ClaimShare", Err: err}
	}

	m.logger.Info("Ceremony share claimed",
		slog.String("username", username))

	return []byte(resp.ShareJSON), nil
}

// ceremonyClient returns the QRDB CeremonyClient from the SDK.
func (m *Manager) ceremonyClient() (quicbaassdk.QRDBCeremonyClient, error) {
	return m.sdk.BarrierCeremony()
}

// WaitReady blocks until the barrier is unsealed or the context is cancelled.
func (m *Manager) WaitReady(ctx context.Context) error {
	if ctx == nil {
		return ErrNilContext
	}
	select {
	case <-m.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// IsSealed returns true if the barrier is currently sealed.
func (m *Manager) IsSealed() bool {
	return m.sealed.Load()
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
	return m.sdk.Barrier()
}

// barrierStatus queries the barrier status via the SDK.
func (m *Manager) barrierStatus(ctx context.Context) (*quicbaassdk.QRDBBarrierStatusResponse, error) {
	barrierClient, err := m.barrierClient()
	if err != nil {
		return nil, err
	}
	return barrierClient.BarrierStatus(ctx)
}

// signalReady signals the ready channel if it has not been signaled already.
func (m *Manager) signalReady() {
	select {
	case <-m.ready:
		// Already closed / signaled.
	default:
		close(m.ready)
	}
}
