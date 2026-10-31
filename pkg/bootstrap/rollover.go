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

package bootstrap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"sync/atomic"
	"time"

	dnsconfig "github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// RolloverPhase represents the current phase of a DANE-EE TLSA rollover.
type RolloverPhase uint32

const (
	// RolloverIdle indicates no rollover is in progress.
	RolloverIdle RolloverPhase = iota
	// RolloverPrePublish indicates the new TLSA record has been published alongside the old.
	RolloverPrePublish
	// RolloverActivated indicates the new certificate is active and old TLSA is draining.
	RolloverActivated
	// RolloverComplete indicates cleanup is done and the manager is returning to idle.
	RolloverComplete
)

// RolloverManager coordinates DANE-EE TLSA record rollover during certificate renewal.
// It implements RFC 7671 Section 8.1 pre-publication rollover using channel-based
// timing instead of time.Sleep.
type RolloverManager struct {
	publisher *DANEPublisher
	reloader  *CertReloader
	config    *dnsconfig.DANEConfig
	phase     atomic.Uint32
	doneChan  chan struct{}
	// failure is written before doneChan closes and read by Wait after it,
	// so the channel close orders the two.
	failure error
	logger  *logging.Logger
}

// NewRolloverManager creates a RolloverManager with the given publisher, certificate
// reloader, DANE configuration, and logger.
func NewRolloverManager(
	publisher *DANEPublisher,
	reloader *CertReloader,
	config *dnsconfig.DANEConfig,
	logger *logging.Logger,
) *RolloverManager {

	return &RolloverManager{
		publisher: publisher,
		reloader:  reloader,
		config:    config,
		doneChan:  make(chan struct{}),
		logger:    logger,
	}
}

// BeginRollover starts a DANE-EE TLSA rollover for the given new certificate.
// If a rollover is already in progress, it returns ErrRolloverInProgress. When
// config.KeyReuse is true (Selector=1/SPKI unchanged), the rollover completes
// immediately by reloading the certificate and updating the TLSA record. When
// key rotation is involved, it pre-publishes the new TLSA record, waits for
// DNS cache expiry (2xTTL), then activates the new certificate and cleans up.
func (m *RolloverManager) BeginRollover(
	ctx context.Context,
	newCert *x509.Certificate,
	newTLSCert *tls.Certificate,
	hostname string,
	port uint16,
	zoneName string,
) error {

	if RolloverPhase(m.phase.Load()) != RolloverIdle {
		return ErrRolloverInProgress{Hostname: hostname}
	}

	m.doneChan = make(chan struct{})
	m.failure = nil

	if m.config.KeyReuse {
		return m.immediateRollover(ctx, newCert, newTLSCert, hostname, port, zoneName)
	}

	if err := m.publisher.PrePublishRollover(ctx, newCert, hostname, port, zoneName); err != nil {
		return err
	}
	m.phase.Store(uint32(RolloverPrePublish))

	m.logger.Info(
		"DANE-EE TLSA rollover started: pre-publish phase",
		slog.String("hostname", hostname),
		slog.Int("port", int(port)),
		slog.String("zone", zoneName),
		slog.Duration("delay", m.rolloverDelay()),
	)

	go m.runRollover(ctx, newCert, newTLSCert, hostname, port, zoneName)

	return nil
}

// Phase returns the current rollover phase atomically.
func (m *RolloverManager) Phase() RolloverPhase {
	return RolloverPhase(m.phase.Load())
}

// Wait blocks until the rollover ends or the context is cancelled. It returns
// nil on successful completion, the error that ended a failed rollover, or the
// context error if cancelled.
func (m *RolloverManager) Wait(ctx context.Context) error {
	select {
	case <-m.doneChan:
		return m.failure
	case <-ctx.Done():
		return ctx.Err()
	}
}

// immediateRollover performs an instant rollover for key-reuse scenarios where
// the SPKI hash does not change.
func (m *RolloverManager) immediateRollover(
	ctx context.Context,
	newCert *x509.Certificate,
	newTLSCert *tls.Certificate,
	hostname string,
	port uint16,
	zoneName string,
) error {

	if err := m.reloader.Reload(newTLSCert); err != nil {
		m.finish(err)
		return err
	}

	// Publish the new record before retiring the old ones, so a publish
	// failure never leaves the name without a TLSA record.
	if err := m.publisher.PrePublishRollover(ctx, newCert, hostname, port, zoneName); err != nil {
		m.finish(err)
		return err
	}
	if err := m.publisher.retireForHostname(ctx, newCert, hostname, port, zoneName); err != nil {
		m.logger.Warn("failed to remove old DANE records", slog.String("hostname", hostname), slog.String("error", err.Error()))
	}

	m.logger.Info(
		"DANE-EE TLSA rollover completed immediately (key reuse)",
		slog.String("hostname", hostname),
		slog.Int("port", int(port)),
	)

	m.finish(nil)
	return nil
}

// runRollover executes the timed rollover sequence in a goroutine. It waits for
// the rollover delay using time.After, then activates the new certificate and
// retires the old TLSA records, or withdraws the rollover if activation fails.
func (m *RolloverManager) runRollover(
	ctx context.Context,
	newCert *x509.Certificate,
	newTLSCert *tls.Certificate,
	hostname string,
	port uint16,
	zoneName string,
) {

	delay := m.rolloverDelay()

	select {
	case <-time.After(delay):
		if err := m.activateRollover(newTLSCert, hostname, port); err != nil {
			m.withdrawRollover(ctx, newCert, hostname, port, zoneName, err)
			return
		}
		m.completeRollover(ctx, newCert, hostname, port, zoneName)
	case <-ctx.Done():
		m.logger.Warn(
			"DANE-EE TLSA rollover cancelled",
			slog.String("hostname", hostname),
			slog.String("reason", ctx.Err().Error()),
		)
		m.finish(nil)
	}
}

// activateRollover reloads the new TLS certificate into the CertReloader and
// transitions the phase to RolloverActivated.
func (m *RolloverManager) activateRollover(
	newTLSCert *tls.Certificate,
	hostname string,
	port uint16,
) error {

	if err := m.reloader.Reload(newTLSCert); err != nil {
		m.logger.Error(err, slog.String("hostname", hostname))
		return err
	}

	m.phase.Store(uint32(RolloverActivated))

	m.logger.Info(
		"DANE-EE TLSA rollover: new certificate activated",
		slog.String("hostname", hostname),
		slog.Int("port", int(port)),
	)
	return nil
}

// withdrawRollover ends a rollover whose new certificate could not be
// activated. The server still presents the old certificate, so its records
// stay and the pre-published record for the new certificate is removed.
// Wait returns cause.
func (m *RolloverManager) withdrawRollover(
	ctx context.Context,
	newCert *x509.Certificate,
	hostname string,
	port uint16,
	zoneName string,
	cause error,
) {

	if err := m.publisher.withdrawRollover(ctx, newCert, hostname, port, zoneName); err != nil {
		m.logger.Error(err, slog.String("hostname", hostname))
	}

	m.logger.Warn(
		"DANE-EE TLSA rollover withdrawn",
		slog.String("hostname", hostname),
		slog.Int("port", int(port)),
		slog.String("zone", zoneName),
	)

	m.finish(cause)
}

// completeRollover removes the old TLSA records, keeping the pre-published
// record for newCert, re-signs the zone, and transitions the phase back to idle.
func (m *RolloverManager) completeRollover(
	ctx context.Context,
	newCert *x509.Certificate,
	hostname string,
	port uint16,
	zoneName string,
) {

	m.phase.Store(uint32(RolloverComplete))

	// Retire the old TLSA records for this hostname, keeping the record
	// pre-published for the certificate now being served.
	if err := m.publisher.retireForHostname(ctx, newCert, hostname, port, zoneName); err != nil {
		m.logger.Error(err, slog.String("hostname", hostname))
	}

	m.logger.Info(
		"DANE-EE TLSA rollover completed",
		slog.String("hostname", hostname),
		slog.Int("port", int(port)),
		slog.String("zone", zoneName),
	)

	m.finish(nil)
}

// finish returns the manager to idle and releases Wait, which returns failure.
func (m *RolloverManager) finish(failure error) {
	m.failure = failure
	m.phase.Store(uint32(RolloverIdle))
	close(m.doneChan)
}

// rolloverDelay returns the duration to wait between pre-publish and activation.
// It uses RolloverTTL if configured and non-zero, otherwise 2x DefaultTTL.
func (m *RolloverManager) rolloverDelay() time.Duration {
	if m.config.RolloverTTL > 0 {
		return time.Duration(m.config.RolloverTTL) * time.Second
	}
	return time.Duration(2*m.config.DefaultTTL) * time.Second
}
