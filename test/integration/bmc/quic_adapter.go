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

// This file implements the BMCCommands interface using the QUIC protocol.
// Non-enrollment BMC operations are not yet wired to the QUIC transport layer;
// Setup returns ErrQUICNotImplemented for those paths. EnrollBMC and RestoreBMC
// are fully implemented via the OpBMCCategory category opcode pattern.

//go:build integration

package bmc_integration

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
)

const (
	defaultQUICBMCTimeout     = 30 * time.Second
	defaultQUICBMCIdleTimeout = 60 * time.Second
)

// =============================================================================
// QUIC Protocol Adapter
// =============================================================================

// QUICAdapter implements BMCCommands using the QUIC protocol. Non-enrollment
// BMC operations (power, boot, media, sensors, etc.) are not yet wired to the
// QUIC transport; Setup returns ErrQUICNotImplemented so the test runner skips
// those subtests gracefully. EnrollBMC and RestoreBMC are fully implemented
// via the category-opcode pattern (OpBMCCategory / BMCSubEnroll, BMCSubRestore).
type QUICAdapter struct {
	endpoint  string
	tlsConfig *tls.Config

	mu     sync.RWMutex
	conn   *quicgo.Conn
	closed bool
}

// NewQUICAdapter creates a new QUIC adapter for BMC integration testing.
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{
		tlsConfig: helpers.QUICTLSConfig([]string{"platform-quic"}),
	}
}

// Name returns the protocol adapter identifier.
func (q *QUICAdapter) Name() string {
	return "QUIC"
}

// Setup returns ErrQUICNotImplemented because the general BMC service is not
// yet exposed over the QUIC transport. Enrollment and restore via EnrollBMC /
// RestoreBMC are available independently once the connection is established.
func (q *QUICAdapter) Setup(ctx context.Context) error {
	return ErrQUICNotImplemented{}
}

// Teardown closes the QUIC connection if one was established.
func (q *QUICAdapter) Teardown() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.conn == nil {
		return nil
	}
	q.closed = true
	return q.conn.CloseWithError(0, "adapter teardown")
}

// dial establishes the QUIC connection lazily. It is called by operations
// that need the connection rather than by Setup, because Setup signals
// "not implemented" for the general BMC QUIC surface.
func (q *QUICAdapter) dial(ctx context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return ErrQUICConnectionFailed{Endpoint: q.endpoint, Err: fmt.Errorf("adapter closed")}
	}
	if q.conn != nil {
		return nil
	}
	endpoint := os.Getenv(EnvPlatformQUICEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformQUIC
	}
	q.endpoint = endpoint

	dialCtx, cancel := context.WithTimeout(ctx, defaultQUICBMCTimeout)
	defer cancel()
	conn, err := quicgo.DialAddr(dialCtx, endpoint, q.tlsConfig, &quicgo.Config{
		MaxIdleTimeout:  defaultQUICBMCIdleTimeout,
		KeepAlivePeriod: 15 * time.Second,
	})
	if err != nil {
		return ErrQUICConnectionFailed{Endpoint: endpoint, Err: err}
	}
	q.conn = conn
	return nil
}

// sendBMCSub issues a BMC category request with the given sub-opcode prefix
// byte. The body (if non-nil) is MessagePack-encoded and appended after the
// sub-opcode. The response payload is MessagePack-decoded into out (if non-nil).
func (q *QUICAdapter) sendBMCSub(ctx context.Context, sub byte, in interface{}, out interface{}) error {
	if err := q.dial(ctx); err != nil {
		return err
	}

	q.mu.RLock()
	conn := q.conn
	q.mu.RUnlock()

	var body []byte
	if in != nil {
		encoded, err := quic.EncodePayload(in)
		if err != nil {
			return fmt.Errorf("quic bmc encode: %w", err)
		}
		body = encoded
	}

	// Category payload layout: [sub-opcode (1 byte)][msgpack body]
	payload := make([]byte, 1+len(body))
	payload[0] = sub
	copy(payload[1:], body)

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("quic bmc open stream: %w", err)
	}
	defer stream.Close()

	if err := quic.WriteRequest(stream, &quic.Request{Opcode: quic.OpBMCCategory, Payload: payload}); err != nil {
		return fmt.Errorf("quic bmc write request: %w", err)
	}

	resp, err := quic.ReadResponse(stream)
	if err != nil {
		return fmt.Errorf("quic bmc read response: %w", err)
	}
	if resp.Status != quic.StatusOK {
		return fmt.Errorf("quic bmc sub 0x%02X failed: status 0x%02X: %s", sub, resp.Status, string(resp.Payload))
	}
	if out != nil && len(resp.Payload) > 0 {
		return quic.DecodePayload(resp.Payload, out)
	}
	return nil
}

// =============================================================================
// Stub Operations (BMC QUIC transport not yet wired)
// =============================================================================

// PowerOn is not implemented for QUIC.
func (q *QUICAdapter) PowerOn(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error) {
	return nil, ErrQUICNotImplemented{}
}

// PowerOff is not implemented for QUIC.
func (q *QUICAdapter) PowerOff(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error) {
	return nil, ErrQUICNotImplemented{}
}

// PowerStatus is not implemented for QUIC.
func (q *QUICAdapter) PowerStatus(ctx context.Context, profileID uint64) (bmcsvc.PowerState, error) {
	return bmcsvc.PowerStateUnspecified, ErrQUICNotImplemented{}
}

// SetBootDevice is not implemented for QUIC.
func (q *QUICAdapter) SetBootDevice(ctx context.Context, profileID uint64, device bmcsvc.BootDevice, persistent bool) error {
	return ErrQUICNotImplemented{}
}

// GetBootDevice is not implemented for QUIC.
func (q *QUICAdapter) GetBootDevice(ctx context.Context, profileID uint64) (bmcsvc.BootDevice, error) {
	return bmcsvc.BootDeviceUnspecified, ErrQUICNotImplemented{}
}

// MountISO is not implemented for QUIC.
func (q *QUICAdapter) MountISO(ctx context.Context, profileID uint64, isoURL string) error {
	return ErrQUICNotImplemented{}
}

// UnmountISO is not implemented for QUIC.
func (q *QUICAdapter) UnmountISO(ctx context.Context, profileID uint64) error {
	return ErrQUICNotImplemented{}
}

// VirtualMediaStatus is not implemented for QUIC.
func (q *QUICAdapter) VirtualMediaStatus(ctx context.Context, profileID uint64) (*bmcsvc.VirtualMediaInfo, error) {
	return nil, ErrQUICNotImplemented{}
}

// GetSensors is not implemented for QUIC.
func (q *QUICAdapter) GetSensors(ctx context.Context, profileID uint64) ([]bmcsvc.SensorReading, error) {
	return nil, ErrQUICNotImplemented{}
}

// GetSystemInfo is not implemented for QUIC.
func (q *QUICAdapter) GetSystemInfo(ctx context.Context, profileID uint64) (*bmcsvc.SystemInfo, error) {
	return nil, ErrQUICNotImplemented{}
}

// GetWebCertificate is not implemented for QUIC.
func (q *QUICAdapter) GetWebCertificate(ctx context.Context, profileID uint64) (*bmcsvc.CertificateInfo, error) {
	return nil, ErrQUICNotImplemented{}
}

// ListUsers is not implemented for QUIC.
func (q *QUICAdapter) ListUsers(ctx context.Context, profileID uint64) ([]bmcsvc.User, error) {
	return nil, ErrQUICNotImplemented{}
}

// =============================================================================
// Enrollment Operations
// =============================================================================

// EnrollBMC runs the BMC enrollment ceremony via QUIC using the
// OpBMCCategory / BMCSubEnroll category opcode pattern. The request and
// response wire types (QUICBMCEnrollRequest / QUICBMCEnrollResponse) use
// MessagePack codec tags that exactly match the server-side definitions in
// pkg/api/daemon/quic_bmc.go.
func (q *QUICAdapter) EnrollBMC(ctx context.Context, profileID uint64, opts *EnrollOptions) (*EnrollResult, error) {
	req := quicBMCEnrollRequestFromOpts(profileID, opts)

	var wire quicBMCEnrollResponse
	if err := q.sendBMCSub(ctx, quic.BMCSubEnroll, req, &wire); err != nil {
		return nil, ErrQUICCallFailed{Method: "BMCEnroll", Err: err}
	}
	return quicBMCEnrollResponseToDomain(&wire), nil
}

// =============================================================================
// Factory Certificate Restore Operations
// =============================================================================

// RestoreBMC runs the BMC factory-certificate restore ceremony via QUIC using
// the OpBMCCategory / BMCSubRestore category opcode pattern. The request and
// response wire types use MessagePack codec tags that exactly match the
// server-side definitions in pkg/api/daemon/quic_bmc.go.
func (q *QUICAdapter) RestoreBMC(ctx context.Context, profileID uint64) (*RestoreResult, error) {
	req := &quicBMCRestoreRequest{ProfileID: profileID}

	var wire quicBMCRestoreResponse
	if err := q.sendBMCSub(ctx, quic.BMCSubRestore, req, &wire); err != nil {
		return nil, ErrQUICCallFailed{Method: "BMCRestore", Err: err}
	}
	return quicBMCRestoreResponseToDomain(&wire), nil
}

// =============================================================================
// QUIC wire types — codec tags MUST match pkg/api/daemon/quic_bmc.go exactly
// =============================================================================

// quicBMCEnrollRequest is the local mirror of daemon.QUICBMCEnrollRequest.
// Optional boolean fields use *bool for presence semantics matching the server.
type quicBMCEnrollRequest struct {
	ProfileID          uint64 `codec:"profile_id"`
	ReplaceCertificate *bool  `codec:"replace_certificate,omitempty"`
	RotatePassword     *bool  `codec:"rotate_password,omitempty"`
	DNSRegister        *bool  `codec:"dns_register,omitempty"`
	DANEPublish        *bool  `codec:"dane_publish,omitempty"`
}

// quicBMCEnrollStepResponse is the local mirror of daemon.QUICBMCEnrollStepResponse.
type quicBMCEnrollStepResponse struct {
	Name   string `codec:"name"`
	OK     bool   `codec:"ok"`
	Detail string `codec:"detail,omitempty"`
}

// quicBMCFactoryCertMetaResponse is the local mirror of daemon.QUICBMCFactoryCertMetaResponse.
// Timestamps are Unix seconds (int64) as on the wire.
type quicBMCFactoryCertMetaResponse struct {
	Subject      string `codec:"subject"`
	Issuer       string `codec:"issuer"`
	SerialNumber string `codec:"serial_number"`
	NotBefore    int64  `codec:"not_before"`
	NotAfter     int64  `codec:"not_after"`
	SPKISHA256   string `codec:"spki_sha256"`
	SHA256       string `codec:"sha256"`
	CapturedAt   int64  `codec:"captured_at"`
}

// quicBMCEnrollResponse is the local mirror of daemon.QUICBMCEnrollResponse.
// DeviceID is uint64 directly — MessagePack preserves full integer precision.
type quicBMCEnrollResponse struct {
	DeviceID        uint64                         `codec:"device_id"`
	Endpoint        string                         `codec:"endpoint"`
	Hostname        string                         `codec:"hostname"`
	DNSName         string                         `codec:"dns_name,omitempty"`
	PinSPKISHA256   string                         `codec:"pin_spki_sha256"`
	FactoryCertPEM  []byte                         `codec:"factory_cert_pem,omitempty"`
	FactoryCertMeta quicBMCFactoryCertMetaResponse `codec:"factory_cert_meta"`
	NewCertPEM      []byte                         `codec:"new_cert_pem,omitempty"`
	CACertPEM       []byte                         `codec:"ca_cert_pem,omitempty"`
	Steps           []quicBMCEnrollStepResponse    `codec:"steps"`
	Timestamp       int64                          `codec:"timestamp"`
}

// quicBMCRestoreRequest is the local mirror of daemon.QUICBMCRestoreRequest.
type quicBMCRestoreRequest struct {
	ProfileID uint64 `codec:"profile_id"`
}

// quicBMCRestoreResponse is the local mirror of daemon.QUICBMCRestoreResponse.
type quicBMCRestoreResponse struct {
	DeviceID    uint64                         `codec:"device_id"`
	Endpoint    string                         `codec:"endpoint"`
	Hostname    string                         `codec:"hostname"`
	NewCertMeta quicBMCFactoryCertMetaResponse `codec:"new_cert_meta"`
	NewCertPEM  []byte                         `codec:"new_cert_pem,omitempty"`
	Steps       []quicBMCEnrollStepResponse    `codec:"steps"`
	Timestamp   int64                          `codec:"timestamp"`
}

// quicBMCEnrollRequestFromOpts builds the QUIC wire request from the domain opts.
func quicBMCEnrollRequestFromOpts(profileID uint64, opts *EnrollOptions) *quicBMCEnrollRequest {
	req := &quicBMCEnrollRequest{ProfileID: profileID}
	if opts != nil {
		req.ReplaceCertificate = opts.ReplaceCertificate
		req.RotatePassword = opts.RotatePassword
		req.DNSRegister = opts.DNSRegister
		req.DANEPublish = opts.DANEPublish
	}
	return req
}

// quicBMCEnrollResponseToDomain converts a QUIC wire response to the local
// domain EnrollResult. Unix-second timestamps are converted to time.Time.
func quicBMCEnrollResponseToDomain(w *quicBMCEnrollResponse) *EnrollResult {
	if w == nil {
		return &EnrollResult{}
	}
	steps := make([]EnrollStep, len(w.Steps))
	for i, s := range w.Steps {
		steps[i] = EnrollStep{Name: s.Name, OK: s.OK, Detail: s.Detail}
	}
	meta := EnrollFactoryCertMeta{
		Subject:      w.FactoryCertMeta.Subject,
		Issuer:       w.FactoryCertMeta.Issuer,
		SerialNumber: w.FactoryCertMeta.SerialNumber,
		SPKISHA256:   w.FactoryCertMeta.SPKISHA256,
		SHA256:       w.FactoryCertMeta.SHA256,
	}
	if w.FactoryCertMeta.NotBefore != 0 {
		meta.NotBefore = time.Unix(w.FactoryCertMeta.NotBefore, 0)
	}
	if w.FactoryCertMeta.NotAfter != 0 {
		meta.NotAfter = time.Unix(w.FactoryCertMeta.NotAfter, 0)
	}
	if w.FactoryCertMeta.CapturedAt != 0 {
		meta.CapturedAt = time.Unix(w.FactoryCertMeta.CapturedAt, 0)
	}
	return &EnrollResult{
		DeviceID:        w.DeviceID,
		Endpoint:        w.Endpoint,
		Hostname:        w.Hostname,
		DNSName:         w.DNSName,
		PinSPKISHA256:   w.PinSPKISHA256,
		FactoryCertMeta: meta,
		Steps:           steps,
	}
}

// quicBMCRestoreResponseToDomain converts a QUIC wire restore response to the
// local domain RestoreResult. Unix-second timestamps are converted to time.Time.
func quicBMCRestoreResponseToDomain(w *quicBMCRestoreResponse) *RestoreResult {
	if w == nil {
		return &RestoreResult{}
	}
	steps := make([]EnrollStep, len(w.Steps))
	for i, s := range w.Steps {
		steps[i] = EnrollStep{Name: s.Name, OK: s.OK, Detail: s.Detail}
	}
	meta := RestoreFactoryCertMeta{
		Subject:      w.NewCertMeta.Subject,
		Issuer:       w.NewCertMeta.Issuer,
		SerialNumber: w.NewCertMeta.SerialNumber,
		SPKISHA256:   w.NewCertMeta.SPKISHA256,
		SHA256:       w.NewCertMeta.SHA256,
	}
	if w.NewCertMeta.NotBefore != 0 {
		meta.NotBefore = time.Unix(w.NewCertMeta.NotBefore, 0)
	}
	if w.NewCertMeta.NotAfter != 0 {
		meta.NotAfter = time.Unix(w.NewCertMeta.NotAfter, 0)
	}
	if w.NewCertMeta.CapturedAt != 0 {
		meta.CapturedAt = time.Unix(w.NewCertMeta.CapturedAt, 0)
	}
	return &RestoreResult{
		DeviceID:    w.DeviceID,
		Endpoint:    w.Endpoint,
		Hostname:    w.Hostname,
		NewCertMeta: meta,
		Steps:       steps,
	}
}

// Ensure QUICAdapter implements BMCCommands interface.
var _ BMCCommands = (*QUICAdapter)(nil)
