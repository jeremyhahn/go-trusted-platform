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

//go:build integration

package ca

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-codec/pkg/factory"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
	quicgo "github.com/quic-go/quic-go"
)

// =============================================================================
// QUIC Adapter Constants
// =============================================================================

const (
	// DefaultQUICTimeoutCA is the default timeout for QUIC CA operations.
	DefaultQUICTimeoutCA = 30 * time.Second

	// MaxQUICPayloadSizeCA is the maximum payload size (16MB).
	MaxQUICPayloadSizeCA uint32 = 16 * 1024 * 1024

	// MaxQUICTokenSizeCA is the maximum token size (8KB).
	MaxQUICTokenSizeCA uint16 = 8 * 1024

	// QUICStatusOKCA is the success status code.
	QUICStatusOKCA byte = 0x00
)

// =============================================================================
// QUIC Error Types
// =============================================================================

// ErrQUICCAConnectionFailed indicates a QUIC connection failure.
type ErrQUICCAConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrQUICCAConnectionFailed) Error() string {
	return fmt.Sprintf("QUIC CA connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrQUICCAConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrQUICCARequestFailed indicates a QUIC request failure.
type ErrQUICCARequestFailed struct {
	Operation string
	Status    byte
	Message   string
}

func (e ErrQUICCARequestFailed) Error() string {
	return fmt.Sprintf("QUIC CA request %s failed (status 0x%02X): %s", e.Operation, e.Status, e.Message)
}

// ErrQUICCAEncodeFailed indicates payload encoding failure.
type ErrQUICCAEncodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICCAEncodeFailed) Error() string {
	return fmt.Sprintf("QUIC CA encode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrQUICCAEncodeFailed) Unwrap() error {
	return e.Err
}

// ErrQUICCADecodeFailed indicates payload decoding failure.
type ErrQUICCADecodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICCADecodeFailed) Error() string {
	return fmt.Sprintf("QUIC CA decode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrQUICCADecodeFailed) Unwrap() error {
	return e.Err
}

// ErrQUICCAClientClosed indicates the QUIC client is closed.
type ErrQUICCAClientClosed struct{}

func (e ErrQUICCAClientClosed) Error() string {
	return "QUIC CA client is closed"
}

// =============================================================================
// QUIC Wire Protocol Types
// =============================================================================

type quicCARequest struct {
	Opcode  byte
	Token   string
	Payload []byte
}

type quicCAResponse struct {
	Status  byte
	Payload []byte
}

// =============================================================================
// QUIC Request/Response Types (matching pkg/api/quic/ca_handlers.go)
// =============================================================================

type quicCAInfoResp struct {
	CommonName       string               `codec:"common_name"`
	IsInitialized    bool                 `codec:"is_initialized"`
	IsIntermediate   bool                 `codec:"is_intermediate"`
	DefaultAlgorithm string               `codec:"default_algorithm"`
	DefaultValidity  int32                `codec:"default_validity"`
	RootCert         *quicCACertSummary   `codec:"root_cert"`
	Intermediates    []*quicCACertSummary `codec:"intermediates"`
	Timestamp        int64                `codec:"timestamp"`
}

type quicCACertSummary struct {
	Serial       string `codec:"serial"`
	CommonName   string `codec:"common_name"`
	Issuer       string `codec:"issuer"`
	NotBefore    int64  `codec:"not_before"`
	NotAfter     int64  `codec:"not_after"`
	Status       string `codec:"status"`
	KeyAlgorithm string `codec:"key_algorithm"`
}

type quicCACert struct {
	Serial             string         `codec:"serial"`
	Subject            *quicCASubject `codec:"subject"`
	Issuer             string         `codec:"issuer"`
	NotBefore          int64          `codec:"not_before"`
	NotAfter           int64          `codec:"not_after"`
	Status             string         `codec:"status"`
	KeyAlgorithm       string         `codec:"key_algorithm"`
	SignatureAlgorithm string         `codec:"signature_algorithm"`
	IsCA               bool           `codec:"is_ca"`
	Pem                string         `codec:"pem"`
	Sans               *quicCASANs    `codec:"sans"`
}

type quicCASubject struct {
	CommonName         string `codec:"common_name"`
	Organization       string `codec:"organization"`
	OrganizationalUnit string `codec:"organizational_unit"`
	Country            string `codec:"country"`
	Province           string `codec:"province"`
	Locality           string `codec:"locality"`
	Address            string `codec:"address"`
	PostalCode         string `codec:"postal_code"`
}

type quicCASANs struct {
	DNS   []string `codec:"dns"`
	IPs   []string `codec:"ips"`
	Email []string `codec:"email"`
	URIs  []string `codec:"uris"`
}

type quicCAIssueReq struct {
	Subject      *quicCASubject `codec:"subject"`
	Sans         *quicCASANs    `codec:"sans"`
	ValidDays    int32          `codec:"valid_days"`
	KeyAlgorithm string         `codec:"key_algorithm"`
	StoreType    string         `codec:"store_type"`
	KeyUsage     []string       `codec:"key_usage"`
	ExtKeyUsage  []string       `codec:"ext_key_usage"`
	IsCA         bool           `codec:"is_ca"`
	MaxPathLen   int32          `codec:"max_path_len"`
}

type quicCAIssueResp struct {
	Certificate *quicCACert `codec:"certificate"`
	Timestamp   int64       `codec:"timestamp"`
}

type quicCAGetReq struct {
	Serial     string `codec:"serial"`
	IncludePem bool   `codec:"include_pem"`
}

type quicCAGetResp struct {
	Certificate *quicCACert `codec:"certificate"`
	Timestamp   int64       `codec:"timestamp"`
}

type quicCAListReq struct {
	Limit  int32  `codec:"limit"`
	Cursor string `codec:"cursor"`
}

type quicCAListResp struct {
	Certificates []*quicCACertSummary `codec:"certificates"`
	NextCursor   string               `codec:"next_cursor"`
	HasMore      bool                 `codec:"has_more"`
	TotalCount   int32                `codec:"total_count"`
	Timestamp    int64                `codec:"timestamp"`
}

type quicCARevokeReq struct {
	Serial     string `codec:"serial"`
	Reason     int32  `codec:"reason"`
	DeleteKeys bool   `codec:"delete_keys"`
}

type quicCARevokeResp struct {
	Serial    string `codec:"serial"`
	Status    string `codec:"status"`
	RevokedAt int64  `codec:"revoked_at"`
	Reason    int32  `codec:"reason"`
	Timestamp int64  `codec:"timestamp"`
}

type quicCARenewReq struct {
	Serial        string `codec:"serial"`
	ExtendDays    int32  `codec:"extend_days"`
	PreserveAttrs bool   `codec:"preserve_attrs"`
}

type quicCARenewResp struct {
	OldSerial   string      `codec:"old_serial"`
	Certificate *quicCACert `codec:"certificate"`
	Timestamp   int64       `codec:"timestamp"`
}

type quicCAVerifyReq struct {
	CertificatePem string `codec:"certificate_pem"`
	CertificateDer []byte `codec:"certificate_der"`
	CheckRevoked   bool   `codec:"check_revoked"`
}

type quicCAVerifyResp struct {
	Valid     bool                 `codec:"valid"`
	Status    string               `codec:"status"`
	Revoked   bool                 `codec:"revoked"`
	Chain     []*quicCACertSummary `codec:"chain"`
	Errors    []string             `codec:"errors"`
	Timestamp int64                `codec:"timestamp"`
}

type quicCACRLResp struct {
	CRL          []byte                    `codec:"crl"`
	LastUpdate   int64                     `codec:"last_update"`
	NextUpdate   int64                     `codec:"next_update"`
	RevokedCount int32                     `codec:"revoked_count"`
	RevokedCerts []*quicCARevokedCertEntry `codec:"revoked_certs"`
	Timestamp    int64                     `codec:"timestamp"`
}

type quicCARevokedCertEntry struct {
	Serial         string `codec:"serial"`
	RevocationTime int64  `codec:"revocation_time"`
	Reason         int32  `codec:"reason"`
}

type quicCABundleReq struct {
	StoreType string `codec:"store_type"`
	Algorithm string `codec:"algorithm"`
}

type quicCABundleResp struct {
	Bundle       []byte               `codec:"bundle"`
	Certificates []*quicCACertSummary `codec:"certificates"`
	CertCount    int32                `codec:"cert_count"`
	Timestamp    int64                `codec:"timestamp"`
}

// =============================================================================
// QUIC Protocol Adapter
// =============================================================================

// QUICAdapter implements CACommands using QUIC calls to platformd.
type QUICAdapter struct {
	endpoint       string
	conn           *quicgo.Conn
	tlsConfig      *tls.Config
	timeout        time.Duration
	maxIdleTimeout time.Duration

	mu     sync.RWMutex
	closed bool
}

// NewQUICAdapter creates a new QUIC protocol adapter instance.
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{
		timeout:        DefaultQUICTimeoutCA,
		maxIdleTimeout: 60 * time.Second,
		tlsConfig:      helpers.QUICTLSConfig(),
	}
}

// Name returns the protocol adapter identifier.
func (q *QUICAdapter) Name() string {
	return "QUIC"
}

// Setup establishes the QUIC connection to platformd.
func (q *QUICAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformQUICEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformQUIC
	}
	q.endpoint = endpoint

	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return ErrQUICCAClientClosed{}
	}

	connCtx, cancel := context.WithTimeout(ctx, q.timeout)
	defer cancel()

	quicConfig := &quicgo.Config{
		MaxIdleTimeout:  q.maxIdleTimeout,
		KeepAlivePeriod: 15 * time.Second,
	}

	conn, err := quicgo.DialAddr(connCtx, q.endpoint, q.tlsConfig, quicConfig)
	if err != nil {
		return ErrQUICCAConnectionFailed{Endpoint: q.endpoint, Err: err}
	}

	q.conn = conn
	return nil
}

// Teardown closes the QUIC connection.
func (q *QUICAdapter) Teardown() error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return nil
	}

	q.closed = true

	if q.conn != nil {
		return q.conn.CloseWithError(0, "adapter teardown")
	}

	return nil
}

// =============================================================================
// Wire Protocol Methods
// =============================================================================

// sendRequest sends a QUIC request and returns the response.
func (q *QUICAdapter) sendRequest(ctx context.Context, opcode byte, payload interface{}) (*quicCAResponse, error) {
	q.mu.RLock()
	if q.closed {
		q.mu.RUnlock()
		return nil, ErrQUICCAClientClosed{}
	}
	conn := q.conn
	q.mu.RUnlock()

	var payloadBytes []byte
	if payload != nil {
		var err error
		payloadBytes, err = encodeCAPayload(payload)
		if err != nil {
			return nil, ErrQUICCAEncodeFailed{Operation: caOpcodeToString(opcode), Err: err}
		}
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, ErrQUICCAConnectionFailed{Endpoint: q.endpoint, Err: err}
	}
	defer stream.Close()

	req := &quicCARequest{
		Opcode:  opcode,
		Payload: payloadBytes,
	}

	if err := writeCARequest(stream, req); err != nil {
		return nil, err
	}

	resp, err := readCAResponse(stream)
	if err != nil {
		return nil, err
	}

	if resp.Status != QUICStatusOKCA {
		errMsg := string(resp.Payload)
		if errMsg == "" {
			errMsg = "unknown error"
		}
		return nil, ErrQUICCARequestFailed{
			Operation: caOpcodeToString(opcode),
			Status:    resp.Status,
			Message:   errMsg,
		}
	}

	return resp, nil
}

// writeCARequest writes a request to the QUIC stream.
func writeCARequest(w io.Writer, req *quicCARequest) error {
	payloadLen := uint32(len(req.Payload))
	tokenLen := uint16(len(req.Token))

	// Write opcode (1 byte)
	if _, err := w.Write([]byte{req.Opcode}); err != nil {
		return fmt.Errorf("failed to write opcode: %w", err)
	}

	// Write token length (2 bytes)
	tokenLenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(tokenLenBuf, tokenLen)
	if _, err := w.Write(tokenLenBuf); err != nil {
		return fmt.Errorf("failed to write token length: %w", err)
	}

	// Write token
	if tokenLen > 0 {
		if _, err := w.Write([]byte(req.Token)); err != nil {
			return fmt.Errorf("failed to write token: %w", err)
		}
	}

	// Write payload length (4 bytes)
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, payloadLen)
	if _, err := w.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to write payload length: %w", err)
	}

	// Write payload
	if payloadLen > 0 {
		if _, err := w.Write(req.Payload); err != nil {
			return fmt.Errorf("failed to write payload: %w", err)
		}
	}

	return nil
}

// readCAResponse reads a response from the QUIC stream.
func readCAResponse(r io.Reader) (*quicCAResponse, error) {
	// Read status (1 byte)
	statusBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, statusBuf); err != nil {
		return nil, fmt.Errorf("failed to read status: %w", err)
	}

	// Read payload length (4 bytes)
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read payload length: %w", err)
	}
	payloadLen := binary.BigEndian.Uint32(lenBuf)

	if payloadLen > MaxQUICPayloadSizeCA {
		return nil, fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxQUICPayloadSizeCA)
	}

	// Read payload
	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("failed to read payload: %w", err)
		}
	}

	return &quicCAResponse{
		Status:  statusBuf[0],
		Payload: payload,
	}, nil
}

// caCodecType is the codec type used for CA payload encoding/decoding.
var caCodecType = codec.MsgPack

// encodeCAPayload encodes an entity using MessagePack.
func encodeCAPayload(entity interface{}) ([]byte, error) {
	if entity == nil {
		return nil, nil
	}

	c, err := factory.New[any](caCodecType)
	if err != nil {
		return nil, fmt.Errorf("failed to create codec: %w", err)
	}

	data, err := c.Marshal(entity)
	if err != nil {
		return nil, fmt.Errorf("failed to encode payload: %w", err)
	}

	return data, nil
}

// decodeCAPayload decodes bytes from MessagePack.
func decodeCAPayload(data []byte, entity interface{}) error {
	if len(data) == 0 {
		return nil
	}

	c, err := factory.New[any](caCodecType)
	if err != nil {
		return fmt.Errorf("failed to create codec: %w", err)
	}

	if err := c.Unmarshal(data, &entity); err != nil {
		return fmt.Errorf("failed to decode payload: %w", err)
	}

	return nil
}

// caOpcodeToString returns a human-readable name for a CA opcode.
func caOpcodeToString(opcode byte) string {
	opcodeNames := map[byte]string{
		quicwire.OpCAInfo:   "CAInfo",
		quicwire.OpCAIssue:  "CAIssue",
		quicwire.OpCARevoke: "CARevoke",
		quicwire.OpCARenew:  "CARenew",
		quicwire.OpCAGet:    "CAGet",
		quicwire.OpCAList:   "CAList",
		quicwire.OpCAVerify: "CAVerify",
		quicwire.OpCACRL:    "CACRL",
		quicwire.OpCABundle: "CABundle",
	}
	if name, ok := opcodeNames[opcode]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%02X)", opcode)
}

// =============================================================================
// CA Info Operations
// =============================================================================

// Info retrieves CA information via QUIC.
func (q *QUICAdapter) Info(ctx context.Context) (*InfoResult, error) {
	resp, err := q.sendRequest(ctx, quicwire.OpCAInfo, nil)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "CAInfo", Err: err}
	}

	var infoResp quicCAInfoResp
	if err := decodeCAPayload(resp.Payload, &infoResp); err != nil {
		return nil, ErrQUICCADecodeFailed{Operation: "CAInfo", Err: err}
	}

	result := &InfoResult{
		CommonName:          infoResp.CommonName,
		IsInitialized:       infoResp.IsInitialized,
		IsIntermediate:      infoResp.IsIntermediate,
		DefaultAlgorithm:    infoResp.DefaultAlgorithm,
		DefaultValidityDays: infoResp.DefaultValidity,
	}

	if infoResp.RootCert != nil {
		result.RootCertificate = convertQUICCertSummary(infoResp.RootCert)
	}

	for _, intermediate := range infoResp.Intermediates {
		if intermediate != nil {
			result.Intermediates = append(result.Intermediates, *convertQUICCertSummary(intermediate))
		}
	}

	return result, nil
}

// =============================================================================
// CA Init Operations
// =============================================================================

// Init initializes the CA via QUIC.
// Note: CA initialization is done during daemon startup, not via QUIC.
func (q *QUICAdapter) Init(ctx context.Context, opts InitOptions) (*InitResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "CA init"}
}

// =============================================================================
// Certificate Issue Operations
// =============================================================================

// IssueCertificate issues a new certificate via QUIC.
func (q *QUICAdapter) IssueCertificate(ctx context.Context, opts IssueCertificateOptions) (*IssueCertificateResult, error) {
	req := &quicCAIssueReq{
		Subject: &quicCASubject{
			CommonName: opts.CommonName,
		},
		ValidDays:    opts.ValidDays,
		KeyAlgorithm: opts.Algorithm,
		StoreType:    opts.StoreType,
		KeyUsage:     opts.KeyUsage,
		ExtKeyUsage:  opts.ExtKeyUsage,
		IsCA:         opts.IsCA,
		MaxPathLen:   opts.MaxPathLen,
	}

	if len(opts.SANsDNS) > 0 || len(opts.SANsIPs) > 0 || len(opts.SANsEmail) > 0 {
		req.Sans = &quicCASANs{
			DNS:   opts.SANsDNS,
			IPs:   opts.SANsIPs,
			Email: opts.SANsEmail,
		}
	}

	resp, err := q.sendRequest(ctx, quicwire.OpCAIssue, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "CAIssue", Err: err}
	}

	var issueResp quicCAIssueResp
	if err := decodeCAPayload(resp.Payload, &issueResp); err != nil {
		return nil, ErrQUICCADecodeFailed{Operation: "CAIssue", Err: err}
	}

	result := &IssueCertificateResult{
		Success: issueResp.Certificate != nil,
	}

	if issueResp.Certificate != nil {
		result.Certificate = convertQUICCertificate(issueResp.Certificate)
	}

	return result, nil
}

// =============================================================================
// Certificate Get Operations
// =============================================================================

// GetCertificate retrieves a certificate via QUIC.
// The serial field accepts either a hex-encoded serial number or a common name,
// so when Serial is empty but CommonName is provided, the CommonName is sent
// as the serial field for CN-based lookup.
func (q *QUICAdapter) GetCertificate(ctx context.Context, opts GetCertificateOptions) (*GetCertificateResult, error) {
	// Determine the identifier to send: prefer Serial, fall back to CommonName
	identifier := opts.Serial
	if identifier == "" && opts.CommonName != "" {
		identifier = opts.CommonName
	}

	req := &quicCAGetReq{
		Serial:     identifier,
		IncludePem: opts.IncludePEM,
	}

	resp, err := q.sendRequest(ctx, quicwire.OpCAGet, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "CAGet", Err: err}
	}

	var getResp quicCAGetResp
	if err := decodeCAPayload(resp.Payload, &getResp); err != nil {
		return nil, ErrQUICCADecodeFailed{Operation: "CAGet", Err: err}
	}

	result := &GetCertificateResult{}
	if getResp.Certificate != nil {
		result.Certificate = convertQUICCertificate(getResp.Certificate)
	}

	return result, nil
}

// =============================================================================
// Certificate List Operations
// =============================================================================

// ListCertificates lists certificates via QUIC.
func (q *QUICAdapter) ListCertificates(ctx context.Context, opts ListCertificatesOptions) (*ListCertificatesResult, error) {
	req := &quicCAListReq{
		Limit: opts.Limit,
	}

	resp, err := q.sendRequest(ctx, quicwire.OpCAList, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "CAList", Err: err}
	}

	var listResp quicCAListResp
	if err := decodeCAPayload(resp.Payload, &listResp); err != nil {
		return nil, ErrQUICCADecodeFailed{Operation: "CAList", Err: err}
	}

	result := &ListCertificatesResult{
		Certificates: make([]CertificateSummary, 0, len(listResp.Certificates)),
		Total:        listResp.TotalCount,
	}

	for _, cert := range listResp.Certificates {
		if cert != nil {
			result.Certificates = append(result.Certificates, *convertQUICCertSummary(cert))
		}
	}

	return result, nil
}

// =============================================================================
// Certificate Verify Operations
// =============================================================================

// VerifyCertificate verifies a certificate via QUIC.
func (q *QUICAdapter) VerifyCertificate(ctx context.Context, opts VerifyCertificateOptions) (*VerifyCertificateResult, error) {
	req := &quicCAVerifyReq{
		CertificatePem: string(opts.CertificatePEM),
		CheckRevoked:   opts.CheckCRL,
	}

	resp, err := q.sendRequest(ctx, quicwire.OpCAVerify, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "CAVerify", Err: err}
	}

	var verifyResp quicCAVerifyResp
	if err := decodeCAPayload(resp.Payload, &verifyResp); err != nil {
		return nil, ErrQUICCADecodeFailed{Operation: "CAVerify", Err: err}
	}

	result := &VerifyCertificateResult{
		Valid:      verifyResp.Valid,
		Revoked:    verifyResp.Revoked,
		ChainValid: verifyResp.Valid && len(verifyResp.Errors) == 0,
		Errors:     verifyResp.Errors,
	}

	if len(verifyResp.Chain) > 0 {
		result.ChainLength = len(verifyResp.Chain)
		for _, c := range verifyResp.Chain {
			if c != nil {
				result.ChainSubjects = append(result.ChainSubjects, c.Serial)
			}
		}
	}

	return result, nil
}

// =============================================================================
// Certificate Revoke Operations
// =============================================================================

// RevokeCertificate revokes a certificate via QUIC.
func (q *QUICAdapter) RevokeCertificate(ctx context.Context, opts RevokeCertificateOptions) (*RevokeCertificateResult, error) {
	req := &quicCARevokeReq{
		Serial:     opts.Serial,
		Reason:     int32(opts.Reason),
		DeleteKeys: opts.DeleteKeys,
	}

	resp, err := q.sendRequest(ctx, quicwire.OpCARevoke, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "CARevoke", Err: err}
	}

	var revokeResp quicCARevokeResp
	if err := decodeCAPayload(resp.Payload, &revokeResp); err != nil {
		return nil, ErrQUICCADecodeFailed{Operation: "CARevoke", Err: err}
	}

	return &RevokeCertificateResult{
		Success:   true,
		Serial:    revokeResp.Serial,
		Status:    CertificateStatusRevoked,
		RevokedAt: time.Unix(revokeResp.RevokedAt, 0),
		Reason:    RevocationReason(revokeResp.Reason),
	}, nil
}

// =============================================================================
// Certificate Renew Operations
// =============================================================================

// RenewCertificate renews a certificate via QUIC.
func (q *QUICAdapter) RenewCertificate(ctx context.Context, opts RenewCertificateOptions) (*RenewCertificateResult, error) {
	req := &quicCARenewReq{
		Serial:        opts.Serial,
		ExtendDays:    opts.ValidDays,
		PreserveAttrs: opts.PreserveSANs,
	}

	resp, err := q.sendRequest(ctx, quicwire.OpCARenew, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "CARenew", Err: err}
	}

	var renewResp quicCARenewResp
	if err := decodeCAPayload(resp.Payload, &renewResp); err != nil {
		return nil, ErrQUICCADecodeFailed{Operation: "CARenew", Err: err}
	}

	result := &RenewCertificateResult{
		Success: renewResp.Certificate != nil,
	}

	if renewResp.Certificate != nil {
		result.NewCertificate = convertQUICCertificate(renewResp.Certificate)
	}

	return result, nil
}

// =============================================================================
// CRL Operations
// =============================================================================

// GetCRL retrieves the CRL via QUIC.
func (q *QUICAdapter) GetCRL(ctx context.Context, opts GetCRLOptions) (*GetCRLResult, error) {
	resp, err := q.sendRequest(ctx, quicwire.OpCACRL, nil)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "CACRL", Err: err}
	}

	var crlResp quicCACRLResp
	if err := decodeCAPayload(resp.Payload, &crlResp); err != nil {
		return nil, ErrQUICCADecodeFailed{Operation: "CACRL", Err: err}
	}

	result := &GetCRLResult{
		Data:         crlResp.CRL,
		RevokedCount: crlResp.RevokedCount,
		ThisUpdate:   time.Unix(crlResp.LastUpdate, 0),
		NextUpdate:   time.Unix(crlResp.NextUpdate, 0),
	}

	for _, entry := range crlResp.RevokedCerts {
		if entry != nil {
			result.RevokedCerts = append(result.RevokedCerts, RevokedCertEntry{
				Serial:         entry.Serial,
				RevocationTime: time.Unix(entry.RevocationTime, 0),
				Reason:         RevocationReason(entry.Reason),
			})
		}
	}

	return result, nil
}

// GenerateCRL generates a new CRL via QUIC.
func (q *QUICAdapter) GenerateCRL(ctx context.Context) (*GenerateCRLResult, error) {
	resp, err := q.sendRequest(ctx, quicwire.OpCACRL, nil)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "GenerateCRL", Err: err}
	}

	var crlResp quicCACRLResp
	if err := decodeCAPayload(resp.Payload, &crlResp); err != nil {
		return nil, ErrQUICCADecodeFailed{Operation: "GenerateCRL", Err: err}
	}

	result := &GenerateCRLResult{
		Success:    true,
		ThisUpdate: time.Unix(crlResp.LastUpdate, 0),
		NextUpdate: time.Unix(crlResp.NextUpdate, 0),
	}

	return result, nil
}

// ExportCRL exports the CRL via QUIC.
// Note: CRL export to file is a CLI operation, not exposed via QUIC.
func (q *QUICAdapter) ExportCRL(ctx context.Context, output string) (*ExportCRLResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "CRL export"}
}

// =============================================================================
// Export Bundle Operations
// =============================================================================

// ExportBundle exports the CA bundle via QUIC.
func (q *QUICAdapter) ExportBundle(ctx context.Context, output string) (*ExportBundleResult, error) {
	req := &quicCABundleReq{}

	resp, err := q.sendRequest(ctx, quicwire.OpCABundle, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "CABundle", Err: err}
	}

	var bundleResp quicCABundleResp
	if err := decodeCAPayload(resp.Payload, &bundleResp); err != nil {
		return nil, ErrQUICCADecodeFailed{Operation: "CABundle", Err: err}
	}

	result := &ExportBundleResult{
		Success:   len(bundleResp.Bundle) > 0,
		CertCount: bundleResp.CertCount,
		Size:      int64(len(bundleResp.Bundle)),
	}

	if output != "" {
		if err := os.WriteFile(output, bundleResp.Bundle, 0644); err != nil {
			return nil, ErrExportFailed{Type: "CA bundle", Path: output, Reason: err.Error()}
		}
		result.FilePath = output
	}

	return result, nil
}

// =============================================================================
// Install/Uninstall Operations
// =============================================================================

// InstallCACertificates installs CA certificates via QUIC.
// Note: CA certificate installation is a local OS operation, not exposed via QUIC.
func (q *QUICAdapter) InstallCACertificates(ctx context.Context) (*InstallCACertificatesResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "install CA certificates"}
}

// UninstallCACertificates uninstalls CA certificates via QUIC.
// Note: CA certificate uninstallation is a local OS operation, not exposed via QUIC.
func (q *QUICAdapter) UninstallCACertificates(ctx context.Context) (*UninstallCACertificatesResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "uninstall CA certificates"}
}

// =============================================================================
// Conversion Helpers
// =============================================================================

// convertQUICCertSummary converts a QUIC certificate summary to the adapter type.
func convertQUICCertSummary(s *quicCACertSummary) *CertificateSummary {
	if s == nil {
		return nil
	}
	return &CertificateSummary{
		Serial:       s.Serial,
		CommonName:   s.CommonName,
		Issuer:       s.Issuer,
		NotBefore:    time.Unix(s.NotBefore, 0),
		NotAfter:     time.Unix(s.NotAfter, 0),
		Status:       quicStatusToCertStatus(s.Status),
		KeyAlgorithm: s.KeyAlgorithm,
	}
}

// convertQUICCertificate converts a QUIC certificate to the adapter type.
func convertQUICCertificate(c *quicCACert) *Certificate {
	if c == nil {
		return nil
	}
	cert := &Certificate{
		Serial:             c.Serial,
		Issuer:             c.Issuer,
		NotBefore:          time.Unix(c.NotBefore, 0),
		NotAfter:           time.Unix(c.NotAfter, 0),
		Status:             quicStatusToCertStatus(c.Status),
		KeyAlgorithm:       c.KeyAlgorithm,
		SignatureAlgorithm: c.SignatureAlgorithm,
		IsCA:               c.IsCA,
		PEM:                []byte(c.Pem),
	}

	if c.Subject != nil {
		cert.Subject = Subject{
			CommonName:         c.Subject.CommonName,
			Organization:       c.Subject.Organization,
			OrganizationalUnit: c.Subject.OrganizationalUnit,
			Country:            c.Subject.Country,
			Province:           c.Subject.Province,
			Locality:           c.Subject.Locality,
			Address:            c.Subject.Address,
			PostalCode:         c.Subject.PostalCode,
		}
	}

	// Convert SANs if present
	if c.Sans != nil {
		cert.SANsDNS = c.Sans.DNS
		cert.SANsIPs = c.Sans.IPs
		cert.SANsEmail = c.Sans.Email
		cert.SANsURIs = c.Sans.URIs
	}

	return cert
}

// quicStatusToCertStatus converts a QUIC status string to CertificateStatus.
func quicStatusToCertStatus(status string) CertificateStatus {
	statusMap := map[string]CertificateStatus{
		"VALID":         CertificateStatusValid,
		"REVOKED":       CertificateStatusRevoked,
		"EXPIRED":       CertificateStatusExpired,
		"NOT_YET_VALID": CertificateStatusPending,
		"PENDING":       CertificateStatusPending,
	}
	if s, ok := statusMap[status]; ok {
		return s
	}
	return CertificateStatusUnspecified
}

// Ensure QUICAdapter implements CACommands interface.
var _ CACommands = (*QUICAdapter)(nil)
