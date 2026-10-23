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

package reporting

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// hostAttestationPath is the node-side quote endpoint (docs/attestation/api.md
// §2, "Collect host attestation").
const hostAttestationPath = "/api/v1/attestation/host"

// nodeClockPath is the node-side clock-state endpoint (docs/attestation/api.md
// §2, "Read node clock state"). It sits behind the same caller gate as the
// quote routes because the collector is its principal: the reporting server
// asks the node whether it can place itself in time, at the moment it asks
// for a quote.
const nodeClockPath = "/api/v1/attestation/clock"

// maxResponseBytes bounds what the collector will read from a node. A quote
// with 24 SHA-256 PCRs and an RSA-2048 signature is a few kilobytes; a
// response many times that is not evidence.
const maxResponseBytes = 1 << 20

// TLSDialer produces the client TLS configuration for one endpoint: the
// collector's identity and the trust anchors for the node's certificate.
// It is a function so the reporting package holds no CA and no key.
type TLSDialer func(ctx context.Context, ep Endpoint) (*tls.Config, error)

// NodeQuoteSourceConfig configures NodeQuoteSource.
type NodeQuoteSourceConfig struct {
	// Addresses finds where to dial. Required.
	Addresses AddressResolver
	// TLS produces per-endpoint client TLS. Required.
	TLS TLSDialer
	// Timeout bounds one collection, across all candidate endpoints.
	Timeout time.Duration
	// PCRs selects the indices the node is asked to quote. Empty asks for
	// the node's default selection.
	PCRs []int
	// Logger is optional.
	Logger *slog.Logger
}

// NodeQuoteSource is the platform's one QuoteSource: the reporting server
// dialling a node's quote endpoint over mTLS with a fresh nonce.
//
// It holds the collector's identity indirectly (through the TLSDialer) and
// nothing else with authority. It is constructed only by the collector
// wiring, and the Collector is its only caller — see the package comment for
// why that matters.
type NodeQuoteSource struct {
	addresses AddressResolver
	tls       TLSDialer
	timeout   time.Duration
	pcrs      []int
	logger    *slog.Logger
}

// NewNodeQuoteSource fails closed on a missing resolver or dialer.
func NewNodeQuoteSource(cfg NodeQuoteSourceConfig) (*NodeQuoteSource, error) {
	if cfg.Addresses == nil {
		return nil, ErrNoAddressResolver{}
	}
	if cfg.TLS == nil {
		return nil, ErrNoTLSDialer{}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &NodeQuoteSource{
		addresses: cfg.Addresses,
		tls:       cfg.TLS,
		timeout:   timeout,
		pcrs:      append([]int(nil), cfg.PCRs...),
		logger:    logger,
	}, nil
}

// Collect implements QuoteSource.
func (s *NodeQuoteSource) Collect(ctx context.Context, deviceID string, nonce []byte) ([]byte, error) {
	if len(nonce) == 0 {
		return nil, ErrInvalidEvidence{Reason: "a collector nonce is required"}
	}
	endpoints, err := s.addresses.Endpoints(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	var attempts []string
	var causes []error
	for _, ep := range endpoints {
		evidence, err := s.collectFrom(ctx, ep, nonce)
		if err == nil {
			return evidence.Encode()
		}
		attempts = append(attempts, ep.Address+" ("+ep.Source+"): "+err.Error())
		causes = append(causes, err)
		s.logger.Debug("attestation reporting: endpoint did not yield evidence",
			"device_id", deviceID, "endpoint", ep.Address, "source", ep.Source, "error", err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, ErrNodeUnreachable{DeviceID: deviceID, Attempts: attempts, Causes: causes}
}

// requestBody encodes the CollectHostAttestation request the node's REST
// route decodes as protobuf JSON. `config` is ALWAYS present: the node's
// gRPC surface refuses a request without one ("quote config is required",
// measured live on the fleet — every collection answered 400), and an empty
// config is the documented way to ask for the node's default PCR selection.
func (s *NodeQuoteSource) requestBody(nonce []byte) ([]byte, error) {
	config := map[string]any{}
	if len(s.pcrs) > 0 {
		config["pcrIndices"] = s.pcrs
	}
	req := map[string]any{
		"nonce":  base64.StdEncoding.EncodeToString(nonce),
		"config": config,
	}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, ErrInvalidEvidence{Reason: "request could not be encoded: " + err.Error()}
	}
	return b, nil
}

// collectFrom asks one endpoint for a quote bound to the connection it is
// asked over. It sends the bare nonce; the node derives the TLS exporter
// binding from its own end of the connection and quotes
// QualifyingData(nonce, binding) (#482). The collector derives the binding
// from its end and accepts only that value. A relay that forwards the nonce
// to a healthy node over a second connection gets a quote bound to the
// second connection, which is refused here with ErrQuoteNotBound.
func (s *NodeQuoteSource) collectFrom(ctx context.Context, ep Endpoint, nonce []byte) (*Evidence, error) {
	conn, err := s.dial(ctx, ep)
	if err != nil {
		return nil, err
	}
	defer s.closeConn(conn)

	state := conn.ConnectionState()
	binding, err := xkms.PeerChannelBinding(&state)
	if err != nil {
		return nil, ErrChannelBinding{Endpoint: ep.Address, Cause: err}
	}
	qualifying := xkms.PeerQualifyingData(nonce, binding)

	body, err := s.requestBody(nonce)
	if err != nil {
		return nil, err
	}
	payload, err := s.exchange(ctx, ep, conn, http.MethodPost, hostAttestationPath, body)
	if err != nil {
		return nil, err
	}
	evidence, err := decodeHostAttestation(payload, qualifying)
	var mismatch ErrNonceMismatch
	if errors.As(err, &mismatch) {
		return nil, ErrQuoteNotBound{Endpoint: ep.Address}
	}
	if err != nil {
		return nil, err
	}
	evidence.Nonce = nonce
	evidence.ChannelBinding = binding
	return evidence, nil
}

// ClockSynced implements ClockSource: it asks the node whether its own time
// daemon currently disciplines its clock.
//
// It is a separate request from the quote because it is a separate question
// and the node answers it from a different subsystem. Failure is an error,
// never a false — the collector renders an unreadable clock as unknown.
func (s *NodeQuoteSource) ClockSynced(ctx context.Context, deviceID string) (bool, error) {
	endpoints, err := s.addresses.Endpoints(ctx, deviceID)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	var attempts []string
	for _, ep := range endpoints {
		payload, err := s.request(ctx, ep, http.MethodGet, nodeClockPath, nil)
		if err == nil {
			return decodeNodeClock(payload)
		}
		attempts = append(attempts, ep.Address+" ("+ep.Source+"): "+err.Error())
		s.logger.Debug("attestation reporting: endpoint did not report clock state",
			"device_id", deviceID, "endpoint", ep.Address, "source", ep.Source, "error", err)
		if ctx.Err() != nil {
			break
		}
	}
	return false, ErrClockStateUnavailable{DeviceID: deviceID, Attempts: attempts}
}

// request performs one mTLS request against a node endpoint on a fresh
// connection and returns the body.
func (s *NodeQuoteSource) request(ctx context.Context, ep Endpoint, method, path string, body []byte) ([]byte, error) {
	conn, err := s.dial(ctx, ep)
	if err != nil {
		return nil, err
	}
	defer s.closeConn(conn)
	return s.exchange(ctx, ep, conn, method, path, body)
}

// dial opens one verified mTLS connection to a node endpoint. It holds the
// TLS policy both node calls share: the collector's identity, a verified
// handshake, and HTTP/1.1 only, because exchange speaks HTTP/1.1 over the
// connection it is handed. The handshake completes here so the caller can
// derive the channel binding before any request is sent.
func (s *NodeQuoteSource) dial(ctx context.Context, ep Endpoint) (*tls.Conn, error) {
	tlsCfg, err := s.tls(ctx, ep)
	if err != nil {
		return nil, err
	}
	if tlsCfg == nil {
		return nil, ErrNoTLSDialer{}
	}
	tlsCfg = tlsCfg.Clone()
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = ep.ServerName
	}
	if tlsCfg.InsecureSkipVerify {
		// A dialer that disables verification is a bug, and refusing here
		// is cheaper than explaining a quote from the wrong machine.
		return nil, ErrInsecureDialer{Endpoint: ep.Address}
	}
	if tlsCfg.MinVersion == 0 {
		tlsCfg.MinVersion = tls.VersionTLS12
	}
	tlsCfg.NextProtos = []string{"http/1.1"}

	var dialer net.Dialer
	raw, err := dialer.DialContext(ctx, "tcp", ep.Address)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, tlsCfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		s.closeConn(conn)
		return nil, err
	}
	return conn, nil
}

// closeConn closes a node connection. The HTTP transport may already have
// closed it after the response, which is not worth a log line.
func (s *NodeQuoteSource) closeConn(conn *tls.Conn) {
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.logger.Debug("attestation reporting: connection close", "error", err)
	}
}

// exchange sends one HTTP request over an already-dialled connection and
// returns the body: no second connection, no redirects, and a bounded read.
// The request must ride the connection the caller dialled, because that is
// the connection the channel binding was derived from.
func (s *NodeQuoteSource) exchange(ctx context.Context, ep Endpoint, conn *tls.Conn, method, path string, body []byte) ([]byte, error) {
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext:    singleUseDialer(ep, conn),
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+ep.Address+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			s.logger.Debug("attestation reporting: response body close", "error", closeErr)
		}
	}()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > maxResponseBytes {
		return nil, ErrInvalidEvidence{Reason: "response exceeds " + strconv.Itoa(maxResponseBytes) + " bytes"}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, ErrNodeRefused{Endpoint: ep.Address, Status: resp.StatusCode, Body: summarise(payload)}
	}
	return payload, nil
}

var _ ClockSource = (*NodeQuoteSource)(nil)

// singleUseDialer hands the HTTP transport one pre-dialled connection and
// refuses every later dial, so a retry cannot move the request onto a
// connection the channel binding was not derived from.
func singleUseDialer(ep Endpoint, conn net.Conn) func(context.Context, string, string) (net.Conn, error) {
	var handed atomic.Bool
	return func(context.Context, string, string) (net.Conn, error) {
		if !handed.CompareAndSwap(false, true) {
			return nil, ErrConnectionSpent{Endpoint: ep.Address}
		}
		return conn, nil
	}
}

// summarise keeps the first line of an error body for the audit trail
// without dragging a whole page into a log line.
func summarise(body []byte) string {
	s := strings.TrimSpace(string(body))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
