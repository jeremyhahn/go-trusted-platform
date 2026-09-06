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
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
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
	// newTransport is a test seam for the HTTP transport; nil uses a fresh
	// http.Transport per endpoint so no connection outlives a collection.
	newTransport func(cfg *tls.Config) http.RoundTripper
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

	body, err := s.requestBody(nonce)
	if err != nil {
		return nil, err
	}

	var attempts []string
	for _, ep := range endpoints {
		evidence, err := s.collectFrom(ctx, ep, body, nonce)
		if err == nil {
			return evidence.Encode()
		}
		attempts = append(attempts, ep.Address+" ("+ep.Source+"): "+err.Error())
		s.logger.Debug("attestation reporting: endpoint did not yield evidence",
			"device_id", deviceID, "endpoint", ep.Address, "source", ep.Source, "error", err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, ErrNodeUnreachable{DeviceID: deviceID, Attempts: attempts}
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

func (s *NodeQuoteSource) collectFrom(ctx context.Context, ep Endpoint, body, nonce []byte) (*Evidence, error) {
	payload, err := s.request(ctx, ep, http.MethodPost, hostAttestationPath, body)
	if err != nil {
		return nil, err
	}
	return decodeHostAttestation(payload, nonce)
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

// request performs one mTLS request against a node endpoint and returns the
// body. It holds the transport policy both node calls share: the collector's
// identity, a verified handshake, no connection reuse, no redirects, and a
// bounded read.
func (s *NodeQuoteSource) request(ctx context.Context, ep Endpoint, method, path string, body []byte) ([]byte, error) {
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

	var rt http.RoundTripper
	if s.newTransport != nil {
		rt = s.newTransport(tlsCfg)
	} else {
		transport := &http.Transport{TLSClientConfig: tlsCfg, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		rt = transport
	}
	client := &http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error {
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
