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

func (s *NodeQuoteSource) requestBody(nonce []byte) ([]byte, error) {
	req := map[string]any{"nonce": base64.StdEncoding.EncodeToString(nonce)}
	if len(s.pcrs) > 0 {
		req["config"] = map[string]any{"pcrIndices": s.pcrs}
	}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, ErrInvalidEvidence{Reason: "request could not be encoded: " + err.Error()}
	}
	return b, nil
}

func (s *NodeQuoteSource) collectFrom(ctx context.Context, ep Endpoint, body, nonce []byte) (*Evidence, error) {
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

	url := "https://" + ep.Address + hostAttestationPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
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
	return decodeHostAttestation(payload, nonce)
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
