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

package network

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

// Common certificate policy OIDs.
var (
	// OIDCertificatePolicies is the OID for the certificate policies extension.
	OIDCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}

	// OIDSubjectAltName is the OID for the subject alternative name extension.
	OIDSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

	// OIDExtendedKeyUsage is the OID for the extended key usage extension.
	OIDExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// PolicyExtractor extracts policy information from x509 certificates.
type PolicyExtractor interface {
	// ExtractPolicyInfo extracts policy information from a certificate.
	ExtractPolicyInfo(ctx context.Context, cert *x509.Certificate) (*PolicyInfo, error)

	// ExtractOIDs extracts policy OIDs from a certificate.
	ExtractOIDs(ctx context.Context, cert *x509.Certificate) ([]asn1.ObjectIdentifier, error)

	// ValidateRequiredOIDs validates that required OIDs are present.
	ValidateRequiredOIDs(ctx context.Context, cert *x509.Certificate, required []asn1.ObjectIdentifier) error
}

// OPAEvaluator evaluates policies using OPA.
type OPAEvaluator interface {
	// Initialize sets up the OPA evaluator.
	Initialize(ctx context.Context, endpoint string, policyPath string) error

	// Evaluate evaluates the policy with the given input.
	Evaluate(ctx context.Context, input *OPAInput) (*OPAResult, error)

	// Close releases resources.
	Close() error
}

// policyExtractor is the concrete implementation of PolicyExtractor.
type policyExtractor struct {
	logger *slog.Logger
}

// PolicyExtractorOption configures a policy extractor.
type PolicyExtractorOption func(*policyExtractor)

// WithPolicyExtractorLogger sets the logger for the policy extractor.
func WithPolicyExtractorLogger(logger *slog.Logger) PolicyExtractorOption {
	return func(p *policyExtractor) {
		p.logger = logger
	}
}

// NewPolicyExtractor creates a new policy extractor.
func NewPolicyExtractor(opts ...PolicyExtractorOption) PolicyExtractor {
	p := &policyExtractor{}

	for _, opt := range opts {
		opt(p)
	}

	if p.logger == nil {
		p.logger = slog.Default()
	}

	return p
}

// ExtractPolicyInfo extracts policy information from a certificate.
func (p *policyExtractor) ExtractPolicyInfo(ctx context.Context, cert *x509.Certificate) (*PolicyInfo, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "ExtractPolicyInfo"}
	default:
	}

	if cert == nil {
		return nil, ErrCertInvalid{Reason: "certificate is nil"}
	}

	oids, err := p.ExtractOIDs(ctx, cert)
	if err != nil {
		return nil, err
	}

	info := &PolicyInfo{
		OIDs:                 oids,
		PolicyQualifiers:     make(map[string]string),
		CertificateSubject:   cert.Subject.String(),
		CertificateIssuer:    cert.Issuer.String(),
		CertificateSerial:    cert.SerialNumber.String(),
		CertificateNotBefore: cert.NotBefore,
		CertificateNotAfter:  cert.NotAfter,
		ExtendedKeyUsages:    cert.ExtKeyUsage,
		KeyUsage:             cert.KeyUsage,
		IsCA:                 cert.IsCA,
		ExtractedAt:          time.Now().UTC(),
	}

	// Extract device ID from certificate subject CN
	if cert.Subject.CommonName != "" {
		info.DeviceID = cert.Subject.CommonName
	}

	p.logger.Debug("extracted policy info",
		"subject", info.CertificateSubject,
		"oid_count", len(oids),
		"device_id", info.DeviceID,
	)

	return info, nil
}

// ExtractOIDs extracts policy OIDs from a certificate.
func (p *policyExtractor) ExtractOIDs(ctx context.Context, cert *x509.Certificate) ([]asn1.ObjectIdentifier, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "ExtractOIDs"}
	default:
	}

	if cert == nil {
		return nil, ErrCertInvalid{Reason: "certificate is nil"}
	}

	// Initialize with empty slice to ensure non-nil return
	oids := make([]asn1.ObjectIdentifier, 0)

	// Extract from PolicyIdentifiers field
	oids = append(oids, cert.PolicyIdentifiers...)

	// Extract from certificate extensions (for custom policies)
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDCertificatePolicies) {
			policyOIDs, err := parseCertificatePolicies(ext.Value)
			if err != nil {
				p.logger.Warn("failed to parse certificate policies extension",
					"error", err,
				)
				continue
			}
			oids = append(oids, policyOIDs...)
		}
	}

	// Deduplicate OIDs
	oids = deduplicateOIDs(oids)

	return oids, nil
}

// ValidateRequiredOIDs validates that required OIDs are present.
func (p *policyExtractor) ValidateRequiredOIDs(
	ctx context.Context,
	cert *x509.Certificate,
	required []asn1.ObjectIdentifier,
) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "ValidateRequiredOIDs"}
	default:
	}

	if cert == nil {
		return ErrCertInvalid{Reason: "certificate is nil"}
	}

	if len(required) == 0 {
		return nil
	}

	oids, err := p.ExtractOIDs(ctx, cert)
	if err != nil {
		return err
	}

	for _, reqOID := range required {
		found := false
		for _, certOID := range oids {
			if reqOID.Equal(certOID) {
				found = true
				break
			}
		}
		if !found {
			return ErrOIDMissing{
				OID:     reqOID.String(),
				Subject: cert.Subject.String(),
			}
		}
	}

	return nil
}

// certificatePolicies represents the ASN.1 structure of certificate policies.
type certificatePolicies struct {
	PolicyIdentifier asn1.ObjectIdentifier
	PolicyQualifiers []policyQualifier `asn1:"optional"`
}

type policyQualifier struct {
	PolicyQualifierId asn1.ObjectIdentifier
	Qualifier         asn1.RawValue
}

// parseCertificatePolicies parses the certificate policies extension.
func parseCertificatePolicies(data []byte) ([]asn1.ObjectIdentifier, error) {
	var policies []certificatePolicies
	rest, err := asn1.Unmarshal(data, &policies)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, ErrCertInvalid{Reason: "trailing data in certificate policies"}
	}

	oids := make([]asn1.ObjectIdentifier, 0, len(policies))
	for _, policy := range policies {
		oids = append(oids, policy.PolicyIdentifier)
	}
	return oids, nil
}

// deduplicateOIDs removes duplicate OIDs from a slice.
// Always returns a non-nil slice (empty slice if no OIDs).
func deduplicateOIDs(oids []asn1.ObjectIdentifier) []asn1.ObjectIdentifier {
	seen := make(map[string]bool)
	result := make([]asn1.ObjectIdentifier, 0, len(oids))

	for _, oid := range oids {
		key := oid.String()
		if !seen[key] {
			seen[key] = true
			result = append(result, oid)
		}
	}

	return result
}

// opaEvaluator is the concrete implementation of OPAEvaluator.
type opaEvaluator struct {
	initialized atomic.Bool
	closed      atomic.Bool
	endpoint    string
	policyPath  string
	client      *http.Client
	logger      *slog.Logger
}

// OPAEvaluatorOption configures an OPA evaluator.
type OPAEvaluatorOption func(*opaEvaluator)

// WithOPAEvaluatorLogger sets the logger for the OPA evaluator.
func WithOPAEvaluatorLogger(logger *slog.Logger) OPAEvaluatorOption {
	return func(o *opaEvaluator) {
		o.logger = logger
	}
}

// WithOPAHTTPClient sets the HTTP client for the OPA evaluator.
func WithOPAHTTPClient(client *http.Client) OPAEvaluatorOption {
	return func(o *opaEvaluator) {
		o.client = client
	}
}

// NewOPAEvaluator creates a new OPA evaluator.
func NewOPAEvaluator(opts ...OPAEvaluatorOption) OPAEvaluator {
	o := &opaEvaluator{}

	for _, opt := range opts {
		opt(o)
	}

	if o.logger == nil {
		o.logger = slog.Default()
	}

	if o.client == nil {
		o.client = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	return o
}

// Initialize sets up the OPA evaluator.
func (o *opaEvaluator) Initialize(ctx context.Context, endpoint string, policyPath string) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "Initialize"}
	default:
	}

	if o.initialized.Load() {
		return ErrInvalidConfig{Reason: "OPA evaluator already initialized"}
	}

	if endpoint == "" {
		return ErrInvalidConfig{Field: "endpoint", Reason: "OPA endpoint cannot be empty"}
	}

	if policyPath == "" {
		return ErrInvalidConfig{Field: "policyPath", Reason: "OPA policy path cannot be empty"}
	}

	o.endpoint = endpoint
	o.policyPath = policyPath
	o.initialized.Store(true)

	o.logger.Info("OPA evaluator initialized",
		"endpoint", endpoint,
		"policy_path", policyPath,
	)

	return nil
}

// opaRequest represents the OPA query request.
type opaRequest struct {
	Input *OPAInput `json:"input"`
}

// opaResponse represents the OPA query response.
type opaResponse struct {
	Result *OPAResult `json:"result"`
}

// Evaluate evaluates the policy with the given input.
func (o *opaEvaluator) Evaluate(ctx context.Context, input *OPAInput) (*OPAResult, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "Evaluate"}
	default:
	}

	if !o.initialized.Load() {
		return nil, ErrServiceNotInitialized{}
	}

	if o.closed.Load() {
		return nil, ErrServiceNotInitialized{}
	}

	if input == nil {
		return nil, ErrInvalidConfig{Field: "input", Reason: "OPA input cannot be nil"}
	}

	// Build the OPA query URL
	url := o.endpoint + "/v1/data/" + o.policyPath

	// Marshal the request
	reqBody := opaRequest{Input: input}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, ErrOPAEvaluation{
			Endpoint:   o.endpoint,
			PolicyPath: o.policyPath,
			Reason:     "failed to marshal input",
			Cause:      err,
		}
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonData))
	if err != nil {
		return nil, ErrOPAEvaluation{
			Endpoint:   o.endpoint,
			PolicyPath: o.policyPath,
			Reason:     "failed to create request",
			Cause:      err,
		}
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, ErrOPAEvaluation{
			Endpoint:   o.endpoint,
			PolicyPath: o.policyPath,
			Reason:     "request failed",
			Cause:      err,
		}
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrOPAEvaluation{
			Endpoint:   o.endpoint,
			PolicyPath: o.policyPath,
			Reason:     "failed to read response",
			Cause:      err,
		}
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, ErrOPAEvaluation{
			Endpoint:   o.endpoint,
			PolicyPath: o.policyPath,
			Reason:     "unexpected status code: " + resp.Status,
		}
	}

	// Parse response
	var opaResp opaResponse
	if err := json.Unmarshal(body, &opaResp); err != nil {
		return nil, ErrOPAEvaluation{
			Endpoint:   o.endpoint,
			PolicyPath: o.policyPath,
			Reason:     "failed to parse response",
			Cause:      err,
		}
	}

	result := opaResp.Result
	if result == nil {
		// Default to deny if no result
		result = &OPAResult{
			Allow:       false,
			Reasons:     []string{"no policy result"},
			EvaluatedAt: time.Now().UTC(),
		}
	} else {
		result.EvaluatedAt = time.Now().UTC()
	}

	o.logger.Debug("OPA evaluation complete",
		"allow", result.Allow,
		"assigned_vlan", result.AssignedVLAN,
		"reasons", result.Reasons,
	)

	return result, nil
}

// Close releases resources.
func (o *opaEvaluator) Close() error {
	if o.closed.Swap(true) {
		return nil
	}

	o.logger.Info("OPA evaluator closed")
	return nil
}

// OIDToString converts an OID to its string representation.
func OIDToString(oid asn1.ObjectIdentifier) string {
	return oid.String()
}

// OIDsToStrings converts a slice of OIDs to their string representations.
func OIDsToStrings(oids []asn1.ObjectIdentifier) []string {
	result := make([]string, len(oids))
	for i, oid := range oids {
		result[i] = oid.String()
	}
	return result
}
