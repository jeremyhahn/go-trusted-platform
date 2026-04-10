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

package attestation

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

const (
	requestTimeout = 30 * time.Second
)

// AttestationService defines the interface for attestation operations.
type AttestationService interface {
	// GetManifest returns the current host manifest.
	GetManifest(ctx context.Context) (*manifest.HostManifest, error)

	// BuildManifest generates a fresh attestation manifest.
	BuildManifest(ctx context.Context, opts *BuildManifestOptions) (*manifest.HostManifest, error)

	// VerifyManifest verifies a host manifest.
	VerifyManifest(ctx context.Context, m *manifest.HostManifest, publicKey crypto.PublicKey, expectedNonce []byte) (*manifest.VerificationResult, error)

	// GetQuote generates a TPM quote.
	GetQuote(ctx context.Context, opts *GetQuoteOptions) (*QuoteResult, error)

	// VerifyQuote verifies a TPM quote.
	VerifyQuote(ctx context.Context, opts *VerifyQuoteOptions) (*manifest.VerificationResult, error)
}

// BuildManifestOptions contains options for building a manifest.
type BuildManifestOptions struct {
	HostID            string
	Nonce             []byte
	PCRIndices        []int
	HashAlgorithm     manifest.HashAlgorithm
	IncludeVMs        bool
	IncludeContainers bool
}

// GetQuoteOptions contains options for generating a quote.
type GetQuoteOptions struct {
	Nonce         []byte
	PCRIndices    []int
	HashAlgorithm manifest.HashAlgorithm
}

// VerifyQuoteOptions contains options for verifying a quote.
type VerifyQuoteOptions struct {
	QuoteData     []byte
	Signature     []byte
	PublicKey     crypto.PublicKey
	ExpectedNonce []byte
	PCRs          []manifest.PCRValue
	HashAlgorithm manifest.HashAlgorithm
}

// QuoteResult contains the result of a quote generation.
type QuoteResult struct {
	QuoteData          []byte
	Signature          []byte
	SignatureAlgorithm string
	PCRs               []manifest.PCRValue
	PCRDigest          []byte
	Nonce              []byte
	Timestamp          time.Time
	AKPublicKey        []byte
	HashAlgorithm      manifest.HashAlgorithm
}

// AttestationHandlers provides REST handlers for attestation operations.
type AttestationHandlers struct {
	logger     *logging.Logger
	service    AttestationService
	respWriter response.HttpWriter
}

// NewAttestationHandlers creates a new AttestationHandlers instance.
func NewAttestationHandlers(
	logger *logging.Logger,
	service AttestationService,
	respWriter response.HttpWriter,
) *AttestationHandlers {
	return &AttestationHandlers{
		logger:     logger,
		service:    service,
		respWriter: respWriter,
	}
}

// Helper methods

func (h *AttestationHandlers) createContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), requestTimeout)
}

func (h *AttestationHandlers) decodeJSON(r *http.Request, v interface{}) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

func (h *AttestationHandlers) handleServiceError(w http.ResponseWriter, r *http.Request, err error) {
	errMsg := err.Error()
	lowerMsg := strings.ToLower(errMsg)

	if containsAny(lowerMsg, "not found", "does not exist", "no such") {
		h.respWriter.Error404(w, r, err)
		return
	}

	if containsAny(lowerMsg, "invalid", "required", "must be", "cannot be", "unsupported") {
		h.respWriter.Error400(w, r, err)
		return
	}

	h.respWriter.Error500(w, r, err)
}

func (h *AttestationHandlers) parseHashAlgorithm(alg string) manifest.HashAlgorithm {
	switch strings.ToLower(alg) {
	case "sha384":
		return manifest.HashAlgorithmSHA384
	case "sha512":
		return manifest.HashAlgorithmSHA512
	case "sha1":
		return manifest.HashAlgorithmSHA1
	default:
		return manifest.HashAlgorithmSHA256
	}
}

func (h *AttestationHandlers) validatePCRIndices(indices []int) error {
	for _, idx := range indices {
		if idx < 0 || idx > 23 {
			return ErrInvalidPCRIndex{Index: idx}
		}
	}
	return nil
}

func (h *AttestationHandlers) getDefaultPCRIndices() []int {
	return []int{0, 1, 2, 3, 4, 5, 6, 7, 14}
}

// Manifest Handlers

// GetManifest handles GET /api/v1/attestation/manifest
func (h *AttestationHandlers) GetManifest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.createContext()
	defer cancel()

	m, err := h.service.GetManifest(ctx)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	if m == nil {
		h.respWriter.Error404(w, r, ErrManifestNotFound{})
		return
	}

	h.respWriter.Success200(w, r, h.manifestToResponse(m))
}

// BuildManifest handles POST /api/v1/attestation/manifest/build
func (h *AttestationHandlers) BuildManifest(w http.ResponseWriter, r *http.Request) {
	var req BuildManifestRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	// Parse hash algorithm
	hashAlg := manifest.HashAlgorithmSHA256
	if req.HashAlgorithm != "" {
		hashAlg = h.parseHashAlgorithm(req.HashAlgorithm)
		if !hashAlg.IsValid() {
			h.respWriter.Error400(w, r, ErrInvalidHashAlgorithm{Algorithm: req.HashAlgorithm})
			return
		}
	}

	// Parse PCR indices
	pcrIndices := h.getDefaultPCRIndices()
	if len(req.PCRIndices) > 0 {
		if err := h.validatePCRIndices(req.PCRIndices); err != nil {
			h.respWriter.Error400(w, r, err)
			return
		}
		pcrIndices = req.PCRIndices
	}

	// Parse nonce if provided
	var nonce []byte
	if req.Nonce != "" {
		var err error
		nonce, err = base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			h.respWriter.Error400(w, r, ErrInvalidBase64{Field: "nonce", Reason: err.Error()})
			return
		}
	}

	ctx, cancel := h.createContext()
	defer cancel()

	opts := &BuildManifestOptions{
		HostID:            req.HostID,
		Nonce:             nonce,
		PCRIndices:        pcrIndices,
		HashAlgorithm:     hashAlg,
		IncludeVMs:        req.IncludeVMs,
		IncludeContainers: req.IncludeContainers,
	}

	m, err := h.service.BuildManifest(ctx, opts)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.respWriter.Success201(w, r, h.manifestToResponse(m))
}

// VerifyManifest handles POST /api/v1/attestation/verify
func (h *AttestationHandlers) VerifyManifest(w http.ResponseWriter, r *http.Request) {
	var req VerifyManifestRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Manifest == nil {
		h.respWriter.Error400(w, r, ErrMissingManifest{})
		return
	}

	// Convert request to manifest
	m, err := h.requestToManifest(req.Manifest)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}

	// Parse expected nonce if provided
	var expectedNonce []byte
	if req.ExpectedNonce != "" {
		expectedNonce, err = base64.StdEncoding.DecodeString(req.ExpectedNonce)
		if err != nil {
			h.respWriter.Error400(w, r, ErrInvalidBase64{Field: "expected_nonce", Reason: err.Error()})
			return
		}
	}

	// Parse public key if provided
	var publicKey crypto.PublicKey
	if req.PublicKeyPEM != "" {
		publicKey, err = manifest.ParsePublicKey([]byte(req.PublicKeyPEM))
		if err != nil {
			h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: "invalid public key: " + err.Error()})
			return
		}
	}

	ctx, cancel := h.createContext()
	defer cancel()

	result, err := h.service.VerifyManifest(ctx, m, publicKey, expectedNonce)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.verificationResultToResponse(result))
}

// Quote Handlers

// GetQuote handles GET /api/v1/attestation/quote
func (h *AttestationHandlers) GetQuote(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	nonceStr := r.URL.Query().Get("nonce")
	pcrStr := r.URL.Query().Get("pcrs")
	hashAlgStr := r.URL.Query().Get("hash_algorithm")

	// Parse nonce
	var nonce []byte
	if nonceStr != "" {
		var err error
		nonce, err = base64.StdEncoding.DecodeString(nonceStr)
		if err != nil {
			h.respWriter.Error400(w, r, ErrInvalidBase64{Field: "nonce", Reason: err.Error()})
			return
		}
	}

	// Parse PCR indices
	pcrIndices := h.getDefaultPCRIndices()
	if pcrStr != "" {
		var err error
		pcrIndices, err = h.parsePCRString(pcrStr)
		if err != nil {
			h.respWriter.Error400(w, r, err)
			return
		}
	}

	// Parse hash algorithm
	hashAlg := manifest.HashAlgorithmSHA256
	if hashAlgStr != "" {
		hashAlg = h.parseHashAlgorithm(hashAlgStr)
		if !hashAlg.IsValid() {
			h.respWriter.Error400(w, r, ErrInvalidHashAlgorithm{Algorithm: hashAlgStr})
			return
		}
	}

	ctx, cancel := h.createContext()
	defer cancel()

	opts := &GetQuoteOptions{
		Nonce:         nonce,
		PCRIndices:    pcrIndices,
		HashAlgorithm: hashAlg,
	}

	result, err := h.service.GetQuote(ctx, opts)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.quoteResultToResponse(result))
}

// VerifyQuote handles POST /api/v1/attestation/quote/verify
func (h *AttestationHandlers) VerifyQuote(w http.ResponseWriter, r *http.Request) {
	var req VerifyQuoteRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	// Validate required fields
	if req.QuoteData == "" {
		h.respWriter.Error400(w, r, ErrMissingQuoteData{})
		return
	}

	if req.Signature == "" {
		h.respWriter.Error400(w, r, ErrMissingSignature{})
		return
	}

	if req.PublicKeyPEM == "" {
		h.respWriter.Error400(w, r, ErrMissingPublicKey{})
		return
	}

	if req.ExpectedNonce == "" {
		h.respWriter.Error400(w, r, ErrMissingNonce{})
		return
	}

	// Decode quote data
	quoteData, err := base64.StdEncoding.DecodeString(req.QuoteData)
	if err != nil {
		h.respWriter.Error400(w, r, ErrInvalidBase64{Field: "quote_data", Reason: err.Error()})
		return
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		h.respWriter.Error400(w, r, ErrInvalidBase64{Field: "signature", Reason: err.Error()})
		return
	}

	// Parse public key
	publicKey, err := manifest.ParsePublicKey([]byte(req.PublicKeyPEM))
	if err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: "invalid public key: " + err.Error()})
		return
	}

	// Decode expected nonce
	expectedNonce, err := base64.StdEncoding.DecodeString(req.ExpectedNonce)
	if err != nil {
		h.respWriter.Error400(w, r, ErrInvalidBase64{Field: "expected_nonce", Reason: err.Error()})
		return
	}

	// Parse PCR values
	var pcrs []manifest.PCRValue
	for _, pcrReq := range req.PCRs {
		value, err := base64.StdEncoding.DecodeString(pcrReq.Value)
		if err != nil {
			h.respWriter.Error400(w, r, ErrInvalidBase64{Field: "pcr_value", Reason: err.Error()})
			return
		}
		pcrs = append(pcrs, manifest.PCRValue{
			Index:     pcrReq.Index,
			Value:     value,
			Algorithm: h.parseHashAlgorithm(pcrReq.Algorithm),
		})
	}

	// Parse hash algorithm
	hashAlg := manifest.HashAlgorithmSHA256
	if req.HashAlgorithm != "" {
		hashAlg = h.parseHashAlgorithm(req.HashAlgorithm)
	}

	ctx, cancel := h.createContext()
	defer cancel()

	opts := &VerifyQuoteOptions{
		QuoteData:     quoteData,
		Signature:     signature,
		PublicKey:     publicKey,
		ExpectedNonce: expectedNonce,
		PCRs:          pcrs,
		HashAlgorithm: hashAlg,
	}

	result, err := h.service.VerifyQuote(ctx, opts)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.verificationResultToResponse(result))
}

// Conversion helpers

func (h *AttestationHandlers) manifestToResponse(m *manifest.HostManifest) *ManifestResponse {
	if m == nil {
		return nil
	}

	resp := &ManifestResponse{
		ID:             m.ID,
		HostID:         m.HostID,
		Timestamp:      m.Timestamp,
		Nonce:          base64.StdEncoding.EncodeToString(m.Nonce),
		VMCount:        len(m.VMs),
		ContainerCount: len(m.Containers),
		MerkleRoot:     base64.StdEncoding.EncodeToString(m.MerkleRoot),
		Version:        m.Version,
		Metadata:       m.Metadata,
	}

	if len(m.Signature) > 0 {
		resp.Signature = base64.StdEncoding.EncodeToString(m.Signature)
		resp.SignatureAlgorithm = m.SignatureAlgorithm
	}

	if m.Host != nil {
		resp.Host = h.hostAttestationToResponse(m.Host)
	}

	return resp
}

func (h *AttestationHandlers) hostAttestationToResponse(a *manifest.HostAttestation) *HostAttestationResponse {
	if a == nil {
		return nil
	}

	resp := &HostAttestationResponse{
		QuoteData:          base64.StdEncoding.EncodeToString(a.QuoteData),
		Signature:          base64.StdEncoding.EncodeToString(a.Signature),
		SignatureAlgorithm: a.SignatureAlgorithm,
		PCRDigest:          base64.StdEncoding.EncodeToString(a.PCRDigest),
		Nonce:              base64.StdEncoding.EncodeToString(a.Nonce),
		Timestamp:          a.Timestamp,
		HashAlgorithm:      a.HashAlgorithm.String(),
		FirmwareVersion:    a.FirmwareVersion,
	}

	if len(a.AKPublicKey) > 0 {
		resp.AKPublicKeyPEM = string(a.AKPublicKey)
	}

	for _, pcr := range a.PCRs {
		resp.PCRs = append(resp.PCRs, PCRValueResponse{
			Index:     pcr.Index,
			Value:     base64.StdEncoding.EncodeToString(pcr.Value),
			Algorithm: pcr.Algorithm.String(),
		})
	}

	return resp
}

func (h *AttestationHandlers) quoteResultToResponse(q *QuoteResult) *QuoteResponse {
	if q == nil {
		return nil
	}

	resp := &QuoteResponse{
		QuoteData:          base64.StdEncoding.EncodeToString(q.QuoteData),
		Signature:          base64.StdEncoding.EncodeToString(q.Signature),
		SignatureAlgorithm: q.SignatureAlgorithm,
		PCRDigest:          base64.StdEncoding.EncodeToString(q.PCRDigest),
		Nonce:              base64.StdEncoding.EncodeToString(q.Nonce),
		Timestamp:          q.Timestamp,
		AKPublicKeyPEM:     string(q.AKPublicKey),
		HashAlgorithm:      q.HashAlgorithm.String(),
	}

	for _, pcr := range q.PCRs {
		resp.PCRs = append(resp.PCRs, PCRValueResponse{
			Index:     pcr.Index,
			Value:     base64.StdEncoding.EncodeToString(pcr.Value),
			Algorithm: pcr.Algorithm.String(),
		})
	}

	return resp
}

func (h *AttestationHandlers) verificationResultToResponse(r *manifest.VerificationResult) *VerificationResponse {
	if r == nil {
		return nil
	}

	return &VerificationResponse{
		Valid:                      r.Status == manifest.VerificationStatusVerified,
		Status:                     r.Status.String(),
		SignatureValid:             r.SignatureValid,
		MerkleRootValid:            r.MerkleRootValid,
		NonceValid:                 r.NonceValid,
		TimestampValid:             r.TimestampValid,
		HostAttestationValid:       r.HostAttestationValid,
		VMAttestationsValid:        r.VMAttestationsValid,
		ContainerAttestationsValid: r.ContainerAttestationsValid,
		VerifiedAt:                 r.VerifiedAt,
		Errors:                     r.Errors,
	}
}

func (h *AttestationHandlers) requestToManifest(req *ManifestRequest) (*manifest.HostManifest, error) {
	if req == nil {
		return nil, ErrMissingManifest{}
	}

	// Decode nonce
	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		return nil, ErrInvalidBase64{Field: "nonce", Reason: err.Error()}
	}

	// Decode merkle root
	merkleRoot, err := base64.StdEncoding.DecodeString(req.MerkleRoot)
	if err != nil {
		return nil, ErrInvalidBase64{Field: "merkle_root", Reason: err.Error()}
	}

	// Decode signature
	var signature []byte
	if req.Signature != "" {
		signature, err = base64.StdEncoding.DecodeString(req.Signature)
		if err != nil {
			return nil, ErrInvalidBase64{Field: "signature", Reason: err.Error()}
		}
	}

	m := &manifest.HostManifest{
		ID:                 req.ID,
		HostID:             req.HostID,
		Timestamp:          req.Timestamp,
		Nonce:              nonce,
		MerkleRoot:         merkleRoot,
		Signature:          signature,
		SignatureAlgorithm: req.SignatureAlgorithm,
		Version:            req.Version,
		Metadata:           req.Metadata,
	}

	// Convert host attestation
	if req.Host != nil {
		host, err := h.requestToHostAttestation(req.Host)
		if err != nil {
			return nil, err
		}
		m.Host = host
	}

	// Convert VM attestations
	for _, vmReq := range req.VMs {
		vm, err := h.requestToVMAttestation(&vmReq)
		if err != nil {
			return nil, err
		}
		m.VMs = append(m.VMs, *vm)
	}

	// Convert container attestations
	for _, containerReq := range req.Containers {
		container, err := h.requestToContainerAttestation(&containerReq)
		if err != nil {
			return nil, err
		}
		m.Containers = append(m.Containers, *container)
	}

	return m, nil
}

func (h *AttestationHandlers) requestToHostAttestation(req *HostAttestationRequest) (*manifest.HostAttestation, error) {
	if req == nil {
		return nil, nil
	}

	quoteData, err := base64.StdEncoding.DecodeString(req.QuoteData)
	if err != nil {
		return nil, ErrInvalidBase64{Field: "quote_data", Reason: err.Error()}
	}

	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return nil, ErrInvalidBase64{Field: "signature", Reason: err.Error()}
	}

	pcrDigest, err := base64.StdEncoding.DecodeString(req.PCRDigest)
	if err != nil {
		return nil, ErrInvalidBase64{Field: "pcr_digest", Reason: err.Error()}
	}

	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		return nil, ErrInvalidBase64{Field: "nonce", Reason: err.Error()}
	}

	var akPublicKey []byte
	if req.AKPublicKey != "" {
		akPublicKey, err = base64.StdEncoding.DecodeString(req.AKPublicKey)
		if err != nil {
			return nil, ErrInvalidBase64{Field: "ak_public_key", Reason: err.Error()}
		}
	}

	var idevidCert []byte
	if req.IDevIDCertificate != "" {
		idevidCert, err = base64.StdEncoding.DecodeString(req.IDevIDCertificate)
		if err != nil {
			return nil, ErrInvalidBase64{Field: "idevid_certificate", Reason: err.Error()}
		}
	}

	host := &manifest.HostAttestation{
		QuoteData:          quoteData,
		Signature:          signature,
		SignatureAlgorithm: req.SignatureAlgorithm,
		PCRDigest:          pcrDigest,
		Nonce:              nonce,
		Timestamp:          req.Timestamp,
		AKPublicKey:        akPublicKey,
		IDevIDCertificate:  idevidCert,
		HashAlgorithm:      h.parseHashAlgorithm(req.HashAlgorithm),
		FirmwareVersion:    req.FirmwareVersion,
	}

	// Convert PCRs
	for _, pcrReq := range req.PCRs {
		value, err := base64.StdEncoding.DecodeString(pcrReq.Value)
		if err != nil {
			return nil, ErrInvalidBase64{Field: "pcr_value", Reason: err.Error()}
		}
		host.PCRs = append(host.PCRs, manifest.PCRValue{
			Index:     pcrReq.Index,
			Value:     value,
			Algorithm: h.parseHashAlgorithm(pcrReq.Algorithm),
		})
	}

	return host, nil
}

func (h *AttestationHandlers) requestToVMAttestation(req *VMAttestationRequest) (*manifest.VMAttestation, error) {
	if req == nil {
		return nil, nil
	}

	quoteData, err := base64.StdEncoding.DecodeString(req.QuoteData)
	if err != nil {
		return nil, ErrInvalidBase64{Field: "quote_data", Reason: err.Error()}
	}

	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return nil, ErrInvalidBase64{Field: "signature", Reason: err.Error()}
	}

	pcrDigest, err := base64.StdEncoding.DecodeString(req.PCRDigest)
	if err != nil {
		return nil, ErrInvalidBase64{Field: "pcr_digest", Reason: err.Error()}
	}

	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		return nil, ErrInvalidBase64{Field: "nonce", Reason: err.Error()}
	}

	var aikPublicKey []byte
	if req.AIKPublicKey != "" {
		aikPublicKey, err = base64.StdEncoding.DecodeString(req.AIKPublicKey)
		if err != nil {
			return nil, ErrInvalidBase64{Field: "aik_public_key", Reason: err.Error()}
		}
	}

	var ekCert []byte
	if req.EKCertificate != "" {
		ekCert, err = base64.StdEncoding.DecodeString(req.EKCertificate)
		if err != nil {
			return nil, ErrInvalidBase64{Field: "ek_certificate", Reason: err.Error()}
		}
	}

	var workloadPCR []byte
	if req.WorkloadPCR != "" {
		workloadPCR, err = base64.StdEncoding.DecodeString(req.WorkloadPCR)
		if err != nil {
			return nil, ErrInvalidBase64{Field: "workload_pcr", Reason: err.Error()}
		}
	}

	vm := &manifest.VMAttestation{
		VMID:               req.VMID,
		HostID:             req.HostID,
		QuoteData:          quoteData,
		Signature:          signature,
		SignatureAlgorithm: req.SignatureAlgorithm,
		PCRDigest:          pcrDigest,
		Nonce:              nonce,
		Timestamp:          req.Timestamp,
		AIKPublicKey:       aikPublicKey,
		EKCertificate:      ekCert,
		WorkloadPCR:        workloadPCR,
		HashAlgorithm:      h.parseHashAlgorithm(req.HashAlgorithm),
		Metadata:           req.Metadata,
	}

	// Convert PCRs
	for _, pcrReq := range req.PCRs {
		value, err := base64.StdEncoding.DecodeString(pcrReq.Value)
		if err != nil {
			return nil, ErrInvalidBase64{Field: "pcr_value", Reason: err.Error()}
		}
		vm.PCRs = append(vm.PCRs, manifest.PCRValue{
			Index:     pcrReq.Index,
			Value:     value,
			Algorithm: h.parseHashAlgorithm(pcrReq.Algorithm),
		})
	}

	return vm, nil
}

func (h *AttestationHandlers) requestToContainerAttestation(req *ContainerAttestationRequest) (*manifest.ContainerAttestation, error) {
	if req == nil {
		return nil, nil
	}

	digest, err := base64.StdEncoding.DecodeString(req.Digest)
	if err != nil {
		return nil, ErrInvalidBase64{Field: "digest", Reason: err.Error()}
	}

	pcrValue, err := base64.StdEncoding.DecodeString(req.PCRValue)
	if err != nil {
		return nil, ErrInvalidBase64{Field: "pcr_value", Reason: err.Error()}
	}

	return &manifest.ContainerAttestation{
		ContainerID: req.ContainerID,
		ImageID:     req.ImageID,
		ImageDigest: req.ImageDigest,
		Digest:      digest,
		PCRValue:    pcrValue,
		Timestamp:   req.Timestamp,
		Metadata:    req.Metadata,
	}, nil
}

func (h *AttestationHandlers) parsePCRString(pcrStr string) ([]int, error) {
	parts := strings.Split(pcrStr, ",")
	indices := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var idx int
		err := json.Unmarshal([]byte(part), &idx)
		if err != nil {
			return nil, ErrInvalidRequestBody{Reason: "invalid PCR index: " + part}
		}
		if idx < 0 || idx > 23 {
			return nil, ErrInvalidPCRIndex{Index: idx}
		}
		indices = append(indices, idx)
	}
	if len(indices) == 0 {
		return h.getDefaultPCRIndices(), nil
	}
	return indices, nil
}

// containsAny checks if the string contains any of the substrings.
func containsAny(s string, substrings ...string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
