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

package kms

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
)

// Handlers serves /api/v1/kms by delegating to QuicBaaS SDK clients.
type Handlers struct {
	logger     *logging.Logger
	kms        kmsclient.Client
	crypto     cryptoclient.Client
	dek        dekclient.Client
	secrets    secretsclient.Client
	respWriter response.HttpWriter
}

// NewHandlers wires the supplied SDK clients.
func NewHandlers(
	logger *logging.Logger,
	kms kmsclient.Client,
	crypto cryptoclient.Client,
	dek dekclient.Client,
	secrets secretsclient.Client,
	respWriter response.HttpWriter,
) *Handlers {
	return &Handlers{
		logger:     logger,
		kms:        kms,
		crypto:     crypto,
		dek:        dek,
		secrets:    secrets,
		respWriter: respWriter,
	}
}

const requestTimeout = 30 * time.Second

func (h *Handlers) ctx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), requestTimeout)
}

func (h *Handlers) name(r *http.Request) string { return mux.Vars(r)["name"] }
func (h *Handlers) path(r *http.Request) string { return mux.Vars(r)["path"] }

// decodeJSON reads the request body into v. Empty body is OK.
func (h *Handlers) decodeJSON(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, v)
}

// success200 writes a 200 envelope.
func (h *Handlers) success200(w http.ResponseWriter, r *http.Request, payload interface{}) {
	h.respWriter.Success200(w, r, payload)
}

// success201 writes a 201 envelope.
func (h *Handlers) success201(w http.ResponseWriter, r *http.Request, payload interface{}) {
	h.respWriter.Success201(w, r, payload)
}

// fail maps SDK errors onto HTTP statuses. SDK returns errors that may
// embed gRPC codes; the QuicBaaS SDK exposes message-level prefixes we
// can match on for not-found / invalid-input / unauthenticated.
func (h *Handlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		h.respWriter.Error500(w, r, errors.New("unknown error"))
		return
	}
	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "not found"), strings.Contains(low, "no such"):
		h.respWriter.Error404(w, r, err)
	case strings.Contains(low, "invalid"), strings.Contains(low, "validation"):
		h.respWriter.Error400(w, r, err)
	case strings.Contains(low, "unauthenticated"), strings.Contains(low, "unauthorized"):
		h.respWriter.Error401(w, r, err)
	case strings.Contains(low, "permission denied"), strings.Contains(low, "forbidden"):
		h.respWriter.Error403(w, r, err, nil)
	default:
		h.respWriter.Error500(w, r, err)
	}
}

// =============================================================================
// Algorithm / status / usage / hash mappings
// =============================================================================

func parseKeyAlgorithm(s string) (kmsclient.KeyAlgorithm, error) {
	// Normalise underscores to dashes so SDK SCREAMING_SNAKE_CASE
	// (e.g. AES_256_GCM, RSA_2048) maps onto the same canonical form
	// the REST contract expects (AES-256-GCM, RSA-2048).
	canon := strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(s)), "_", "-")
	switch canon {
	case "AES-256-GCM", "AES256GCM", "AES-256":
		return kmsclient.AlgorithmAES256GCM, nil
	case "CHACHA20-POLY1305", "CHACHA20POLY1305":
		return kmsclient.AlgorithmChaCha20Poly1305, nil
	case "RSA-2048", "RSA2048":
		return kmsclient.AlgorithmRSA2048, nil
	case "RSA-4096", "RSA4096":
		return kmsclient.AlgorithmRSA4096, nil
	case "ECDSA-P256", "ECDSAP256", "P256":
		return kmsclient.AlgorithmECDSAP256, nil
	case "ECDSA-P384", "ECDSAP384", "P384":
		return kmsclient.AlgorithmECDSAP384, nil
	case "ED25519":
		return kmsclient.AlgorithmED25519, nil
	}
	return kmsclient.AlgorithmAES256GCM, &ErrUnknownAlgorithm{Algorithm: s}
}

func parseKeyUsage(ss []string) ([]kmsclient.KeyUsage, error) {
	out := make([]kmsclient.KeyUsage, 0, len(ss))
	for _, s := range ss {
		switch strings.ToUpper(strings.TrimSpace(s)) {
		case "ENCRYPT":
			out = append(out, kmsclient.KeyUsageEncrypt)
		case "DECRYPT":
			out = append(out, kmsclient.KeyUsageDecrypt)
		case "SIGN":
			out = append(out, kmsclient.KeyUsageSign)
		case "VERIFY":
			out = append(out, kmsclient.KeyUsageVerify)
		case "WRAP":
			out = append(out, kmsclient.KeyUsageWrap)
		case "UNWRAP":
			out = append(out, kmsclient.KeyUsageUnwrap)
		default:
			return nil, &ErrInvalidRequest{Field: "usage", Reason: "unknown usage " + s}
		}
	}
	return out, nil
}

func keyUsageToStrings(usages []kmsclient.KeyUsage) []string {
	out := make([]string, 0, len(usages))
	for _, u := range usages {
		out = append(out, u.String())
	}
	return out
}

func parseKeyStatus(s string) (kmsclient.KeyStatus, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ENABLED":
		return kmsclient.KeyStatusEnabled, nil
	case "DISABLED":
		return kmsclient.KeyStatusDisabled, nil
	case "PENDING_DELETION":
		return kmsclient.KeyStatusPendingDeletion, nil
	case "DELETED":
		return kmsclient.KeyStatusDeleted, nil
	case "ROTATING":
		return kmsclient.KeyStatusRotating, nil
	case "COMPROMISED":
		return kmsclient.KeyStatusCompromised, nil
	}
	return kmsclient.KeyStatusEnabled, &ErrInvalidRequest{Field: "status", Reason: "unknown status " + s}
}

func parseHashAlgorithm(s string) cryptoclient.HashAlgorithm {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "SHA-384", "SHA384":
		return cryptoclient.HashSHA384
	case "SHA-512", "SHA512":
		return cryptoclient.HashSHA512
	}
	return cryptoclient.HashSHA256
}

// =============================================================================
// Keys (kms.Client)
// =============================================================================

func (h *Handlers) ensureKMS(w http.ResponseWriter, r *http.Request) bool {
	if h.kms == nil {
		h.respWriter.Error500(w, r, &ErrServiceUnavailable{Service: "key-management"})
		return false
	}
	return true
}

// GenerateKey handles POST /api/v1/kms/keys.
func (h *Handlers) GenerateKey(w http.ResponseWriter, r *http.Request) {
	if !h.ensureKMS(w, r) {
		return
	}
	var req GenerateKeyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.Resolve()
	alg, err := parseKeyAlgorithm(req.Algorithm)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	usages, err := parseKeyUsage(req.Usage)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.kms.GenerateKey(ctx, &kmsclient.GenerateKeyRequest{
		Name:      req.Name,
		Algorithm: alg,
		Usage:     usages,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success201(w, r, &GenerateKeyResponse{
		KeyID:     resp.KeyID,
		Version:   resp.Version,
		Algorithm: resp.Algorithm.String(),
	})
}

// ImportKey handles POST /api/v1/kms/keys/import.
func (h *Handlers) ImportKey(w http.ResponseWriter, r *http.Request) {
	if !h.ensureKMS(w, r) {
		return
	}
	var req ImportKeyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	alg, err := parseKeyAlgorithm(req.Algorithm)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	usages, err := parseKeyUsage(req.Usage)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.kms.ImportKey(ctx, &kmsclient.ImportKeyRequest{
		KeyMaterial:   req.KeyMaterial,
		WrappingKeyID: req.WrappingKeyID,
		Name:          req.Name,
		Description:   req.Description,
		Algorithm:     alg,
		Usage:         usages,
		Tags:          req.Tags,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success201(w, r, &ImportKeyResponse{
		KeyID:     resp.KeyID,
		Version:   resp.Version,
		Algorithm: resp.Algorithm.String(),
	})
}

// ListKeys handles GET /api/v1/kms/keys.
func (h *Handlers) ListKeys(w http.ResponseWriter, r *http.Request) {
	if !h.ensureKMS(w, r) {
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.kms.ListKeys(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := &ListKeysResponse{Keys: make([]KeyInfoResponse, 0, len(resp.Keys))}
	for _, k := range resp.Keys {
		out.Keys = append(out.Keys, KeyInfoResponse{
			KeyID:     k.KeyID,
			Name:      k.Name,
			Algorithm: k.Algorithm.String(),
			Version:   k.Version,
			Usage:     keyUsageToStrings(k.Usage),
			CreatedAt: k.CreatedAt,
			RotatedAt: k.RotatedAt,
		})
	}
	h.success200(w, r, out)
}

// GetKey handles GET /api/v1/kms/keys/{name}.
func (h *Handlers) GetKey(w http.ResponseWriter, r *http.Request) {
	if !h.ensureKMS(w, r) {
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	k, err := h.kms.GetKey(ctx, h.name(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &KeyInfoResponse{
		KeyID:     k.KeyID,
		Name:      k.Name,
		Algorithm: k.Algorithm.String(),
		Version:   k.Version,
		Usage:     keyUsageToStrings(k.Usage),
		CreatedAt: k.CreatedAt,
		RotatedAt: k.RotatedAt,
	})
}

// DeleteKey handles DELETE /api/v1/kms/keys/{name}.
func (h *Handlers) DeleteKey(w http.ResponseWriter, r *http.Request) {
	if !h.ensureKMS(w, r) {
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	if err := h.kms.DeleteKey(ctx, h.name(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, struct{}{})
}

// RotateKey handles POST /api/v1/kms/keys/{name}/rotate.
func (h *Handlers) RotateKey(w http.ResponseWriter, r *http.Request) {
	if !h.ensureKMS(w, r) {
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.kms.RotateKey(ctx, h.name(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &RotateKeyResponse{
		KeyID:      resp.KeyID,
		NewVersion: resp.NewVersion,
	})
}

// UpdateKeyStatus handles PUT /api/v1/kms/keys/{name}/status.
func (h *Handlers) UpdateKeyStatus(w http.ResponseWriter, r *http.Request) {
	if !h.ensureKMS(w, r) {
		return
	}
	var req UpdateKeyStatusRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	st, err := parseKeyStatus(req.Status)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.kms.UpdateKeyStatus(ctx, &kmsclient.UpdateKeyStatusRequest{
		KeyID:   h.name(r),
		Version: req.Version,
		Status:  st,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &UpdateKeyStatusResponse{
		KeyID:   resp.KeyID,
		Version: resp.Version,
		Status:  resp.Status.String(),
	})
}

// ListKeyVersions handles GET /api/v1/kms/keys/{name}/versions.
func (h *Handlers) ListKeyVersions(w http.ResponseWriter, r *http.Request) {
	if !h.ensureKMS(w, r) {
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.kms.ListKeyVersions(ctx, h.name(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := &ListKeyVersionsResponse{Versions: make([]KeyVersionInfoResponse, 0, len(resp.Versions))}
	for _, v := range resp.Versions {
		out.Versions = append(out.Versions, KeyVersionInfoResponse{
			Version:    v.Version,
			Status:     v.Status.String(),
			Algorithm:  v.Algorithm.String(),
			CreatedAt:  v.CreatedAt,
			DisabledAt: v.DisabledAt,
		})
	}
	h.success200(w, r, out)
}

// =============================================================================
// Crypto (crypto.Client)
// =============================================================================

func (h *Handlers) ensureCrypto(w http.ResponseWriter, r *http.Request) bool {
	if h.crypto == nil {
		h.respWriter.Error500(w, r, &ErrServiceUnavailable{Service: "crypto"})
		return false
	}
	return true
}

// Encrypt handles POST /api/v1/kms/encrypt/{name}.
func (h *Handlers) Encrypt(w http.ResponseWriter, r *http.Request) {
	if !h.ensureCrypto(w, r) {
		return
	}
	var req EncryptRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.crypto.Encrypt(ctx, &cryptoclient.EncryptRequest{
		KeyID:     h.name(r),
		Plaintext: req.Plaintext,
		Context:   req.Context,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &EncryptResponse{
		KeyID:      h.name(r),
		Version:    resp.KeyVersion,
		Ciphertext: resp.Ciphertext,
	})
}

// Decrypt handles POST /api/v1/kms/decrypt/{name}.
func (h *Handlers) Decrypt(w http.ResponseWriter, r *http.Request) {
	if !h.ensureCrypto(w, r) {
		return
	}
	var req DecryptRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.crypto.Decrypt(ctx, &cryptoclient.DecryptRequest{
		KeyID:      h.name(r),
		Ciphertext: req.Ciphertext,
		Context:    req.Context,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &DecryptResponse{Plaintext: resp.Plaintext})
}

// Sign handles POST /api/v1/kms/sign/{name}.
func (h *Handlers) Sign(w http.ResponseWriter, r *http.Request) {
	if !h.ensureCrypto(w, r) {
		return
	}
	var req SignRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.crypto.Sign(ctx, &cryptoclient.SignRequest{
		KeyID:   h.name(r),
		Data:    req.Data,
		HashAlg: parseHashAlgorithm(req.Hash),
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &SignResponse{
		KeyID:     h.name(r),
		Version:   resp.KeyVersion,
		Signature: resp.Signature,
	})
}

// Verify handles POST /api/v1/kms/verify/{name}.
func (h *Handlers) Verify(w http.ResponseWriter, r *http.Request) {
	if !h.ensureCrypto(w, r) {
		return
	}
	var req VerifyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.crypto.Verify(ctx, &cryptoclient.VerifyRequest{
		KeyID:     h.name(r),
		Data:      req.Data,
		Signature: req.Signature,
		HashAlg:   parseHashAlgorithm(req.Hash),
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &VerifyResponse{Valid: resp.Valid})
}

// HMAC handles POST /api/v1/kms/hmac/{name}.
func (h *Handlers) HMAC(w http.ResponseWriter, r *http.Request) {
	if !h.ensureCrypto(w, r) {
		return
	}
	var req HMACRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.crypto.GenerateHMAC(ctx, &cryptoclient.GenerateHMACRequest{
		KeyID:   h.name(r),
		Message: req.Data,
		HashAlg: parseHashAlgorithm(req.Hash),
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &HMACResponse{KeyID: resp.KeyID, HMAC: resp.HMAC})
}

// VerifyHMAC handles POST /api/v1/kms/hmac/{name}/verify.
func (h *Handlers) VerifyHMAC(w http.ResponseWriter, r *http.Request) {
	if !h.ensureCrypto(w, r) {
		return
	}
	var req VerifyHMACRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.crypto.VerifyHMAC(ctx, &cryptoclient.VerifyHMACRequest{
		KeyID:   h.name(r),
		Message: req.Data,
		HMAC:    req.HMAC,
		HashAlg: parseHashAlgorithm(req.Hash),
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &VerifyHMACResponse{Valid: resp.Valid})
}

// Hash handles POST /api/v1/kms/hash.
func (h *Handlers) Hash(w http.ResponseWriter, r *http.Request) {
	if !h.ensureCrypto(w, r) {
		return
	}
	var req HashRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	alg := parseHashAlgorithm(req.Hash)
	resp, err := h.crypto.Hash(ctx, &cryptoclient.HashRequest{
		Data:    req.Data,
		HashAlg: alg,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &HashResponse{Hash: resp.HashAlg.String(), Digest: resp.Hash})
}

// GenerateRandom handles POST /api/v1/kms/random.
func (h *Handlers) GenerateRandom(w http.ResponseWriter, r *http.Request) {
	if !h.ensureCrypto(w, r) {
		return
	}
	var req GenerateRandomRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	if req.NumBytes <= 0 {
		h.respWriter.Error400(w, r, &ErrInvalidRequest{Field: "num_bytes", Reason: "must be > 0"})
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.crypto.GenerateRandom(ctx, &cryptoclient.GenerateRandomRequest{NumBytes: req.NumBytes})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &GenerateRandomResponse{Bytes: resp.RandomBytes})
}

// =============================================================================
// DEKs (dek.Client)
// =============================================================================

func (h *Handlers) ensureDEK(w http.ResponseWriter, r *http.Request) bool {
	if h.dek == nil {
		h.respWriter.Error500(w, r, &ErrServiceUnavailable{Service: "dek"})
		return false
	}
	return true
}

func encodeDEK(d *dekclient.DEKInfo) DEKInfoResponse {
	if d == nil {
		return DEKInfoResponse{}
	}
	return DEKInfoResponse{
		Path:        d.Path,
		Algorithm:   d.Algorithm,
		Version:     d.Version,
		Status:      d.Status,
		IsDefault:   d.IsDefault,
		CreatedAt:   d.CreatedAt,
		RotatedAt:   d.RotatedAt,
		UsageCount:  d.UsageCount,
		BytesUsed:   d.BytesUsed,
		Description: d.Description,
		BackendType: d.BackendType,
	}
}

// CreateDEK handles POST /api/v1/kms/deks.
func (h *Handlers) CreateDEK(w http.ResponseWriter, r *http.Request) {
	if !h.ensureDEK(w, r) {
		return
	}
	var req CreateDEKRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	if req.Path == "" {
		h.respWriter.Error400(w, r, &ErrInvalidRequest{Field: "path", Reason: "is required"})
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.dek.CreateDEK(ctx, &dekclient.CreateDEKRequest{
		Path:        req.Path,
		Algorithm:   req.Algorithm,
		Description: req.Description,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := &CreateDEKResponse{Path: req.Path, Algorithm: req.Algorithm}
	if resp.DEK != nil {
		out.Version = resp.DEK.Version
		out.Algorithm = resp.DEK.Algorithm
	}
	h.success201(w, r, out)
}

// ListDEKs handles GET /api/v1/kms/deks.
func (h *Handlers) ListDEKs(w http.ResponseWriter, r *http.Request) {
	if !h.ensureDEK(w, r) {
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.dek.ListDEKs(ctx, &dekclient.ListDEKsRequest{})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := &ListDEKsResponse{DEKs: make([]DEKInfoResponse, 0, len(resp.DEKs))}
	for i := range resp.DEKs {
		out.DEKs = append(out.DEKs, encodeDEK(&resp.DEKs[i]))
	}
	h.success200(w, r, out)
}

// GetDEK handles GET /api/v1/kms/deks/{path:.+}.
func (h *Handlers) GetDEK(w http.ResponseWriter, r *http.Request) {
	if !h.ensureDEK(w, r) {
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	d, err := h.dek.GetDEK(ctx, h.path(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	resp := encodeDEK(d)
	h.success200(w, r, &resp)
}

// DeleteDEK handles DELETE /api/v1/kms/deks/{path:.+}.
func (h *Handlers) DeleteDEK(w http.ResponseWriter, r *http.Request) {
	if !h.ensureDEK(w, r) {
		return
	}
	force := r.URL.Query().Get("force") == "true"
	ctx, cancel := h.ctx(r)
	defer cancel()
	if _, err := h.dek.DeleteDEK(ctx, &dekclient.DeleteDEKRequest{Path: h.path(r), Force: force}); err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, struct{}{})
}

// RotateDEK handles POST /api/v1/kms/deks/{path:.+}/rotate.
func (h *Handlers) RotateDEK(w http.ResponseWriter, r *http.Request) {
	if !h.ensureDEK(w, r) {
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.dek.RotateDEK(ctx, &dekclient.RotateDEKRequest{Path: h.path(r)})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &RotateDEKResponse{Path: h.path(r), NewVersion: resp.NewVersion})
}

// GetDEKStatus handles GET /api/v1/kms/deks/{path:.+}/status.
func (h *Handlers) GetDEKStatus(w http.ResponseWriter, r *http.Request) {
	if !h.ensureDEK(w, r) {
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	st, err := h.dek.GetDEKStatus(ctx, h.path(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := &DEKStatusResponse{}
	if st.DEK != nil {
		d := st.DEK
		out.Path = d.Path
		out.Algorithm = d.Algorithm
		out.Version = d.Version
		out.Status = d.Status
		out.IsDefault = d.IsDefault
		out.UsageCount = d.UsageCount
		out.BytesUsed = d.BytesUsed
		out.MaxUsageCount = d.MaxUsageCount
		out.MaxBytesUsed = d.MaxBytesUsed
		out.WarningPercent = d.WarningPercent
		out.CreatedAt = d.CreatedAt
		out.RotatedAt = d.RotatedAt
	}
	h.success200(w, r, out)
}

// =============================================================================
// Secrets (secrets.Client)
// =============================================================================

func (h *Handlers) ensureSecrets(w http.ResponseWriter, r *http.Request) bool {
	if h.secrets == nil {
		h.respWriter.Error500(w, r, &ErrServiceUnavailable{Service: "secrets"})
		return false
	}
	return true
}

// StoreSecret handles POST /api/v1/kms/secrets.
func (h *Handlers) StoreSecret(w http.ResponseWriter, r *http.Request) {
	if !h.ensureSecrets(w, r) {
		return
	}
	var req StoreSecretRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	if req.Path == "" && req.Name != "" {
		// WebUI forms send `name`; promote to the path field used
		// downstream so flat REST clients and the SDK agree.
		req.Path = req.Name
	}
	if req.Path == "" {
		h.respWriter.Error400(w, r, &ErrInvalidRequest{Field: "path", Reason: "is required"})
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	data := map[string]interface{}{"value": req.Value}
	if req.ContentType != "" {
		data["content_type"] = req.ContentType
	}
	if req.Description != "" {
		data["description"] = req.Description
	}
	resp, err := h.secrets.Store(ctx, &secretsclient.StoreSecretRequest{
		Path:     req.Path,
		Data:     data,
		Metadata: req.Tags,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success201(w, r, &StoreSecretResponse{Path: req.Path, Version: resp.Version})
}

// ListSecrets handles GET /api/v1/kms/secrets.
func (h *Handlers) ListSecrets(w http.ResponseWriter, r *http.Request) {
	if !h.ensureSecrets(w, r) {
		return
	}
	prefix := r.URL.Query().Get("prefix")
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.secrets.List(ctx, prefix)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := &ListSecretsResponse{Secrets: make([]SecretSummary, 0, len(resp.Paths))}
	for _, path := range resp.Paths {
		out.Secrets = append(out.Secrets, SecretSummary{Path: path})
	}
	h.success200(w, r, out)
}

// GetSecret handles GET /api/v1/kms/secrets/{name}.
func (h *Handlers) GetSecret(w http.ResponseWriter, r *http.Request) {
	if !h.ensureSecrets(w, r) {
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	s, err := h.secrets.Get(ctx, h.name(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := &SecretResponse{
		Path:      s.Path,
		Version:   s.Version,
		Tags:      s.Metadata,
		CreatedAt: s.CreatedAt,
		UpdatedAt: s.CreatedAt,
	}
	if v, ok := s.Data["value"]; ok {
		switch typed := v.(type) {
		case string:
			out.Value = []byte(typed)
		case []byte:
			out.Value = typed
		}
	}
	if v, ok := s.Data["content_type"]; ok {
		if str, ok := v.(string); ok {
			out.ContentType = str
		}
	}
	if v, ok := s.Data["description"]; ok {
		if str, ok := v.(string); ok {
			out.Description = str
		}
	}
	h.success200(w, r, out)
}

// DeleteSecret handles DELETE /api/v1/kms/secrets/{name}.
func (h *Handlers) DeleteSecret(w http.ResponseWriter, r *http.Request) {
	if !h.ensureSecrets(w, r) {
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	if err := h.secrets.Delete(ctx, h.name(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, struct{}{})
}

// RotateSecret handles POST /api/v1/kms/secrets/{name}/rotate.
func (h *Handlers) RotateSecret(w http.ResponseWriter, r *http.Request) {
	if !h.ensureSecrets(w, r) {
		return
	}
	var req RotateSecretRequest
	_ = h.decodeJSON(r, &req)
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.secrets.Rotate(ctx, &secretsclient.RotateSecretRequest{
		SecretID: h.name(r),
		NewData:  req.Value,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &RotateSecretResponse{Path: h.name(r), Version: resp.NewVersion})
}

// RollbackSecret handles POST /api/v1/kms/secrets/{name}/rollback.
func (h *Handlers) RollbackSecret(w http.ResponseWriter, r *http.Request) {
	if !h.ensureSecrets(w, r) {
		return
	}
	var req RollbackSecretRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	if req.Version <= 0 {
		h.respWriter.Error400(w, r, &ErrInvalidRequest{Field: "version", Reason: "must be > 0"})
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.secrets.Rollback(ctx, &secretsclient.RollbackSecretRequest{
		SecretID:     h.name(r),
		TargetVersion: req.Version,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &RollbackSecretResponse{Path: h.name(r), Version: resp.NewVersion})
}

// UpdateSecretStatus handles PUT /api/v1/kms/secrets/{name}/status.
func (h *Handlers) UpdateSecretStatus(w http.ResponseWriter, r *http.Request) {
	if !h.ensureSecrets(w, r) {
		return
	}
	var req UpdateSecretStatusRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	status := secretsclient.SecretStatusEnabled
	if !req.Enabled {
		status = secretsclient.SecretStatusDisabled
	}
	if err := h.secrets.UpdateStatus(ctx, &secretsclient.UpdateSecretStatusRequest{
		SecretID: h.name(r),
		Status:   status,
	}); err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, struct{}{})
}

// ListSecretVersions handles GET /api/v1/kms/secrets/{name}/versions.
func (h *Handlers) ListSecretVersions(w http.ResponseWriter, r *http.Request) {
	if !h.ensureSecrets(w, r) {
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.secrets.ListVersions(ctx, h.name(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := &ListSecretVersionsResponse{Versions: make([]SecretVersionResponse, 0, len(resp.Versions))}
	for i := range resp.Versions {
		v := &resp.Versions[i]
		out.Versions = append(out.Versions, SecretVersionResponse{
			Path:      h.name(r),
			Version:   v.Version,
			CreatedAt: v.CreatedAt,
		})
	}
	h.success200(w, r, out)
}

// GetSecretVersion handles GET /api/v1/kms/secrets/{name}/versions/{version}.
func (h *Handlers) GetSecretVersion(w http.ResponseWriter, r *http.Request) {
	if !h.ensureSecrets(w, r) {
		return
	}
	versionStr := mux.Vars(r)["version"]
	versionInt, err := strconv.Atoi(versionStr)
	if err != nil {
		h.respWriter.Error400(w, r, &ErrInvalidRequest{Field: "version", Reason: "must be integer"})
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	v, err := h.secrets.GetVersion(ctx, &secretsclient.GetSecretVersionRequest{
		SecretID: h.name(r),
		Version:  versionInt,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &SecretVersionResponse{
		Path:      h.name(r),
		Version:   v.Version,
		Value:     v.Data,
		CreatedAt: v.CreatedAt,
	})
}

// GetRotationPolicy handles GET /api/v1/kms/secrets/{name}/policy.
func (h *Handlers) GetRotationPolicy(w http.ResponseWriter, r *http.Request) {
	if !h.ensureSecrets(w, r) {
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	pol, err := h.secrets.GetRotationPolicy(ctx, h.name(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := &RotationPolicyResponse{
		Enabled:         pol.Enabled,
		IntervalSeconds: int64(pol.Interval / time.Second),
		Method:          pol.RotationLambda,
	}
	if !pol.NextRotation.IsZero() {
		out.NextRotationUnixTime = pol.NextRotation.Unix()
	}
	h.success200(w, r, out)
}

// SetRotationPolicy handles PUT /api/v1/kms/secrets/{name}/policy.
func (h *Handlers) SetRotationPolicy(w http.ResponseWriter, r *http.Request) {
	if !h.ensureSecrets(w, r) {
		return
	}
	var req RotationPolicyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	policy := &secretsclient.RotationPolicy{
		Enabled:        req.Enabled,
		Interval:       time.Duration(req.IntervalSeconds) * time.Second,
		RotationLambda: req.Method,
	}
	if req.NextRotationUnixTime > 0 {
		policy.NextRotation = time.Unix(req.NextRotationUnixTime, 0)
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	if err := h.secrets.SetRotationPolicy(ctx, &secretsclient.SetRotationPolicyRequest{
		SecretID: h.name(r),
		Policy:   policy,
	}); err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, struct{}{})
}
