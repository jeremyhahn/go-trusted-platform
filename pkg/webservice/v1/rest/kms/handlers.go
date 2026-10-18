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
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	kmssdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"

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

func (h *Handlers) name(r *http.Request) string { return pathVar(r, "name") }
func (h *Handlers) path(r *http.Request) string { return pathVar(r, "path") }

// pathVar returns the route variable key unescaped. The KMS subrouter matches
// on the encoded path (KMSRouter.RegisterRoutes), so a secret named
// "db/password" arrives as "db%2Fpassword". A variable that is not valid
// percent-encoding is returned as sent; the lookup it feeds then reports the
// name as not found.
func pathVar(r *http.Request, key string) string {
	raw := mux.Vars(r)[key]
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return raw
	}
	return decoded
}

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
		h.respWriter.Error503(w, r, &ErrServiceUnavailable{Service: "key-management"})
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
		Name:               req.Name,
		Algorithm:          alg,
		Usage:              usages,
		Exportable:         req.Exportable,
		DeletionProtection: req.DeletionProtection,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success201(w, r, &GenerateKeyResponse{
		KeyID:              resp.KeyID,
		Version:            resp.Version,
		Algorithm:          resp.Algorithm.String(),
		Exportable:         resp.Exportable,
		DeletionProtection: resp.DeletionProtection,
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

// RevokeKey handles POST /api/v1/kms/keys/{name}/revoke.
//
// The SDK revoke call carries no reason field, so the operator-supplied
// reason is recorded in the platform log for audit purposes. The
// response status reflects the persisted key state after revocation and
// revoked_at is stamped at request time, mirroring the QuicBaaS service
// which timestamps revocations with the server clock.
func (h *Handlers) RevokeKey(w http.ResponseWriter, r *http.Request) {
	if !h.ensureKMS(w, r) {
		return
	}
	var req RevokeKeyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	name := h.name(r)
	if err := h.kms.RevokeKey(ctx, name, req.Reason); err != nil {
		h.fail(w, r, err)
		return
	}
	if req.Reason != "" {
		h.logger.Warnf("kms: key revoked: key_id=%s reason=%q", name, req.Reason)
	}
	meta, err := h.kms.GetKeyMetadata(ctx, name)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &RevokeKeyResponse{
		KeyID:     meta.KeyID,
		Status:    meta.Status.String(),
		RevokedAt: time.Now(),
	})
}

// GetKeyMetadata handles GET /api/v1/kms/keys/{name}/metadata.
func (h *Handlers) GetKeyMetadata(w http.ResponseWriter, r *http.Request) {
	if !h.ensureKMS(w, r) {
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	name := h.name(r)
	meta, err := h.kms.GetKeyMetadata(ctx, name)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	pol, err := h.kms.GetKeyRotationPolicy(ctx, name)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, keyMetadataToResponse(meta, pol))
}

// UpdateKeyMetadata handles PUT /api/v1/kms/keys/{name}/metadata.
func (h *Handlers) UpdateKeyMetadata(w http.ResponseWriter, r *http.Request) {
	if !h.ensureKMS(w, r) {
		return
	}
	var req UpdateKeyMetadataRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	meta, err := h.kms.UpdateKeyMetadata(ctx, &kmsclient.UpdateKeyMetadataRequest{
		KeyID:       h.name(r),
		Name:        req.Name,
		Description: req.Description,
		Tags:        req.Tags,
		RemoveTags:  req.RemoveTags,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, keyMetadataToResponse(meta, nil))
}

// GetKeyPolicy handles GET /api/v1/kms/keys/{name}/policy.
func (h *Handlers) GetKeyPolicy(w http.ResponseWriter, r *http.Request) {
	if !h.ensureKMS(w, r) {
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	pol, err := h.kms.GetKeyPolicy(ctx, h.name(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, keyPolicyToResponse(pol))
}

// SetKeyPolicy handles PUT /api/v1/kms/keys/{name}/policy.
func (h *Handlers) SetKeyPolicy(w http.ResponseWriter, r *http.Request) {
	if !h.ensureKMS(w, r) {
		return
	}
	var req SetKeyPolicyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	ops, err := parseKeyUsage(req.Operations)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	policy := &kmsclient.KeyPolicy{
		AllowedOperations: ops,
		AllowedPrincipals: req.AllowPrincipals,
		DeniedPrincipals:  req.DenyPrincipals,
		RotationRequired:  req.RotationRequired,
		MaxUsageCount:     req.MaxUsageCount,
		RequireMFA:        req.RequireMFA,
	}
	if req.ExpiresIn != "" {
		d, err := time.ParseDuration(req.ExpiresIn)
		if err != nil {
			h.respWriter.Error400(w, r, &ErrInvalidRequest{Field: "expires_in", Reason: err.Error()})
			return
		}
		policy.ExpiresAt = time.Now().Add(d)
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	name := h.name(r)
	if err := h.kms.SetKeyPolicy(ctx, &kmsclient.SetKeyPolicyRequest{
		KeyID:  name,
		Policy: policy,
	}); err != nil {
		h.fail(w, r, err)
		return
	}
	// The SDK set call returns no body; read the stamped policy back so
	// the response reports the authoritative version and timestamp.
	stamped, err := h.kms.GetKeyPolicy(ctx, name)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &SetKeyPolicyResponse{
		KeyID:         stamped.KeyID,
		PolicyVersion: stamped.Version,
		UpdatedAt:     stamped.UpdatedAt,
	})
}

// ListAlgorithms handles GET /api/v1/kms/algorithms.
func (h *Handlers) ListAlgorithms(w http.ResponseWriter, r *http.Request) {
	if !h.ensureKMS(w, r) {
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.kms.GetSupportedAlgorithms(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &ListAlgorithmsResponse{Algorithms: resp.Algorithms})
}

// BackendStatus handles GET /api/v1/kms/backend/status.
func (h *Handlers) BackendStatus(w http.ResponseWriter, r *http.Request) {
	if !h.ensureKMS(w, r) {
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.kms.BackendStatus(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &BackendStatusResponse{
		BackendType:  resp.BackendType,
		Status:       resp.Status,
		Device:       resp.Device,
		Region:       resp.Region,
		KeyID:        resp.KeyID,
		PCRBanks:     resp.PCRBanks,
		PCRRegisters: resp.PCRRegisters,
		Capabilities: resp.Capabilities,
	})
}

// keyMetadataToResponse maps the SDK key metadata (and optional key
// rotation policy) onto the REST wire envelope.
func keyMetadataToResponse(meta *kmsclient.KeyMetadataResponse, pol *kmsclient.KeyRotationPolicy) *KeyMetadataResponse {
	out := &KeyMetadataResponse{
		KeyID:              meta.KeyID,
		Name:               meta.Name,
		Description:        meta.Description,
		Algorithm:          meta.Algorithm.String(),
		Status:             meta.Status.String(),
		Version:            meta.Version,
		Exportable:         meta.Exportable,
		DeletionProtection: meta.DeletionProtection,
		Usage:              keyUsageToStrings(meta.Usage),
		Owner:              meta.Owner,
		CreatedAt:          meta.CreatedAt,
		UpdatedAt:          meta.UpdatedAt,
		LastUsedAt:         meta.LastUsedAt,
		Tags:               meta.Tags,
	}
	if pol != nil {
		out.RotationPolicy = &KeyRotationPolicyResponse{
			Enabled:         pol.Enabled,
			AutoRotate:      pol.AutoRotate,
			IntervalSeconds: pol.IntervalSeconds,
			NextRotation:    pol.NextRotationAt,
			RetainVersions:  pol.RetainVersions,
		}
	}
	return out
}

// keyPolicyToResponse maps the SDK key policy onto the REST wire envelope.
func keyPolicyToResponse(pol *kmsclient.KeyPolicy) *KeyPolicyResponse {
	return &KeyPolicyResponse{
		KeyID:             pol.KeyID,
		Version:           pol.Version,
		AllowedOperations: keyUsageToStrings(pol.AllowedOperations),
		AllowedPrincipals: pol.AllowedPrincipals,
		DeniedPrincipals:  pol.DeniedPrincipals,
		ExpiresAt:         pol.ExpiresAt,
		RotationRequired:  pol.RotationRequired,
		MaxUsageCount:     pol.MaxUsageCount,
		RequireMFA:        pol.RequireMFA,
		UpdatedAt:         pol.UpdatedAt,
	}
}

// =============================================================================
// Crypto (crypto.Client)
// =============================================================================

func (h *Handlers) ensureCrypto(w http.ResponseWriter, r *http.Request) bool {
	if h.crypto == nil {
		h.respWriter.Error503(w, r, &ErrServiceUnavailable{Service: "crypto"})
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
	if req.Version != 0 {
		h.respWriter.Error400(w, r, &ErrKeyVersionUnsupported{Version: req.Version})
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
		KeyID:     h.name(r),
		Data:      req.Data,
		HashAlg:   parseHashAlgorithm(req.Hash),
		PreHashed: req.PreHashed,
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

// GenerateDataKey handles POST /api/v1/kms/data-keys. It mints a data key
// wrapped by the named key-encryption key and returns both forms; unlike
// POST /deks it stores nothing.
func (h *Handlers) GenerateDataKey(w http.ResponseWriter, r *http.Request) {
	if !h.ensureCrypto(w, r) {
		return
	}
	var req GenerateDataKeyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	if err := validateDataKeyRequest("key_id", req.KeyID, req.Algorithm, req.KeySize); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.crypto.GenerateDataKey(ctx, &cryptoclient.GenerateDataKeyRequest{
		KeyID:   req.KeyID,
		KeySize: int(req.KeySize),
		Context: req.Context,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &GenerateDataKeyResponse{
		KeyID:        req.KeyID,
		PlaintextKey: resp.Plaintext,
		EncryptedKey: resp.CiphertextBlob,
	})
}

// GenerateWrappedDataKey handles POST /api/v1/kms/data-keys/wrapped. It mints
// a data key and returns only its wrapped form; the plaintext never leaves the
// service.
func (h *Handlers) GenerateWrappedDataKey(w http.ResponseWriter, r *http.Request) {
	if !h.ensureCrypto(w, r) {
		return
	}
	var req GenerateWrappedDataKeyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	if err := validateDataKeyRequest("wrapping_key_id", req.WrappingKeyID, req.KeyAlgorithm, req.KeySize); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.crypto.GenerateWrappedDataKey(ctx, &cryptoclient.GenerateWrappedDataKeyRequest{
		KeyID:   req.WrappingKeyID,
		KeySize: int(req.KeySize),
		Context: req.Context,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.success200(w, r, &GenerateWrappedDataKeyResponse{
		WrappingKeyID: req.WrappingKeyID,
		WrappedKey:    resp.CiphertextBlob,
	})
}

// validateDataKeyRequest checks the fields both data-key routes share: the
// wrapping key is named, and the algorithm and key_size (in bits) resolve,
// by the rule gRPC mints under, to a size the SDK call can carry. The SDK
// crypto client sends neither field, so the service mints its 256-bit
// default; any other size is refused rather than silently replaced.
func validateDataKeyRequest(keyField, keyID, algorithm string, keySize int32) error {
	if keyID == "" {
		return &ErrInvalidRequest{Field: keyField, Reason: "is required"}
	}
	alg, err := parseDataKeyAlgorithm(algorithm)
	if err != nil {
		return err
	}
	_, bits, err := kmssdk.ResolveDataKey(alg, keySize)
	if err != nil {
		return err
	}
	if bits != kmssdk.DefaultDataKeyBits {
		return &ErrDataKeySizeNotCarried{Bits: bits}
	}
	return nil
}

// kmsKeyAlgorithmPrefix is the prefix every proto KMSKeyAlgorithm name carries.
const kmsKeyAlgorithmPrefix = "KMS_KEY_ALGORITHM_"

// parseDataKeyAlgorithm reads a proto KMSKeyAlgorithm name, with or
// without its KMS_KEY_ALGORITHM_ prefix and with dashes for underscores
// ("aes-256", as the CLI spells it). An empty name is unspecified.
func parseDataKeyAlgorithm(s string) (platformv1.KMSKeyAlgorithm, error) {
	name := strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(s)), "-", "_")
	if name == "" {
		return platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED, nil
	}
	value, ok := platformv1.KMSKeyAlgorithm_value[kmsKeyAlgorithmPrefix+strings.TrimPrefix(name, kmsKeyAlgorithmPrefix)]
	if !ok {
		return platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED, &ErrUnknownAlgorithm{Algorithm: s}
	}
	return platformv1.KMSKeyAlgorithm(value), nil
}

// =============================================================================
// DEKs (dek.Client)
// =============================================================================

func (h *Handlers) ensureDEK(w http.ResponseWriter, r *http.Request) bool {
	if h.dek == nil {
		h.respWriter.Error503(w, r, &ErrServiceUnavailable{Service: "dek"})
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
		h.respWriter.Error503(w, r, &ErrServiceUnavailable{Service: "secrets"})
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
	data := map[string]interface{}{SecretValueKey: req.Value}
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
	query := r.URL.Query()
	limit, err := parseListLimit(query.Get("limit"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	ctx, cancel := h.ctx(r)
	defer cancel()
	resp, err := h.secrets.List(ctx, query.Get("prefix"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	page, next := PageSecretPaths(resp.Paths, query.Get("cursor"), limit)
	out := &ListSecretsResponse{Secrets: make([]SecretSummary, 0, len(page)), NextCursor: next}
	for _, path := range page {
		out.Secrets = append(out.Secrets, SecretSummary{Path: path})
	}
	h.success200(w, r, out)
}

// parseListLimit reads the ?limit= page size. An absent limit is 0, which
// means every path; anything else must be a positive integer.
func parseListLimit(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 {
		return 0, &ErrInvalidRequest{Field: "limit", Reason: "must be a positive integer"}
	}
	return limit, nil
}

// PageSecretPaths sorts the paths, keeps those after cursor, and returns
// at most limit of them (all of them when limit is 0). next is the last
// returned path when more follow, and empty on the final page.
func PageSecretPaths(paths []string, cursor string, limit int) (page []string, next string) {
	sorted := slices.Clone(paths)
	slices.Sort(sorted)
	if cursor != "" {
		start, found := slices.BinarySearch(sorted, cursor)
		if found {
			start++
		}
		sorted = sorted[start:]
	}
	if limit == 0 || len(sorted) <= limit {
		return sorted, ""
	}
	return sorted[:limit], sorted[limit-1]
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
	value, err := DecodeStoredSecretValue(s.Path, s.Data[SecretValueKey])
	if err != nil {
		h.respWriter.Error500(w, r, err)
		return
	}
	out := &SecretResponse{
		Path:      s.Path,
		Value:     value,
		Version:   s.Version,
		Tags:      s.Metadata,
		CreatedAt: s.CreatedAt,
		UpdatedAt: s.CreatedAt,
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

// DecodeStoredSecretValue returns the bytes the caller stored under a
// secret's "value" key. The go-quicbaas secrets backend JSON-encodes the
// data map, so bytes stored by StoreSecret read back as standard base64
// text; a backend that keeps the map in memory hands the bytes back as is.
func DecodeStoredSecretValue(path string, v interface{}) ([]byte, error) {
	switch typed := v.(type) {
	case nil:
		return nil, nil
	case string:
		decoded, err := base64.StdEncoding.DecodeString(typed)
		if err != nil {
			return nil, &ErrSecretValueMalformed{Path: path}
		}
		return decoded, nil
	case []byte:
		return typed, nil
	case SecretValue:
		return []byte(typed), nil
	default:
		return nil, &ErrSecretValueMalformed{Path: path}
	}
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
		SecretID:      h.name(r),
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
		RetainVersions:  pol.RetainVersions,
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
		RetainVersions: req.RetainVersions,
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
