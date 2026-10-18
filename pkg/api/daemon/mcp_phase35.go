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

package daemon

import (
	"context"
	"encoding/base64"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// Phase35Services bundles the four Phase 3.5 service pointers the MCP
// provider needs to satisfy mcp.Phase35Provider. Fields may be nil, in which
// case the corresponding provider methods return the service-level
// ErrXxxNotConfigured sentinel.
type Phase35Services struct {
	Ceremony *CeremonyService
	PIV      *PIVService
	LUKS     *LUKSService
	FIDO2    *FIDO2Service
}

// phase35State holds the Phase 3.5 services behind a mutex so daemon startup
// can wire them in post-construction without racing with MCP tool dispatch.
type phase35State struct {
	mu       sync.RWMutex
	services Phase35Services
}

func (s *phase35State) snapshot() Phase35Services {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.services
}

func (s *phase35State) replace(svcs Phase35Services) {
	s.mu.Lock()
	s.services = svcs
	s.mu.Unlock()
}

// SetPhase35Services wires the ceremony/piv/luks/fido2 services into the MCP
// provider so MCP tools can delegate to them. Subsequent calls replace the
// previous wiring. Passing a zero-valued Phase35Services clears the wiring.
func (p *MCPServiceProvider) SetPhase35Services(svcs Phase35Services) {
	p.phase35.replace(svcs)
}

// Phase35Services returns a snapshot of the currently wired Phase 3.5
// services. It is intended for introspection and tests.
func (p *MCPServiceProvider) Phase35Services() Phase35Services {
	return p.phase35.snapshot()
}

// =============================================================================
// Ceremony MCP delegations
// =============================================================================

// CeremonyInit implements mcp.Phase35Provider.
func (p *MCPServiceProvider) CeremonyInit(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc := p.phase35.snapshot().Ceremony
	if svc == nil {
		return nil, ErrCeremonyNotConfigured
	}
	req := &CeremonyInitRequest{
		SOPIN:                  mapGetString(args, "so_pin"),
		UserPIN:                mapGetString(args, "user_pin"),
		Threshold:              mapGetString(args, "threshold"),
		Hostname:               mapGetString(args, "hostname"),
		SANs:                   mapGetStringSlice(args, "sans"),
		CredentialSealStrategy: mapGetString(args, "credential_seal_strategy"),
	}
	out, err := svc.Init(ctx, req)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"ceremony_id":    out.CeremonyID,
		"state":          string(out.State),
		"initialized_at": out.InitializedAt,
		"admin_cert_pem": out.AdminCertPEM,
		"admin_key_pem":  out.AdminKeyPEM,
		"spki_pin":       out.SPKIPin,
	}, nil
}

// CeremonyStatus implements mcp.Phase35Provider.
func (p *MCPServiceProvider) CeremonyStatus(ctx context.Context) (interface{}, error) {
	svc := p.phase35.snapshot().Ceremony
	if svc == nil {
		return nil, ErrCeremonyNotConfigured
	}
	out, err := svc.Status(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"ceremony_id":       out.CeremonyID,
		"state":             string(out.State),
		"threshold":         out.Threshold,
		"officers_enrolled": out.OfficersEnrolled,
		"officers_required": out.OfficersRequired,
		"initialized_at":    out.InitializedAt,
	}, nil
}

// CeremonyClaimCertBegin implements mcp.Phase35Provider.
func (p *MCPServiceProvider) CeremonyClaimCertBegin(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc := p.phase35.snapshot().Ceremony
	if svc == nil {
		return nil, ErrCeremonyNotConfigured
	}
	req := &CeremonyClaimCertBeginRequest{
		Username:          mapGetString(args, "username"),
		AuthenticatorType: CeremonyAuthenticatorType(mapGetString(args, "authenticator_type")),
		Slot:              mapGetString(args, "slot"),
		CredentialID:      mapGetString(args, "credential_id"),
	}
	out, err := svc.ClaimCertBegin(ctx, req)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"nonce":        out.Nonce,
		"challenge_id": out.ChallengeID,
		"expires_at":   out.ExpiresAt,
	}, nil
}

// CeremonyClaimCertComplete implements mcp.Phase35Provider.
func (p *MCPServiceProvider) CeremonyClaimCertComplete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc := p.phase35.snapshot().Ceremony
	if svc == nil {
		return nil, ErrCeremonyNotConfigured
	}
	req := &CeremonyClaimCertCompleteRequest{
		Username:  mapGetString(args, "username"),
		Nonce:     mapGetString(args, "nonce"),
		Signature: mapGetString(args, "signature"),
	}
	out, err := svc.ClaimCertComplete(ctx, req)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"certificate_pem": out.CertificatePEM,
		"chain_pem":       out.ChainPEM,
	}, nil
}

// CeremonyClaimShareBegin implements mcp.Phase35Provider.
func (p *MCPServiceProvider) CeremonyClaimShareBegin(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc := p.phase35.snapshot().Ceremony
	if svc == nil {
		return nil, ErrCeremonyNotConfigured
	}
	out, err := svc.ClaimShareBegin(ctx, &CeremonyClaimShareBeginRequest{
		Username: mapGetString(args, "username"),
	})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"nonce":      out.Nonce,
		"expires_at": out.ExpiresAt,
	}, nil
}

// CeremonyClaimShareComplete implements mcp.Phase35Provider. The signature
// travels as base64 because MCP tool arguments are JSON values.
func (p *MCPServiceProvider) CeremonyClaimShareComplete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc := p.phase35.snapshot().Ceremony
	if svc == nil {
		return nil, ErrCeremonyNotConfigured
	}
	signature, err := mapGetBase64(args, "signature")
	if err != nil {
		return nil, err
	}
	out, err := svc.ClaimShareComplete(ctx, &CeremonyClaimShareCompleteRequest{
		Username:  mapGetString(args, "username"),
		Nonce:     mapGetString(args, "nonce"),
		Signature: signature,
	})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"share": out.Share,
		"index": out.Index,
	}, nil
}

// CeremonySignCSR implements mcp.Phase35Provider.
func (p *MCPServiceProvider) CeremonySignCSR(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc := p.phase35.snapshot().Ceremony
	if svc == nil {
		return nil, ErrCeremonyNotConfigured
	}
	req := &CeremonySignCSRRequest{
		Username: mapGetString(args, "username"),
		SOPIN:    mapGetString(args, "so_pin"),
		CSRPEM:   mapGetString(args, "csr_pem"),
		Role:     CeremonyOfficerRole(mapGetString(args, "role")),
	}
	out, err := svc.SignCSR(ctx, req)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"certificate_pem": out.CertificatePEM,
		"chain_pem":       out.ChainPEM,
	}, nil
}

// =============================================================================
// PIV MCP delegations
// =============================================================================

// PIVListDevices implements mcp.Phase35Provider.
func (p *MCPServiceProvider) PIVListDevices(ctx context.Context) (interface{}, error) {
	svc := p.phase35.snapshot().PIV
	if svc == nil {
		return nil, ErrPIVNotConfigured
	}
	devices, err := svc.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"devices": devices}, nil
}

// PIVListSlots implements mcp.Phase35Provider.
func (p *MCPServiceProvider) PIVListSlots(ctx context.Context, device string) (interface{}, error) {
	svc := p.phase35.snapshot().PIV
	if svc == nil {
		return nil, ErrPIVNotConfigured
	}
	slots, err := svc.ListSlots(ctx, device)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"slots": slots}, nil
}

// PIVSlotInfo implements mcp.Phase35Provider.
func (p *MCPServiceProvider) PIVSlotInfo(ctx context.Context, device, slot string) (interface{}, error) {
	svc := p.phase35.snapshot().PIV
	if svc == nil {
		return nil, ErrPIVNotConfigured
	}
	return svc.SlotInfo(ctx, device, slot)
}

// PIVGenerate implements mcp.Phase35Provider.
func (p *MCPServiceProvider) PIVGenerate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc := p.phase35.snapshot().PIV
	if svc == nil {
		return nil, ErrPIVNotConfigured
	}
	req := &PIVGenerateRequest{
		Slot:       mapGetString(args, "slot"),
		Algorithm:  PIVAlgorithm(mapGetString(args, "algorithm")),
		PINEnclave: memguard.NewMemoryEnclaveFromString(mapGetString(args, "pin")),
	}
	defer req.Destroy()
	out, err := svc.Generate(ctx, req)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"public_key_pem": out.PublicKeyPEM}, nil
}

// PIVImport implements mcp.Phase35Provider.
func (p *MCPServiceProvider) PIVImport(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc := p.phase35.snapshot().PIV
	if svc == nil {
		return nil, ErrPIVNotConfigured
	}
	req := &PIVImportRequest{
		Slot:       mapGetString(args, "slot"),
		PrivateKey: memguard.NewMemoryEnclaveFromString(mapGetString(args, "private_key_pem")),
		PINEnclave: memguard.NewMemoryEnclaveFromString(mapGetString(args, "pin")),
	}
	defer req.Destroy()
	if err := svc.Import(ctx, req); err != nil {
		return nil, err
	}
	return map[string]interface{}{"imported": true}, nil
}

// PIVSign implements mcp.Phase35Provider. The payload MUST be base64-encoded
// per the MCP tool schema.
func (p *MCPServiceProvider) PIVSign(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc := p.phase35.snapshot().PIV
	if svc == nil {
		return nil, ErrPIVNotConfigured
	}
	payload, err := decodePayload(mapGetString(args, "payload"))
	if err != nil {
		return nil, err
	}
	req := &PIVSignRequest{
		Slot:       mapGetString(args, "slot"),
		Payload:    payload,
		PINEnclave: memguard.NewMemoryEnclaveFromString(mapGetString(args, "pin")),
	}
	defer req.Destroy()
	sig, err := svc.Sign(ctx, req)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"signature": base64.StdEncoding.EncodeToString(sig)}, nil
}

// PIVAttest implements mcp.Phase35Provider.
func (p *MCPServiceProvider) PIVAttest(ctx context.Context, slot string) (interface{}, error) {
	svc := p.phase35.snapshot().PIV
	if svc == nil {
		return nil, ErrPIVNotConfigured
	}
	out, err := svc.Attest(ctx, slot)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"attestation_cert_pem":  out.AttestationCertPEM,
		"attestation_chain_pem": out.AttestationChainPEM,
	}, nil
}

// PIVReset implements mcp.Phase35Provider.
func (p *MCPServiceProvider) PIVReset(ctx context.Context, device string) (interface{}, error) {
	svc := p.phase35.snapshot().PIV
	if svc == nil {
		return nil, ErrPIVNotConfigured
	}
	if err := svc.Reset(ctx, device); err != nil {
		return nil, err
	}
	return map[string]interface{}{"reset": true}, nil
}

// =============================================================================
// LUKS MCP delegations
// =============================================================================

// luksService returns the LUKS service, or the not-configured error a gRPC
// caller would read.
func (p *MCPServiceProvider) luksService() (*LUKSService, error) {
	svc := p.phase35.snapshot().LUKS
	if svc == nil {
		return nil, ErrLUKSOperation{Cause: ErrLUKSNotConfigured}
	}
	return svc, nil
}

// LUKSStatus implements mcp.Phase35Provider.
func (p *MCPServiceProvider) LUKSStatus(ctx context.Context, device string) (interface{}, error) {
	svc, err := p.luksService()
	if err != nil {
		return nil, err
	}
	result, err := svc.Status(ctx, device)
	if err != nil {
		return nil, ErrLUKSOperation{Cause: err}
	}
	return result, nil
}

// LUKSListSlots implements mcp.Phase35Provider.
func (p *MCPServiceProvider) LUKSListSlots(ctx context.Context, device string) (interface{}, error) {
	svc, err := p.luksService()
	if err != nil {
		return nil, err
	}
	result, err := svc.ListSlots(ctx, device)
	if err != nil {
		return nil, ErrLUKSOperation{Cause: err}
	}
	return result, nil
}

// LUKSInfo implements mcp.Phase35Provider.
func (p *MCPServiceProvider) LUKSInfo(ctx context.Context, device string) (interface{}, error) {
	svc, err := p.luksService()
	if err != nil {
		return nil, err
	}
	result, err := svc.Info(ctx, device)
	if err != nil {
		return nil, ErrLUKSOperation{Cause: err}
	}
	return result, nil
}

// LUKSEnrollPassphrase implements mcp.Phase35Provider.
func (p *MCPServiceProvider) LUKSEnrollPassphrase(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc, err := p.luksService()
	if err != nil {
		return nil, err
	}
	req := &LUKSEnrollPassphraseRequest{
		Device:             mapGetString(args, "device"),
		ExistingPassphrase: mapGetString(args, "existing_passphrase"),
		NewPassphrase:      mapGetString(args, "new_passphrase"),
	}
	result, err := svc.EnrollPassphrase(ctx, req)
	if err != nil {
		return nil, ErrLUKSOperation{Cause: err}
	}
	return result, nil
}

// LUKSEnrollFIDO2 implements mcp.Phase35Provider.
func (p *MCPServiceProvider) LUKSEnrollFIDO2(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc, err := p.luksService()
	if err != nil {
		return nil, err
	}
	req := &LUKSEnrollFIDO2Request{
		Device:             mapGetString(args, "device"),
		ExistingPassphrase: mapGetString(args, "existing_passphrase"),
		CredentialID:       mapGetString(args, "credential_id"),
		RequirePIN:         mapGetBool(args, "require_pin"),
		RequireUV:          mapGetBool(args, "require_uv"),
	}
	result, err := svc.EnrollFIDO2(ctx, req)
	if err != nil {
		return nil, ErrLUKSOperation{Cause: err}
	}
	return result, nil
}

// LUKSEnrollTPM implements mcp.Phase35Provider.
func (p *MCPServiceProvider) LUKSEnrollTPM(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc, err := p.luksService()
	if err != nil {
		return nil, err
	}
	req := &LUKSEnrollTPMRequest{
		Device:             mapGetString(args, "device"),
		ExistingPassphrase: mapGetString(args, "existing_passphrase"),
		PCRs:               mapGetInt32Slice(args, "pcrs"),
	}
	result, err := svc.EnrollTPM(ctx, req)
	if err != nil {
		return nil, ErrLUKSOperation{Cause: err}
	}
	return result, nil
}

// LUKSEnrollRecovery implements mcp.Phase35Provider.
func (p *MCPServiceProvider) LUKSEnrollRecovery(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc, err := p.luksService()
	if err != nil {
		return nil, err
	}
	req := &LUKSEnrollRecoveryRequest{
		Device:             mapGetString(args, "device"),
		ExistingPassphrase: mapGetString(args, "existing_passphrase"),
	}
	result, err := svc.EnrollRecovery(ctx, req)
	if err != nil {
		return nil, ErrLUKSOperation{Cause: err}
	}
	return result, nil
}

// LUKSRemoveKey implements mcp.Phase35Provider.
func (p *MCPServiceProvider) LUKSRemoveKey(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc, err := p.luksService()
	if err != nil {
		return nil, err
	}
	req := &LUKSRemoveKeyRequest{
		Device: mapGetString(args, "device"),
		Slot:   mapGetInt32(args, "slot"),
	}
	if err := svc.RemoveKey(ctx, req); err != nil {
		return nil, ErrLUKSOperation{Cause: err}
	}
	return map[string]interface{}{"removed": true}, nil
}

// LUKSTestUnlock implements mcp.Phase35Provider by refusing: the request
// carries no key and the backend only checks that the keyslot exists, so
// any "unlocked" answer would be unverified. It never reaches the backend.
func (p *MCPServiceProvider) LUKSTestUnlock(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	return nil, ErrLUKSOperation{Cause: ErrLUKSTestUnlockUnverified}
}

// LUKSChangePassphrase implements mcp.Phase35Provider.
func (p *MCPServiceProvider) LUKSChangePassphrase(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc, err := p.luksService()
	if err != nil {
		return nil, err
	}
	req := &LUKSChangePassphraseRequest{
		Device:        mapGetString(args, "device"),
		Slot:          mapGetInt32(args, "slot"),
		OldPassphrase: mapGetString(args, "old_passphrase"),
		NewPassphrase: mapGetString(args, "new_passphrase"),
	}
	if err := svc.ChangePassphrase(ctx, req); err != nil {
		return nil, ErrLUKSOperation{Cause: err}
	}
	return map[string]interface{}{"changed": true}, nil
}

// =============================================================================
// FIDO2 MCP delegations
// =============================================================================

// FIDO2ListDevices implements mcp.Phase35Provider.
func (p *MCPServiceProvider) FIDO2ListDevices(ctx context.Context) (interface{}, error) {
	svc := p.phase35.snapshot().FIDO2
	if svc == nil {
		return nil, ErrFIDO2NotConfigured
	}
	devices, err := svc.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"devices": devices}, nil
}

// FIDO2WaitDevice implements mcp.Phase35Provider.
func (p *MCPServiceProvider) FIDO2WaitDevice(ctx context.Context, timeout time.Duration) (interface{}, error) {
	svc := p.phase35.snapshot().FIDO2
	if svc == nil {
		return nil, ErrFIDO2NotConfigured
	}
	return svc.WaitDevice(ctx, timeout)
}

// FIDO2Info implements mcp.Phase35Provider.
func (p *MCPServiceProvider) FIDO2Info(ctx context.Context, device string) (interface{}, error) {
	svc := p.phase35.snapshot().FIDO2
	if svc == nil {
		return nil, ErrFIDO2NotConfigured
	}
	return svc.Info(ctx, device)
}

// FIDO2Register implements mcp.Phase35Provider.
func (p *MCPServiceProvider) FIDO2Register(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	svc := p.phase35.snapshot().FIDO2
	if svc == nil {
		return nil, ErrFIDO2NotConfigured
	}
	req := &FIDO2RegisterRequest{
		Username:   mapGetString(args, "username"),
		Role:       FIDO2Role(mapGetString(args, "role")),
		RequirePIN: mapGetBool(args, "require_pin"),
		RequireUV:  mapGetBool(args, "require_uv"),
		RPID:       mapGetString(args, "rp_id"),
	}
	return svc.Register(ctx, req)
}

// FIDO2Authenticate implements mcp.Phase35Provider.
func (p *MCPServiceProvider) FIDO2Authenticate(ctx context.Context, credentialID string) (interface{}, error) {
	svc := p.phase35.snapshot().FIDO2
	if svc == nil {
		return nil, ErrFIDO2NotConfigured
	}
	return svc.Authenticate(ctx, credentialID)
}

// =============================================================================
// Helpers
// =============================================================================

// mapGetString mirrors the unexported helper in pkg/api/mcp/tools.go. It is
// duplicated here because the mcp helpers are package-private. Kept tiny and
// trivial; no runtime cost.
func mapGetString(args map[string]interface{}, key string) string {
	if args == nil {
		return ""
	}
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

// mapGetBase64 decodes a base64 (std encoding) string argument into raw
// bytes. Returns ErrCeremonySignatureInvalid when the value is present but
// not decodable; a missing key yields nil bytes and no error so required-field
// validation stays in the service layer.
func mapGetBase64(args map[string]interface{}, key string) ([]byte, error) {
	s := mapGetString(args, key)
	if s == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrCeremonySignatureInvalid
	}
	return decoded, nil
}

func mapGetBool(args map[string]interface{}, key string) bool {
	if args == nil {
		return false
	}
	if v, ok := args[key].(bool); ok {
		return v
	}
	return false
}

func mapGetStringSlice(args map[string]interface{}, key string) []string {
	if args == nil {
		return nil
	}
	raw, ok := args[key].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func mapGetInt32(args map[string]interface{}, key string) int32 {
	if args == nil {
		return 0
	}
	switch v := args[key].(type) {
	case float64:
		return int32(v)
	case int:
		return int32(v)
	case int32:
		return v
	case int64:
		return int32(v)
	}
	return 0
}

func mapGetInt32Slice(args map[string]interface{}, key string) []int32 {
	if args == nil {
		return nil
	}
	raw, ok := args[key].([]interface{})
	if !ok {
		return nil
	}
	out := make([]int32, 0, len(raw))
	for _, v := range raw {
		switch n := v.(type) {
		case float64:
			out = append(out, int32(n))
		case int:
			out = append(out, int32(n))
		case int32:
			out = append(out, n)
		case int64:
			out = append(out, int32(n))
		}
	}
	return out
}

// decodePayload decodes a base64-encoded payload string. Both standard and
// URL-safe alphabets are accepted.
func decodePayload(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}
	if b, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(encoded)
}

// Compile-time interface compliance check: MCPServiceProvider must implement
// the mcp.Phase35Provider optional interface so the MCP tool dispatcher can
// type-assert and route Phase 3.5 calls to the daemon service layer.
var _ mcp.Phase35Provider = (*MCPServiceProvider)(nil)
