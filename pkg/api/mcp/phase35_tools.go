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

package mcp

import (
	"context"
	"errors"
	"time"
)

// ErrPhase35NotConfigured indicates the Phase 3.5 service tree is not wired
// into the MCP tool registry.
var ErrPhase35NotConfigured = errors.New("phase35: service provider not configured")

// Phase35Provider is the optional interface a ServiceProvider can satisfy to
// unlock ceremony/piv/luks/fido2 MCP tools. Implementations are expected to
// delegate to the underlying daemon service layers.
//
// Method names map to MCP tools: platform_ceremony_init, etc.
type Phase35Provider interface {
	// Ceremony
	CeremonyInit(ctx context.Context, args map[string]interface{}) (interface{}, error)
	CeremonyStatus(ctx context.Context) (interface{}, error)
	CeremonyClaimCertBegin(ctx context.Context, args map[string]interface{}) (interface{}, error)
	CeremonyClaimCertComplete(ctx context.Context, args map[string]interface{}) (interface{}, error)
	CeremonyClaimShareBegin(ctx context.Context, args map[string]interface{}) (interface{}, error)
	CeremonyClaimShareComplete(ctx context.Context, args map[string]interface{}) (interface{}, error)
	CeremonySignCSR(ctx context.Context, args map[string]interface{}) (interface{}, error)

	// PIV
	PIVListDevices(ctx context.Context) (interface{}, error)
	PIVListSlots(ctx context.Context, device string) (interface{}, error)
	PIVSlotInfo(ctx context.Context, device, slot string) (interface{}, error)
	PIVGenerate(ctx context.Context, args map[string]interface{}) (interface{}, error)
	PIVImport(ctx context.Context, args map[string]interface{}) (interface{}, error)
	PIVSign(ctx context.Context, args map[string]interface{}) (interface{}, error)
	PIVAttest(ctx context.Context, slot string) (interface{}, error)
	PIVReset(ctx context.Context, device string) (interface{}, error)

	// LUKS
	LUKSStatus(ctx context.Context, device string) (interface{}, error)
	LUKSListSlots(ctx context.Context, device string) (interface{}, error)
	LUKSInfo(ctx context.Context, device string) (interface{}, error)
	LUKSEnrollPassphrase(ctx context.Context, args map[string]interface{}) (interface{}, error)
	LUKSEnrollFIDO2(ctx context.Context, args map[string]interface{}) (interface{}, error)
	LUKSEnrollTPM(ctx context.Context, args map[string]interface{}) (interface{}, error)
	LUKSEnrollRecovery(ctx context.Context, args map[string]interface{}) (interface{}, error)
	LUKSRemoveKey(ctx context.Context, args map[string]interface{}) (interface{}, error)
	LUKSTestUnlock(ctx context.Context, args map[string]interface{}) (interface{}, error)
	LUKSChangePassphrase(ctx context.Context, args map[string]interface{}) (interface{}, error)

	// FIDO2
	FIDO2ListDevices(ctx context.Context) (interface{}, error)
	FIDO2WaitDevice(ctx context.Context, timeout time.Duration) (interface{}, error)
	FIDO2Info(ctx context.Context, device string) (interface{}, error)
	FIDO2Register(ctx context.Context, args map[string]interface{}) (interface{}, error)
	FIDO2Authenticate(ctx context.Context, credentialID string) (interface{}, error)
}

// phase35Provider returns the Phase35Provider interface if the ServiceProvider
// implements it, else nil.
func (r *ToolRegistry) phase35Provider() Phase35Provider {
	if p, ok := r.service.(Phase35Provider); ok {
		return p
	}
	return nil
}

// registerPhase35Tools registers all Phase 3.5 MCP tools.
func (r *ToolRegistry) registerPhase35Tools() {
	// Ceremony tools.
	r.addTool(ToolDefinition{
		Name:        "platform_ceremony_init",
		Description: "Initialize the platform ceremony (SO/user PIN, Shamir threshold)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"so_pin":                   map[string]interface{}{"type": "string"},
				"user_pin":                 map[string]interface{}{"type": "string"},
				"threshold":                map[string]interface{}{"type": "string"},
				"hostname":                 map[string]interface{}{"type": "string"},
				"sans":                     map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
				"credential_seal_strategy": map[string]interface{}{"type": "string"},
			},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_ceremony_status",
		Description: "Get current ceremony state",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_ceremony_claim_cert_begin",
		Description: "Begin a claim-cert challenge for an officer",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"username":           map[string]interface{}{"type": "string"},
				"authenticator_type": map[string]interface{}{"type": "string"},
				"slot":               map[string]interface{}{"type": "string"},
				"credential_id":      map[string]interface{}{"type": "string"},
			},
			"required": []string{"username"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_ceremony_claim_cert_complete",
		Description: "Complete a claim-cert challenge",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"username":  map[string]interface{}{"type": "string"},
				"nonce":     map[string]interface{}{"type": "string"},
				"signature": map[string]interface{}{"type": "string"},
			},
			"required": []string{"username", "nonce", "signature"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_ceremony_claim_share_begin",
		Description: "Begin a claim-share challenge for an officer",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"username": map[string]interface{}{"type": "string"}},
			"required":   []string{"username"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_ceremony_claim_share_complete",
		Description: "Complete a claim-share challenge and return the caller's Shamir share",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"username":  map[string]interface{}{"type": "string"},
				"nonce":     map[string]interface{}{"type": "string"},
				"signature": map[string]interface{}{"type": "string", "description": "base64-encoded signature over the nonce"},
			},
			"required": []string{"username", "nonce", "signature"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_ceremony_sign_csr",
		Description: "Sign a CSR using the ceremony CA",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"username": map[string]interface{}{"type": "string"},
				"so_pin":   map[string]interface{}{"type": "string"},
				"csr_pem":  map[string]interface{}{"type": "string"},
				"role":     map[string]interface{}{"type": "string"},
			},
			"required": []string{"username", "csr_pem"},
		},
	})

	// PIV tools.
	r.addTool(ToolDefinition{
		Name:        "platform_piv_list_devices",
		Description: "Enumerate PIV devices attached to the host",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_piv_list_slots",
		Description: "List the slots on a PIV device",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"device": map[string]interface{}{"type": "string"}},
			"required":   []string{"device"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_piv_slot_info",
		Description: "Return detailed info about a PIV slot",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"slot":   map[string]interface{}{"type": "string"},
				"device": map[string]interface{}{"type": "string"},
			},
			"required": []string{"slot"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_piv_generate",
		Description: "Generate a fresh key in a PIV slot",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"slot":      map[string]interface{}{"type": "string"},
				"algorithm": map[string]interface{}{"type": "string"},
				"pin":       map[string]interface{}{"type": "string"},
			},
			"required": []string{"slot", "algorithm"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_piv_import",
		Description: "Import an externally generated key into a PIV slot",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"slot":            map[string]interface{}{"type": "string"},
				"private_key_pem": map[string]interface{}{"type": "string"},
				"pin":             map[string]interface{}{"type": "string"},
			},
			"required": []string{"slot", "private_key_pem"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_piv_sign",
		Description: "Sign a payload with a PIV slot's key",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"slot":    map[string]interface{}{"type": "string"},
				"payload": map[string]interface{}{"type": "string", "description": "base64-encoded payload"},
				"pin":     map[string]interface{}{"type": "string"},
			},
			"required": []string{"slot", "payload"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_piv_attest",
		Description: "Return attestation certificate(s) for a PIV slot",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"slot": map[string]interface{}{"type": "string"}},
			"required":   []string{"slot"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_piv_reset",
		Description: "Factory-reset a PIV device",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"device": map[string]interface{}{"type": "string"}},
			"required":   []string{"device"},
		},
	})

	// LUKS tools.
	r.addTool(ToolDefinition{
		Name:        "platform_luks_status",
		Description: "Return LUKS device status",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"device": map[string]interface{}{"type": "string"}},
			"required":   []string{"device"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_luks_list_slots",
		Description: "List LUKS keyslots",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"device": map[string]interface{}{"type": "string"}},
			"required":   []string{"device"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_luks_info",
		Description: "Detailed LUKS2 header dump",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"device": map[string]interface{}{"type": "string"}},
			"required":   []string{"device"},
		},
	})
	luksEnrollCommon := map[string]interface{}{
		"device":              map[string]interface{}{"type": "string"},
		"existing_passphrase": map[string]interface{}{"type": "string"},
	}
	passphraseProps := copyMap(luksEnrollCommon)
	passphraseProps["new_passphrase"] = map[string]interface{}{"type": "string"}
	r.addTool(ToolDefinition{
		Name:        "platform_luks_enroll_passphrase",
		Description: "Add a passphrase LUKS keyslot",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": passphraseProps,
			"required":   []string{"device", "existing_passphrase", "new_passphrase"},
		},
	})
	fido2Props := copyMap(luksEnrollCommon)
	fido2Props["credential_id"] = map[string]interface{}{"type": "string"}
	fido2Props["require_pin"] = map[string]interface{}{"type": "boolean"}
	fido2Props["require_uv"] = map[string]interface{}{"type": "boolean"}
	r.addTool(ToolDefinition{
		Name:        "platform_luks_enroll_fido2",
		Description: "Add a FIDO2 LUKS keyslot",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": fido2Props,
			"required":   []string{"device", "existing_passphrase", "credential_id"},
		},
	})
	tpmProps := copyMap(luksEnrollCommon)
	tpmProps["pcrs"] = map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "integer"}}
	tpmProps["handle"] = map[string]interface{}{"type": "string"}
	r.addTool(ToolDefinition{
		Name:        "platform_luks_enroll_tpm",
		Description: "Add a TPM2-sealed LUKS keyslot",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": tpmProps,
			"required":   []string{"device", "existing_passphrase"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_luks_enroll_recovery",
		Description: "Add a recovery-key LUKS keyslot",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": luksEnrollCommon,
			"required":   []string{"device", "existing_passphrase"},
		},
	})
	slotProps := map[string]interface{}{
		"device": map[string]interface{}{"type": "string"},
		"slot":   map[string]interface{}{"type": "integer"},
	}
	r.addTool(ToolDefinition{
		Name:        "platform_luks_remove_key",
		Description: "Remove a LUKS keyslot",
		InputSchema: map[string]interface{}{"type": "object", "properties": slotProps, "required": []string{"device", "slot"}},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_luks_test_unlock",
		Description: "Verify a LUKS keyslot can unlock the device",
		InputSchema: map[string]interface{}{"type": "object", "properties": slotProps, "required": []string{"device", "slot"}},
	})
	changePPProps := map[string]interface{}{
		"device":         map[string]interface{}{"type": "string"},
		"slot":           map[string]interface{}{"type": "integer"},
		"old_passphrase": map[string]interface{}{"type": "string"},
		"new_passphrase": map[string]interface{}{"type": "string"},
	}
	r.addTool(ToolDefinition{
		Name:        "platform_luks_change_passphrase",
		Description: "Change an existing LUKS passphrase slot",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": changePPProps,
			"required":   []string{"device", "slot", "old_passphrase", "new_passphrase"},
		},
	})

	// FIDO2 tools.
	r.addTool(ToolDefinition{
		Name:        "platform_fido2_list_devices",
		Description: "Enumerate FIDO2 authenticators",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_fido2_wait_device",
		Description: "Block until a FIDO2 authenticator is detected",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"timeout_seconds": map[string]interface{}{"type": "integer"}},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_fido2_info",
		Description: "Authenticator capabilities",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"device": map[string]interface{}{"type": "string"}},
			"required":   []string{"device"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_fido2_register",
		Description: "Register a WebAuthn credential",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"username":    map[string]interface{}{"type": "string"},
				"role":        map[string]interface{}{"type": "string"},
				"require_pin": map[string]interface{}{"type": "boolean"},
				"require_uv":  map[string]interface{}{"type": "boolean"},
				"rp_id":       map[string]interface{}{"type": "string"},
			},
			"required": []string{"username"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_fido2_authenticate",
		Description: "Run a WebAuthn authenticate ceremony against a credential",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"credential_id": map[string]interface{}{"type": "string"}},
			"required":   []string{"credential_id"},
		},
	})
}

// copyMap makes a shallow copy of a map[string]interface{}.
func copyMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// phase35ToolHandler dispatches a Phase 3.5 tool. Uses map-based dispatch per
// project conventions to give O(1) routing.
type phase35ToolHandler func(*ToolRegistry, context.Context, map[string]interface{}) (interface{}, error)

var phase35ToolDispatch = map[string]phase35ToolHandler{
	"platform_ceremony_init":                 (*ToolRegistry).executePhase35CeremonyInit,
	"platform_ceremony_status":               (*ToolRegistry).executePhase35CeremonyStatus,
	"platform_ceremony_claim_cert_begin":     (*ToolRegistry).executePhase35CeremonyClaimCertBegin,
	"platform_ceremony_claim_cert_complete":  (*ToolRegistry).executePhase35CeremonyClaimCertComplete,
	"platform_ceremony_claim_share_begin":    (*ToolRegistry).executePhase35CeremonyClaimShareBegin,
	"platform_ceremony_claim_share_complete": (*ToolRegistry).executePhase35CeremonyClaimShareComplete,
	"platform_ceremony_sign_csr":             (*ToolRegistry).executePhase35CeremonySignCSR,

	"platform_piv_list_devices": (*ToolRegistry).executePhase35PIVListDevices,
	"platform_piv_list_slots":   (*ToolRegistry).executePhase35PIVListSlots,
	"platform_piv_slot_info":    (*ToolRegistry).executePhase35PIVSlotInfo,
	"platform_piv_generate":     (*ToolRegistry).executePhase35PIVGenerate,
	"platform_piv_import":       (*ToolRegistry).executePhase35PIVImport,
	"platform_piv_sign":         (*ToolRegistry).executePhase35PIVSign,
	"platform_piv_attest":       (*ToolRegistry).executePhase35PIVAttest,
	"platform_piv_reset":        (*ToolRegistry).executePhase35PIVReset,

	"platform_luks_status":            (*ToolRegistry).executePhase35LUKSStatus,
	"platform_luks_list_slots":        (*ToolRegistry).executePhase35LUKSListSlots,
	"platform_luks_info":              (*ToolRegistry).executePhase35LUKSInfo,
	"platform_luks_enroll_passphrase": (*ToolRegistry).executePhase35LUKSEnrollPassphrase,
	"platform_luks_enroll_fido2":      (*ToolRegistry).executePhase35LUKSEnrollFIDO2,
	"platform_luks_enroll_tpm":        (*ToolRegistry).executePhase35LUKSEnrollTPM,
	"platform_luks_enroll_recovery":   (*ToolRegistry).executePhase35LUKSEnrollRecovery,
	"platform_luks_remove_key":        (*ToolRegistry).executePhase35LUKSRemoveKey,
	"platform_luks_test_unlock":       (*ToolRegistry).executePhase35LUKSTestUnlock,
	"platform_luks_change_passphrase": (*ToolRegistry).executePhase35LUKSChangePassphrase,

	"platform_fido2_list_devices": (*ToolRegistry).executePhase35FIDO2ListDevices,
	"platform_fido2_wait_device":  (*ToolRegistry).executePhase35FIDO2WaitDevice,
	"platform_fido2_info":         (*ToolRegistry).executePhase35FIDO2Info,
	"platform_fido2_register":     (*ToolRegistry).executePhase35FIDO2Register,
	"platform_fido2_authenticate": (*ToolRegistry).executePhase35FIDO2Authenticate,
}

// dispatchPhase35Tool looks up a phase35 tool and runs it. Returns (result,
// handled, err). If handled is false the caller should fall through.
func (r *ToolRegistry) dispatchPhase35Tool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	fn, ok := phase35ToolDispatch[name]
	if !ok {
		return nil, false, nil
	}
	result, err := fn(r, ctx, args)
	return result, true, err
}

// Ceremony executors.
func (r *ToolRegistry) executePhase35CeremonyInit(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.CeremonyInit(ctx, args)
}

func (r *ToolRegistry) executePhase35CeremonyStatus(ctx context.Context, _ map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.CeremonyStatus(ctx)
}

func (r *ToolRegistry) executePhase35CeremonyClaimCertBegin(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.CeremonyClaimCertBegin(ctx, args)
}

func (r *ToolRegistry) executePhase35CeremonyClaimCertComplete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.CeremonyClaimCertComplete(ctx, args)
}

func (r *ToolRegistry) executePhase35CeremonyClaimShareBegin(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.CeremonyClaimShareBegin(ctx, args)
}

func (r *ToolRegistry) executePhase35CeremonyClaimShareComplete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.CeremonyClaimShareComplete(ctx, args)
}

func (r *ToolRegistry) executePhase35CeremonySignCSR(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.CeremonySignCSR(ctx, args)
}

// PIV executors.
func (r *ToolRegistry) executePhase35PIVListDevices(ctx context.Context, _ map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.PIVListDevices(ctx)
}

func (r *ToolRegistry) executePhase35PIVListSlots(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.PIVListSlots(ctx, getString(args, "device"))
}

func (r *ToolRegistry) executePhase35PIVSlotInfo(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.PIVSlotInfo(ctx, getString(args, "device"), getString(args, "slot"))
}

func (r *ToolRegistry) executePhase35PIVGenerate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.PIVGenerate(ctx, args)
}

func (r *ToolRegistry) executePhase35PIVImport(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.PIVImport(ctx, args)
}

func (r *ToolRegistry) executePhase35PIVSign(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.PIVSign(ctx, args)
}

func (r *ToolRegistry) executePhase35PIVAttest(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.PIVAttest(ctx, getString(args, "slot"))
}

func (r *ToolRegistry) executePhase35PIVReset(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.PIVReset(ctx, getString(args, "device"))
}

// LUKS executors.
func (r *ToolRegistry) executePhase35LUKSStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.LUKSStatus(ctx, getString(args, "device"))
}

func (r *ToolRegistry) executePhase35LUKSListSlots(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.LUKSListSlots(ctx, getString(args, "device"))
}

func (r *ToolRegistry) executePhase35LUKSInfo(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.LUKSInfo(ctx, getString(args, "device"))
}

func (r *ToolRegistry) executePhase35LUKSEnrollPassphrase(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.LUKSEnrollPassphrase(ctx, args)
}

func (r *ToolRegistry) executePhase35LUKSEnrollFIDO2(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.LUKSEnrollFIDO2(ctx, args)
}

func (r *ToolRegistry) executePhase35LUKSEnrollTPM(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.LUKSEnrollTPM(ctx, args)
}

func (r *ToolRegistry) executePhase35LUKSEnrollRecovery(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.LUKSEnrollRecovery(ctx, args)
}

func (r *ToolRegistry) executePhase35LUKSRemoveKey(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.LUKSRemoveKey(ctx, args)
}

func (r *ToolRegistry) executePhase35LUKSTestUnlock(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.LUKSTestUnlock(ctx, args)
}

func (r *ToolRegistry) executePhase35LUKSChangePassphrase(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.LUKSChangePassphrase(ctx, args)
}

// FIDO2 executors.
func (r *ToolRegistry) executePhase35FIDO2ListDevices(ctx context.Context, _ map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.FIDO2ListDevices(ctx)
}

func (r *ToolRegistry) executePhase35FIDO2WaitDevice(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	var timeout time.Duration
	if v, ok := args["timeout_seconds"].(float64); ok && v > 0 {
		timeout = time.Duration(v) * time.Second
	}
	return p.FIDO2WaitDevice(ctx, timeout)
}

func (r *ToolRegistry) executePhase35FIDO2Info(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.FIDO2Info(ctx, getString(args, "device"))
}

func (r *ToolRegistry) executePhase35FIDO2Register(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.FIDO2Register(ctx, args)
}

func (r *ToolRegistry) executePhase35FIDO2Authenticate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.phase35Provider()
	if p == nil {
		return nil, ErrPhase35NotConfigured
	}
	return p.FIDO2Authenticate(ctx, getString(args, "credential_id"))
}
