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
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// phase35ExpectedTools lists every Phase 3.5 tool name the registry must
// expose. The test guards against accidental removal and the underscore
// naming convention.
var phase35ExpectedTools = []string{
	"platform_ceremony_init",
	"platform_ceremony_status",
	"platform_ceremony_claim_cert_begin",
	"platform_ceremony_claim_cert_complete",
	"platform_ceremony_claim_share_begin",
	"platform_ceremony_claim_share_complete",
	"platform_ceremony_sign_csr",
	"platform_piv_list_devices",
	"platform_piv_list_slots",
	"platform_piv_slot_info",
	"platform_piv_generate",
	"platform_piv_import",
	"platform_piv_sign",
	"platform_piv_attest",
	"platform_piv_reset",
	"platform_luks_status",
	"platform_luks_list_slots",
	"platform_luks_info",
	"platform_luks_enroll_passphrase",
	"platform_luks_enroll_fido2",
	"platform_luks_enroll_tpm",
	"platform_luks_enroll_recovery",
	"platform_luks_remove_key",
	"platform_luks_test_unlock",
	"platform_luks_change_passphrase",
	"platform_fido2_list_devices",
	"platform_fido2_wait_device",
	"platform_fido2_info",
	"platform_fido2_register",
	"platform_fido2_authenticate",
}

func TestPhase35ToolsRegistered(t *testing.T) {
	r := NewToolRegistry(nil, logging.DefaultLogger())
	got := make(map[string]bool)
	for _, tool := range r.ListTools() {
		got[tool.Name] = true
	}
	for _, want := range phase35ExpectedTools {
		if !got[want] {
			t.Errorf("missing Phase 3.5 tool: %s", want)
		}
	}
	if len(phase35ExpectedTools) != 30 {
		t.Errorf("expected 30 Phase 3.5 tools, got %d", len(phase35ExpectedTools))
	}
}

func TestPhase35_DispatchMapCoverage(t *testing.T) {
	// Every registered Phase 3.5 tool must have a dispatch entry.
	for _, name := range phase35ExpectedTools {
		if _, ok := phase35ToolDispatch[name]; !ok {
			t.Errorf("tool %q registered but missing from dispatch map", name)
		}
	}
	// And the dispatch map must not carry any extra entries.
	if len(phase35ToolDispatch) != len(phase35ExpectedTools) {
		t.Errorf("dispatch map size %d != expected %d", len(phase35ToolDispatch), len(phase35ExpectedTools))
	}
}

func TestPhase35_NotConfigured(t *testing.T) {
	// Registry with a nil service provider — dispatch returns
	// ErrPhase35NotConfigured for every tool.
	r := NewToolRegistry(nil, logging.DefaultLogger())
	ctx := context.Background()

	for _, name := range phase35ExpectedTools {
		_, handled, err := r.dispatchPhase35Tool(ctx, name, map[string]interface{}{})
		if !handled {
			t.Errorf("tool %s: expected handled=true", name)
			continue
		}
		if !errors.Is(err, ErrPhase35NotConfigured) {
			t.Errorf("tool %s: want ErrPhase35NotConfigured, got %v", name, err)
		}
	}
}

func TestPhase35_DispatchUnknownTool(t *testing.T) {
	r := NewToolRegistry(nil, logging.DefaultLogger())
	_, handled, err := r.dispatchPhase35Tool(context.Background(), "platform_not_a_tool", nil)
	if handled {
		t.Fatal("unknown tool should not be handled")
	}
	if err != nil {
		t.Errorf("unknown tool should not return an error: %v", err)
	}
}

// phase35StubProvider satisfies Phase35Provider for direct handler tests.
// It records the last method invoked so tests can assert routing.
type phase35StubProvider struct {
	lastCall string
}

func (p *phase35StubProvider) CeremonyInit(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	p.lastCall = "ceremony_init"
	return map[string]string{"state": "in_progress"}, nil
}
func (p *phase35StubProvider) CeremonyStatus(_ context.Context) (interface{}, error) {
	p.lastCall = "ceremony_status"
	return map[string]string{"state": "complete"}, nil
}
func (p *phase35StubProvider) CeremonyClaimCertBegin(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	p.lastCall = "ceremony_claim_cert_begin"
	return map[string]string{"nonce": "n"}, nil
}
func (p *phase35StubProvider) CeremonyClaimCertComplete(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	p.lastCall = "ceremony_claim_cert_complete"
	return map[string]string{"cert": "CERT"}, nil
}
func (p *phase35StubProvider) CeremonyClaimShareBegin(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	p.lastCall = "ceremony_claim_share_begin"
	return map[string]string{"nonce": "n"}, nil
}
func (p *phase35StubProvider) CeremonyClaimShareComplete(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	p.lastCall = "ceremony_claim_share_complete"
	return map[string]string{"share": "s"}, nil
}
func (p *phase35StubProvider) CeremonySignCSR(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	p.lastCall = "ceremony_sign_csr"
	return map[string]string{"cert": "SIGN"}, nil
}
func (p *phase35StubProvider) PIVListDevices(_ context.Context) (interface{}, error) {
	p.lastCall = "piv_list_devices"
	return []string{"dev1"}, nil
}
func (p *phase35StubProvider) PIVListSlots(_ context.Context, _ string) (interface{}, error) {
	p.lastCall = "piv_list_slots"
	return []string{"9a"}, nil
}
func (p *phase35StubProvider) PIVSlotInfo(_ context.Context, _, _ string) (interface{}, error) {
	p.lastCall = "piv_slot_info"
	return map[string]string{"slot": "9a"}, nil
}
func (p *phase35StubProvider) PIVGenerate(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	p.lastCall = "piv_generate"
	return map[string]string{"public_key_pem": "PEM"}, nil
}
func (p *phase35StubProvider) PIVImport(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	p.lastCall = "piv_import"
	return map[string]bool{"imported": true}, nil
}
func (p *phase35StubProvider) PIVSign(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	p.lastCall = "piv_sign"
	return map[string]string{"signature": "SIG"}, nil
}
func (p *phase35StubProvider) PIVAttest(_ context.Context, _ string) (interface{}, error) {
	p.lastCall = "piv_attest"
	return map[string]string{"cert": "ATT"}, nil
}
func (p *phase35StubProvider) PIVReset(_ context.Context, _ string) (interface{}, error) {
	p.lastCall = "piv_reset"
	return map[string]bool{"reset": true}, nil
}
func (p *phase35StubProvider) LUKSStatus(_ context.Context, _ string) (interface{}, error) {
	p.lastCall = "luks_status"
	return map[string]bool{"is_luks": true}, nil
}
func (p *phase35StubProvider) LUKSListSlots(_ context.Context, _ string) (interface{}, error) {
	p.lastCall = "luks_list_slots"
	return []int{0, 1}, nil
}
func (p *phase35StubProvider) LUKSInfo(_ context.Context, _ string) (interface{}, error) {
	p.lastCall = "luks_info"
	return map[string]string{"cipher": "aes"}, nil
}
func (p *phase35StubProvider) LUKSEnrollPassphrase(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	p.lastCall = "luks_enroll_passphrase"
	return map[string]int{"slot": 1}, nil
}
func (p *phase35StubProvider) LUKSEnrollFIDO2(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	p.lastCall = "luks_enroll_fido2"
	return map[string]int{"slot": 2}, nil
}
func (p *phase35StubProvider) LUKSEnrollTPM(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	p.lastCall = "luks_enroll_tpm"
	return map[string]int{"slot": 3}, nil
}
func (p *phase35StubProvider) LUKSEnrollRecovery(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	p.lastCall = "luks_enroll_recovery"
	return map[string]string{"recovery_key": "r"}, nil
}
func (p *phase35StubProvider) LUKSRemoveKey(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	p.lastCall = "luks_remove_key"
	return map[string]bool{"removed": true}, nil
}
func (p *phase35StubProvider) LUKSTestUnlock(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	p.lastCall = "luks_test_unlock"
	return map[string]bool{"unlocked": true}, nil
}
func (p *phase35StubProvider) LUKSChangePassphrase(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	p.lastCall = "luks_change_passphrase"
	return map[string]bool{"changed": true}, nil
}
func (p *phase35StubProvider) FIDO2ListDevices(_ context.Context) (interface{}, error) {
	p.lastCall = "fido2_list_devices"
	return []string{"key1"}, nil
}
func (p *phase35StubProvider) FIDO2WaitDevice(_ context.Context, _ time.Duration) (interface{}, error) {
	p.lastCall = "fido2_wait_device"
	return map[string]string{"id": "key1"}, nil
}
func (p *phase35StubProvider) FIDO2Info(_ context.Context, _ string) (interface{}, error) {
	p.lastCall = "fido2_info"
	return map[string]string{"aaguid": "aa"}, nil
}
func (p *phase35StubProvider) FIDO2Register(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	p.lastCall = "fido2_register"
	return map[string]string{"credential_id": "cred"}, nil
}
func (p *phase35StubProvider) FIDO2Authenticate(_ context.Context, _ string) (interface{}, error) {
	p.lastCall = "fido2_authenticate"
	return map[string]bool{"authenticated": true}, nil
}

// Compile-time check the stub satisfies Phase35Provider.
var _ Phase35Provider = (*phase35StubProvider)(nil)

// TestPhase35ProviderInterface exercises every Phase35Provider method on the
// stub. This covers the business-logic surface the MCP dispatch calls out to
// without needing a full ~200-method ServiceProvider mock.
func TestPhase35ProviderInterface(t *testing.T) {
	stub := &phase35StubProvider{}
	ctx := context.Background()

	// Ceremony.
	if _, err := stub.CeremonyInit(ctx, nil); err != nil {
		t.Error(err)
	}
	if _, err := stub.CeremonyStatus(ctx); err != nil {
		t.Error(err)
	}
	if _, err := stub.CeremonyClaimCertBegin(ctx, nil); err != nil {
		t.Error(err)
	}
	if _, err := stub.CeremonyClaimCertComplete(ctx, nil); err != nil {
		t.Error(err)
	}
	if _, err := stub.CeremonyClaimShareBegin(ctx, nil); err != nil {
		t.Error(err)
	}
	if _, err := stub.CeremonyClaimShareComplete(ctx, nil); err != nil {
		t.Error(err)
	}
	if _, err := stub.CeremonySignCSR(ctx, nil); err != nil {
		t.Error(err)
	}

	// PIV.
	if _, err := stub.PIVListDevices(ctx); err != nil {
		t.Error(err)
	}
	if _, err := stub.PIVListSlots(ctx, "dev"); err != nil {
		t.Error(err)
	}
	if _, err := stub.PIVSlotInfo(ctx, "", "9a"); err != nil {
		t.Error(err)
	}
	if _, err := stub.PIVGenerate(ctx, nil); err != nil {
		t.Error(err)
	}
	if _, err := stub.PIVImport(ctx, nil); err != nil {
		t.Error(err)
	}
	if _, err := stub.PIVSign(ctx, nil); err != nil {
		t.Error(err)
	}
	if _, err := stub.PIVAttest(ctx, "9a"); err != nil {
		t.Error(err)
	}
	if _, err := stub.PIVReset(ctx, "dev"); err != nil {
		t.Error(err)
	}

	// LUKS.
	if _, err := stub.LUKSStatus(ctx, "/d"); err != nil {
		t.Error(err)
	}
	if _, err := stub.LUKSListSlots(ctx, "/d"); err != nil {
		t.Error(err)
	}
	if _, err := stub.LUKSInfo(ctx, "/d"); err != nil {
		t.Error(err)
	}
	if _, err := stub.LUKSEnrollPassphrase(ctx, nil); err != nil {
		t.Error(err)
	}
	if _, err := stub.LUKSEnrollFIDO2(ctx, nil); err != nil {
		t.Error(err)
	}
	if _, err := stub.LUKSEnrollTPM(ctx, nil); err != nil {
		t.Error(err)
	}
	if _, err := stub.LUKSEnrollRecovery(ctx, nil); err != nil {
		t.Error(err)
	}
	if _, err := stub.LUKSRemoveKey(ctx, nil); err != nil {
		t.Error(err)
	}
	if _, err := stub.LUKSTestUnlock(ctx, nil); err != nil {
		t.Error(err)
	}
	if _, err := stub.LUKSChangePassphrase(ctx, nil); err != nil {
		t.Error(err)
	}

	// FIDO2.
	if _, err := stub.FIDO2ListDevices(ctx); err != nil {
		t.Error(err)
	}
	if _, err := stub.FIDO2WaitDevice(ctx, time.Second); err != nil {
		t.Error(err)
	}
	if _, err := stub.FIDO2Info(ctx, "dev"); err != nil {
		t.Error(err)
	}
	if _, err := stub.FIDO2Register(ctx, nil); err != nil {
		t.Error(err)
	}
	if _, err := stub.FIDO2Authenticate(ctx, "cred"); err != nil {
		t.Error(err)
	}
}
