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
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
)

// The existing test files in this package (ceremony_service_test.go,
// piv_service_test.go, luks_service_test.go, fido2_service_test.go) already
// declare fakeCeremonyBackend / fakePIVBackend / fakeLUKSBackend /
// fakeFIDO2Backend. We reuse those to keep DRY, and introduce wrapper types
// below where the existing fakes cannot record the call-level information
// the MCP provider tests need.

// recordingCeremonyBackend wraps a CeremonyBackend and records the last
// request body passed to each method, enabling arg-translation assertions.
type recordingCeremonyBackend struct {
	inner             CeremonyBackend
	lastInit          *CeremonyInitRequest
	lastClaimBegin    *CeremonyClaimCertBeginRequest
	lastClaimComplete *CeremonyClaimCertCompleteRequest
	lastShareUser     string
	lastShareComplete *CeremonyClaimShareCompleteRequest
	lastSignCSR       *CeremonySignCSRRequest
}

func (r *recordingCeremonyBackend) Initialize(ctx context.Context, req *CeremonyInitRequest) (*CeremonyInitResult, error) {
	r.lastInit = req
	return r.inner.Initialize(ctx, req)
}
func (r *recordingCeremonyBackend) Status(ctx context.Context) (*CeremonyStatusInfo, error) {
	return r.inner.Status(ctx)
}
func (r *recordingCeremonyBackend) ClaimCertBegin(ctx context.Context, req *CeremonyClaimCertBeginRequest) (*CeremonyClaimCertBeginResult, error) {
	r.lastClaimBegin = req
	return r.inner.ClaimCertBegin(ctx, req)
}
func (r *recordingCeremonyBackend) ClaimCertComplete(ctx context.Context, req *CeremonyClaimCertCompleteRequest) (*CeremonyClaimCertCompleteResult, error) {
	r.lastClaimComplete = req
	return r.inner.ClaimCertComplete(ctx, req)
}
func (r *recordingCeremonyBackend) ClaimShareBegin(ctx context.Context, req *CeremonyClaimShareBeginRequest) (*CeremonyClaimShareBeginResult, error) {
	r.lastShareUser = req.Username
	return r.inner.ClaimShareBegin(ctx, req)
}
func (r *recordingCeremonyBackend) ClaimShareComplete(ctx context.Context, req *CeremonyClaimShareCompleteRequest) (*CeremonyClaimShareResult, error) {
	r.lastShareComplete = req
	return r.inner.ClaimShareComplete(ctx, req)
}
func (r *recordingCeremonyBackend) SignCSR(ctx context.Context, req *CeremonySignCSRRequest) (*CeremonySignCSRResult, error) {
	r.lastSignCSR = req
	return r.inner.SignCSR(ctx, req)
}

// recordingPIVBackend wraps a PIVBackend to capture the last call arguments.
type recordingPIVBackend struct {
	inner       PIVBackend
	lastGen     *PIVGenerateRequest
	lastImport  *PIVImportRequest
	lastSign    *PIVSignRequest
	lastReset   string
	lastAttest  string
	lastDevice  string
	lastSlotDev string
	lastSlotID  string
}

func (r *recordingPIVBackend) ListDevices(ctx context.Context) ([]PIVDevice, error) {
	return r.inner.ListDevices(ctx)
}
func (r *recordingPIVBackend) ListSlots(ctx context.Context, device string) ([]PIVSlot, error) {
	r.lastDevice = device
	return r.inner.ListSlots(ctx, device)
}
func (r *recordingPIVBackend) SlotInfo(ctx context.Context, device, slot string) (*PIVSlotInfo, error) {
	r.lastSlotDev = device
	r.lastSlotID = slot
	return r.inner.SlotInfo(ctx, device, slot)
}
func (r *recordingPIVBackend) Generate(ctx context.Context, req *PIVGenerateRequest) (*PIVGenerateResult, error) {
	r.lastGen = req
	return r.inner.Generate(ctx, req)
}
func (r *recordingPIVBackend) Import(ctx context.Context, req *PIVImportRequest) error {
	r.lastImport = req
	return r.inner.Import(ctx, req)
}
func (r *recordingPIVBackend) Sign(ctx context.Context, req *PIVSignRequest) ([]byte, error) {
	r.lastSign = req
	return r.inner.Sign(ctx, req)
}
func (r *recordingPIVBackend) Attest(ctx context.Context, slot string) (*PIVAttestResult, error) {
	r.lastAttest = slot
	return r.inner.Attest(ctx, slot)
}
func (r *recordingPIVBackend) Reset(ctx context.Context, device string) error {
	r.lastReset = device
	return r.inner.Reset(ctx, device)
}

// recordingLUKSBackend wraps a LUKSBackend to count calls.
type recordingLUKSBackend struct {
	inner      LUKSBackend
	removeHit  int
	changeHit  int
	unlockHit  int
	lastEnroll *LUKSEnrollTPMRequest
}

func (r *recordingLUKSBackend) Status(ctx context.Context, device string) (*LUKSStatus, error) {
	return r.inner.Status(ctx, device)
}
func (r *recordingLUKSBackend) ListSlots(ctx context.Context, device string) (*LUKSListSlotsResult, error) {
	return r.inner.ListSlots(ctx, device)
}
func (r *recordingLUKSBackend) Info(ctx context.Context, device string) (*LUKSInfo, error) {
	return r.inner.Info(ctx, device)
}
func (r *recordingLUKSBackend) EnrollPassphrase(ctx context.Context, req *LUKSEnrollPassphraseRequest) (*LUKSEnrollPassphraseResult, error) {
	return r.inner.EnrollPassphrase(ctx, req)
}
func (r *recordingLUKSBackend) EnrollFIDO2(ctx context.Context, req *LUKSEnrollFIDO2Request) (*LUKSEnrollFIDO2Result, error) {
	return r.inner.EnrollFIDO2(ctx, req)
}
func (r *recordingLUKSBackend) EnrollTPM(ctx context.Context, req *LUKSEnrollTPMRequest) (*LUKSEnrollTPMResult, error) {
	r.lastEnroll = req
	return r.inner.EnrollTPM(ctx, req)
}
func (r *recordingLUKSBackend) EnrollRecovery(ctx context.Context, req *LUKSEnrollRecoveryRequest) (*LUKSEnrollRecoveryResult, error) {
	return r.inner.EnrollRecovery(ctx, req)
}
func (r *recordingLUKSBackend) RemoveKey(ctx context.Context, req *LUKSRemoveKeyRequest) error {
	r.removeHit++
	return r.inner.RemoveKey(ctx, req)
}
func (r *recordingLUKSBackend) TestUnlock(ctx context.Context, req *LUKSTestUnlockRequest) (bool, error) {
	r.unlockHit++
	return r.inner.TestUnlock(ctx, req)
}
func (r *recordingLUKSBackend) ChangePassphrase(ctx context.Context, req *LUKSChangePassphraseRequest) error {
	r.changeHit++
	return r.inner.ChangePassphrase(ctx, req)
}

// recordingFIDO2Backend wraps a FIDO2Backend to capture call arguments.
type recordingFIDO2Backend struct {
	inner        FIDO2Backend
	lastRegister *FIDO2RegisterRequest
	lastAuth     string
}

func (r *recordingFIDO2Backend) ListDevices(ctx context.Context) ([]FIDO2Device, error) {
	return r.inner.ListDevices(ctx)
}
func (r *recordingFIDO2Backend) WaitDevice(ctx context.Context, timeout time.Duration) (*FIDO2Device, error) {
	return r.inner.WaitDevice(ctx, timeout)
}
func (r *recordingFIDO2Backend) Info(ctx context.Context, device string) (*FIDO2Info, error) {
	return r.inner.Info(ctx, device)
}
func (r *recordingFIDO2Backend) Register(ctx context.Context, req *FIDO2RegisterRequest) (*FIDO2RegisterResult, error) {
	r.lastRegister = req
	return r.inner.Register(ctx, req)
}
func (r *recordingFIDO2Backend) Authenticate(ctx context.Context, credentialID string) (*FIDO2AuthenticateResult, error) {
	r.lastAuth = credentialID
	return r.inner.Authenticate(ctx, credentialID)
}

// =============================================================================
// Interface compliance
// =============================================================================

func TestPhase35Provider_InterfaceCompliance(t *testing.T) {
	var _ mcp.Phase35Provider = (*MCPServiceProvider)(nil)
}

// =============================================================================
// Not-configured paths: every method returns the right sentinel when the
// corresponding service is nil.
// =============================================================================

func TestPhase35Provider_NotConfigured(t *testing.T) {
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	ctx := context.Background()

	// Ceremony
	if _, err := p.CeremonyInit(ctx, nil); !errors.Is(err, ErrCeremonyNotConfigured) {
		t.Errorf("CeremonyInit: want ErrCeremonyNotConfigured, got %v", err)
	}
	if _, err := p.CeremonyStatus(ctx); !errors.Is(err, ErrCeremonyNotConfigured) {
		t.Errorf("CeremonyStatus: want ErrCeremonyNotConfigured, got %v", err)
	}
	if _, err := p.CeremonyClaimCertBegin(ctx, nil); !errors.Is(err, ErrCeremonyNotConfigured) {
		t.Errorf("CeremonyClaimCertBegin: want ErrCeremonyNotConfigured, got %v", err)
	}
	if _, err := p.CeremonyClaimCertComplete(ctx, nil); !errors.Is(err, ErrCeremonyNotConfigured) {
		t.Errorf("CeremonyClaimCertComplete: want ErrCeremonyNotConfigured, got %v", err)
	}
	if _, err := p.CeremonyClaimShareBegin(ctx, map[string]interface{}{"username": "u"}); !errors.Is(err, ErrCeremonyNotConfigured) {
		t.Errorf("CeremonyClaimShareBegin: want ErrCeremonyNotConfigured, got %v", err)
	}
	if _, err := p.CeremonyClaimShareComplete(ctx, map[string]interface{}{"username": "u"}); !errors.Is(err, ErrCeremonyNotConfigured) {
		t.Errorf("CeremonyClaimShareComplete: want ErrCeremonyNotConfigured, got %v", err)
	}
	if _, err := p.CeremonySignCSR(ctx, nil); !errors.Is(err, ErrCeremonyNotConfigured) {
		t.Errorf("CeremonySignCSR: want ErrCeremonyNotConfigured, got %v", err)
	}

	// PIV
	if _, err := p.PIVListDevices(ctx); !errors.Is(err, ErrPIVNotConfigured) {
		t.Errorf("PIVListDevices: want ErrPIVNotConfigured, got %v", err)
	}
	if _, err := p.PIVListSlots(ctx, "d"); !errors.Is(err, ErrPIVNotConfigured) {
		t.Errorf("PIVListSlots: want ErrPIVNotConfigured, got %v", err)
	}
	if _, err := p.PIVSlotInfo(ctx, "d", "9a"); !errors.Is(err, ErrPIVNotConfigured) {
		t.Errorf("PIVSlotInfo: want ErrPIVNotConfigured, got %v", err)
	}
	if _, err := p.PIVGenerate(ctx, nil); !errors.Is(err, ErrPIVNotConfigured) {
		t.Errorf("PIVGenerate: want ErrPIVNotConfigured, got %v", err)
	}
	if _, err := p.PIVImport(ctx, nil); !errors.Is(err, ErrPIVNotConfigured) {
		t.Errorf("PIVImport: want ErrPIVNotConfigured, got %v", err)
	}
	if _, err := p.PIVSign(ctx, nil); !errors.Is(err, ErrPIVNotConfigured) {
		t.Errorf("PIVSign: want ErrPIVNotConfigured, got %v", err)
	}
	if _, err := p.PIVAttest(ctx, "9a"); !errors.Is(err, ErrPIVNotConfigured) {
		t.Errorf("PIVAttest: want ErrPIVNotConfigured, got %v", err)
	}
	if _, err := p.PIVReset(ctx, "d"); !errors.Is(err, ErrPIVNotConfigured) {
		t.Errorf("PIVReset: want ErrPIVNotConfigured, got %v", err)
	}

	// LUKS
	if _, err := p.LUKSStatus(ctx, "/dev/x"); !errors.Is(err, ErrLUKSNotConfigured) {
		t.Errorf("LUKSStatus: want ErrLUKSNotConfigured, got %v", err)
	}
	if _, err := p.LUKSListSlots(ctx, "/dev/x"); !errors.Is(err, ErrLUKSNotConfigured) {
		t.Errorf("LUKSListSlots: want ErrLUKSNotConfigured, got %v", err)
	}
	if _, err := p.LUKSInfo(ctx, "/dev/x"); !errors.Is(err, ErrLUKSNotConfigured) {
		t.Errorf("LUKSInfo: want ErrLUKSNotConfigured, got %v", err)
	}
	if _, err := p.LUKSEnrollPassphrase(ctx, nil); !errors.Is(err, ErrLUKSNotConfigured) {
		t.Errorf("LUKSEnrollPassphrase: want ErrLUKSNotConfigured, got %v", err)
	}
	if _, err := p.LUKSEnrollFIDO2(ctx, nil); !errors.Is(err, ErrLUKSNotConfigured) {
		t.Errorf("LUKSEnrollFIDO2: want ErrLUKSNotConfigured, got %v", err)
	}
	if _, err := p.LUKSEnrollTPM(ctx, nil); !errors.Is(err, ErrLUKSNotConfigured) {
		t.Errorf("LUKSEnrollTPM: want ErrLUKSNotConfigured, got %v", err)
	}
	if _, err := p.LUKSEnrollRecovery(ctx, nil); !errors.Is(err, ErrLUKSNotConfigured) {
		t.Errorf("LUKSEnrollRecovery: want ErrLUKSNotConfigured, got %v", err)
	}
	if _, err := p.LUKSRemoveKey(ctx, nil); !errors.Is(err, ErrLUKSNotConfigured) {
		t.Errorf("LUKSRemoveKey: want ErrLUKSNotConfigured, got %v", err)
	}
	if _, err := p.LUKSTestUnlock(ctx, nil); !errors.Is(err, ErrLUKSNotConfigured) {
		t.Errorf("LUKSTestUnlock: want ErrLUKSNotConfigured, got %v", err)
	}
	if _, err := p.LUKSChangePassphrase(ctx, nil); !errors.Is(err, ErrLUKSNotConfigured) {
		t.Errorf("LUKSChangePassphrase: want ErrLUKSNotConfigured, got %v", err)
	}

	// FIDO2
	if _, err := p.FIDO2ListDevices(ctx); !errors.Is(err, ErrFIDO2NotConfigured) {
		t.Errorf("FIDO2ListDevices: want ErrFIDO2NotConfigured, got %v", err)
	}
	if _, err := p.FIDO2WaitDevice(ctx, 0); !errors.Is(err, ErrFIDO2NotConfigured) {
		t.Errorf("FIDO2WaitDevice: want ErrFIDO2NotConfigured, got %v", err)
	}
	if _, err := p.FIDO2Info(ctx, "d"); !errors.Is(err, ErrFIDO2NotConfigured) {
		t.Errorf("FIDO2Info: want ErrFIDO2NotConfigured, got %v", err)
	}
	if _, err := p.FIDO2Register(ctx, nil); !errors.Is(err, ErrFIDO2NotConfigured) {
		t.Errorf("FIDO2Register: want ErrFIDO2NotConfigured, got %v", err)
	}
	if _, err := p.FIDO2Authenticate(ctx, "c"); !errors.Is(err, ErrFIDO2NotConfigured) {
		t.Errorf("FIDO2Authenticate: want ErrFIDO2NotConfigured, got %v", err)
	}
}

// =============================================================================
// Delegation tests — wired provider routes to the fake backend with correct
// arg translation.
// =============================================================================

func TestPhase35Provider_CeremonyDelegation(t *testing.T) {
	cb := &recordingCeremonyBackend{inner: &fakeCeremonyBackend{}}
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	p.SetPhase35Services(Phase35Services{Ceremony: NewCeremonyService(nil, cb)})
	ctx := context.Background()

	// Init: args pass through and the admin bundle comes back.
	initOut, err := p.CeremonyInit(ctx, map[string]interface{}{
		"so_pin":                   "1234",
		"user_pin":                 "5678",
		"threshold":                "2-of-3",
		"hostname":                 "cp01.lan",
		"sans":                     []interface{}{"a.lan", "b.lan"},
		"credential_seal_strategy": "tpm",
	})
	if err != nil {
		t.Fatalf("CeremonyInit: %v", err)
	}
	initMap := initOut.(map[string]interface{})
	if initMap["admin_cert_pem"] != "ADMIN-CERT" || initMap["admin_key_pem"] != "ADMIN-KEY" || initMap["spki_pin"] != "PIN" {
		t.Errorf("CeremonyInit: admin bundle not returned: %+v", initMap)
	}
	if cb.lastInit == nil || cb.lastInit.SOPIN != "1234" || cb.lastInit.Threshold != "2-of-3" {
		t.Errorf("CeremonyInit: bad request translation: %+v", cb.lastInit)
	}
	if len(cb.lastInit.SANs) != 2 || cb.lastInit.SANs[0] != "a.lan" {
		t.Errorf("CeremonyInit: SANs not translated: %+v", cb.lastInit.SANs)
	}

	// Status → map result shape.
	res, err := p.CeremonyStatus(ctx)
	if err != nil {
		t.Fatalf("CeremonyStatus: %v", err)
	}
	m, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("CeremonyStatus: want map, got %T", res)
	}
	if _, hasState := m["state"]; !hasState {
		t.Errorf("CeremonyStatus: state missing from result: %v", m)
	}

	// ClaimCertBegin: username, authenticator_type translated.
	if _, err := p.CeremonyClaimCertBegin(ctx, map[string]interface{}{
		"username":           "alice",
		"authenticator_type": "piv",
		"slot":               "9a",
		"credential_id":      "cid",
	}); err != nil {
		t.Fatalf("CeremonyClaimCertBegin: %v", err)
	}
	if cb.lastClaimBegin == nil || cb.lastClaimBegin.Username != "alice" ||
		cb.lastClaimBegin.AuthenticatorType != CeremonyAuthenticatorPIV {
		t.Errorf("CeremonyClaimCertBegin: bad args: %+v", cb.lastClaimBegin)
	}

	// ClaimCertComplete.
	if _, err := p.CeremonyClaimCertComplete(ctx, map[string]interface{}{
		"username": "alice", "nonce": "n", "signature": "s",
	}); err != nil {
		t.Fatalf("CeremonyClaimCertComplete: %v", err)
	}
	if cb.lastClaimComplete == nil || cb.lastClaimComplete.Nonce != "n" {
		t.Errorf("CeremonyClaimCertComplete: bad args: %+v", cb.lastClaimComplete)
	}

	// ClaimShareBegin.
	if _, err := p.CeremonyClaimShareBegin(ctx, map[string]interface{}{"username": "alice"}); err != nil {
		t.Fatalf("CeremonyClaimShareBegin: %v", err)
	}
	if cb.lastShareUser != "alice" {
		t.Errorf("CeremonyClaimShareBegin: username not passed, got %q", cb.lastShareUser)
	}

	// ClaimShareComplete. The signature travels base64-encoded.
	if _, err := p.CeremonyClaimShareComplete(ctx, map[string]interface{}{
		"username": "alice", "nonce": "n",
		"signature": base64.StdEncoding.EncodeToString([]byte("sig")),
	}); err != nil {
		t.Fatalf("CeremonyClaimShareComplete: %v", err)
	}
	if cb.lastShareComplete == nil || cb.lastShareComplete.Nonce != "n" || string(cb.lastShareComplete.Signature) != "sig" {
		t.Errorf("CeremonyClaimShareComplete: bad args: %+v", cb.lastShareComplete)
	}

	// ClaimShareComplete rejects a non-base64 signature.
	if _, err := p.CeremonyClaimShareComplete(ctx, map[string]interface{}{
		"username": "alice", "nonce": "n", "signature": "!!!not-base64!!!",
	}); !errors.Is(err, ErrCeremonySignatureInvalid) {
		t.Errorf("CeremonyClaimShareComplete: want ErrCeremonySignatureInvalid, got %v", err)
	}

	// SignCSR.
	if _, err := p.CeremonySignCSR(ctx, map[string]interface{}{
		"username": "alice", "so_pin": "1234", "csr_pem": "CSR", "role": "admin",
	}); err != nil {
		t.Fatalf("CeremonySignCSR: %v", err)
	}
	if cb.lastSignCSR == nil || cb.lastSignCSR.Role != CeremonyRoleAdmin {
		t.Errorf("CeremonySignCSR: bad args: %+v", cb.lastSignCSR)
	}
}

func TestPhase35Provider_PIVDelegation(t *testing.T) {
	pb := &recordingPIVBackend{inner: &fakePIVBackend{
		devices: []PIVDevice{{ID: "yk5"}},
		slots:   []PIVSlot{{ID: "9a"}},
	}}
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	p.SetPhase35Services(Phase35Services{PIV: NewPIVService(nil, pb)})
	ctx := context.Background()

	if _, err := p.PIVListDevices(ctx); err != nil {
		t.Fatalf("PIVListDevices: %v", err)
	}
	if _, err := p.PIVListSlots(ctx, "yk5"); err != nil {
		t.Fatalf("PIVListSlots: %v", err)
	}
	if pb.lastDevice != "yk5" {
		t.Errorf("ListSlots: device not passed, got %q", pb.lastDevice)
	}
	if _, err := p.PIVSlotInfo(ctx, "yk5", "9a"); err != nil {
		t.Fatalf("PIVSlotInfo: %v", err)
	}
	if pb.lastSlotID != "9a" {
		t.Errorf("SlotInfo: slot not passed, got %q", pb.lastSlotID)
	}

	if _, err := p.PIVGenerate(ctx, map[string]interface{}{
		"slot": "9a", "algorithm": "rsa", "pin": "123456",
	}); err != nil {
		t.Fatalf("PIVGenerate: %v", err)
	}
	if pb.lastGen == nil || pb.lastGen.Algorithm != PIVAlgorithmRSA {
		t.Errorf("Generate: bad args: %+v", pb.lastGen)
	}

	if _, err := p.PIVImport(ctx, map[string]interface{}{
		"slot": "9c", "private_key_pem": "PEM", "pin": "123456",
	}); err != nil {
		t.Fatalf("PIVImport: %v", err)
	}
	if pb.lastImport == nil || pb.lastImport.Slot != "9c" {
		t.Errorf("Import: bad args: %+v", pb.lastImport)
	}

	// Sign: payload is base64 on the wire.
	payload := []byte("hello world")
	encoded := base64.StdEncoding.EncodeToString(payload)
	res, err := p.PIVSign(ctx, map[string]interface{}{
		"slot": "9a", "payload": encoded, "pin": "123456",
	})
	if err != nil {
		t.Fatalf("PIVSign: %v", err)
	}
	if pb.lastSign == nil || string(pb.lastSign.Payload) != "hello world" {
		t.Errorf("Sign: payload not decoded: %+v", pb.lastSign)
	}
	m := res.(map[string]interface{})
	// fakePIVBackend.Sign echoes the payload, so the returned signature is
	// base64(payload).
	wantSig := base64.StdEncoding.EncodeToString(payload)
	if got := m["signature"].(string); got != wantSig {
		t.Errorf("Sign: signature not base64 encoded: want %q got %q", wantSig, got)
	}

	if _, err := p.PIVAttest(ctx, "9a"); err != nil {
		t.Fatalf("PIVAttest: %v", err)
	}
	if pb.lastAttest != "9a" {
		t.Errorf("Attest: slot not passed, got %q", pb.lastAttest)
	}

	if _, err := p.PIVReset(ctx, "yk5"); err != nil {
		t.Fatalf("PIVReset: %v", err)
	}
	if pb.lastReset != "yk5" {
		t.Errorf("Reset: device not passed, got %q", pb.lastReset)
	}
}

func TestPhase35Provider_LUKSDelegation(t *testing.T) {
	lb := &recordingLUKSBackend{inner: &fakeLUKSBackend{}}
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	p.SetPhase35Services(Phase35Services{
		LUKS: NewLUKSService(nil, lb, RootCheckerFunc(func() bool { return true })),
	})
	ctx := context.Background()

	if _, err := p.LUKSStatus(ctx, "/dev/x"); err != nil {
		t.Fatalf("LUKSStatus: %v", err)
	}
	if _, err := p.LUKSListSlots(ctx, "/dev/x"); err != nil {
		t.Fatalf("LUKSListSlots: %v", err)
	}
	if _, err := p.LUKSInfo(ctx, "/dev/x"); err != nil {
		t.Fatalf("LUKSInfo: %v", err)
	}

	if _, err := p.LUKSEnrollPassphrase(ctx, map[string]interface{}{
		"device": "/dev/x", "existing_passphrase": "a", "new_passphrase": "b",
	}); err != nil {
		t.Fatalf("LUKSEnrollPassphrase: %v", err)
	}
	if _, err := p.LUKSEnrollFIDO2(ctx, map[string]interface{}{
		"device": "/dev/x", "existing_passphrase": "a", "credential_id": "c", "require_uv": true,
	}); err != nil {
		t.Fatalf("LUKSEnrollFIDO2: %v", err)
	}
	if _, err := p.LUKSEnrollTPM(ctx, map[string]interface{}{
		"device": "/dev/x", "existing_passphrase": "a",
		"pcrs": []interface{}{float64(0), float64(7)}, "handle": "0x81000004",
	}); err != nil {
		t.Fatalf("LUKSEnrollTPM: %v", err)
	}
	if lb.lastEnroll == nil || len(lb.lastEnroll.PCRs) != 2 || lb.lastEnroll.Handle != "0x81000004" {
		t.Errorf("EnrollTPM: bad args: %+v", lb.lastEnroll)
	}
	if _, err := p.LUKSEnrollRecovery(ctx, map[string]interface{}{
		"device": "/dev/x", "existing_passphrase": "a",
	}); err != nil {
		t.Fatalf("LUKSEnrollRecovery: %v", err)
	}
	if _, err := p.LUKSRemoveKey(ctx, map[string]interface{}{"device": "/dev/x", "slot": float64(2)}); err != nil {
		t.Fatalf("LUKSRemoveKey: %v", err)
	}
	if lb.removeHit != 1 {
		t.Errorf("RemoveKey: want 1 call, got %d", lb.removeHit)
	}
	if _, err := p.LUKSChangePassphrase(ctx, map[string]interface{}{
		"device": "/dev/x", "slot": float64(1), "old_passphrase": "a", "new_passphrase": "b",
	}); err != nil {
		t.Fatalf("LUKSChangePassphrase: %v", err)
	}
	if lb.changeHit != 1 {
		t.Errorf("ChangePassphrase: want 1 call, got %d", lb.changeHit)
	}
}

func TestPhase35Provider_FIDO2Delegation(t *testing.T) {
	fb := &recordingFIDO2Backend{inner: &fakeFIDO2Backend{}}
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	p.SetPhase35Services(Phase35Services{FIDO2: NewFIDO2Service(nil, fb)})
	ctx := context.Background()

	if _, err := p.FIDO2ListDevices(ctx); err != nil {
		t.Fatalf("FIDO2ListDevices: %v", err)
	}
	if _, err := p.FIDO2WaitDevice(ctx, time.Millisecond); err != nil {
		t.Fatalf("FIDO2WaitDevice: %v", err)
	}
	if _, err := p.FIDO2Info(ctx, "fidok1"); err != nil {
		t.Fatalf("FIDO2Info: %v", err)
	}
	if _, err := p.FIDO2Register(ctx, map[string]interface{}{
		"username": "alice", "role": "admin", "require_pin": true, "require_uv": false, "rp_id": "lan",
	}); err != nil {
		t.Fatalf("FIDO2Register: %v", err)
	}
	if fb.lastRegister == nil || fb.lastRegister.Username != "alice" ||
		fb.lastRegister.Role != FIDO2RoleAdmin || fb.lastRegister.RPID != "lan" {
		t.Errorf("Register: bad args: %+v", fb.lastRegister)
	}
	if _, err := p.FIDO2Authenticate(ctx, "cred-1"); err != nil {
		t.Fatalf("FIDO2Authenticate: %v", err)
	}
	if fb.lastAuth != "cred-1" {
		t.Errorf("Authenticate: credentialID not passed, got %q", fb.lastAuth)
	}
}

// =============================================================================
// Helper function tests — cover arg-extraction edge cases.
// =============================================================================

func TestMapGetString_Empty(t *testing.T) {
	if got := mapGetString(nil, "k"); got != "" {
		t.Errorf("nil map: want empty, got %q", got)
	}
	if got := mapGetString(map[string]interface{}{"k": 123}, "k"); got != "" {
		t.Errorf("non-string value: want empty, got %q", got)
	}
	if got := mapGetString(map[string]interface{}{"k": "v"}, "k"); got != "v" {
		t.Errorf("string value: want v, got %q", got)
	}
}

func TestMapGetBool_Empty(t *testing.T) {
	if mapGetBool(nil, "k") {
		t.Errorf("nil map: want false, got true")
	}
	if mapGetBool(map[string]interface{}{"k": "true"}, "k") {
		t.Errorf("non-bool value: want false, got true")
	}
	if !mapGetBool(map[string]interface{}{"k": true}, "k") {
		t.Errorf("bool value: want true, got false")
	}
}

func TestMapGetInt32_Variants(t *testing.T) {
	cases := []struct {
		name string
		val  interface{}
		want int32
	}{
		{"float64", float64(42), 42},
		{"int", int(42), 42},
		{"int32", int32(42), 42},
		{"int64", int64(42), 42},
		{"string", "42", 0},
		{"nil", nil, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mapGetInt32(map[string]interface{}{"k": c.val}, "k")
			if got != c.want {
				t.Errorf("%s: want %d, got %d", c.name, c.want, got)
			}
		})
	}
	if got := mapGetInt32(nil, "k"); got != 0 {
		t.Errorf("nil map: want 0, got %d", got)
	}
}

func TestMapGetStringSlice(t *testing.T) {
	in := map[string]interface{}{"k": []interface{}{"a", "b", 42}}
	got := mapGetStringSlice(in, "k")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("want [a b], got %v", got)
	}
	if got := mapGetStringSlice(nil, "k"); got != nil {
		t.Errorf("nil map: want nil, got %v", got)
	}
	if got := mapGetStringSlice(map[string]interface{}{"k": "not-a-slice"}, "k"); got != nil {
		t.Errorf("non-slice value: want nil, got %v", got)
	}
}

func TestMapGetInt32Slice(t *testing.T) {
	in := map[string]interface{}{"k": []interface{}{float64(0), float64(7), "bad", int(3)}}
	got := mapGetInt32Slice(in, "k")
	if len(got) != 3 {
		t.Fatalf("want 3 elements, got %d", len(got))
	}
	if got[0] != 0 || got[1] != 7 || got[2] != 3 {
		t.Errorf("bad translation: %v", got)
	}
	if got := mapGetInt32Slice(nil, "k"); got != nil {
		t.Errorf("nil map: want nil, got %v", got)
	}
	if got := mapGetInt32Slice(map[string]interface{}{"k": "nope"}, "k"); got != nil {
		t.Errorf("non-slice: want nil, got %v", got)
	}
}

func TestDecodePayload(t *testing.T) {
	if got, err := decodePayload(""); err != nil || got != nil {
		t.Errorf("empty: want (nil, nil), got (%v, %v)", got, err)
	}
	enc := base64.StdEncoding.EncodeToString([]byte("abc"))
	if got, err := decodePayload(enc); err != nil || string(got) != "abc" {
		t.Errorf("std: want abc, got (%v, %v)", string(got), err)
	}
	// URL-safe fallback.
	enc = base64.URLEncoding.EncodeToString([]byte("hello?"))
	if got, err := decodePayload(enc); err != nil || string(got) != "hello?" {
		t.Errorf("url: want hello?, got (%v, %v)", string(got), err)
	}
	if _, err := decodePayload("!!!!!"); err == nil {
		t.Errorf("invalid: want error, got nil")
	}
}

// =============================================================================
// Phase35Services round-trip.
// =============================================================================

func TestPhase35Services_SetAndGet(t *testing.T) {
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	if svcs := p.Phase35Services(); svcs.Ceremony != nil || svcs.PIV != nil || svcs.LUKS != nil || svcs.FIDO2 != nil {
		t.Errorf("initial snapshot should be zero, got %+v", svcs)
	}
	p.SetPhase35Services(Phase35Services{Ceremony: NewCeremonyService(nil, nil)})
	if p.Phase35Services().Ceremony == nil {
		t.Error("Ceremony service not stored")
	}
	// Replacing with zero value clears.
	p.SetPhase35Services(Phase35Services{})
	if p.Phase35Services().Ceremony != nil {
		t.Error("Ceremony service should have been cleared")
	}
}
