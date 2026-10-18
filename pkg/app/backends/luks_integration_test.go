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

//go:build integration

package backends

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"
	luks "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/luks"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/secure"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestLUKSBackend_LoopbackEnrollAndTest walks a passphrase enroll +
// test-unlock cycle against a loopback LUKS2 volume. Must run as root in the
// devcontainer.
func TestLUKSBackend_LoopbackEnrollAndTest(t *testing.T) {
	loop, cleanup := setupLoopbackLUKS(t)
	defer cleanup()

	b := NewLUKSBackend(logging.DefaultLogger())
	ctx := context.Background()

	status, err := b.Status(ctx, loop)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.IsLUKS {
		t.Fatalf("expected LUKS device")
	}

	enrollRes, err := b.EnrollPassphrase(ctx, &daemon.LUKSEnrollPassphraseRequest{
		Device:             loop,
		ExistingPassphrase: "initialpass",
		NewPassphrase:      "secondpass",
	})
	if err != nil {
		t.Fatalf("EnrollPassphrase: %v", err)
	}
	if enrollRes.Slot < 0 {
		t.Fatalf("bad slot: %d", enrollRes.Slot)
	}

	ok, err := b.TestUnlock(ctx, &daemon.LUKSTestUnlockRequest{
		Device: loop,
		Slot:   enrollRes.Slot,
	})
	if err != nil {
		t.Fatalf("TestUnlock: %v", err)
	}
	if !ok {
		t.Fatalf("TestUnlock returned false for valid slot")
	}
}

// TestLUKSBackend_EnrollFIDO2_WithStubHandler drives the FIDO2 enrol path
// against a real loopback LUKS2 device but with a deterministic stub
// authenticator — a real FIDO2 token is not available in the devcontainer.
// The test confirms the derived key unlocks the volume and that the FIDO2
// token (credential id + salt) is persisted.
func TestLUKSBackend_EnrollFIDO2_WithStubHandler(t *testing.T) {
	loop, cleanup := setupLoopbackLUKS(t)
	defer cleanup()

	stub := &integrationStubFIDO2{seed: []byte("integration-seed")}
	handler, err := NewLUKSFIDO2Handler(logging.DefaultLogger(), stub, "example.com")
	if err != nil {
		t.Fatalf("NewLUKSFIDO2Handler: %v", err)
	}
	b := NewLUKSBackend(logging.DefaultLogger(), WithLUKSFIDO2Handler(handler))
	ctx := context.Background()

	credID := hex.EncodeToString([]byte("integration-cred"))
	res, err := b.EnrollFIDO2(ctx, &daemon.LUKSEnrollFIDO2Request{
		Device:             loop,
		ExistingPassphrase: "initialpass",
		CredentialID:       credID,
		RequireUV:          true,
	})
	if err != nil {
		t.Fatalf("EnrollFIDO2: %v", err)
	}
	if res.Slot < 0 {
		t.Fatalf("bad slot: %d", res.Slot)
	}

	// The token must exist and contain the credential + salt fields.
	tokens, err := luks2.ListTokens(loop)
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	var found bool
	for _, tok := range tokens {
		if tok.Type == LUKSFIDO2TokenType {
			found = true
			raw, err := luks2.ExportToken(loop, 0)
			if err != nil {
				t.Fatalf("ExportToken: %v", err)
			}
			var parsed fido2LUKSToken
			if err := json.Unmarshal(raw, &parsed); err == nil {
				if parsed.CredentialID != credID {
					t.Errorf("token credential = %q, want %q", parsed.CredentialID, credID)
				}
				if parsed.Salt == "" {
					t.Errorf("token salt empty")
				}
			}
		}
	}
	if !found {
		t.Errorf("fido2 token not persisted in header")
	}

	// Reproduce the derived key via the handler and confirm it unlocks the
	// newly enrolled slot. In the stub the derivation is deterministic so
	// the key matches even though this is a fresh handler instance.
	reproduced, err := stub.derive(credID, tokenSalt(t, loop, int(res.Slot)))
	if err != nil {
		t.Fatalf("stub derive: %v", err)
	}
	if err := luks2.TestKey(loop, reproduced); err != nil {
		t.Fatalf("reproduced key failed TestKey: %v", err)
	}
	_ = reproduced
}

// TestLUKSBackend_EnrollTPM_StubHandler exercises the EnrollTPM path using
// an in-process stub that returns a fixed passphrase + token JSON. A real
// TPM round-trip lives in the package-level sim tests (opt-in build tag).
func TestLUKSBackend_EnrollTPM_StubHandler(t *testing.T) {
	loop, cleanup := setupLoopbackLUKS(t)
	defer cleanup()

	fixedPass := bytes.Repeat([]byte{0x42}, 32)
	stub := &integrationStubTPM{passphrase: fixedPass}
	b := NewLUKSBackend(logging.DefaultLogger(), WithLUKSTPMHandler(stub))
	ctx := context.Background()

	_, err := b.EnrollTPM(ctx, &daemon.LUKSEnrollTPMRequest{
		Device:             loop,
		ExistingPassphrase: "initialpass",
	})
	if err != nil {
		t.Fatalf("EnrollTPM: %v", err)
	}
	if err := luks2.TestKey(loop, fixedPass); err != nil {
		t.Fatalf("fixed TPM key did not unlock slot: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Shared loopback helper
// ---------------------------------------------------------------------------

// luksPrerequisiteError is a typed error reported when the host cannot run
// the loopback LUKS2 tests. Per the platform testing policy they never call
// t.Skip: a missing prerequisite is a loud failure that names it.
type luksPrerequisiteError struct {
	// Missing names the prerequisite that is absent.
	Missing string
}

func (e *luksPrerequisiteError) Error() string {
	return fmt.Sprintf("loopback LUKS2 test prerequisite missing: %s; run it as root in the devcontainer", e.Missing)
}

// setupLoopbackLUKS formats a 64 MiB loop device as LUKS2 with the
// passphrase "initialpass". Attaching a loop device needs root.
func setupLoopbackLUKS(t *testing.T) (loop string, cleanup func()) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatalf("%v", &luksPrerequisiteError{Missing: "root, to attach and format a loop device"})
	}
	f, err := os.CreateTemp("", "luks2-backend-*.img")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	fpath := f.Name()
	if err := f.Truncate(64 * 1024 * 1024); err != nil {
		os.Remove(fpath)
		t.Fatalf("truncate: %v", err)
	}
	f.Close()

	loop, err = luks2.SetupLoopDevice(fpath)
	if err != nil {
		os.Remove(fpath)
		t.Fatalf("SetupLoopDevice: %v", err)
	}

	if err := luks2.Format(luks2.FormatOptions{
		Device:     loop,
		Passphrase: []byte("initialpass"),
	}); err != nil {
		luks2.DetachLoopDevice(loop)
		os.Remove(fpath)
		t.Fatalf("Format: %v", err)
	}

	return loop, func() {
		luks2.DetachLoopDevice(loop)
		os.Remove(fpath)
	}
}

// tokenSalt reads the FIDO2 token attached to the given slot and returns
// the decoded salt. Used in integration tests to reproduce a derived key.
func tokenSalt(t *testing.T, device string, slot int) []byte {
	t.Helper()
	tokens, err := luks2.ListTokens(device)
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	for id := range tokens {
		raw, err := luks2.ExportToken(device, id)
		if err != nil {
			continue
		}
		var tok fido2LUKSToken
		if err := json.Unmarshal(raw, &tok); err != nil {
			continue
		}
		if tok.Type != LUKSFIDO2TokenType {
			continue
		}
		for _, s := range tok.Keyslots {
			if s == indexString(slot) {
				salt, err := base64StdDecode(tok.Salt)
				if err != nil {
					t.Fatalf("decode salt: %v", err)
				}
				return salt
			}
		}
	}
	t.Fatalf("no fido2 token found for slot %d", slot)
	return nil
}

// indexString is a tiny helper so we don't drag strconv into the test file.
func indexString(i int) string {
	// LUKS keyslot IDs are small non-negative integers.
	if i == 0 {
		return "0"
	}
	var out []byte
	for i > 0 {
		out = append([]byte{byte('0' + i%10)}, out...)
		i /= 10
	}
	return string(out)
}

// base64StdDecode wraps encoding/base64 so the integration tests can read
// the salt back out of the LUKS2 token.
func base64StdDecode(s string) ([]byte, error) {
	return stdB64.DecodeString(s)
}

var stdB64 = base64.StdEncoding

// ---------------------------------------------------------------------------
// Stubs
// ---------------------------------------------------------------------------

// integrationStubFIDO2 mirrors stubXKMSFIDO2Handler but lives outside the
// test file that defines the unit-test version so the integration build tag
// isolates it from everyday runs.
type integrationStubFIDO2 struct {
	seed []byte
}

func (s *integrationStubFIDO2) EnrollKey(_ *fido2.EnrollmentConfig) (*fido2.EnrollmentResult, error) {
	return &fido2.EnrollmentResult{}, nil
}

func (s *integrationStubFIDO2) UnlockWithKey(cfg *fido2.AuthenticationConfig) ([]byte, error) {
	return s.derive(hex.EncodeToString(cfg.CredentialID), cfg.Salt)
}

func (s *integrationStubFIDO2) derive(credIDHex string, salt []byte) ([]byte, error) {
	cred, err := hex.DecodeString(credIDHex)
	if err != nil {
		return nil, err
	}
	key := append([]byte{}, cred...)
	key = append(key, s.seed...)
	mac := hmac.New(sha256.New, key)
	mac.Write(salt)
	return mac.Sum(nil), nil
}

func (s *integrationStubFIDO2) ListDevices() ([]fido2.Device, error) { return nil, nil }
func (s *integrationStubFIDO2) WaitForDevice(ctx context.Context) (*fido2.Device, error) {
	return nil, context.Canceled
}
func (s *integrationStubFIDO2) Close() error { return nil }

// integrationStubTPM is a deterministic LUKSTPMHandler for integration
// tests — it skips the TPM entirely and returns a fixed passphrase plus a
// valid JSON token so the LUKS code paths still persist metadata.
type integrationStubTPM struct {
	passphrase []byte
}

func (s *integrationStubTPM) SealPassphrase(_ context.Context, _ []int32) (*LUKSTPMSealResult, error) {
	passphrase, err := secure.NewBufferFromBytes(bytes.Clone(s.passphrase))
	if err != nil {
		return nil, err
	}
	return &LUKSTPMSealResult{
		Passphrase: passphrase,
		Token: &luks2.Token{
			Type:          LUKSXKMSTPMTokenType,
			TPM2Blob:      luks.EncodeTPMSealBlobs([]byte{0x01}, []byte{0x02}),
			TPM2KeyHandle: 0x81000001,
		},
	}, nil
}
