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

package backends

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmsbackend "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/backend"
	xkmstransport "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/transport"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

var errPIVKeygen = errors.New("piv keygen failure")

// recordingPIVGen records the backend and algorithm the xkms PIV manager
// asked it to generate a key for.
type recordingPIVGen struct {
	signer    crypto.Signer
	err       error
	backend   string
	algorithm string
}

func (g *recordingPIVGen) GeneratePIVKey(_ xkmssdk.PIVSlot, algorithm string, _ string) (crypto.Signer, error) {
	g.algorithm = algorithm
	if g.err != nil {
		return nil, g.err
	}
	return g.signer, nil
}

func (g *recordingPIVGen) GetPIVSigner(_ xkmssdk.PIVSlot, _ string) (crypto.Signer, error) {
	return g.signer, nil
}

// setupRecordingPIV installs a PIV manager whose key generator is gen.
func setupRecordingPIV(t *testing.T, gen *recordingPIVGen) {
	t.Helper()
	setupBackendPIV(t, nil)
	if err := xkmsbackend.SetPIVBackendResolver(func(name string) (xkmsbackend.PIVKeyGenerator, error) {
		gen.backend = name
		return gen, nil
	}); err != nil {
		t.Fatalf("SetPIVBackendResolver: %v", err)
	}
}

func newECDSASigner(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func TestPIVBackend_ListDevices_ReportsTheDefaultBackend(t *testing.T) {
	setupBackendPIV(t, nil)
	for _, name := range []string{"", "hsm"} {
		devices, err := NewPIVBackend(logging.DefaultLogger()).WithDefaultBackend(name).ListDevices(context.Background())
		if err != nil {
			t.Fatalf("ListDevices(%q): %v", name, err)
		}
		want := name
		if want == "" {
			want = DefaultPIVBackendName
		}
		expected := daemon.PIVDevice{ID: want, Name: want, Manufacturer: "go-xkms", Model: "software"}
		if len(devices) != 1 || devices[0] != expected {
			t.Fatalf("ListDevices(%q) = %+v, want [%+v]", name, devices, expected)
		}
	}
}

func TestPIVBackend_ListSlots_ReportsEveryStandardSlot(t *testing.T) {
	store := setupBackendPIV(t, nil)
	if err := store.Store(xkmssdk.PIVSlotAuthentication, makeTestCert(t, "piv-9a")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	b := NewPIVBackend(logging.DefaultLogger())

	// An empty device name and the explicit default backend resolve to the
	// same store.
	for _, device := range []string{"", DefaultPIVBackendName} {
		slots, err := b.ListSlots(context.Background(), device)
		if err != nil {
			t.Fatalf("ListSlots(%q): %v", device, err)
		}
		// PIV defines 4 primary slots, attestation f9 and 20 retired slots.
		if len(slots) != 25 {
			t.Fatalf("ListSlots(%q) returned %d slots, want 25", device, len(slots))
		}
		auth := daemon.PIVSlot{ID: "9a", Name: "PIV Authentication", Algorithm: daemon.PIVAlgorithmECDSA, HasKey: true, HasCertificate: true}
		if slots[0] != auth {
			t.Errorf("slot 9a = %+v, want %+v", slots[0], auth)
		}
		sig := daemon.PIVSlot{ID: "9c", Name: "Digital Signature", Algorithm: daemon.PIVAlgorithmUnspecified}
		if slots[1] != sig {
			t.Errorf("slot 9c = %+v, want %+v", slots[1], sig)
		}
	}
}

func TestPIVBackend_ListSlots_Errors(t *testing.T) {
	setupBackendPIV(t, nil)
	if _, err := NewPIVBackend(logging.DefaultLogger()).ListSlots(context.Background(), "no-such-backend"); err == nil {
		t.Fatal("ListSlots on an unregistered backend succeeded")
	}

	xkmsbackend.ResetPIV()
	if _, err := NewPIVBackend(logging.DefaultLogger()).ListSlots(context.Background(), ""); !errors.Is(err, ErrPIVBackendUnavailable) {
		t.Fatalf("err = %v, want ErrPIVBackendUnavailable", err)
	}
}

func TestPIVBackend_SlotInfo_ReturnsTheSlotAndItsCertificate(t *testing.T) {
	store := setupBackendPIV(t, nil)
	cert := makeTestCert(t, "piv-9a")
	if err := store.Store(xkmssdk.PIVSlotAuthentication, cert); err != nil {
		t.Fatalf("seed: %v", err)
	}
	b := NewPIVBackend(logging.DefaultLogger())

	info, err := b.SlotInfo(context.Background(), "", "9a")
	if err != nil {
		t.Fatalf("SlotInfo(9a): %v", err)
	}
	wantPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	if info.Slot.ID != "9a" || !info.Slot.HasCertificate || info.CertificatePEM != wantPEM {
		t.Fatalf("SlotInfo(9a) = %+v, want slot 9a with its certificate PEM", info)
	}

	empty, err := b.SlotInfo(context.Background(), "", "9c")
	if err != nil {
		t.Fatalf("SlotInfo(9c): %v", err)
	}
	if empty.Slot.ID != "9c" || empty.Slot.HasKey || empty.CertificatePEM != "" {
		t.Fatalf("SlotInfo(9c) = %+v, want an empty slot without a certificate", empty)
	}
}

func TestPIVBackend_SlotInfo_Errors(t *testing.T) {
	setupBackendPIV(t, nil)
	b := NewPIVBackend(logging.DefaultLogger())

	if _, err := b.SlotInfo(context.Background(), "", "zz"); !errors.Is(err, xkmsbackend.ErrPIVInvalidSlot) {
		t.Errorf("unknown slot err = %v, want ErrPIVInvalidSlot", err)
	}
	_, listErr := b.ListSlots(context.Background(), "no-such-backend")
	if _, err := b.SlotInfo(context.Background(), "no-such-backend", "9a"); err == nil || err.Error() != listErr.Error() {
		t.Errorf("unregistered backend err = %v, want the ListSlots error %v", err, listErr)
	}

	xkmsbackend.ResetPIV()
	if _, err := b.SlotInfo(context.Background(), "", "9a"); !errors.Is(err, ErrPIVBackendUnavailable) {
		t.Errorf("uninitialised err = %v, want ErrPIVBackendUnavailable", err)
	}
}

func TestPIVBackend_Generate_MapsTheAlgorithmAndReturnsThePublicKey(t *testing.T) {
	tests := []struct {
		algorithm daemon.PIVAlgorithm
		want      string
	}{
		{daemon.PIVAlgorithmRSA, "rsa2048"},
		{daemon.PIVAlgorithmECDSA, "ecdsap256"},
		{daemon.PIVAlgorithmEd25519, "ed25519"},
		{daemon.PIVAlgorithm("ecdsap384"), "ecdsap384"},
	}
	for _, tt := range tests {
		t.Run(string(tt.algorithm), func(t *testing.T) {
			key := newECDSASigner(t)
			gen := &recordingPIVGen{signer: key}
			setupRecordingPIV(t, gen)

			res, err := NewPIVBackend(logging.DefaultLogger()).WithDefaultBackend("hsm").Generate(context.Background(), &daemon.PIVGenerateRequest{
				Slot: "9c", Algorithm: tt.algorithm,
			})
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if gen.algorithm != tt.want || gen.backend != "hsm" {
				t.Errorf("generator got algorithm %q on %q, want %q on hsm", gen.algorithm, gen.backend, tt.want)
			}
			block, _ := pem.Decode([]byte(res.PublicKeyPEM))
			if block == nil || block.Type != "PUBLIC KEY" {
				t.Fatalf("PublicKeyPEM = %q", res.PublicKeyPEM)
			}
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				t.Fatalf("parse public key: %v", err)
			}
			if !key.PublicKey.Equal(pub) {
				t.Error("returned public key is not the generated key's")
			}
		})
	}
}

func TestPIVBackend_Generate_Errors(t *testing.T) {
	t.Run("generator failure", func(t *testing.T) {
		setupRecordingPIV(t, &recordingPIVGen{err: errPIVKeygen})
		_, err := NewPIVBackend(logging.DefaultLogger()).Generate(context.Background(), &daemon.PIVGenerateRequest{Slot: "9c"})
		if !errors.Is(err, errPIVKeygen) {
			t.Fatalf("err = %v, want the generator error", err)
		}
	})
	t.Run("invalid slot", func(t *testing.T) {
		setupRecordingPIV(t, &recordingPIVGen{signer: newECDSASigner(t)})
		_, err := NewPIVBackend(logging.DefaultLogger()).Generate(context.Background(), &daemon.PIVGenerateRequest{Slot: "zz"})
		if !errors.Is(err, xkmsbackend.ErrPIVInvalidSlot) {
			t.Fatalf("err = %v, want ErrPIVInvalidSlot", err)
		}
	})
	t.Run("uninitialised manager", func(t *testing.T) {
		xkmsbackend.ResetPIV()
		_, err := NewPIVBackend(logging.DefaultLogger()).Generate(context.Background(), &daemon.PIVGenerateRequest{Slot: "9c"})
		if !errors.Is(err, ErrPIVBackendUnavailable) {
			t.Fatalf("err = %v, want ErrPIVBackendUnavailable", err)
		}
	})
}

func TestPIVBackend_Reset_PropagatesUpstreamFailure(t *testing.T) {
	setupBackendPIV(t, nil)
	b := NewPIVBackend(logging.DefaultLogger())
	b.ConfirmReset()
	if err := b.Reset(context.Background(), "no-such-backend"); err == nil {
		t.Fatal("Reset of an unregistered backend succeeded")
	}
	// The confirmation was consumed by the failed call.
	if err := b.Reset(context.Background(), ""); !errors.Is(err, ErrPIVResetNotConfirmed) {
		t.Fatalf("second Reset err = %v, want ErrPIVResetNotConfirmed", err)
	}
}

func TestPIVSlotFromStatus(t *testing.T) {
	tests := []struct {
		algorithm string
		want      daemon.PIVAlgorithm
	}{
		{"rsa4096", daemon.PIVAlgorithmRSA},
		{"RSA", daemon.PIVAlgorithmRSA},
		{"ecdsap384", daemon.PIVAlgorithmECDSA},
		{"Ed25519", daemon.PIVAlgorithmEd25519},
		{"", daemon.PIVAlgorithmUnspecified},
		{"dsa", daemon.PIVAlgorithmUnspecified},
	}
	for _, tt := range tests {
		got := pivSlotFromStatus(xkmstransport.PIVSlotStatus{
			Slot: "9d", Name: "Key Management", Algorithm: tt.algorithm, HasKey: true, HasCert: false,
		})
		want := daemon.PIVSlot{ID: "9d", Name: "Key Management", Algorithm: tt.want, HasKey: true}
		if got != want {
			t.Errorf("algorithm %q: got %+v, want %+v", tt.algorithm, got, want)
		}
	}
}
