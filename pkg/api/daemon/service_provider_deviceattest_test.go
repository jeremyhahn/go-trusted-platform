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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// buildAttestTestQuote marshals a synthetic TPMS_ATTEST quote with the given
// nonce and SHA-256 PCR values, matching the shape the platform's TPM quote
// path produces.
func buildAttestTestQuote(t *testing.T, nonce []byte, pcrValues map[int][]byte) []byte {
	t.Helper()

	indices := make([]int, 0, len(pcrValues))
	for idx := range pcrValues {
		indices = append(indices, idx)
	}
	sort.Ints(indices)

	hasher := sha256.New()
	pcrs := make([]uint, 0, len(indices))
	for _, idx := range indices {
		hasher.Write(pcrValues[idx])
		pcrs = append(pcrs, uint(idx))
	}
	digest := hasher.Sum(nil)

	attest := tpm2.TPMSAttest{
		Magic:           tpm2.TPMGeneratedValue,
		Type:            tpm2.TPMSTAttestQuote,
		QualifiedSigner: tpm2.TPM2BName{Buffer: []byte("test-ak")},
		ExtraData:       tpm2.TPM2BData{Buffer: nonce},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{
						Hash:      tpm2.TPMAlgSHA256,
						PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
					},
				},
			},
			PCRDigest: tpm2.TPM2BDigest{Buffer: digest},
		}),
	}
	return tpm2.Marshal(attest)
}

// newAttestTestKey returns a fresh RSA key and its PKIX public key PEM.
func newAttestTestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return key, string(pemBytes)
}

func signAttestQuote(t *testing.T, key *rsa.PrivateKey, quote []byte) []byte {
	t.Helper()
	hashed := sha256.Sum256(quote)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

// enrolledDeviceProvider wires a PlatformServiceProvider over the quote
// fixture and returns it with the fixture's device ID.
func enrolledDeviceProvider(t *testing.T, f *quoteFixture) (*PlatformServiceProvider, uint64) {
	t.Helper()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DeviceService:  f.devices,
		ProfileService: f.profiles,
		AKTrust:        f.trust,
		VerdictSink:    f.sink,
	})
	provider.quoteVerifier.now = func() time.Time { return f.now }
	return provider, f.device.ID
}

func TestPlatformServiceProvider_DeviceAttest_Success(t *testing.T) {
	f := newQuoteFixture(t)
	provider, id := enrolledDeviceProvider(t, f)

	raw, err := provider.DeviceAttest(context.Background(), itoa(id), f.evidence(t, []byte("fresh-nonce-000001"), goldenPCRs()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, ok := raw.(*DeviceAttestationResult)
	if !ok {
		t.Fatalf("result type = %T, want *DeviceAttestationResult", raw)
	}
	if !result.Verified || !result.AKCertificateVerified || !result.SignatureValid || !result.NonceValid || !result.PCRsValid {
		t.Fatalf("expected every check to pass: %+v", result)
	}
	if result.Status != "verified" {
		t.Errorf("status = %q, want verified", result.Status)
	}
	if !result.PCRBaselineCaptured {
		t.Error("the first verified quote must capture the profile baseline")
	}
}

func TestPlatformServiceProvider_DeviceAttest_BadSignature(t *testing.T) {
	f := newQuoteFixture(t)
	provider, id := enrolledDeviceProvider(t, f)
	otherKey, _ := newAttestTestKey(t)

	raw, err := provider.DeviceAttest(context.Background(), itoa(id),
		signedEvidence(t, otherKey, []byte("fresh-nonce-000002"), goldenPCRs(), goldenPCRs()))
	if err != nil {
		t.Fatalf("a failed verification is a result, not an error: %v", err)
	}
	result := raw.(*DeviceAttestationResult)
	if result.Verified || result.SignatureValid {
		t.Fatalf("expected the signature check to fail: %+v", result)
	}
	if result.Status != "failed" || result.Message == "" {
		t.Errorf("a negative verdict must say why: %+v", result)
	}
}

func TestPlatformServiceProvider_DeviceAttest_UnknownDevice(t *testing.T) {
	f := newQuoteFixture(t)
	provider, _ := enrolledDeviceProvider(t, f)

	_, err := provider.DeviceAttest(context.Background(), "999", f.evidence(t, []byte("nonce"), goldenPCRs()))
	if _, ok := err.(ErrDeviceNotFound); !ok {
		t.Fatalf("expected ErrDeviceNotFound, got %T (%v)", err, err)
	}
}

func TestPlatformServiceProvider_DeviceAttest_NoEnrolledCertificate(t *testing.T) {
	f := newQuoteFixture(t)
	f.device.AttestCert = ""
	provider, id := enrolledDeviceProvider(t, f)

	raw, err := provider.DeviceAttest(context.Background(), itoa(id), f.evidence(t, []byte("nonce"), goldenPCRs()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := raw.(*DeviceAttestationResult)
	if result.Verified || result.AKCertificateVerified {
		t.Fatalf("a device without an attestation certificate must fail closed: %+v", result)
	}
}

func TestPlatformServiceProvider_DeviceAttest_InvalidEvidence(t *testing.T) {
	f := newQuoteFixture(t)
	provider, id := enrolledDeviceProvider(t, f)

	cases := map[string][]byte{
		"not json":     []byte("not json"),
		"missing pcrs": mustJSON(t, DeviceQuoteEvidence{Quote: []byte("q"), Signature: []byte("s"), Nonce: []byte("n")}),
	}
	for name, evidence := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := provider.DeviceAttest(context.Background(), itoa(id), evidence)
			if _, ok := err.(ErrInvalidAttestationEvidence); !ok {
				t.Fatalf("expected ErrInvalidAttestationEvidence, got %T (%v)", err, err)
			}
		})
	}
}

func TestPlatformServiceProvider_DeviceAttest_NilService(t *testing.T) {
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})
	_, err := provider.DeviceAttest(context.Background(), "1", []byte(`{}`))
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// mustJSON marshals v or fails the test.
func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// jsonUnmarshal is json.Unmarshal under a name that reads well beside
// mustJSON in table tests.
func jsonUnmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

func TestPlatformServiceProvider_DeviceProvision_Success(t *testing.T) {
	devSvc := newSPMockDeviceService()
	dev := &deviceentities.Device{Model: "prov-model", Serial: "SN-9"}
	_ = devSvc.Save(context.Background(), dev)

	profSvc := newMCPMockDeviceProfileService()
	profile := &deviceentities.DeviceProfile{
		Name:  "prov-profile",
		Model: "prov-model",
		Networks: map[string]*deviceentities.NetworkPhaseConfig{
			deviceentities.DefaultEnrollmentNetwork: {VLAN: 100, Zone: "provisioning"},
		},
	}
	_ = profSvc.Save(context.Background(), profile)

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DeviceService:  devSvc,
		ProfileService: profSvc,
	})

	if err := provider.DeviceProvision(context.Background(), itoa(dev.ID), itoa(profile.ID)); err != nil {
		t.Fatalf("DeviceProvision returned error: %v", err)
	}
}

func TestPlatformServiceProvider_DeviceProvision_MatchByModel(t *testing.T) {
	devSvc := newSPMockDeviceService()
	dev := &deviceentities.Device{Model: "match-model", Serial: "SN-10"}
	_ = devSvc.Save(context.Background(), dev)

	profSvc := newMCPMockDeviceProfileService()
	profile := &deviceentities.DeviceProfile{
		Name:  "match-profile",
		Model: "match-model",
		Networks: map[string]*deviceentities.NetworkPhaseConfig{
			deviceentities.DefaultEnrollmentNetwork: {VLAN: 100, Zone: "provisioning"},
		},
	}
	_ = profSvc.Save(context.Background(), profile)

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DeviceService:  devSvc,
		ProfileService: profSvc,
	})

	// Non-numeric profile forces the match-by-characteristics path.
	if err := provider.DeviceProvision(context.Background(), itoa(dev.ID), "auto"); err != nil {
		t.Fatalf("DeviceProvision (match) returned error: %v", err)
	}
}

func TestPlatformServiceProvider_DeviceProvision_NoNetworkConfig(t *testing.T) {
	devSvc := newSPMockDeviceService()
	dev := &deviceentities.Device{Model: "m", Serial: "s"}
	_ = devSvc.Save(context.Background(), dev)

	profSvc := newMCPMockDeviceProfileService()
	profile := &deviceentities.DeviceProfile{Name: "empty", Model: "m"} // no networks
	_ = profSvc.Save(context.Background(), profile)

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DeviceService:  devSvc,
		ProfileService: profSvc,
	})

	err := provider.DeviceProvision(context.Background(), itoa(dev.ID), itoa(profile.ID))
	if _, ok := err.(ErrProvisioningFailed); !ok {
		t.Fatalf("expected ErrProvisioningFailed, got %T (%v)", err, err)
	}
}

func TestPlatformServiceProvider_DeviceProvision_ProfileNotFound(t *testing.T) {
	devSvc := newSPMockDeviceService()
	dev := &deviceentities.Device{Model: "m", Serial: "s"}
	_ = devSvc.Save(context.Background(), dev)

	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DeviceService:  devSvc,
		ProfileService: newMCPMockDeviceProfileService(),
	})

	err := provider.DeviceProvision(context.Background(), itoa(dev.ID), "12345")
	if _, ok := err.(ErrProfileNotFound); !ok {
		t.Fatalf("expected ErrProfileNotFound, got %T (%v)", err, err)
	}
}

func TestPlatformServiceProvider_DeviceProvision_NilServices(t *testing.T) {
	t.Run("nil device service", func(t *testing.T) {
		provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})
		err := provider.DeviceProvision(context.Background(), "1", "1")
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Fatalf("expected ErrServiceNotAvailable, got %T (%v)", err, err)
		}
	})

	t.Run("nil profile service", func(t *testing.T) {
		provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
			DeviceService: newSPMockDeviceService(),
		})
		err := provider.DeviceProvision(context.Background(), "1", "1")
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Fatalf("expected ErrServiceNotAvailable, got %T (%v)", err, err)
		}
	})
}

// itoa renders a uint64 device/profile ID for the string-typed provider API.
func itoa(id uint64) string {
	return strconv.FormatUint(id, 10)
}
