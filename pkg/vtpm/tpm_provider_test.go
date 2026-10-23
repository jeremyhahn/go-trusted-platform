package vtpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// A bundle vTPM is provisioned with an IAK, and go-xkms refuses to create an
// IAK without a common name; the configuration must carry the bundle hostname.
func TestTPMOperationsConfig_IAKCommonNameIsBundleHostname(t *testing.T) {
	cfg := tpmOperationsConfig("/run/vtpm/vm-01.sock", EKAlgorithmRSA, "vm-01.example.com")

	if cfg.IAK == nil {
		t.Fatal("IAK configuration missing: Provision creates an IAK")
	}
	if cfg.IAK.CN != "vm-01.example.com" {
		t.Errorf("IAK CN = %q, want the bundle hostname", cfg.IAK.CN)
	}
	if cfg.SSRK == nil || cfg.SSRK.Handle != 0x81000001 {
		t.Errorf("SSRK = %+v, want the TCG shared SRK handle 0x81000001", cfg.SSRK)
	}
	if cfg.Device != "/run/vtpm/vm-01.sock" {
		t.Errorf("Device = %q, want the swtpm socket", cfg.Device)
	}
}

func TestTPMOperationsConfig_EKFollowsAlgorithm(t *testing.T) {
	tests := []struct {
		name       string
		algorithm  EKAlgorithm
		handle     uint32
		certHandle uint32
		keyAlg     string
	}{
		{"RSA", EKAlgorithmRSA, 0x81010001, NVIndexRSAEKCert, "RSA"},
		{"ECC", EKAlgorithmECC, 0x81010002, NVIndexECCEKCert, "ECDSA"},
		{"unknown falls back to RSA", EKAlgorithm("dsa"), 0x81010001, NVIndexRSAEKCert, "RSA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ek := tpmOperationsConfig("/s.sock", tt.algorithm, "vm-01").EK
			if ek.Handle != tt.handle || ek.CertHandle != tt.certHandle || ek.KeyAlgorithm != tt.keyAlg {
				t.Errorf("EK = {handle 0x%08X, cert 0x%08X, %s}, want {0x%08X, 0x%08X, %s}",
					ek.Handle, ek.CertHandle, ek.KeyAlgorithm, tt.handle, tt.certHandle, tt.keyAlg)
			}
		})
	}
}

// ekCacheTPM models go-xkms's EK accessors: EK answers only after
// EKAttributes has read the persistent EK, as on a freshly provisioned TPM.
type ekCacheTPM struct {
	xkmssdk.TrustedPlatformModule
	attrsErr error
	pub      crypto.PublicKey
	loaded   bool
}

func (f *ekCacheTPM) EKAttributes() (*xkmssdk.KeyAttributes, error) {
	if f.attrsErr != nil {
		return nil, f.attrsErr
	}
	f.loaded = true
	return &xkmssdk.KeyAttributes{CN: "ek"}, nil
}

func (f *ekCacheTPM) EK() (crypto.PublicKey, error) {
	if !f.loaded {
		return nil, errors.New("tpm: endorsement key not initialized")
	}
	return f.pub, nil
}

func TestGetEKPublicKey_LoadsEKAttributesFirst(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ops := &TPMOperations{tpm: &ekCacheTPM{pub: key.Public()}}

	pub, err := ops.GetEKPublicKey()
	if err != nil {
		t.Fatalf("GetEKPublicKey on a provisioned TPM: %v", err)
	}
	if !key.PublicKey.Equal(pub) {
		t.Error("GetEKPublicKey returned a different key than the TPM's EK")
	}
}

func TestGetEKPublicKey_EKAttributesError(t *testing.T) {
	cause := errors.New("TPM_RC_HANDLE")
	ops := &TPMOperations{tpm: &ekCacheTPM{attrsErr: cause}}

	_, err := ops.GetEKPublicKey()
	var injErr ErrEKCertInjectionFailed
	if !errors.As(err, &injErr) {
		t.Fatalf("error = %v, want ErrEKCertInjectionFailed", err)
	}
	if !errors.Is(err, cause) {
		t.Errorf("error = %v, want it to wrap the EKAttributes failure", err)
	}
}
