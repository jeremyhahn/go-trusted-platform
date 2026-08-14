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

package container

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// mockQuoteTPM is a mock QuoteTPM for HostTPMProvider tests. It signs
// quotes with a real RSA key so signature verification exercises the real
// crypto path.
type mockQuoteTPM struct {
	key         *rsa.PrivateKey
	extendCalls int
	extendAlg   string
	extendErr   error
	readErr     error
	quoteErr    error
	iakErr      error
	pcrValues   map[int][]byte
}

func newMockQuoteTPM(t *testing.T) *mockQuoteTPM {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return &mockQuoteTPM{
		key:       key,
		pcrValues: map[int][]byte{DefaultPCRIndex: bytes.Repeat([]byte{0xAB}, 32)},
	}
}

func (m *mockQuoteTPM) ExtendPCR(pcrIndex int, hashAlg string, data []byte) error {
	m.extendCalls++
	m.extendAlg = hashAlg
	return m.extendErr
}

func (m *mockQuoteTPM) ReadPCRs(pcrList []uint) ([]xkmssdk.PCRBank, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}
	bank := xkmssdk.PCRBank{Algorithm: sha256BankName}
	for _, idx := range pcrList {
		if value, ok := m.pcrValues[int(idx)]; ok {
			bank.PCRs = append(bank.PCRs, xkmssdk.PCR{ID: int32(idx), Value: value})
		}
	}
	return []xkmssdk.PCRBank{bank}, nil
}

// Quote returns a real TPMS_ATTEST over the PCRs the mock reports, signed with
// the mock's RSA key. The body has to be well formed because the SDK binds the
// PCR read to the pcrDigest inside it; a placeholder string would fail to
// parse long before any signature was checked.
func (m *mockQuoteTPM) Quote(pcrs []uint, nonce []byte) (xkmssdk.Quote, error) {
	if m.quoteErr != nil {
		return xkmssdk.Quote{}, m.quoteErr
	}
	quoted, err := newSyntheticQuote(sha256BankName, m.pcrValues, pcrs, nonce).quoted()
	if err != nil {
		return xkmssdk.Quote{}, err
	}
	digest := sha256.Sum256(quoted)
	signature, err := rsa.SignPKCS1v15(rand.Reader, m.key, crypto.SHA256, digest[:])
	if err != nil {
		return xkmssdk.Quote{}, err
	}
	return xkmssdk.Quote{
		Quoted:    quoted,
		Signature: signature,
		Nonce:     nonce,
	}, nil
}

func (m *mockQuoteTPM) IAK() (crypto.PublicKey, error) {
	if m.iakErr != nil {
		return nil, m.iakErr
	}
	return &m.key.PublicKey, nil
}

func TestNewHostTPMProvider(t *testing.T) {
	t.Run("creates provider with TPM", func(t *testing.T) {
		provider, err := NewHostTPMProvider(newMockQuoteTPM(t))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if provider == nil {
			t.Fatal("expected provider")
		}
	})

	t.Run("rejects nil TPM", func(t *testing.T) {
		provider, err := NewHostTPMProvider(nil)
		if provider != nil {
			t.Fatal("expected nil provider")
		}
		var target ErrHostTPMRequired
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrHostTPMRequired, got %v", err)
		}
	})

	// The whole point of the provider after the SDK convergence: it fills the
	// go-quicbaas HostTPM seam, so the platform contributes no TPM interface
	// of its own. The assignments below are compile-time assertions — the build
	// breaks if the provider ever stops satisfying either interface.
	t.Run("fills the SDK host TPM seam", func(t *testing.T) {
		provider, err := NewHostTPMProvider(newMockQuoteTPM(t))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var _ orchestration.HostTPM = provider
		var _ QuoteVerifier = provider
	})
}

func TestHostTPMProvider_ExtendPCR(t *testing.T) {
	data := bytes.Repeat([]byte{0x01}, SHA256Size)

	t.Run("extends PCR in lowercase sha256 bank", func(t *testing.T) {
		tpm := newMockQuoteTPM(t)
		provider, _ := NewHostTPMProvider(tpm)

		if err := provider.ExtendPCR(DefaultPCRIndex, "SHA256", data); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tpm.extendCalls != 1 {
			t.Fatalf("expected 1 extend call, got %d", tpm.extendCalls)
		}
		if tpm.extendAlg != "sha256" {
			t.Fatalf("expected sha256 bank, got %q", tpm.extendAlg)
		}
	})

	t.Run("defaults the bank when unset", func(t *testing.T) {
		tpm := newMockQuoteTPM(t)
		provider, _ := NewHostTPMProvider(tpm)

		if err := provider.ExtendPCR(DefaultPCRIndex, "", data); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tpm.extendAlg != orchestration.DefaultMeasurementBank {
			t.Fatalf("expected %q, got %q", orchestration.DefaultMeasurementBank, tpm.extendAlg)
		}
	})

	t.Run("rejects out-of-range PCR index", func(t *testing.T) {
		provider, _ := NewHostTPMProvider(newMockQuoteTPM(t))
		if err := provider.ExtendPCR(24, "sha256", data); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("expected ErrInvalidSpec, got %v", err)
		}
		if err := provider.ExtendPCR(-1, "sha256", data); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("expected ErrInvalidSpec, got %v", err)
		}
	})

	t.Run("rejects empty measurement", func(t *testing.T) {
		provider, _ := NewHostTPMProvider(newMockQuoteTPM(t))
		if err := provider.ExtendPCR(DefaultPCRIndex, "sha256", nil); !errors.Is(err, ErrMeasurementLogInvalid) {
			t.Fatalf("expected ErrMeasurementLogInvalid, got %v", err)
		}
	})

	t.Run("wraps TPM failure", func(t *testing.T) {
		tpm := newMockQuoteTPM(t)
		tpm.extendErr = errors.New("tpm unavailable")
		provider, _ := NewHostTPMProvider(tpm)

		err := provider.ExtendPCR(DefaultPCRIndex, "sha256", data)
		var target ErrHostTPMOperationFailed
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrHostTPMOperationFailed, got %v", err)
		}
	})
}

func TestHostTPMProvider_ReadPCRs(t *testing.T) {
	t.Run("reads the SHA-256 bank", func(t *testing.T) {
		tpm := newMockQuoteTPM(t)
		provider, _ := NewHostTPMProvider(tpm)

		banks, err := provider.ReadPCRs([]uint{DefaultPCRIndex})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		value, ok := sha256PCRValue(banks, DefaultPCRIndex)
		if !ok {
			t.Fatal("expected a SHA-256 value for the workload PCR")
		}
		if !bytes.Equal(value, tpm.pcrValues[DefaultPCRIndex]) {
			t.Fatal("PCR value mismatch")
		}
	})

	t.Run("rejects out-of-range PCR index", func(t *testing.T) {
		provider, _ := NewHostTPMProvider(newMockQuoteTPM(t))
		if _, err := provider.ReadPCRs([]uint{99}); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("expected ErrInvalidSpec, got %v", err)
		}
	})

	t.Run("wraps TPM read failure", func(t *testing.T) {
		tpm := newMockQuoteTPM(t)
		tpm.readErr = errors.New("read failed")
		provider, _ := NewHostTPMProvider(tpm)

		_, err := provider.ReadPCRs([]uint{DefaultPCRIndex})
		var target ErrHostTPMOperationFailed
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrHostTPMOperationFailed, got %v", err)
		}
	})

	t.Run("reports a missing PCR", func(t *testing.T) {
		provider, _ := NewHostTPMProvider(newMockQuoteTPM(t))
		banks, err := provider.ReadPCRs([]uint{7})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := sha256PCRValue(banks, 7); ok {
			t.Fatal("PCR 7 should not be present")
		}
	})
}

func TestHostTPMProvider_Quote(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x42}, 32)

	t.Run("generates signed quote", func(t *testing.T) {
		provider, _ := NewHostTPMProvider(newMockQuoteTPM(t))

		quote, err := provider.Quote([]uint{DefaultPCRIndex}, nonce)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(quote.Quoted) == 0 || len(quote.Signature) == 0 {
			t.Fatal("expected quote data and signature")
		}
		if !bytes.Equal(quote.Nonce, nonce) {
			t.Fatal("nonce mismatch")
		}
	})

	t.Run("rejects empty PCR selection", func(t *testing.T) {
		provider, _ := NewHostTPMProvider(newMockQuoteTPM(t))
		if _, err := provider.Quote(nil, nonce); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("expected ErrInvalidSpec, got %v", err)
		}
	})

	t.Run("rejects out-of-range PCR index", func(t *testing.T) {
		provider, _ := NewHostTPMProvider(newMockQuoteTPM(t))
		if _, err := provider.Quote([]uint{99}, nonce); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("expected ErrInvalidSpec, got %v", err)
		}
	})

	t.Run("wraps TPM quote failure", func(t *testing.T) {
		tpm := newMockQuoteTPM(t)
		tpm.quoteErr = errors.New("quote failed")
		provider, _ := NewHostTPMProvider(tpm)

		_, err := provider.Quote([]uint{DefaultPCRIndex}, nonce)
		var target ErrHostTPMOperationFailed
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrHostTPMOperationFailed, got %v", err)
		}
	})
}

func TestHostTPMProvider_VerifyQuote(t *testing.T) {
	ctx := context.Background()
	nonce := bytes.Repeat([]byte{0x42}, 32)

	t.Run("verifies IAK-signed quote", func(t *testing.T) {
		provider, _ := NewHostTPMProvider(newMockQuoteTPM(t))

		quote, err := provider.Quote([]uint{DefaultPCRIndex}, nonce)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := provider.VerifyQuote(ctx, quote.Quoted, quote.Signature); err != nil {
			t.Fatalf("expected quote to verify, got %v", err)
		}
	})

	t.Run("rejects tampered quote", func(t *testing.T) {
		provider, _ := NewHostTPMProvider(newMockQuoteTPM(t))

		quote, err := provider.Quote([]uint{DefaultPCRIndex}, nonce)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tampered := append(append([]byte(nil), quote.Quoted...), 0xFF)

		var target ErrHostTPMOperationFailed
		if err := provider.VerifyQuote(ctx, tampered, quote.Signature); !errors.As(err, &target) {
			t.Fatalf("expected ErrHostTPMOperationFailed for tampered quote, got %v", err)
		}
	})

	t.Run("rejects empty quote", func(t *testing.T) {
		provider, _ := NewHostTPMProvider(newMockQuoteTPM(t))
		if err := provider.VerifyQuote(ctx, nil, nil); !errors.Is(err, ErrInvalidQuote) {
			t.Fatalf("expected ErrInvalidQuote, got %v", err)
		}
	})

	t.Run("rejects cancelled context", func(t *testing.T) {
		provider, _ := NewHostTPMProvider(newMockQuoteTPM(t))
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if err := provider.VerifyQuote(cancelled, []byte("q"), []byte("s")); err == nil {
			t.Fatal("expected error for cancelled context")
		}
	})

	t.Run("wraps IAK retrieval failure", func(t *testing.T) {
		tpm := newMockQuoteTPM(t)
		tpm.iakErr = errors.New("no IAK")
		provider, _ := NewHostTPMProvider(tpm)

		var target ErrHostTPMOperationFailed
		err := provider.VerifyQuote(ctx, []byte("q"), []byte("s"))
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrHostTPMOperationFailed, got %v", err)
		}
	})
}

// sha256PCRValue extracts the SHA-256 value for the given PCR index from a
// set of PCR banks. The second return value reports whether it was found.
func sha256PCRValue(banks []orchestration.PCRBank, pcrIndex int) ([]byte, bool) {
	for _, bank := range banks {
		if !strings.EqualFold(bank.Algorithm, sha256BankName) {
			continue
		}
		for _, pcr := range bank.PCRs {
			if int(pcr.ID) == pcrIndex {
				return pcr.Value, true
			}
		}
	}
	return nil, false
}

// TestHostTPMProviderErrors covers the typed error contract callers match on.
func TestHostTPMProviderErrors(t *testing.T) {
	t.Run("ErrHostTPMRequired", func(t *testing.T) {
		err := ErrHostTPMRequired{}
		if !strings.Contains(err.Error(), "TPM is required") {
			t.Errorf("message = %q", err.Error())
		}
	})

	t.Run("ErrHostTPMOperationFailed", func(t *testing.T) {
		cause := errors.New("device busy")
		err := ErrHostTPMOperationFailed{Op: "quote", Cause: cause}
		if !strings.Contains(err.Error(), "quote") {
			t.Errorf("message %q must name the operation", err.Error())
		}
		if !errors.Is(err, cause) {
			t.Error("must unwrap to the cause")
		}
	})
}
