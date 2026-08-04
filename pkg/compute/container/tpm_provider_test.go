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
	"testing"

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
	bank := xkmssdk.PCRBank{Algorithm: "SHA256"}
	for _, idx := range pcrList {
		if value, ok := m.pcrValues[int(idx)]; ok {
			bank.PCRs = append(bank.PCRs, xkmssdk.PCR{ID: int32(idx), Value: value})
		}
	}
	return []xkmssdk.PCRBank{bank}, nil
}

func (m *mockQuoteTPM) Quote(pcrs []uint, nonce []byte) (xkmssdk.Quote, error) {
	if m.quoteErr != nil {
		return xkmssdk.Quote{}, m.quoteErr
	}
	quoted := append([]byte("quote-data-"), nonce...)
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
}

func TestHostTPMProvider_ExtendPCR(t *testing.T) {
	ctx := context.Background()
	hash := bytes.Repeat([]byte{0x01}, SHA256Size)

	t.Run("extends PCR in lowercase sha256 bank", func(t *testing.T) {
		tpm := newMockQuoteTPM(t)
		provider, _ := NewHostTPMProvider(tpm)

		if err := provider.ExtendPCR(ctx, DefaultPCRIndex, hash); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tpm.extendCalls != 1 {
			t.Fatalf("expected 1 extend call, got %d", tpm.extendCalls)
		}
		if tpm.extendAlg != "sha256" {
			t.Fatalf("expected sha256 bank, got %q", tpm.extendAlg)
		}
	})

	t.Run("rejects out-of-range PCR index", func(t *testing.T) {
		provider, _ := NewHostTPMProvider(newMockQuoteTPM(t))
		if err := provider.ExtendPCR(ctx, 24, hash); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("expected ErrInvalidSpec, got %v", err)
		}
	})

	t.Run("rejects non-SHA256 hash length", func(t *testing.T) {
		provider, _ := NewHostTPMProvider(newMockQuoteTPM(t))
		if err := provider.ExtendPCR(ctx, DefaultPCRIndex, []byte{0x01}); !errors.Is(err, ErrMeasurementLogInvalid) {
			t.Fatalf("expected ErrMeasurementLogInvalid, got %v", err)
		}
	})

	t.Run("wraps TPM failure", func(t *testing.T) {
		tpm := newMockQuoteTPM(t)
		tpm.extendErr = errors.New("tpm unavailable")
		provider, _ := NewHostTPMProvider(tpm)

		err := provider.ExtendPCR(ctx, DefaultPCRIndex, hash)
		var target ErrHostTPMOperationFailed
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrHostTPMOperationFailed, got %v", err)
		}
	})

	t.Run("rejects cancelled context", func(t *testing.T) {
		provider, _ := NewHostTPMProvider(newMockQuoteTPM(t))
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if err := provider.ExtendPCR(cancelled, DefaultPCRIndex, hash); err == nil {
			t.Fatal("expected error for cancelled context")
		}
	})
}

func TestHostTPMProvider_ReadPCR(t *testing.T) {
	ctx := context.Background()

	t.Run("reads SHA-256 PCR value", func(t *testing.T) {
		tpm := newMockQuoteTPM(t)
		provider, _ := NewHostTPMProvider(tpm)

		value, err := provider.ReadPCR(ctx, DefaultPCRIndex)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(value, tpm.pcrValues[DefaultPCRIndex]) {
			t.Fatal("PCR value mismatch")
		}
	})

	t.Run("rejects out-of-range PCR index", func(t *testing.T) {
		provider, _ := NewHostTPMProvider(newMockQuoteTPM(t))
		if _, err := provider.ReadPCR(ctx, -1); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("expected ErrInvalidSpec, got %v", err)
		}
	})

	t.Run("wraps TPM read failure", func(t *testing.T) {
		tpm := newMockQuoteTPM(t)
		tpm.readErr = errors.New("read failed")
		provider, _ := NewHostTPMProvider(tpm)

		_, err := provider.ReadPCR(ctx, DefaultPCRIndex)
		var target ErrHostTPMOperationFailed
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrHostTPMOperationFailed, got %v", err)
		}
	})

	t.Run("returns typed error for missing PCR", func(t *testing.T) {
		tpm := newMockQuoteTPM(t)
		provider, _ := NewHostTPMProvider(tpm)

		_, err := provider.ReadPCR(ctx, 7)
		var target ErrPCRValueNotFound
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrPCRValueNotFound, got %v", err)
		}
		if target.PCRIndex != 7 {
			t.Fatalf("expected PCR 7 in error, got %d", target.PCRIndex)
		}
	})
}

func TestHostTPMProvider_GenerateQuote(t *testing.T) {
	ctx := context.Background()
	nonce := bytes.Repeat([]byte{0x42}, 32)

	t.Run("generates signed quote", func(t *testing.T) {
		tpm := newMockQuoteTPM(t)
		provider, _ := NewHostTPMProvider(tpm)

		quote, err := provider.GenerateQuote(ctx, []int{DefaultPCRIndex}, nonce)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(quote.QuoteData) == 0 || len(quote.Signature) == 0 {
			t.Fatal("expected quote data and signature")
		}
		if !bytes.Equal(quote.Nonce, nonce) {
			t.Fatal("nonce mismatch")
		}
	})

	t.Run("rejects empty PCR selection", func(t *testing.T) {
		provider, _ := NewHostTPMProvider(newMockQuoteTPM(t))
		if _, err := provider.GenerateQuote(ctx, nil, nonce); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("expected ErrInvalidSpec, got %v", err)
		}
	})

	t.Run("rejects out-of-range PCR index", func(t *testing.T) {
		provider, _ := NewHostTPMProvider(newMockQuoteTPM(t))
		if _, err := provider.GenerateQuote(ctx, []int{99}, nonce); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("expected ErrInvalidSpec, got %v", err)
		}
	})

	t.Run("wraps TPM quote failure", func(t *testing.T) {
		tpm := newMockQuoteTPM(t)
		tpm.quoteErr = errors.New("quote failed")
		provider, _ := NewHostTPMProvider(tpm)

		_, err := provider.GenerateQuote(ctx, []int{DefaultPCRIndex}, nonce)
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
		tpm := newMockQuoteTPM(t)
		provider, _ := NewHostTPMProvider(tpm)

		quote, err := provider.GenerateQuote(ctx, []int{DefaultPCRIndex}, nonce)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := provider.VerifyQuote(ctx, quote); err != nil {
			t.Fatalf("expected quote to verify, got %v", err)
		}
	})

	t.Run("rejects tampered quote", func(t *testing.T) {
		tpm := newMockQuoteTPM(t)
		provider, _ := NewHostTPMProvider(tpm)

		quote, err := provider.GenerateQuote(ctx, []int{DefaultPCRIndex}, nonce)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		quote.QuoteData = append(quote.QuoteData, 0xFF)

		var target ErrHostTPMOperationFailed
		if err := provider.VerifyQuote(ctx, quote); !errors.As(err, &target) {
			t.Fatalf("expected ErrHostTPMOperationFailed for tampered quote, got %v", err)
		}
	})

	t.Run("rejects nil quote", func(t *testing.T) {
		provider, _ := NewHostTPMProvider(newMockQuoteTPM(t))
		if err := provider.VerifyQuote(ctx, nil); !errors.Is(err, ErrInvalidQuote) {
			t.Fatalf("expected ErrInvalidQuote, got %v", err)
		}
	})

	t.Run("wraps IAK retrieval failure", func(t *testing.T) {
		tpm := newMockQuoteTPM(t)
		tpm.iakErr = errors.New("no IAK")
		provider, _ := NewHostTPMProvider(tpm)

		var target ErrHostTPMOperationFailed
		err := provider.VerifyQuote(ctx, &Quote{QuoteData: []byte("q"), Signature: []byte("s")})
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrHostTPMOperationFailed, got %v", err)
		}
	})
}
