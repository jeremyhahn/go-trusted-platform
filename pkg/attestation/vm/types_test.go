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

package vm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestHashAlgorithm_String(t *testing.T) {
	tests := []struct {
		alg      HashAlgorithm
		expected string
	}{
		{HashAlgorithmSHA1, "sha1"},
		{HashAlgorithmSHA256, "sha256"},
		{HashAlgorithmSHA384, "sha384"},
		{HashAlgorithmSHA512, "sha512"},
		{HashAlgorithm("custom"), "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.alg.String(); got != tt.expected {
				t.Errorf("String() = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestHashAlgorithm_IsValid(t *testing.T) {
	tests := []struct {
		alg      HashAlgorithm
		expected bool
	}{
		{HashAlgorithmSHA1, true},
		{HashAlgorithmSHA256, true},
		{HashAlgorithmSHA384, true},
		{HashAlgorithmSHA512, true},
		{HashAlgorithm("md5"), false},
		{HashAlgorithm(""), false},
		{HashAlgorithm("SHA256"), false}, // case sensitive
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			if got := tt.alg.IsValid(); got != tt.expected {
				t.Errorf("IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHashAlgorithm_DigestSize(t *testing.T) {
	tests := []struct {
		alg      HashAlgorithm
		expected int
	}{
		{HashAlgorithmSHA1, 20},
		{HashAlgorithmSHA256, 32},
		{HashAlgorithmSHA384, 48},
		{HashAlgorithmSHA512, 64},
		{HashAlgorithm("invalid"), 0},
		{HashAlgorithm(""), 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			if got := tt.alg.DigestSize(); got != tt.expected {
				t.Errorf("DigestSize() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestVerificationStatus_String(t *testing.T) {
	tests := []struct {
		status   VerificationStatus
		expected string
	}{
		{VerificationStatusUnknown, "unknown"},
		{VerificationStatusPending, "pending"},
		{VerificationStatusVerified, "verified"},
		{VerificationStatusFailed, "failed"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.status.String(); got != tt.expected {
				t.Errorf("String() = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestVerificationStatus_IsValid(t *testing.T) {
	tests := []struct {
		status   VerificationStatus
		expected bool
	}{
		{VerificationStatusUnknown, true},
		{VerificationStatusPending, true},
		{VerificationStatusVerified, true},
		{VerificationStatusFailed, true},
		{VerificationStatus("invalid"), false},
		{VerificationStatus(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.IsValid(); got != tt.expected {
				t.Errorf("IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestVMIdentity_FormatCN(t *testing.T) {
	tests := []struct {
		name     string
		identity VMIdentity
		expected string
	}{
		{
			name: "basic",
			identity: VMIdentity{
				VMID:   "vm-123",
				HostID: "host-456",
			},
			expected: "vm:vm-123@host:host-456",
		},
		{
			name: "uuid format",
			identity: VMIdentity{
				VMID:   "550e8400-e29b-41d4-a716-446655440000",
				HostID: "host-abc-def-123",
			},
			expected: "vm:550e8400-e29b-41d4-a716-446655440000@host:host-abc-def-123",
		},
		{
			name: "empty values",
			identity: VMIdentity{
				VMID:   "",
				HostID: "",
			},
			expected: "vm:@host:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.identity.FormatCN(); got != tt.expected {
				t.Errorf("FormatCN() = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestParseCN(t *testing.T) {
	tests := []struct {
		name      string
		cn        string
		wantVMID  string
		wantHost  string
		wantError bool
	}{
		{
			name:      "valid CN",
			cn:        "vm:vm-123@host:host-456",
			wantVMID:  "vm-123",
			wantHost:  "host-456",
			wantError: false,
		},
		{
			name:      "UUID format",
			cn:        "vm:550e8400-e29b-41d4-a716-446655440000@host:host-abc",
			wantVMID:  "550e8400-e29b-41d4-a716-446655440000",
			wantHost:  "host-abc",
			wantError: false,
		},
		{
			name:      "invalid format - missing prefix",
			cn:        "vm-123@host:host-456",
			wantError: true,
		},
		{
			name:      "invalid format - missing @",
			cn:        "vm:vm-123host:host-456",
			wantError: true,
		},
		{
			name:      "invalid format - empty",
			cn:        "",
			wantError: true,
		},
		{
			name:      "invalid format - wrong separator",
			cn:        "vm:vm-123|host:host-456",
			wantError: true,
		},
		{
			name:      "empty vmID",
			cn:        "vm:@host:host-456",
			wantError: true,
		},
		{
			name:      "empty hostID",
			cn:        "vm:vm-123@host:",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCN(tt.cn)
			if tt.wantError {
				if err == nil {
					t.Errorf("ParseCN() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("ParseCN() unexpected error: %v", err)
				return
			}
			if got.VMID != tt.wantVMID {
				t.Errorf("VMID = %s, want %s", got.VMID, tt.wantVMID)
			}
			if got.HostID != tt.wantHost {
				t.Errorf("HostID = %s, want %s", got.HostID, tt.wantHost)
			}
		})
	}
}

func TestVMIdentity_Validate(t *testing.T) {
	tests := []struct {
		name      string
		identity  VMIdentity
		wantError bool
	}{
		{
			name: "valid identity",
			identity: VMIdentity{
				VMID:   "vm-123",
				HostID: "host-456",
			},
			wantError: false,
		},
		{
			name: "empty VMID",
			identity: VMIdentity{
				VMID:   "",
				HostID: "host-456",
			},
			wantError: true,
		},
		{
			name: "empty HostID",
			identity: VMIdentity{
				VMID:   "vm-123",
				HostID: "",
			},
			wantError: true,
		},
		{
			name: "both empty",
			identity: VMIdentity{
				VMID:   "",
				HostID: "",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.identity.Validate()
			if tt.wantError {
				if err == nil {
					t.Errorf("Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestVMQuote_Validate(t *testing.T) {
	validPCRs := []PCRValue{
		{Index: 0, Value: make([]byte, 32), Algorithm: HashAlgorithmSHA256},
	}

	tests := []struct {
		name      string
		quote     VMQuote
		wantError bool
	}{
		{
			name: "valid quote",
			quote: VMQuote{
				QuoteData:     []byte{0x01, 0x02, 0x03},
				Signature:     []byte{0x04, 0x05, 0x06},
				PCRs:          validPCRs,
				Nonce:         []byte{0x07, 0x08, 0x09},
				HashAlgorithm: HashAlgorithmSHA256,
			},
			wantError: false,
		},
		{
			name: "empty quote data",
			quote: VMQuote{
				QuoteData:     []byte{},
				Signature:     []byte{0x04, 0x05, 0x06},
				PCRs:          validPCRs,
				Nonce:         []byte{0x07, 0x08, 0x09},
				HashAlgorithm: HashAlgorithmSHA256,
			},
			wantError: true,
		},
		{
			name: "empty signature",
			quote: VMQuote{
				QuoteData:     []byte{0x01, 0x02, 0x03},
				Signature:     []byte{},
				PCRs:          validPCRs,
				Nonce:         []byte{0x07, 0x08, 0x09},
				HashAlgorithm: HashAlgorithmSHA256,
			},
			wantError: true,
		},
		{
			name: "no PCRs",
			quote: VMQuote{
				QuoteData:     []byte{0x01, 0x02, 0x03},
				Signature:     []byte{0x04, 0x05, 0x06},
				PCRs:          []PCRValue{},
				Nonce:         []byte{0x07, 0x08, 0x09},
				HashAlgorithm: HashAlgorithmSHA256,
			},
			wantError: true,
		},
		{
			name: "empty nonce",
			quote: VMQuote{
				QuoteData:     []byte{0x01, 0x02, 0x03},
				Signature:     []byte{0x04, 0x05, 0x06},
				PCRs:          validPCRs,
				Nonce:         []byte{},
				HashAlgorithm: HashAlgorithmSHA256,
			},
			wantError: true,
		},
		{
			name: "invalid hash algorithm",
			quote: VMQuote{
				QuoteData:     []byte{0x01, 0x02, 0x03},
				Signature:     []byte{0x04, 0x05, 0x06},
				PCRs:          validPCRs,
				Nonce:         []byte{0x07, 0x08, 0x09},
				HashAlgorithm: HashAlgorithm("invalid"),
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.quote.Validate()
			if tt.wantError {
				if err == nil {
					t.Errorf("Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestVMAttestation_Validate(t *testing.T) {
	validIdentity := &VMIdentity{VMID: "vm-123", HostID: "host-456"}
	validQuote := &VMQuote{
		QuoteData:     []byte{0x01, 0x02, 0x03},
		Signature:     []byte{0x04, 0x05, 0x06},
		PCRs:          []PCRValue{{Index: 0, Value: make([]byte, 32), Algorithm: HashAlgorithmSHA256}},
		Nonce:         []byte{0x07, 0x08, 0x09},
		HashAlgorithm: HashAlgorithmSHA256,
	}

	tests := []struct {
		name        string
		attestation VMAttestation
		wantError   bool
	}{
		{
			name: "valid attestation",
			attestation: VMAttestation{
				Identity: validIdentity,
				Quote:    validQuote,
			},
			wantError: false,
		},
		{
			name: "nil identity",
			attestation: VMAttestation{
				Identity: nil,
				Quote:    validQuote,
			},
			wantError: true,
		},
		{
			name: "nil quote",
			attestation: VMAttestation{
				Identity: validIdentity,
				Quote:    nil,
			},
			wantError: true,
		},
		{
			name: "invalid identity",
			attestation: VMAttestation{
				Identity: &VMIdentity{VMID: "", HostID: "host-456"},
				Quote:    validQuote,
			},
			wantError: true,
		},
		{
			name: "invalid quote",
			attestation: VMAttestation{
				Identity: validIdentity,
				Quote: &VMQuote{
					QuoteData:     []byte{},
					Signature:     []byte{0x04},
					PCRs:          []PCRValue{{Index: 0, Value: make([]byte, 32), Algorithm: HashAlgorithmSHA256}},
					Nonce:         []byte{0x07},
					HashAlgorithm: HashAlgorithmSHA256,
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.attestation.Validate()
			if tt.wantError {
				if err == nil {
					t.Errorf("Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestVMAttestation_IsVerified(t *testing.T) {
	tests := []struct {
		name        string
		attestation VMAttestation
		expected    bool
	}{
		{
			name: "verified",
			attestation: VMAttestation{
				VerificationResult: &VerificationResult{
					Status: VerificationStatusVerified,
				},
			},
			expected: true,
		},
		{
			name: "failed",
			attestation: VMAttestation{
				VerificationResult: &VerificationResult{
					Status: VerificationStatusFailed,
				},
			},
			expected: false,
		},
		{
			name: "pending",
			attestation: VMAttestation{
				VerificationResult: &VerificationResult{
					Status: VerificationStatusPending,
				},
			},
			expected: false,
		},
		{
			name: "nil result",
			attestation: VMAttestation{
				VerificationResult: nil,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.attestation.IsVerified(); got != tt.expected {
				t.Errorf("IsVerified() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestVerificationResult_AddError(t *testing.T) {
	result := &VerificationResult{}

	result.AddError("error 1")
	result.AddError("error 2")

	if len(result.Errors) != 2 {
		t.Errorf("Expected 2 errors, got %d", len(result.Errors))
	}
	if result.Errors[0] != "error 1" {
		t.Errorf("Expected 'error 1', got %s", result.Errors[0])
	}
	if result.Errors[1] != "error 2" {
		t.Errorf("Expected 'error 2', got %s", result.Errors[1])
	}
}

func TestVerificationResult_HasErrors(t *testing.T) {
	t.Run("no errors", func(t *testing.T) {
		result := &VerificationResult{}
		if result.HasErrors() {
			t.Error("Expected no errors")
		}
	})

	t.Run("with errors", func(t *testing.T) {
		result := &VerificationResult{}
		result.AddError("test error")
		if !result.HasErrors() {
			t.Error("Expected errors")
		}
	})
}

func TestQuoteRequest_Validate(t *testing.T) {
	tests := []struct {
		name      string
		request   QuoteRequest
		wantError bool
	}{
		{
			name: "valid request",
			request: QuoteRequest{
				Nonce:         []byte{0x01, 0x02, 0x03},
				PCRIndices:    []int{0, 1, 7, 14},
				HashAlgorithm: HashAlgorithmSHA256,
			},
			wantError: false,
		},
		{
			name: "empty nonce",
			request: QuoteRequest{
				Nonce:         []byte{},
				PCRIndices:    []int{0, 1, 7},
				HashAlgorithm: HashAlgorithmSHA256,
			},
			wantError: true,
		},
		{
			name: "empty PCR indices",
			request: QuoteRequest{
				Nonce:         []byte{0x01, 0x02},
				PCRIndices:    []int{},
				HashAlgorithm: HashAlgorithmSHA256,
			},
			wantError: true,
		},
		{
			name: "invalid PCR index negative",
			request: QuoteRequest{
				Nonce:         []byte{0x01, 0x02},
				PCRIndices:    []int{-1},
				HashAlgorithm: HashAlgorithmSHA256,
			},
			wantError: true,
		},
		{
			name: "invalid PCR index too high",
			request: QuoteRequest{
				Nonce:         []byte{0x01, 0x02},
				PCRIndices:    []int{24},
				HashAlgorithm: HashAlgorithmSHA256,
			},
			wantError: true,
		},
		{
			name: "invalid hash algorithm",
			request: QuoteRequest{
				Nonce:         []byte{0x01, 0x02},
				PCRIndices:    []int{0, 1},
				HashAlgorithm: HashAlgorithm("invalid"),
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantError {
				if err == nil {
					t.Errorf("Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestVerifyRequest_Validate(t *testing.T) {
	// Create a test certificate
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	caCert, _ := x509.ParseCertificate(certBytes)

	validQuote := &VMQuote{
		QuoteData:     []byte{0x01},
		Signature:     []byte{0x02},
		PCRs:          []PCRValue{{Index: 0, Value: make([]byte, 32), Algorithm: HashAlgorithmSHA256}},
		Nonce:         []byte{0x03},
		HashAlgorithm: HashAlgorithmSHA256,
	}
	validIdentity := &VMIdentity{VMID: "vm-123", HostID: "host-456"}

	tests := []struct {
		name      string
		request   VerifyRequest
		wantError bool
	}{
		{
			name: "valid request",
			request: VerifyRequest{
				Quote:          validQuote,
				Identity:       validIdentity,
				ExpectedNonce:  []byte{0x01, 0x02, 0x03},
				PlatformCACert: caCert,
			},
			wantError: false,
		},
		{
			name: "nil quote",
			request: VerifyRequest{
				Quote:          nil,
				Identity:       validIdentity,
				ExpectedNonce:  []byte{0x01, 0x02, 0x03},
				PlatformCACert: caCert,
			},
			wantError: true,
		},
		{
			name: "nil identity",
			request: VerifyRequest{
				Quote:          validQuote,
				Identity:       nil,
				ExpectedNonce:  []byte{0x01, 0x02, 0x03},
				PlatformCACert: caCert,
			},
			wantError: true,
		},
		{
			name: "empty expected nonce",
			request: VerifyRequest{
				Quote:          validQuote,
				Identity:       validIdentity,
				ExpectedNonce:  []byte{},
				PlatformCACert: caCert,
			},
			wantError: true,
		},
		{
			name: "nil platform CA cert",
			request: VerifyRequest{
				Quote:          validQuote,
				Identity:       validIdentity,
				ExpectedNonce:  []byte{0x01, 0x02, 0x03},
				PlatformCACert: nil,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantError {
				if err == nil {
					t.Errorf("Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestAttestorConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    AttestorConfig
		wantError bool
	}{
		{
			name: "valid config",
			config: AttestorConfig{
				VTPMDevicePath:       "/dev/tpm0",
				DefaultHashAlgorithm: HashAlgorithmSHA256,
			},
			wantError: false,
		},
		{
			name: "empty device path",
			config: AttestorConfig{
				VTPMDevicePath:       "",
				DefaultHashAlgorithm: HashAlgorithmSHA256,
			},
			wantError: true,
		},
		{
			name: "invalid hash algorithm",
			config: AttestorConfig{
				VTPMDevicePath:       "/dev/tpm0",
				DefaultHashAlgorithm: HashAlgorithm("invalid"),
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError {
				if err == nil {
					t.Errorf("Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestVerifierConfig_Validate(t *testing.T) {
	// Create a test certificate
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	caCert, _ := x509.ParseCertificate(certBytes)

	tests := []struct {
		name      string
		config    VerifierConfig
		wantError bool
	}{
		{
			name: "valid config",
			config: VerifierConfig{
				PlatformCACert: caCert,
				MaxQuoteAge:    300,
			},
			wantError: false,
		},
		{
			name: "nil platform CA cert",
			config: VerifierConfig{
				PlatformCACert: nil,
			},
			wantError: true,
		},
		{
			name: "negative max quote age",
			config: VerifierConfig{
				PlatformCACert: caCert,
				MaxQuoteAge:    -1,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError {
				if err == nil {
					t.Errorf("Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestPCRValue_Fields(t *testing.T) {
	pcr := PCRValue{
		Index:     14,
		Value:     []byte{0x01, 0x02, 0x03},
		Algorithm: HashAlgorithmSHA256,
	}

	if pcr.Index != 14 {
		t.Errorf("Index = %d, want 14", pcr.Index)
	}
	if len(pcr.Value) != 3 {
		t.Errorf("Value length = %d, want 3", len(pcr.Value))
	}
	if pcr.Algorithm != HashAlgorithmSHA256 {
		t.Errorf("Algorithm = %s, want sha256", pcr.Algorithm)
	}
}

func TestPCRMismatchDetail_Fields(t *testing.T) {
	mismatch := PCRMismatchDetail{
		Index:    7,
		Expected: []byte{0x01, 0x02},
		Actual:   []byte{0x03, 0x04},
	}

	if mismatch.Index != 7 {
		t.Errorf("Index = %d, want 7", mismatch.Index)
	}
	if len(mismatch.Expected) != 2 {
		t.Errorf("Expected length = %d, want 2", len(mismatch.Expected))
	}
	if len(mismatch.Actual) != 2 {
		t.Errorf("Actual length = %d, want 2", len(mismatch.Actual))
	}
}
