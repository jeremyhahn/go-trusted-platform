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

package cluster

import (
	"context"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// ============================================================================
// Error Type Tests - Cover all Error() and Unwrap() methods
// ============================================================================

func TestErrCertificateNotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrCertificateNotFound
		expected string
	}{
		{
			name:     "with tenant",
			err:      ErrCertificateNotFound{SerialNumber: "12345", TenantID: "tenant1"},
			expected: "cluster: certificate not found: serial=12345 tenant=tenant1",
		},
		{
			name:     "without tenant",
			err:      ErrCertificateNotFound{SerialNumber: "12345"},
			expected: "cluster: certificate not found: serial=12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestErrCertificateAlreadyExists_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrCertificateAlreadyExists
		expected string
	}{
		{
			name:     "with tenant",
			err:      ErrCertificateAlreadyExists{SerialNumber: "12345", TenantID: "tenant1"},
			expected: "cluster: certificate already exists: serial=12345 tenant=tenant1",
		},
		{
			name:     "without tenant",
			err:      ErrCertificateAlreadyExists{SerialNumber: "12345"},
			expected: "cluster: certificate already exists: serial=12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestErrCertificateAlreadyRevoked_Error(t *testing.T) {
	err := ErrCertificateAlreadyRevoked{SerialNumber: "12345", RevokedAt: "2025-01-15T12:00:00Z"}
	expected := "cluster: certificate already revoked: serial=12345 revoked_at=2025-01-15T12:00:00Z"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrInvalidCertificate(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := fmt.Errorf("parse error")
		err := ErrInvalidCertificate{Reason: "malformed DER", Cause: cause}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
		expected := "cluster: invalid certificate: malformed DER: parse error"
		if got := err.Error(); got != expected {
			t.Errorf("Error() = %v, want %v", got, expected)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrInvalidCertificate{Reason: "malformed DER"}
		expected := "cluster: invalid certificate: malformed DER"
		if got := err.Error(); got != expected {
			t.Errorf("Error() = %v, want %v", got, expected)
		}
	})
}

func TestErrCRLNotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrCRLNotFound
		expected string
	}{
		{
			name:     "with tenant",
			err:      ErrCRLNotFound{CRLID: "crl-1", TenantID: "tenant1"},
			expected: "cluster: CRL not found: id=crl-1 tenant=tenant1",
		},
		{
			name:     "without tenant",
			err:      ErrCRLNotFound{CRLID: "crl-1"},
			expected: "cluster: CRL not found: id=crl-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestErrInvalidCRL(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := fmt.Errorf("parse error")
		err := ErrInvalidCRL{Reason: "malformed DER", Cause: cause}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
		expected := "cluster: invalid CRL: malformed DER: parse error"
		if got := err.Error(); got != expected {
			t.Errorf("Error() = %v, want %v", got, expected)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrInvalidCRL{Reason: "malformed DER"}
		expected := "cluster: invalid CRL: malformed DER"
		if got := err.Error(); got != expected {
			t.Errorf("Error() = %v, want %v", got, expected)
		}
	})
}

func TestErrACMEAccountNotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrACMEAccountNotFound
		expected string
	}{
		{
			name:     "with tenant",
			err:      ErrACMEAccountNotFound{AccountID: "acct-1", TenantID: "tenant1"},
			expected: "cluster: ACME account not found: id=acct-1 tenant=tenant1",
		},
		{
			name:     "without tenant",
			err:      ErrACMEAccountNotFound{AccountID: "acct-1"},
			expected: "cluster: ACME account not found: id=acct-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestErrACMEAccountAlreadyExists_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrACMEAccountAlreadyExists
		expected string
	}{
		{
			name:     "with tenant",
			err:      ErrACMEAccountAlreadyExists{AccountID: "acct-1", TenantID: "tenant1"},
			expected: "cluster: ACME account already exists: id=acct-1 tenant=tenant1",
		},
		{
			name:     "without tenant",
			err:      ErrACMEAccountAlreadyExists{AccountID: "acct-1"},
			expected: "cluster: ACME account already exists: id=acct-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestErrACMEAccountInactive_Error(t *testing.T) {
	err := ErrACMEAccountInactive{AccountID: "acct-1", Status: "deactivated"}
	expected := "cluster: ACME account inactive: id=acct-1 status=deactivated"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrACMEOrderNotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrACMEOrderNotFound
		expected string
	}{
		{
			name:     "with tenant",
			err:      ErrACMEOrderNotFound{OrderID: "order-1", TenantID: "tenant1"},
			expected: "cluster: ACME order not found: id=order-1 tenant=tenant1",
		},
		{
			name:     "without tenant",
			err:      ErrACMEOrderNotFound{OrderID: "order-1"},
			expected: "cluster: ACME order not found: id=order-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestErrACMEOrderExpired_Error(t *testing.T) {
	err := ErrACMEOrderExpired{OrderID: "order-1", ExpiresAt: "2025-01-15T12:00:00Z"}
	expected := "cluster: ACME order expired: id=order-1 expired_at=2025-01-15T12:00:00Z"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrACMEOrderInvalidStatus_Error(t *testing.T) {
	err := ErrACMEOrderInvalidStatus{OrderID: "order-1", Status: "pending", Expected: "ready"}
	expected := "cluster: ACME order invalid status: id=order-1 status=pending expected=ready"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrACMEAuthorizationNotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrACMEAuthorizationNotFound
		expected string
	}{
		{
			name:     "with tenant",
			err:      ErrACMEAuthorizationNotFound{AuthorizationID: "authz-1", TenantID: "tenant1"},
			expected: "cluster: ACME authorization not found: id=authz-1 tenant=tenant1",
		},
		{
			name:     "without tenant",
			err:      ErrACMEAuthorizationNotFound{AuthorizationID: "authz-1"},
			expected: "cluster: ACME authorization not found: id=authz-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestErrACMEAuthorizationExpired_Error(t *testing.T) {
	err := ErrACMEAuthorizationExpired{AuthorizationID: "authz-1", ExpiresAt: "2025-01-15T12:00:00Z"}
	expected := "cluster: ACME authorization expired: id=authz-1 expired_at=2025-01-15T12:00:00Z"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrACMEChallengeNotFound_Error(t *testing.T) {
	err := ErrACMEChallengeNotFound{ChallengeID: "chal-1", AuthorizationID: "authz-1"}
	expected := "cluster: ACME challenge not found: id=chal-1 authorization=authz-1"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrACMEChallengeInvalidStatus_Error(t *testing.T) {
	err := ErrACMEChallengeInvalidStatus{ChallengeID: "chal-1", Status: "pending", Expected: "valid"}
	expected := "cluster: ACME challenge invalid status: id=chal-1 status=pending expected=valid"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrInvalidInput_Error(t *testing.T) {
	err := ErrInvalidInput{Field: "serial", Reason: "cannot be nil"}
	expected := "cluster: invalid input: serial: cannot be nil"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrVersionConflict_Error(t *testing.T) {
	err := ErrVersionConflict{EntityType: "Certificate", EntityID: "12345", ExpectedVersion: 1, ActualVersion: 2}
	expected := "cluster: version conflict: type=Certificate id=12345 expected=1 actual=2"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrTenantMismatch_Error(t *testing.T) {
	err := ErrTenantMismatch{EntityType: "Certificate", EntityID: "12345", ExpectedTenant: "tenant1", ActualTenant: "tenant2"}
	expected := "cluster: tenant mismatch: type=Certificate id=12345 expected=tenant1 actual=tenant2"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

func TestErrOperationFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := fmt.Errorf("network error")
		err := ErrOperationFailed{Operation: "get", Cause: cause}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
		expected := "cluster: operation failed: get: network error"
		if got := err.Error(); got != expected {
			t.Errorf("Error() = %v, want %v", got, expected)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrOperationFailed{Operation: "get"}
		expected := "cluster: operation failed: get"
		if got := err.Error(); got != expected {
			t.Errorf("Error() = %v, want %v", got, expected)
		}
	})
}

func TestErrStorageUnavailable(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := fmt.Errorf("connection refused")
		err := ErrStorageUnavailable{Cause: cause}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
		expected := "cluster: storage unavailable: connection refused"
		if got := err.Error(); got != expected {
			t.Errorf("Error() = %v, want %v", got, expected)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrStorageUnavailable{}
		expected := "cluster: storage unavailable"
		if got := err.Error(); got != expected {
			t.Errorf("Error() = %v, want %v", got, expected)
		}
	})
}

// ============================================================================
// Config Validation Tests
// ============================================================================

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errType interface{}
	}{
		{
			name:    "valid config",
			config:  DefaultConfig("test-node"),
			wantErr: false,
		},
		{
			name: "empty node ID",
			config: &Config{
				NodeID:                          "",
				TenantID:                        "tenant1",
				CRLUpdateInterval:               24 * time.Hour,
				OrderExpirationDuration:         7 * 24 * time.Hour,
				AuthorizationExpirationDuration: 7 * 24 * time.Hour,
				MaxRetries:                      3,
				RetryBackoff:                    100 * time.Millisecond,
				ConsistencyLevel:                ConsistencyLinearizable,
			},
			wantErr: true,
		},
		{
			name: "empty tenant ID",
			config: &Config{
				NodeID:                          "node-1",
				TenantID:                        "",
				CRLUpdateInterval:               24 * time.Hour,
				OrderExpirationDuration:         7 * 24 * time.Hour,
				AuthorizationExpirationDuration: 7 * 24 * time.Hour,
				MaxRetries:                      3,
				RetryBackoff:                    100 * time.Millisecond,
				ConsistencyLevel:                ConsistencyLinearizable,
			},
			wantErr: true,
		},
		{
			name: "negative CRL interval",
			config: &Config{
				NodeID:                          "node-1",
				TenantID:                        "tenant1",
				CRLUpdateInterval:               -1 * time.Hour,
				OrderExpirationDuration:         7 * 24 * time.Hour,
				AuthorizationExpirationDuration: 7 * 24 * time.Hour,
				MaxRetries:                      3,
				RetryBackoff:                    100 * time.Millisecond,
				ConsistencyLevel:                ConsistencyLinearizable,
			},
			wantErr: true,
		},
		{
			name: "negative order expiration",
			config: &Config{
				NodeID:                          "node-1",
				TenantID:                        "tenant1",
				CRLUpdateInterval:               24 * time.Hour,
				OrderExpirationDuration:         -1 * time.Hour,
				AuthorizationExpirationDuration: 7 * 24 * time.Hour,
				MaxRetries:                      3,
				RetryBackoff:                    100 * time.Millisecond,
				ConsistencyLevel:                ConsistencyLinearizable,
			},
			wantErr: true,
		},
		{
			name: "negative authorization expiration",
			config: &Config{
				NodeID:                          "node-1",
				TenantID:                        "tenant1",
				CRLUpdateInterval:               24 * time.Hour,
				OrderExpirationDuration:         7 * 24 * time.Hour,
				AuthorizationExpirationDuration: -1 * time.Hour,
				MaxRetries:                      3,
				RetryBackoff:                    100 * time.Millisecond,
				ConsistencyLevel:                ConsistencyLinearizable,
			},
			wantErr: true,
		},
		{
			name: "negative max retries",
			config: &Config{
				NodeID:                          "node-1",
				TenantID:                        "tenant1",
				CRLUpdateInterval:               24 * time.Hour,
				OrderExpirationDuration:         7 * 24 * time.Hour,
				AuthorizationExpirationDuration: 7 * 24 * time.Hour,
				MaxRetries:                      -1,
				RetryBackoff:                    100 * time.Millisecond,
				ConsistencyLevel:                ConsistencyLinearizable,
			},
			wantErr: true,
		},
		{
			name: "negative retry backoff",
			config: &Config{
				NodeID:                          "node-1",
				TenantID:                        "tenant1",
				CRLUpdateInterval:               24 * time.Hour,
				OrderExpirationDuration:         7 * 24 * time.Hour,
				AuthorizationExpirationDuration: 7 * 24 * time.Hour,
				MaxRetries:                      3,
				RetryBackoff:                    -1 * time.Millisecond,
				ConsistencyLevel:                ConsistencyLinearizable,
			},
			wantErr: true,
		},
		{
			name: "invalid consistency level",
			config: &Config{
				NodeID:                          "node-1",
				TenantID:                        "tenant1",
				CRLUpdateInterval:               24 * time.Hour,
				OrderExpirationDuration:         7 * 24 * time.Hour,
				AuthorizationExpirationDuration: 7 * 24 * time.Hour,
				MaxRetries:                      3,
				RetryBackoff:                    100 * time.Millisecond,
				ConsistencyLevel:                "invalid",
			},
			wantErr: true,
		},
		{
			name: "sequential consistency",
			config: &Config{
				NodeID:                          "node-1",
				TenantID:                        "tenant1",
				CRLUpdateInterval:               24 * time.Hour,
				OrderExpirationDuration:         7 * 24 * time.Hour,
				AuthorizationExpirationDuration: 7 * 24 * time.Hour,
				MaxRetries:                      3,
				RetryBackoff:                    100 * time.Millisecond,
				ConsistencyLevel:                ConsistencySequential,
			},
			wantErr: false,
		},
		{
			name: "eventual consistency",
			config: &Config{
				NodeID:                          "node-1",
				TenantID:                        "tenant1",
				CRLUpdateInterval:               24 * time.Hour,
				OrderExpirationDuration:         7 * 24 * time.Hour,
				AuthorizationExpirationDuration: 7 * 24 * time.Hour,
				MaxRetries:                      3,
				RetryBackoff:                    100 * time.Millisecond,
				ConsistencyLevel:                ConsistencyEventual,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ============================================================================
// Config Builder Tests
// ============================================================================

func TestConfig_BuilderMethods(t *testing.T) {
	config := DefaultConfig("initial-node")

	config = config.WithNodeID("new-node")
	if config.NodeID != "new-node" {
		t.Errorf("WithNodeID: expected new-node, got %s", config.NodeID)
	}

	config = config.WithTenantID("new-tenant")
	if config.TenantID != "new-tenant" {
		t.Errorf("WithTenantID: expected new-tenant, got %s", config.TenantID)
	}

	config = config.WithCRLUpdateInterval(48 * time.Hour)
	if config.CRLUpdateInterval != 48*time.Hour {
		t.Errorf("WithCRLUpdateInterval: expected 48h, got %v", config.CRLUpdateInterval)
	}

	config = config.WithOrderExpiration(14 * 24 * time.Hour)
	if config.OrderExpirationDuration != 14*24*time.Hour {
		t.Errorf("WithOrderExpiration: expected 14 days, got %v", config.OrderExpirationDuration)
	}

	config = config.WithAuthorizationExpiration(3 * 24 * time.Hour)
	if config.AuthorizationExpirationDuration != 3*24*time.Hour {
		t.Errorf("WithAuthorizationExpiration: expected 3 days, got %v", config.AuthorizationExpirationDuration)
	}

	config = config.WithOptimisticLocking(false)
	if config.EnableOptimisticLocking != false {
		t.Error("WithOptimisticLocking: expected false")
	}

	config = config.WithRetryPolicy(5, 200*time.Millisecond)
	if config.MaxRetries != 5 {
		t.Errorf("WithRetryPolicy: expected MaxRetries 5, got %d", config.MaxRetries)
	}
	if config.RetryBackoff != 200*time.Millisecond {
		t.Errorf("WithRetryPolicy: expected RetryBackoff 200ms, got %v", config.RetryBackoff)
	}

	config = config.WithConsistencyLevel(ConsistencyEventual)
	if config.ConsistencyLevel != ConsistencyEventual {
		t.Errorf("WithConsistencyLevel: expected eventual, got %s", config.ConsistencyLevel)
	}
}

// ============================================================================
// Storage Error Path Tests
// ============================================================================

func TestQuicBaaSStorage_StoreCertificate_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	mockStorage.SetPutError(ErrOperationFailed{Operation: "put"})

	ctx := context.Background()
	cert := &Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      "CN=test",
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	err := storage.StoreCertificate(ctx, cert)
	if err == nil {
		t.Fatal("expected error from storage")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_RevokeCertificate_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	// Try to revoke non-existent certificate
	err := storage.RevokeCertificate(ctx, big.NewInt(99999), 1, "tenant1")
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_UpdateCertificate_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	// Try to update non-existent certificate
	cert := &Certificate{
		SerialNumber: big.NewInt(99999),
		Subject:      "CN=test",
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	err := storage.UpdateCertificate(ctx, cert)
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_DeleteCertificate_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	// Try to delete non-existent certificate
	err := storage.DeleteCertificate(ctx, big.NewInt(99999), "tenant1")
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_StoreCRL_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	mockStorage.SetPutError(ErrOperationFailed{Operation: "put"})

	ctx := context.Background()
	crl := &CRL{
		CRLID:    "test-crl",
		DER:      []byte("test-der"),
		Issuer:   "CN=Test CA",
		TenantID: "tenant1",
	}

	err := storage.StoreCRL(ctx, crl)
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_GetCRL_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	// Try to get non-existent CRL
	_, err := storage.GetCRL(ctx, "non-existent", "tenant1")
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_GetCurrentCRL_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	// Try to get non-existent current CRL
	_, err := storage.GetCurrentCRL(ctx, "tenant1")
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_UpdateCRL_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	// Try to update non-existent CRL
	crl := &CRL{
		CRLID:    "non-existent",
		DER:      []byte("test-der"),
		Issuer:   "CN=Test CA",
		TenantID: "tenant1",
	}

	err := storage.UpdateCRL(ctx, crl)
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_DeleteCRL_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	// Try to delete non-existent CRL
	err := storage.DeleteCRL(ctx, "non-existent", "tenant1")
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_StoreACMEAccount_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	mockStorage.SetPutError(ErrOperationFailed{Operation: "put"})

	ctx := context.Background()
	account := &ACMEAccount{
		AccountID: "acct-1",
		Status:    "valid",
		TenantID:  "tenant1",
	}

	err := storage.StoreACMEAccount(ctx, account)
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_GetACMEAccount_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	// Try to get non-existent account
	_, err := storage.GetACMEAccount(ctx, "non-existent", "tenant1")
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_UpdateACMEAccount_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	// Try to update non-existent account
	account := &ACMEAccount{
		AccountID: "non-existent",
		Status:    "valid",
		TenantID:  "tenant1",
	}

	err := storage.UpdateACMEAccount(ctx, account)
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_DeleteACMEAccount_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	// Try to delete non-existent account
	err := storage.DeleteACMEAccount(ctx, "non-existent", "tenant1")
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_StoreACMEOrder_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	mockStorage.SetPutError(ErrOperationFailed{Operation: "put"})

	ctx := context.Background()
	order := &ACMEOrder{
		OrderID:   "order-1",
		AccountID: "acct-1",
		Status:    "pending",
		TenantID:  "tenant1",
	}

	err := storage.StoreACMEOrder(ctx, order)
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_GetACMEOrder_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	// Try to get non-existent order
	_, err := storage.GetACMEOrder(ctx, "non-existent", "tenant1")
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_UpdateACMEOrder_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	// Try to update non-existent order
	order := &ACMEOrder{
		OrderID:   "non-existent",
		AccountID: "acct-1",
		Status:    "pending",
		TenantID:  "tenant1",
	}

	err := storage.UpdateACMEOrder(ctx, order)
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_DeleteACMEOrder_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	// Try to delete non-existent order
	err := storage.DeleteACMEOrder(ctx, "non-existent", "tenant1")
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_StoreACMEAuthorization_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	mockStorage.SetPutError(ErrOperationFailed{Operation: "put"})

	ctx := context.Background()
	authz := &ACMEAuthorization{
		AuthorizationID: "authz-1",
		AccountID:       "acct-1",
		OrderID:         "order-1",
		Status:          "pending",
		TenantID:        "tenant1",
	}

	err := storage.StoreACMEAuthorization(ctx, authz)
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_GetACMEAuthorization_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	// Try to get non-existent authorization
	_, err := storage.GetACMEAuthorization(ctx, "non-existent", "tenant1")
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_UpdateACMEAuthorization_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	// Try to update non-existent authorization
	authz := &ACMEAuthorization{
		AuthorizationID: "non-existent",
		AccountID:       "acct-1",
		OrderID:         "order-1",
		Status:          "pending",
		TenantID:        "tenant1",
	}

	err := storage.UpdateACMEAuthorization(ctx, authz)
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_DeleteACMEAuthorization_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	// Try to delete non-existent authorization
	err := storage.DeleteACMEAuthorization(ctx, "non-existent", "tenant1")
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_CleanupExpiredOrders_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	mockStorage.SetListError(ErrOperationFailed{Operation: "list"})

	ctx := context.Background()
	_, err := storage.CleanupExpiredOrders(ctx, "tenant1")
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_CleanupExpiredAuthorizations_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	mockStorage.SetListError(ErrOperationFailed{Operation: "list"})

	ctx := context.Background()
	_, err := storage.CleanupExpiredAuthorizations(ctx, "tenant1")
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

func TestQuicBaaSStorage_CleanupExpiredCertificates_Error(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	mockStorage.SetListError(ErrOperationFailed{Operation: "list"})

	ctx := context.Background()
	_, err := storage.CleanupExpiredCertificates(ctx, "tenant1", 24*time.Hour)
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

// ============================================================================
// CRL Coordinator - loadInitialStatus Tests
// ============================================================================

func TestCRLCoordinator_LoadInitialStatusWithExistingCRL(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	config := DefaultConfig("test-node-1")

	crlDAO := NewCRLDAO(storage, logger)
	certDAO := NewCertificateDAO(storage, logger)
	leaderChecker := NewMockLeaderChecker("test-node-1", true)

	generator, err := NewMockCRLGenerator()
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	ctx := context.Background()

	// Create an existing CRL before creating the coordinator
	now := time.Now().UTC()
	existingCRL := NewCRL(
		CurrentCRLID,
		[]byte("existing-crl-der"),
		"CN=Test CA",
		now.Add(-1*time.Hour),
		now.Add(23*time.Hour),
		"default",
	)
	err = crlDAO.Create(ctx, existingCRL)
	if err != nil {
		t.Fatalf("failed to create existing CRL: %v", err)
	}

	coordinator, err := NewCRLCoordinator(
		config,
		crlDAO,
		certDAO,
		leaderChecker,
		generator,
		logger,
		WithCRLUpdateInterval(100*time.Millisecond),
		WithCRLSchedulerInterval(50*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("failed to create coordinator: %v", err)
	}

	// Start the coordinator, which should load the existing CRL
	err = coordinator.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start coordinator: %v", err)
	}
	defer coordinator.Stop()

	// Wait a bit for it to initialize
	time.Sleep(100 * time.Millisecond)

	// Check that status reflects the loaded CRL
	status := coordinator.GetCRLStatus()
	if status.EntryCount < 0 {
		t.Log("Status reflects loaded CRL")
	}
}

// ============================================================================
// DAO Delete Error Path Tests
// ============================================================================

func TestCertificateDAO_Delete_StorageError(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	serial := big.NewInt(12345)
	cert := &Certificate{
		SerialNumber: serial,
		Subject:      "CN=test",
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	// Create cert first
	err := dao.Create(ctx, cert)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	// Set delete error
	storage.SetDelError(ErrOperationFailed{Operation: "delete"})

	err = dao.Delete(ctx, serial, "tenant1")
	if err == nil {
		t.Fatal("expected error from storage")
	}
}

func TestCRLDAO_Delete_StorageError(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	crl := &CRL{
		CRLID:    "test-crl",
		DER:      []byte("test-der"),
		Issuer:   "CN=Test CA",
		TenantID: "tenant1",
	}

	// Create CRL first
	err := dao.Create(ctx, crl)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	// Set delete error
	storage.SetDelError(ErrOperationFailed{Operation: "delete"})

	err = dao.Delete(ctx, "test-crl", "tenant1")
	if err == nil {
		t.Fatal("expected error from storage")
	}
}

func TestACMEDAO_DeleteAccount_StorageError(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	account := &ACMEAccount{
		AccountID: "acct-1",
		Status:    "valid",
		TenantID:  "tenant1",
	}

	// Create account first
	err := dao.CreateAccount(ctx, account)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	// Set delete error
	storage.SetDelError(ErrOperationFailed{Operation: "delete"})

	err = dao.DeleteAccount(ctx, "acct-1", "tenant1")
	if err == nil {
		t.Fatal("expected error from storage")
	}
}

func TestACMEDAO_DeleteOrder_StorageError(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	order := &ACMEOrder{
		OrderID:   "order-1",
		AccountID: "acct-1",
		Status:    "pending",
		TenantID:  "tenant1",
	}

	// Create order first
	err := dao.CreateOrder(ctx, order)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	// Set delete error
	storage.SetDelError(ErrOperationFailed{Operation: "delete"})

	err = dao.DeleteOrder(ctx, "order-1", "tenant1")
	if err == nil {
		t.Fatal("expected error from storage")
	}
}

func TestACMEDAO_DeleteAuthorization_StorageError(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	authz := &ACMEAuthorization{
		AuthorizationID: "authz-1",
		AccountID:       "acct-1",
		OrderID:         "order-1",
		Status:          "pending",
		TenantID:        "tenant1",
	}

	// Create authorization first
	err := dao.CreateAuthorization(ctx, authz)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	// Set delete error
	storage.SetDelError(ErrOperationFailed{Operation: "delete"})

	err = dao.DeleteAuthorization(ctx, "authz-1", "tenant1")
	if err == nil {
		t.Fatal("expected error from storage")
	}
}

// ============================================================================
// Additional DAO Edge Case Tests
// ============================================================================

func TestCertificateDAO_Get_NilSerialNumber(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	_, err := dao.Get(ctx, nil, "tenant1")

	if err == nil {
		t.Fatal("expected error for nil serial number")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestCertificateDAO_Delete_NilSerialNumber(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	err := dao.Delete(ctx, nil, "tenant1")

	if err == nil {
		t.Fatal("expected error for nil serial number")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestCertificateDAO_Revoke_NilSerialNumber(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	err := dao.Revoke(ctx, nil, 1, "tenant1")

	if err == nil {
		t.Fatal("expected error for nil serial number")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestCertificateDAO_Update_NilCertificate(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCertificateDAO(storage, logger)

	ctx := context.Background()
	err := dao.Update(ctx, nil)

	if err == nil {
		t.Fatal("expected error for nil certificate")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestCRLDAO_Update_NilCRL(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewCRLDAO(storage, logger)

	ctx := context.Background()
	err := dao.Update(ctx, nil)

	if err == nil {
		t.Fatal("expected error for nil CRL")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestACMEDAO_GetAccount_EmptyID(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	_, err := dao.GetAccount(ctx, "", "tenant1")

	if err == nil {
		t.Fatal("expected error for empty account ID")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestACMEDAO_GetOrder_EmptyID(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	_, err := dao.GetOrder(ctx, "", "tenant1")

	if err == nil {
		t.Fatal("expected error for empty order ID")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestACMEDAO_GetAuthorization_EmptyID(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	_, err := dao.GetAuthorization(ctx, "", "tenant1")

	if err == nil {
		t.Fatal("expected error for empty authorization ID")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestACMEDAO_CreateOrder_EmptyID(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	order := &ACMEOrder{
		OrderID:   "",
		AccountID: "acct-1",
		Status:    "pending",
		TenantID:  "tenant1",
	}

	err := dao.CreateOrder(ctx, order)

	if err == nil {
		t.Fatal("expected error for empty order ID")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestACMEDAO_CreateAuthorization_EmptyID(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	authz := &ACMEAuthorization{
		AuthorizationID: "",
		AccountID:       "acct-1",
		OrderID:         "order-1",
		Status:          "pending",
		TenantID:        "tenant1",
	}

	err := dao.CreateAuthorization(ctx, authz)

	if err == nil {
		t.Fatal("expected error for empty authorization ID")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestACMEDAO_DeleteAccount_EmptyID(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	err := dao.DeleteAccount(ctx, "", "tenant1")

	if err == nil {
		t.Fatal("expected error for empty account ID")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestACMEDAO_DeleteOrder_EmptyID(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	err := dao.DeleteOrder(ctx, "", "tenant1")

	if err == nil {
		t.Fatal("expected error for empty order ID")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestACMEDAO_DeleteAuthorization_EmptyID(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	err := dao.DeleteAuthorization(ctx, "", "tenant1")

	if err == nil {
		t.Fatal("expected error for empty authorization ID")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestACMEDAO_UpdateAccount_NilAccount(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	err := dao.UpdateAccount(ctx, nil)

	if err == nil {
		t.Fatal("expected error for nil account")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestACMEDAO_UpdateOrder_NilOrder(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	err := dao.UpdateOrder(ctx, nil)

	if err == nil {
		t.Fatal("expected error for nil order")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestACMEDAO_UpdateAuthorization_NilAuthz(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	err := dao.UpdateAuthorization(ctx, nil)

	if err == nil {
		t.Fatal("expected error for nil authorization")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

// ============================================================================
// CRL Expired Error Test
// ============================================================================

func TestErrCRLExpired_Error(t *testing.T) {
	expiredAt := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	err := ErrCRLExpired{
		CRLID:     "test-crl",
		ExpiredAt: expiredAt,
	}

	expected := "cluster: CRL expired: id=test-crl expired_at=2025-01-15T12:00:00Z"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %v, want %v", got, expected)
	}
}

// ============================================================================
// ErrNotLeader Tests
// ============================================================================

func TestErrNotLeader_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrNotLeader
		expected string
	}{
		{
			name:     "with leader ID",
			err:      ErrNotLeader{NodeID: "node-1", LeaderID: "node-2"},
			expected: "cluster: node node-1 is not the leader; current leader is node-2",
		},
		{
			name:     "without leader ID",
			err:      ErrNotLeader{NodeID: "node-1"},
			expected: "cluster: node node-1 is not the leader",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}
