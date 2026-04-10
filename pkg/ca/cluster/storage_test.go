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
	"math/big"
	"testing"
	"time"
)

func newTestConfig() *Config {
	return DefaultConfig("test-node")
}

func TestNewQuicBaaSStorage(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()

	storage, err := NewQuicBaaSStorage(mockStorage, config, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if storage == nil {
		t.Fatal("expected non-nil storage")
	}

	if storage.Config() != config {
		t.Error("expected config to match")
	}
}

func TestNewQuicBaaSStorage_NilStorage(t *testing.T) {
	logger := newTestLogger()
	config := newTestConfig()

	_, err := NewQuicBaaSStorage(nil, config, logger)
	if err == nil {
		t.Fatal("expected error for nil storage")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestNewQuicBaaSStorage_NilConfig(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()

	_, err := NewQuicBaaSStorage(mockStorage, nil, logger)
	if err == nil {
		t.Fatal("expected error for nil config")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestNewQuicBaaSStorage_NilLogger(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	config := newTestConfig()

	_, err := NewQuicBaaSStorage(mockStorage, config, nil)
	if err == nil {
		t.Fatal("expected error for nil logger")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestNewQuicBaaSStorage_InvalidConfig(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := &Config{
		NodeID:   "",
		TenantID: "test",
	}

	_, err := NewQuicBaaSStorage(mockStorage, config, logger)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestNewQuicBaaSStorage_Options(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()

	storage, err := NewQuicBaaSStorage(
		mockStorage,
		config,
		logger,
		WithStorageRequestTimeout(10*time.Second),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if storage.requestTimeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", storage.requestTimeout)
	}
}

// ============================================================================
// Certificate Storage Tests
// ============================================================================

func TestQuicBaaSStorage_StoreCertificate(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	cert := &Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      "CN=test",
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	err := storage.StoreCertificate(ctx, cert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	stats := storage.GetStats()
	if stats.CertificatesCreated != 1 {
		t.Errorf("expected CertificatesCreated 1, got %d", stats.CertificatesCreated)
	}
}

func TestQuicBaaSStorage_GetCertificate(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	serial := big.NewInt(12345)
	cert := &Certificate{
		SerialNumber: serial,
		Subject:      "CN=test",
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	err := storage.StoreCertificate(ctx, cert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	retrieved, err := storage.GetCertificate(ctx, serial, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if retrieved.Subject != cert.Subject {
		t.Errorf("expected subject %s, got %s", cert.Subject, retrieved.Subject)
	}

	stats := storage.GetStats()
	if stats.CertificatesRetrieved != 1 {
		t.Errorf("expected CertificatesRetrieved 1, got %d", stats.CertificatesRetrieved)
	}
}

func TestQuicBaaSStorage_ListCertificates(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		cert := &Certificate{
			SerialNumber: big.NewInt(int64(i)),
			Subject:      "CN=test",
			TenantID:     "tenant1",
			DER:          []byte("test-der"),
		}
		err := storage.StoreCertificate(ctx, cert)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	}

	certs, _, err := storage.ListCertificates(ctx, "tenant1", 10, "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(certs) != 5 {
		t.Errorf("expected 5 certificates, got %d", len(certs))
	}
}

func TestQuicBaaSStorage_ListValidCertificates(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	now := time.Now()

	// Create valid certificate
	validCert := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      "CN=valid",
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}
	err := storage.StoreCertificate(ctx, validCert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Create expired certificate
	expiredCert := &Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      "CN=expired",
		NotBefore:    now.Add(-48 * time.Hour),
		NotAfter:     now.Add(-24 * time.Hour),
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}
	err = storage.StoreCertificate(ctx, expiredCert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	validCerts, err := storage.ListValidCertificates(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(validCerts) != 1 {
		t.Errorf("expected 1 valid certificate, got %d", len(validCerts))
	}
}

func TestQuicBaaSStorage_RevokeCertificate(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	serial := big.NewInt(12345)
	cert := &Certificate{
		SerialNumber: serial,
		Subject:      "CN=test",
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	err := storage.StoreCertificate(ctx, cert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = storage.RevokeCertificate(ctx, serial, 1, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	stats := storage.GetStats()
	if stats.CertificatesRevoked != 1 {
		t.Errorf("expected CertificatesRevoked 1, got %d", stats.CertificatesRevoked)
	}
}

func TestQuicBaaSStorage_UpdateCertificate(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	serial := big.NewInt(12345)
	cert := &Certificate{
		SerialNumber: serial,
		Subject:      "CN=test",
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	err := storage.StoreCertificate(ctx, cert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	cert.Subject = "CN=updated"
	err = storage.UpdateCertificate(ctx, cert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	stats := storage.GetStats()
	if stats.CertificatesUpdated != 1 {
		t.Errorf("expected CertificatesUpdated 1, got %d", stats.CertificatesUpdated)
	}
}

func TestQuicBaaSStorage_DeleteCertificate(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	serial := big.NewInt(12345)
	cert := &Certificate{
		SerialNumber: serial,
		Subject:      "CN=test",
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}

	err := storage.StoreCertificate(ctx, cert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = storage.DeleteCertificate(ctx, serial, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	stats := storage.GetStats()
	if stats.CertificatesDeleted != 1 {
		t.Errorf("expected CertificatesDeleted 1, got %d", stats.CertificatesDeleted)
	}
}

// ============================================================================
// CRL Storage Tests
// ============================================================================

func TestQuicBaaSStorage_StoreCRL(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	crl := &CRL{
		CRLID:    "test-crl",
		DER:      []byte("test-crl-der"),
		Issuer:   "CN=Test CA",
		TenantID: "tenant1",
	}

	err := storage.StoreCRL(ctx, crl)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	stats := storage.GetStats()
	if stats.CRLsCreated != 1 {
		t.Errorf("expected CRLsCreated 1, got %d", stats.CRLsCreated)
	}
}

func TestQuicBaaSStorage_GetCRL(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	crl := &CRL{
		CRLID:    "test-crl",
		DER:      []byte("test-crl-der"),
		Issuer:   "CN=Test CA",
		TenantID: "tenant1",
	}

	err := storage.StoreCRL(ctx, crl)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	retrieved, err := storage.GetCRL(ctx, "test-crl", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if retrieved.CRLID != crl.CRLID {
		t.Errorf("expected CRLID %s, got %s", crl.CRLID, retrieved.CRLID)
	}

	stats := storage.GetStats()
	if stats.CRLsRetrieved != 1 {
		t.Errorf("expected CRLsRetrieved 1, got %d", stats.CRLsRetrieved)
	}
}

func TestQuicBaaSStorage_GetCurrentCRL(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	crl := &CRL{
		CRLID:    CurrentCRLID,
		DER:      []byte("current-crl-der"),
		Issuer:   "CN=Test CA",
		TenantID: "tenant1",
	}

	err := storage.StoreCRL(ctx, crl)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	retrieved, err := storage.GetCurrentCRL(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if retrieved.CRLID != CurrentCRLID {
		t.Errorf("expected CRLID %s, got %s", CurrentCRLID, retrieved.CRLID)
	}
}

func TestQuicBaaSStorage_UpdateCRL(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	crl := &CRL{
		CRLID:    "test-crl",
		DER:      []byte("original-der"),
		Issuer:   "CN=Test CA",
		TenantID: "tenant1",
	}

	err := storage.StoreCRL(ctx, crl)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	crl.DER = []byte("updated-der")
	err = storage.UpdateCRL(ctx, crl)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	stats := storage.GetStats()
	if stats.CRLsUpdated != 1 {
		t.Errorf("expected CRLsUpdated 1, got %d", stats.CRLsUpdated)
	}
}

func TestQuicBaaSStorage_DeleteCRL(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	crl := &CRL{
		CRLID:    "test-crl",
		DER:      []byte("test-crl-der"),
		Issuer:   "CN=Test CA",
		TenantID: "tenant1",
	}

	err := storage.StoreCRL(ctx, crl)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = storage.DeleteCRL(ctx, "test-crl", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// ============================================================================
// ACME Storage Tests
// ============================================================================

func TestQuicBaaSStorage_StoreACMEAccount(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	account := &ACMEAccount{
		AccountID: "acct-1",
		Status:    "valid",
		TenantID:  "tenant1",
	}

	err := storage.StoreACMEAccount(ctx, account)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	stats := storage.GetStats()
	if stats.ACMEAccountsCreated != 1 {
		t.Errorf("expected ACMEAccountsCreated 1, got %d", stats.ACMEAccountsCreated)
	}
}

func TestQuicBaaSStorage_GetACMEAccount(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	account := &ACMEAccount{
		AccountID: "acct-1",
		Status:    "valid",
		TenantID:  "tenant1",
	}

	err := storage.StoreACMEAccount(ctx, account)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	retrieved, err := storage.GetACMEAccount(ctx, "acct-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if retrieved.AccountID != account.AccountID {
		t.Errorf("expected AccountID %s, got %s", account.AccountID, retrieved.AccountID)
	}
}

func TestQuicBaaSStorage_UpdateACMEAccount(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	account := &ACMEAccount{
		AccountID: "acct-1",
		Status:    "valid",
		TenantID:  "tenant1",
	}

	err := storage.StoreACMEAccount(ctx, account)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	account.Status = "deactivated"
	err = storage.UpdateACMEAccount(ctx, account)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestQuicBaaSStorage_DeleteACMEAccount(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	account := &ACMEAccount{
		AccountID: "acct-1",
		Status:    "valid",
		TenantID:  "tenant1",
	}

	err := storage.StoreACMEAccount(ctx, account)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = storage.DeleteACMEAccount(ctx, "acct-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestQuicBaaSStorage_StoreACMEOrder(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	order := &ACMEOrder{
		OrderID:   "order-1",
		AccountID: "acct-1",
		Status:    "pending",
		TenantID:  "tenant1",
	}

	err := storage.StoreACMEOrder(ctx, order)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	stats := storage.GetStats()
	if stats.ACMEOrdersCreated != 1 {
		t.Errorf("expected ACMEOrdersCreated 1, got %d", stats.ACMEOrdersCreated)
	}
}

func TestQuicBaaSStorage_GetACMEOrder(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	order := &ACMEOrder{
		OrderID:   "order-1",
		AccountID: "acct-1",
		Status:    "pending",
		TenantID:  "tenant1",
	}

	err := storage.StoreACMEOrder(ctx, order)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	retrieved, err := storage.GetACMEOrder(ctx, "order-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if retrieved.OrderID != order.OrderID {
		t.Errorf("expected OrderID %s, got %s", order.OrderID, retrieved.OrderID)
	}
}

func TestQuicBaaSStorage_ListACMEOrdersByAccount(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		order := &ACMEOrder{
			OrderID:   "order-" + string(rune('0'+i)),
			AccountID: "acct-1",
			Status:    "pending",
			TenantID:  "tenant1",
		}
		err := storage.StoreACMEOrder(ctx, order)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	}

	orders, err := storage.ListACMEOrdersByAccount(ctx, "acct-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(orders) != 3 {
		t.Errorf("expected 3 orders, got %d", len(orders))
	}
}

func TestQuicBaaSStorage_UpdateACMEOrder(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	order := &ACMEOrder{
		OrderID:   "order-1",
		AccountID: "acct-1",
		Status:    "pending",
		TenantID:  "tenant1",
	}

	err := storage.StoreACMEOrder(ctx, order)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	order.Status = "ready"
	err = storage.UpdateACMEOrder(ctx, order)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestQuicBaaSStorage_DeleteACMEOrder(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	order := &ACMEOrder{
		OrderID:   "order-1",
		AccountID: "acct-1",
		Status:    "pending",
		TenantID:  "tenant1",
	}

	err := storage.StoreACMEOrder(ctx, order)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = storage.DeleteACMEOrder(ctx, "order-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestQuicBaaSStorage_StoreACMEAuthorization(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	authz := &ACMEAuthorization{
		AuthorizationID: "authz-1",
		AccountID:       "acct-1",
		OrderID:         "order-1",
		Status:          "pending",
		TenantID:        "tenant1",
	}

	err := storage.StoreACMEAuthorization(ctx, authz)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	stats := storage.GetStats()
	if stats.ACMEAuthzCreated != 1 {
		t.Errorf("expected ACMEAuthzCreated 1, got %d", stats.ACMEAuthzCreated)
	}
}

func TestQuicBaaSStorage_GetACMEAuthorization(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	authz := &ACMEAuthorization{
		AuthorizationID: "authz-1",
		AccountID:       "acct-1",
		OrderID:         "order-1",
		Status:          "pending",
		TenantID:        "tenant1",
	}

	err := storage.StoreACMEAuthorization(ctx, authz)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	retrieved, err := storage.GetACMEAuthorization(ctx, "authz-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if retrieved.AuthorizationID != authz.AuthorizationID {
		t.Errorf("expected AuthorizationID %s, got %s", authz.AuthorizationID, retrieved.AuthorizationID)
	}
}

func TestQuicBaaSStorage_ListACMEAuthorizationsByOrder(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		authz := &ACMEAuthorization{
			AuthorizationID: "authz-" + string(rune('0'+i)),
			AccountID:       "acct-1",
			OrderID:         "order-1",
			Status:          "pending",
			TenantID:        "tenant1",
		}
		err := storage.StoreACMEAuthorization(ctx, authz)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	}

	authzs, err := storage.ListACMEAuthorizationsByOrder(ctx, "order-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(authzs) != 3 {
		t.Errorf("expected 3 authorizations, got %d", len(authzs))
	}
}

func TestQuicBaaSStorage_UpdateACMEAuthorization(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	authz := &ACMEAuthorization{
		AuthorizationID: "authz-1",
		AccountID:       "acct-1",
		OrderID:         "order-1",
		Status:          "pending",
		TenantID:        "tenant1",
	}

	err := storage.StoreACMEAuthorization(ctx, authz)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	authz.Status = "valid"
	err = storage.UpdateACMEAuthorization(ctx, authz)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestQuicBaaSStorage_DeleteACMEAuthorization(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	authz := &ACMEAuthorization{
		AuthorizationID: "authz-1",
		AccountID:       "acct-1",
		OrderID:         "order-1",
		Status:          "pending",
		TenantID:        "tenant1",
	}

	err := storage.StoreACMEAuthorization(ctx, authz)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = storage.DeleteACMEAuthorization(ctx, "authz-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// ============================================================================
// Cleanup Tests
// ============================================================================

func TestQuicBaaSStorage_CleanupExpiredOrders(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	now := time.Now().UTC()

	// Create expired order
	expiredOrder := &ACMEOrder{
		OrderID:   "order-expired",
		AccountID: "acct-1",
		Status:    "pending",
		ExpiresAt: now.Add(-1 * time.Hour),
		TenantID:  "tenant1",
	}
	err := storage.StoreACMEOrder(ctx, expiredOrder)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	deleted, err := storage.CleanupExpiredOrders(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", deleted)
	}

	stats := storage.GetStats()
	if stats.CleanupOperations != 1 {
		t.Errorf("expected CleanupOperations 1, got %d", stats.CleanupOperations)
	}
}

func TestQuicBaaSStorage_CleanupExpiredAuthorizations(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	now := time.Now().UTC()

	// Create expired authorization
	expiredAuthz := &ACMEAuthorization{
		AuthorizationID: "authz-expired",
		AccountID:       "acct-1",
		OrderID:         "order-1",
		Status:          "pending",
		ExpiresAt:       now.Add(-1 * time.Hour),
		TenantID:        "tenant1",
	}
	err := storage.StoreACMEAuthorization(ctx, expiredAuthz)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	deleted, err := storage.CleanupExpiredAuthorizations(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", deleted)
	}
}

func TestQuicBaaSStorage_CleanupExpiredCertificates(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	now := time.Now()

	// Create expired certificate (past grace period)
	expiredCert := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      "CN=expired",
		NotBefore:    now.Add(-96 * time.Hour),
		NotAfter:     now.Add(-72 * time.Hour),
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}
	err := storage.StoreCertificate(ctx, expiredCert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	deleted, err := storage.CleanupExpiredCertificates(ctx, "tenant1", 24*time.Hour)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", deleted)
	}
}

// ============================================================================
// Count Tests
// ============================================================================

func TestQuicBaaSStorage_GetCertificateCount(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		cert := &Certificate{
			SerialNumber: big.NewInt(int64(i)),
			Subject:      "CN=test",
			TenantID:     "tenant1",
			DER:          []byte("test-der"),
		}
		err := storage.StoreCertificate(ctx, cert)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	}

	count, err := storage.GetCertificateCount(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if count != 5 {
		t.Errorf("expected count 5, got %d", count)
	}
}

func TestQuicBaaSStorage_GetCRLCount(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		crl := &CRL{
			CRLID:    "crl-" + string(rune('0'+i)),
			DER:      []byte("test-der"),
			Issuer:   "CN=Test CA",
			TenantID: "tenant1",
		}
		err := storage.StoreCRL(ctx, crl)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	}

	count, err := storage.GetCRLCount(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if count != 3 {
		t.Errorf("expected count 3, got %d", count)
	}
}

func TestQuicBaaSStorage_GetACMEAccountCount(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	for i := 1; i <= 4; i++ {
		account := &ACMEAccount{
			AccountID: "acct-" + string(rune('0'+i)),
			Status:    "valid",
			TenantID:  "tenant1",
		}
		err := storage.StoreACMEAccount(ctx, account)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	}

	count, err := storage.GetACMEAccountCount(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if count != 4 {
		t.Errorf("expected count 4, got %d", count)
	}
}

func TestQuicBaaSStorage_GetACMEOrderCount(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	for i := 1; i <= 6; i++ {
		order := &ACMEOrder{
			OrderID:   "order-" + string(rune('0'+i)),
			AccountID: "acct-1",
			Status:    "pending",
			TenantID:  "tenant1",
		}
		err := storage.StoreACMEOrder(ctx, order)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	}

	count, err := storage.GetACMEOrderCount(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if count != 6 {
		t.Errorf("expected count 6, got %d", count)
	}
}

func TestQuicBaaSStorage_GetACMEAuthorizationCount(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	for i := 1; i <= 2; i++ {
		authz := &ACMEAuthorization{
			AuthorizationID: "authz-" + string(rune('0'+i)),
			AccountID:       "acct-1",
			OrderID:         "order-1",
			Status:          "pending",
			TenantID:        "tenant1",
		}
		err := storage.StoreACMEAuthorization(ctx, authz)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	}

	count, err := storage.GetACMEAuthorizationCount(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}
}

// ============================================================================
// Statistics Tests
// ============================================================================

func TestQuicBaaSStorage_GetStats(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	// Create some entities to generate stats
	cert := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      "CN=test",
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}
	storage.StoreCertificate(ctx, cert)

	crl := &CRL{
		CRLID:    "test-crl",
		DER:      []byte("test-der"),
		Issuer:   "CN=Test CA",
		TenantID: "tenant1",
	}
	storage.StoreCRL(ctx, crl)

	account := &ACMEAccount{
		AccountID: "acct-1",
		Status:    "valid",
		TenantID:  "tenant1",
	}
	storage.StoreACMEAccount(ctx, account)

	stats := storage.GetStats()

	if stats.CertificatesCreated != 1 {
		t.Errorf("expected CertificatesCreated 1, got %d", stats.CertificatesCreated)
	}

	if stats.CRLsCreated != 1 {
		t.Errorf("expected CRLsCreated 1, got %d", stats.CRLsCreated)
	}

	if stats.ACMEAccountsCreated != 1 {
		t.Errorf("expected ACMEAccountsCreated 1, got %d", stats.ACMEAccountsCreated)
	}
}

func TestQuicBaaSStorage_ErrorStatistics(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	// Try to get a non-existent certificate
	_, err := storage.GetCertificate(ctx, big.NewInt(99999), "tenant1")
	if err == nil {
		t.Fatal("expected error")
	}

	stats := storage.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("expected TotalErrors 1, got %d", stats.TotalErrors)
	}
}

// ============================================================================
// Interface Compliance Test
// ============================================================================

func TestQuicBaaSStorage_ImplementsStorage(t *testing.T) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	// This test verifies the interface is properly implemented
	var _ Storage = storage
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkQuicBaaSStorage_StoreCertificate(b *testing.B) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cert := &Certificate{
			SerialNumber: big.NewInt(int64(i)),
			Subject:      "CN=test",
			TenantID:     "tenant1",
			DER:          []byte("test-der"),
		}
		_ = storage.StoreCertificate(ctx, cert)
	}
}

func BenchmarkQuicBaaSStorage_GetCertificate(b *testing.B) {
	mockStorage := NewMockDAOStorage()
	logger := newTestLogger()
	config := newTestConfig()
	storage, _ := NewQuicBaaSStorage(mockStorage, config, logger)

	ctx := context.Background()
	serial := big.NewInt(12345)
	cert := &Certificate{
		SerialNumber: serial,
		Subject:      "CN=test",
		TenantID:     "tenant1",
		DER:          []byte("test-der"),
	}
	_ = storage.StoreCertificate(ctx, cert)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = storage.GetCertificate(ctx, serial, "tenant1")
	}
}
