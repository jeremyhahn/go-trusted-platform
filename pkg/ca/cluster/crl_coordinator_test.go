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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Mock Implementations for Testing
// ============================================================================

// MockLeaderChecker is a mock implementation of LeaderChecker.
type MockLeaderChecker struct {
	mu         sync.RWMutex
	isLeader   bool
	leaderID   string
	nodeID     string
	waitCalled atomic.Int64
}

// NewMockLeaderChecker creates a new MockLeaderChecker.
func NewMockLeaderChecker(nodeID string, isLeader bool) *MockLeaderChecker {
	leaderID := ""
	if isLeader {
		leaderID = nodeID
	} else {
		leaderID = "other-node"
	}
	return &MockLeaderChecker{
		isLeader: isLeader,
		leaderID: leaderID,
		nodeID:   nodeID,
	}
}

func (m *MockLeaderChecker) IsLeader() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isLeader
}

func (m *MockLeaderChecker) GetLeaderID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.leaderID
}

func (m *MockLeaderChecker) WaitForLeadership(ctx context.Context) error {
	m.waitCalled.Add(1)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if m.IsLeader() {
				return nil
			}
		}
	}
}

func (m *MockLeaderChecker) SetLeader(isLeader bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.isLeader = isLeader
	if isLeader {
		m.leaderID = m.nodeID
	} else {
		m.leaderID = "other-node"
	}
}

// MockCRLGenerator is a mock implementation of CRLGenerator.
type MockCRLGenerator struct {
	mu               sync.RWMutex
	issuerCert       *x509.Certificate
	issuerKey        crypto.Signer
	generateCalls    atomic.Int64
	generateErr      error
	lastRevokedCerts []*RevokedCertificate
}

// NewMockCRLGenerator creates a new MockCRLGenerator with test keys.
func NewMockCRLGenerator() (*MockCRLGenerator, error) {
	// Generate a test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create a self-signed CA certificate
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &MockCRLGenerator{
		issuerCert: cert,
		issuerKey:  privateKey,
	}, nil
}

func (m *MockCRLGenerator) GenerateCRL(
	ctx context.Context,
	revokedCerts []*RevokedCertificate,
	issuer *x509.Certificate,
	issuerKey crypto.Signer,
	thisUpdate time.Time,
	nextUpdate time.Time,
) ([]byte, error) {
	m.generateCalls.Add(1)

	m.mu.Lock()
	m.lastRevokedCerts = revokedCerts
	err := m.generateErr
	m.mu.Unlock()

	if err != nil {
		return nil, err
	}

	// Create a real CRL
	revokedList := make([]pkix.RevokedCertificate, len(revokedCerts))
	for i, rc := range revokedCerts {
		revokedList[i] = pkix.RevokedCertificate{
			SerialNumber:   rc.SerialNumber,
			RevocationTime: rc.RevocationTime,
		}
	}

	crlTemplate := &x509.RevocationList{
		RevokedCertificates: revokedList,
		Number:              big.NewInt(time.Now().UnixNano()),
		ThisUpdate:          thisUpdate,
		NextUpdate:          nextUpdate,
	}

	return x509.CreateRevocationList(rand.Reader, crlTemplate, issuer, issuerKey)
}

func (m *MockCRLGenerator) GetIssuerCertificate() *x509.Certificate {
	return m.issuerCert
}

func (m *MockCRLGenerator) GetIssuerKey() crypto.Signer {
	return m.issuerKey
}

func (m *MockCRLGenerator) SetGenerateError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generateErr = err
}

func (m *MockCRLGenerator) GetGenerateCalls() int64 {
	return m.generateCalls.Load()
}

func (m *MockCRLGenerator) GetLastRevokedCerts() []*RevokedCertificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastRevokedCerts
}

// ============================================================================
// Test Helper Functions
// ============================================================================

func createTestCRLCoordinator(t *testing.T, isLeader bool) (
	*crlCoordinator,
	*MockDAOStorage,
	*MockLeaderChecker,
	*MockCRLGenerator,
) {
	t.Helper()

	storage := NewMockDAOStorage()
	logger := newTestLogger()

	config := DefaultConfig("test-node-1")

	crlDAO := NewCRLDAO(storage, logger)
	certDAO := NewCertificateDAO(storage, logger)

	leaderChecker := NewMockLeaderChecker("test-node-1", isLeader)

	generator, err := NewMockCRLGenerator()
	if err != nil {
		t.Fatalf("failed to create mock generator: %v", err)
	}

	coordinator, err := NewCRLCoordinator(
		config,
		crlDAO,
		certDAO,
		leaderChecker,
		generator,
		logger,
		WithCRLUpdateInterval(100*time.Millisecond),
		WithCRLGracePeriod(10*time.Millisecond),
		WithCRLSchedulerInterval(50*time.Millisecond),
		WithCRLOperationTimeout(5*time.Second),
	)
	if err != nil {
		t.Fatalf("failed to create coordinator: %v", err)
	}

	return coordinator.(*crlCoordinator), storage, leaderChecker, generator
}

func createRevokedCertificate(serial int64) *Certificate {
	now := time.Now().UTC()
	revokedAt := now.Add(-1 * time.Hour)
	return &Certificate{
		SerialNumber:     big.NewInt(serial),
		Subject:          "CN=Test",
		Issuer:           "CN=Test CA",
		NotBefore:        now.Add(-24 * time.Hour),
		NotAfter:         now.Add(24 * time.Hour),
		IssuedAt:         now.Add(-24 * time.Hour),
		RevokedAt:        &revokedAt,
		RevocationReason: 1,
		TenantID:         "default",
		Version:          1,
	}
}

// ============================================================================
// Constructor Tests
// ============================================================================

func TestNewCRLCoordinator(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	config := DefaultConfig("test-node")

	crlDAO := NewCRLDAO(storage, logger)
	certDAO := NewCertificateDAO(storage, logger)
	leaderChecker := NewMockLeaderChecker("test-node", true)

	generator, err := NewMockCRLGenerator()
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	coordinator, err := NewCRLCoordinator(
		config,
		crlDAO,
		certDAO,
		leaderChecker,
		generator,
		logger,
	)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if coordinator == nil {
		t.Fatal("expected coordinator to be created")
	}
}

func TestNewCRLCoordinator_NilConfig(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()

	crlDAO := NewCRLDAO(storage, logger)
	certDAO := NewCertificateDAO(storage, logger)
	leaderChecker := NewMockLeaderChecker("test-node", true)

	generator, err := NewMockCRLGenerator()
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	_, err = NewCRLCoordinator(
		nil,
		crlDAO,
		certDAO,
		leaderChecker,
		generator,
		logger,
	)

	if err == nil {
		t.Fatal("expected error for nil config")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestNewCRLCoordinator_NilCRLDAO(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	config := DefaultConfig("test-node")

	certDAO := NewCertificateDAO(storage, logger)
	leaderChecker := NewMockLeaderChecker("test-node", true)

	generator, err := NewMockCRLGenerator()
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	_, err = NewCRLCoordinator(
		config,
		nil,
		certDAO,
		leaderChecker,
		generator,
		logger,
	)

	if err == nil {
		t.Fatal("expected error for nil crlDAO")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestNewCRLCoordinator_NilCertDAO(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	config := DefaultConfig("test-node")

	crlDAO := NewCRLDAO(storage, logger)
	leaderChecker := NewMockLeaderChecker("test-node", true)

	generator, err := NewMockCRLGenerator()
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	_, err = NewCRLCoordinator(
		config,
		crlDAO,
		nil,
		leaderChecker,
		generator,
		logger,
	)

	if err == nil {
		t.Fatal("expected error for nil certDAO")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestNewCRLCoordinator_NilLeaderChecker(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	config := DefaultConfig("test-node")

	crlDAO := NewCRLDAO(storage, logger)
	certDAO := NewCertificateDAO(storage, logger)

	generator, err := NewMockCRLGenerator()
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	_, err = NewCRLCoordinator(
		config,
		crlDAO,
		certDAO,
		nil,
		generator,
		logger,
	)

	if err == nil {
		t.Fatal("expected error for nil leaderChecker")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestNewCRLCoordinator_NilGenerator(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	config := DefaultConfig("test-node")

	crlDAO := NewCRLDAO(storage, logger)
	certDAO := NewCertificateDAO(storage, logger)
	leaderChecker := NewMockLeaderChecker("test-node", true)

	_, err := NewCRLCoordinator(
		config,
		crlDAO,
		certDAO,
		leaderChecker,
		nil,
		logger,
	)

	if err == nil {
		t.Fatal("expected error for nil generator")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestNewCRLCoordinator_NilLogger(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	config := DefaultConfig("test-node")

	crlDAO := NewCRLDAO(storage, logger)
	certDAO := NewCertificateDAO(storage, logger)
	leaderChecker := NewMockLeaderChecker("test-node", true)

	generator, err := NewMockCRLGenerator()
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	_, err = NewCRLCoordinator(
		config,
		crlDAO,
		certDAO,
		leaderChecker,
		generator,
		nil,
	)

	if err == nil {
		t.Fatal("expected error for nil logger")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestNewCRLCoordinator_WithOptions(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	config := DefaultConfig("test-node")

	crlDAO := NewCRLDAO(storage, logger)
	certDAO := NewCertificateDAO(storage, logger)
	leaderChecker := NewMockLeaderChecker("test-node", true)

	generator, err := NewMockCRLGenerator()
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	coordinator, err := NewCRLCoordinator(
		config,
		crlDAO,
		certDAO,
		leaderChecker,
		generator,
		logger,
		WithCRLUpdateInterval(48*time.Hour),
		WithCRLGracePeriod(2*time.Hour),
		WithCRLHistoryRetention(10),
		WithCRLSchedulerInterval(5*time.Minute),
		WithCRLOperationTimeout(10*time.Minute),
		WithCRLLeaderCheckRetries(5),
	)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	c := coordinator.(*crlCoordinator)

	if c.updateInterval != 48*time.Hour {
		t.Errorf("expected update interval 48h, got %v", c.updateInterval)
	}

	if c.gracePeriod != 2*time.Hour {
		t.Errorf("expected grace period 2h, got %v", c.gracePeriod)
	}

	if c.historyRetention != 10 {
		t.Errorf("expected history retention 10, got %d", c.historyRetention)
	}

	if c.schedulerInterval != 5*time.Minute {
		t.Errorf("expected scheduler interval 5m, got %v", c.schedulerInterval)
	}

	if c.operationTimeout != 10*time.Minute {
		t.Errorf("expected operation timeout 10m, got %v", c.operationTimeout)
	}

	if c.leaderCheckRetries != 5 {
		t.Errorf("expected leader check retries 5, got %d", c.leaderCheckRetries)
	}
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

func TestCRLCoordinator_Start(t *testing.T) {
	coordinator, _, _, _ := createTestCRLCoordinator(t, true)

	ctx := context.Background()
	err := coordinator.Start(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !coordinator.running.Load() {
		t.Error("expected coordinator to be running")
	}

	// Clean up
	coordinator.Stop()
}

func TestCRLCoordinator_Start_AlreadyRunning(t *testing.T) {
	coordinator, _, _, _ := createTestCRLCoordinator(t, true)

	ctx := context.Background()
	err := coordinator.Start(ctx)
	if err != nil {
		t.Fatalf("expected no error on first start, got %v", err)
	}

	// Try to start again
	err = coordinator.Start(ctx)

	if err == nil {
		t.Fatal("expected error when starting already running coordinator")
	}

	if _, ok := err.(ErrCRLCoordinatorAlreadyRunning); !ok {
		t.Errorf("expected ErrCRLCoordinatorAlreadyRunning, got %T", err)
	}

	// Clean up
	coordinator.Stop()
}

func TestCRLCoordinator_Stop(t *testing.T) {
	coordinator, _, _, _ := createTestCRLCoordinator(t, true)

	ctx := context.Background()
	err := coordinator.Start(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = coordinator.Stop()
	if err != nil {
		t.Fatalf("expected no error on stop, got %v", err)
	}

	if coordinator.running.Load() {
		t.Error("expected coordinator to not be running")
	}
}

func TestCRLCoordinator_Stop_NotRunning(t *testing.T) {
	coordinator, _, _, _ := createTestCRLCoordinator(t, true)

	err := coordinator.Stop()

	if err == nil {
		t.Fatal("expected error when stopping non-running coordinator")
	}

	if _, ok := err.(ErrCRLCoordinatorNotRunning); !ok {
		t.Errorf("expected ErrCRLCoordinatorNotRunning, got %T", err)
	}
}

func TestCRLCoordinator_Start_AfterStop(t *testing.T) {
	coordinator, _, _, _ := createTestCRLCoordinator(t, true)

	ctx := context.Background()
	err := coordinator.Start(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = coordinator.Stop()
	if err != nil {
		t.Fatalf("expected no error on stop, got %v", err)
	}

	// Try to start again - should fail because stopped flag is set
	err = coordinator.Start(ctx)

	if err == nil {
		t.Fatal("expected error when restarting stopped coordinator")
	}

	if _, ok := err.(ErrCRLCoordinatorStopped); !ok {
		t.Errorf("expected ErrCRLCoordinatorStopped, got %T", err)
	}
}

// ============================================================================
// Leadership Tests
// ============================================================================

func TestCRLCoordinator_IsResponsible_Leader(t *testing.T) {
	coordinator, _, _, _ := createTestCRLCoordinator(t, true)

	if !coordinator.IsResponsible() {
		t.Error("expected IsResponsible to return true for leader")
	}
}

func TestCRLCoordinator_IsResponsible_NotLeader(t *testing.T) {
	coordinator, _, _, _ := createTestCRLCoordinator(t, false)

	if coordinator.IsResponsible() {
		t.Error("expected IsResponsible to return false for non-leader")
	}
}

func TestCRLCoordinator_RegenerateCRL_NotRunning(t *testing.T) {
	coordinator, _, _, _ := createTestCRLCoordinator(t, true)

	err := coordinator.RegenerateCRL()

	if err == nil {
		t.Fatal("expected error when coordinator not running")
	}

	if _, ok := err.(ErrCRLCoordinatorNotRunning); !ok {
		t.Errorf("expected ErrCRLCoordinatorNotRunning, got %T", err)
	}
}

func TestCRLCoordinator_RegenerateCRL_NotLeader(t *testing.T) {
	coordinator, _, _, _ := createTestCRLCoordinator(t, false)

	ctx := context.Background()
	err := coordinator.Start(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer coordinator.Stop()

	err = coordinator.RegenerateCRL()

	if err == nil {
		t.Fatal("expected error when not leader")
	}

	if _, ok := err.(ErrNotLeader); !ok {
		t.Errorf("expected ErrNotLeader, got %T", err)
	}
}

func TestCRLCoordinator_RegenerateCRL_AsLeader(t *testing.T) {
	coordinator, _, _, generator := createTestCRLCoordinator(t, true)

	ctx := context.Background()
	err := coordinator.Start(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer coordinator.Stop()

	err = coordinator.RegenerateCRL()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Wait for CRL generation
	time.Sleep(200 * time.Millisecond)

	if generator.GetGenerateCalls() == 0 {
		t.Error("expected generator to be called")
	}
}

// ============================================================================
// CRL Generation Tests
// ============================================================================

func TestCRLCoordinator_AutomaticCRLGeneration(t *testing.T) {
	coordinator, _, _, generator := createTestCRLCoordinator(t, true)

	ctx := context.Background()
	err := coordinator.Start(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer coordinator.Stop()

	// Wait for automatic CRL generation (scheduler runs at 50ms intervals)
	time.Sleep(300 * time.Millisecond)

	if generator.GetGenerateCalls() == 0 {
		t.Error("expected automatic CRL generation")
	}
}

func TestCRLCoordinator_NoGenerationWhenNotLeader(t *testing.T) {
	coordinator, _, _, generator := createTestCRLCoordinator(t, false)

	ctx := context.Background()
	err := coordinator.Start(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer coordinator.Stop()

	// Wait for scheduler to run
	time.Sleep(200 * time.Millisecond)

	if generator.GetGenerateCalls() != 0 {
		t.Error("expected no CRL generation when not leader")
	}
}

func TestCRLCoordinator_GeneratesWithRevokedCerts(t *testing.T) {
	coordinator, storage, _, generator := createTestCRLCoordinator(t, true)

	ctx := context.Background()

	// Add some revoked certificate entries
	certDAO := NewCertificateDAO(storage, newTestLogger())

	for i := 1; i <= 3; i++ {
		cert := createRevokedCertificate(int64(i * 1000))
		err := certDAO.Create(ctx, cert)
		if err != nil {
			t.Fatalf("failed to create cert: %v", err)
		}
	}

	err := coordinator.Start(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer coordinator.Stop()

	// Wait for CRL generation
	time.Sleep(300 * time.Millisecond)

	revokedCerts := generator.GetLastRevokedCerts()
	if len(revokedCerts) != 3 {
		t.Errorf("expected 3 revoked certs in CRL, got %d", len(revokedCerts))
	}
}

func TestCRLCoordinator_LeadershipChange(t *testing.T) {
	coordinator, _, leaderChecker, generator := createTestCRLCoordinator(t, false)

	ctx := context.Background()
	err := coordinator.Start(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer coordinator.Stop()

	// Initially not leader - no generation
	time.Sleep(150 * time.Millisecond)
	initialCalls := generator.GetGenerateCalls()

	if initialCalls != 0 {
		t.Errorf("expected no generation when not leader, got %d calls", initialCalls)
	}

	// Become leader
	leaderChecker.SetLeader(true)

	// Wait for CRL generation after becoming leader
	time.Sleep(200 * time.Millisecond)

	if generator.GetGenerateCalls() == 0 {
		t.Error("expected CRL generation after becoming leader")
	}
}

// ============================================================================
// CRL Storage Tests
// ============================================================================

func TestCRLCoordinator_GetCurrentCRL(t *testing.T) {
	coordinator, storage, _, _ := createTestCRLCoordinator(t, true)

	ctx := context.Background()

	// Create a CRL in storage
	crlDAO := NewCRLDAO(storage, newTestLogger())
	now := time.Now().UTC()
	crl := NewCRL(
		CurrentCRLID,
		[]byte("test-crl-der"),
		"CN=Test CA",
		now,
		now.Add(24*time.Hour),
		"default",
	)
	err := crlDAO.Create(ctx, crl)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	// Get current CRL
	retrievedCRL, err := coordinator.GetCurrentCRL()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if retrievedCRL.CRLID != CurrentCRLID {
		t.Errorf("expected CRL ID %s, got %s", CurrentCRLID, retrievedCRL.CRLID)
	}
}

func TestCRLCoordinator_GetCurrentCRL_NotFound(t *testing.T) {
	coordinator, _, _, _ := createTestCRLCoordinator(t, true)

	_, err := coordinator.GetCurrentCRL()

	if err == nil {
		t.Fatal("expected error when no CRL exists")
	}

	if _, ok := err.(ErrCRLNotFound); !ok {
		t.Errorf("expected ErrCRLNotFound, got %T", err)
	}
}

// ============================================================================
// Status Tests
// ============================================================================

func TestCRLCoordinator_GetCRLStatus(t *testing.T) {
	coordinator, _, _, _ := createTestCRLCoordinator(t, true)

	ctx := context.Background()
	err := coordinator.Start(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer coordinator.Stop()

	// Wait for CRL generation
	time.Sleep(200 * time.Millisecond)

	status := coordinator.GetCRLStatus()

	if !status.IsLeader {
		t.Error("expected IsLeader to be true")
	}

	if status.UpdatesGenerated == 0 {
		t.Error("expected at least one update generated")
	}

	if status.LastUpdateTime.IsZero() {
		t.Error("expected LastUpdateTime to be set")
	}

	if status.NextUpdateTime.IsZero() {
		t.Error("expected NextUpdateTime to be set")
	}
}

func TestCRLCoordinator_GetCRLStatus_NotLeader(t *testing.T) {
	coordinator, _, _, _ := createTestCRLCoordinator(t, false)

	status := coordinator.GetCRLStatus()

	if status.IsLeader {
		t.Error("expected IsLeader to be false")
	}
}

// ============================================================================
// History Tests
// ============================================================================

func TestCRLCoordinator_GetHistory(t *testing.T) {
	coordinator, _, _, _ := createTestCRLCoordinator(t, true)

	ctx := context.Background()
	err := coordinator.Start(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer coordinator.Stop()

	// Trigger multiple regenerations
	for i := 0; i < 3; i++ {
		coordinator.RegenerateCRL()
		time.Sleep(100 * time.Millisecond)
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	history := coordinator.GetHistory()

	if len(history) == 0 {
		t.Error("expected history entries")
	}

	for _, entry := range history {
		if entry.GeneratedBy != "test-node-1" {
			t.Errorf("expected GeneratedBy 'test-node-1', got '%s'", entry.GeneratedBy)
		}
	}
}

func TestCRLCoordinator_HistoryRetention(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	config := DefaultConfig("test-node")

	crlDAO := NewCRLDAO(storage, logger)
	certDAO := NewCertificateDAO(storage, logger)
	leaderChecker := NewMockLeaderChecker("test-node", true)

	generator, err := NewMockCRLGenerator()
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	coordinator, err := NewCRLCoordinator(
		config,
		crlDAO,
		certDAO,
		leaderChecker,
		generator,
		logger,
		WithCRLHistoryRetention(3),
		WithCRLSchedulerInterval(20*time.Millisecond),
		WithCRLUpdateInterval(10*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	err = coordinator.Start(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer coordinator.Stop()

	// Wait for multiple generations
	time.Sleep(300 * time.Millisecond)

	c := coordinator.(*crlCoordinator)
	history := c.GetHistory()

	if len(history) > 3 {
		t.Errorf("expected at most 3 history entries, got %d", len(history))
	}
}

// ============================================================================
// Error Handling Tests
// ============================================================================

func TestCRLCoordinator_GenerationError(t *testing.T) {
	coordinator, _, _, generator := createTestCRLCoordinator(t, true)

	generator.SetGenerateError(ErrCRLGenerationFailed{Reason: "test error"})

	ctx := context.Background()
	err := coordinator.Start(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer coordinator.Stop()

	// Wait for generation attempt
	time.Sleep(200 * time.Millisecond)

	status := coordinator.GetCRLStatus()

	if status.LastError == "" {
		t.Error("expected LastError to be set after generation failure")
	}

	history := coordinator.GetHistory()
	var foundFailure bool
	for _, h := range history {
		if !h.Success {
			foundFailure = true
			break
		}
	}

	if !foundFailure {
		t.Error("expected to find failure in history")
	}
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestCRLCoordinator_ConcurrentAccess(t *testing.T) {
	coordinator, _, _, _ := createTestCRLCoordinator(t, true)

	ctx := context.Background()
	err := coordinator.Start(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer coordinator.Stop()

	var wg sync.WaitGroup
	numGoroutines := 10

	// Concurrent status reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = coordinator.GetCRLStatus()
				_ = coordinator.IsResponsible()
			}
		}()
	}

	// Concurrent regeneration triggers
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				coordinator.RegenerateCRL()
				time.Sleep(10 * time.Millisecond)
			}
		}()
	}

	wg.Wait()
}

// ============================================================================
// DefaultCRLGenerator Tests
// ============================================================================

func TestDefaultCRLGenerator_New(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	generator, err := NewDefaultCRLGenerator(cert, privateKey)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if generator.GetIssuerCertificate() != cert {
		t.Error("issuer certificate mismatch")
	}

	if generator.GetIssuerKey() != privateKey {
		t.Error("issuer key mismatch")
	}
}

func TestDefaultCRLGenerator_NilCert(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	_, err = NewDefaultCRLGenerator(nil, privateKey)

	if err == nil {
		t.Fatal("expected error for nil cert")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestDefaultCRLGenerator_NilKey(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	_, err := NewDefaultCRLGenerator(cert, nil)

	if err == nil {
		t.Fatal("expected error for nil key")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestDefaultCRLGenerator_GenerateCRL(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	generator, err := NewDefaultCRLGenerator(cert, privateKey)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	ctx := context.Background()
	now := time.Now().UTC()
	revokedCerts := []*RevokedCertificate{
		{
			SerialNumber:     big.NewInt(100),
			RevocationTime:   now.Add(-1 * time.Hour),
			RevocationReason: 1,
		},
		{
			SerialNumber:     big.NewInt(200),
			RevocationTime:   now.Add(-2 * time.Hour),
			RevocationReason: 2,
		},
	}

	crlDER, err := generator.GenerateCRL(
		ctx,
		revokedCerts,
		cert,
		privateKey,
		now,
		now.Add(24*time.Hour),
	)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(crlDER) == 0 {
		t.Error("expected non-empty CRL DER")
	}

	// Parse and verify the CRL
	parsedCRL, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("failed to parse generated CRL: %v", err)
	}

	if len(parsedCRL.RevokedCertificateEntries) != 2 {
		t.Errorf("expected 2 revoked certificate entries, got %d", len(parsedCRL.RevokedCertificateEntries))
	}
}

// ============================================================================
// SimpleLeaderChecker Tests
// ============================================================================

func TestSimpleLeaderChecker(t *testing.T) {
	isLeader := true
	leaderID := "node-1"

	checker := NewSimpleLeaderChecker(
		"node-1",
		func() bool { return isLeader },
		func() string { return leaderID },
	)

	if !checker.IsLeader() {
		t.Error("expected IsLeader to return true")
	}

	if checker.GetLeaderID() != "node-1" {
		t.Errorf("expected leader ID 'node-1', got '%s'", checker.GetLeaderID())
	}

	// Change leadership
	isLeader = false
	leaderID = "node-2"

	if checker.IsLeader() {
		t.Error("expected IsLeader to return false")
	}

	if checker.GetLeaderID() != "node-2" {
		t.Errorf("expected leader ID 'node-2', got '%s'", checker.GetLeaderID())
	}
}

func TestSimpleLeaderChecker_NilFunctions(t *testing.T) {
	checker := NewSimpleLeaderChecker("node-1", nil, nil)

	if checker.IsLeader() {
		t.Error("expected IsLeader to return false with nil function")
	}

	if checker.GetLeaderID() != "" {
		t.Error("expected empty leader ID with nil function")
	}
}

func TestSimpleLeaderChecker_WaitForLeadership(t *testing.T) {
	var isLeader atomic.Bool
	isLeader.Store(false)

	checker := NewSimpleLeaderChecker(
		"node-1",
		func() bool { return isLeader.Load() },
		func() string { return "node-1" },
	)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Start goroutine to become leader
	go func() {
		time.Sleep(100 * time.Millisecond)
		isLeader.Store(true)
	}()

	err := checker.WaitForLeadership(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestSimpleLeaderChecker_WaitForLeadership_Timeout(t *testing.T) {
	checker := NewSimpleLeaderChecker(
		"node-1",
		func() bool { return false },
		func() string { return "other-node" },
	)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := checker.WaitForLeadership(ctx)
	if err == nil {
		t.Fatal("expected timeout error")
	}

	if err != context.DeadlineExceeded {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
}

// ============================================================================
// Error Type Tests
// ============================================================================

func TestErrCRLCoordinatorAlreadyRunning(t *testing.T) {
	err := ErrCRLCoordinatorAlreadyRunning{}
	expected := "cluster: CRL coordinator is already running"

	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrCRLCoordinatorNotRunning(t *testing.T) {
	err := ErrCRLCoordinatorNotRunning{}
	expected := "cluster: CRL coordinator is not running"

	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrCRLCoordinatorStopped(t *testing.T) {
	err := ErrCRLCoordinatorStopped{}
	expected := "cluster: CRL coordinator has been stopped and cannot be restarted"

	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrNotLeader(t *testing.T) {
	err := ErrNotLeader{NodeID: "node-1", LeaderID: "node-2"}
	expected := "cluster: node node-1 is not the leader; current leader is node-2"

	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	// Test without leader ID
	err2 := ErrNotLeader{NodeID: "node-1"}
	expected2 := "cluster: node node-1 is not the leader"

	if err2.Error() != expected2 {
		t.Errorf("expected '%s', got '%s'", expected2, err2.Error())
	}
}

func TestErrCRLGenerationFailed(t *testing.T) {
	cause := ErrOperationFailed{Operation: "test"}
	err := ErrCRLGenerationFailed{Reason: "test error", Cause: cause}
	expected := "cluster: CRL generation failed: test error: cluster: operation failed: test"

	if err.Error() != expected {
		t.Errorf("expected '%s', got '%s'", expected, err.Error())
	}

	if err.Unwrap() != cause {
		t.Error("Unwrap should return cause")
	}

	// Test without cause
	err2 := ErrCRLGenerationFailed{Reason: "no cause"}
	expected2 := "cluster: CRL generation failed: no cause"

	if err2.Error() != expected2 {
		t.Errorf("expected '%s', got '%s'", expected2, err2.Error())
	}
}

func TestErrCRLExpired(t *testing.T) {
	expiredAt := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	err := ErrCRLExpired{
		CRLID:     "test-crl",
		ExpiredAt: expiredAt,
	}

	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}

	if err.CRLID != "test-crl" {
		t.Errorf("expected CRLID 'test-crl', got '%s'", err.CRLID)
	}
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkCRLCoordinator_GetCRLStatus(b *testing.B) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	config := DefaultConfig("test-node")

	crlDAO := NewCRLDAO(storage, logger)
	certDAO := NewCertificateDAO(storage, logger)
	leaderChecker := NewMockLeaderChecker("test-node", true)

	generator, _ := NewMockCRLGenerator()

	coordinator, _ := NewCRLCoordinator(
		config,
		crlDAO,
		certDAO,
		leaderChecker,
		generator,
		logger,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = coordinator.GetCRLStatus()
	}
}

func BenchmarkCRLCoordinator_IsResponsible(b *testing.B) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	config := DefaultConfig("test-node")

	crlDAO := NewCRLDAO(storage, logger)
	certDAO := NewCertificateDAO(storage, logger)
	leaderChecker := NewMockLeaderChecker("test-node", true)

	generator, _ := NewMockCRLGenerator()

	coordinator, _ := NewCRLCoordinator(
		config,
		crlDAO,
		certDAO,
		leaderChecker,
		generator,
		logger,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = coordinator.IsResponsible()
	}
}

func BenchmarkDefaultCRLGenerator_GenerateCRL(b *testing.B) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	generator, _ := NewDefaultCRLGenerator(cert, privateKey)

	ctx := context.Background()
	now := time.Now().UTC()
	revokedCerts := make([]*RevokedCertificate, 100)
	for i := 0; i < 100; i++ {
		revokedCerts[i] = &RevokedCertificate{
			SerialNumber:     big.NewInt(int64(i + 1)),
			RevocationTime:   now.Add(-time.Duration(i) * time.Hour),
			RevocationReason: 1,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = generator.GenerateCRL(ctx, revokedCerts, cert, privateKey, now, now.Add(24*time.Hour))
	}
}
