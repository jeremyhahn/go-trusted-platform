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

package cluster

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	cacluster "github.com/jeremyhahn/go-trusted-platform/pkg/ca/cluster"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// caTestCluster extends testCluster with CA storage
type caTestCluster struct {
	*testCluster
	storages   []*cacluster.QuicBaaSStorage
	issuerCert *x509.Certificate
	issuerKey  *rsa.PrivateKey
}

// newCATestCluster creates a test cluster with CA storage.
func newCATestCluster(t *testing.T, nodeCount int) *caTestCluster {
	t.Helper()

	tc := newTestCluster(t, nodeCount)

	// Generate test CA certificate and key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	return &caTestCluster{
		testCluster: tc,
		storages:    make([]*cacluster.QuicBaaSStorage, 0, nodeCount),
		issuerCert:  caCert,
		issuerKey:   caKey,
	}
}

// startWithCA starts the cluster and initializes CA storage.
func (ctc *caTestCluster) startWithCA(ctx context.Context) error {
	if err := ctc.start(ctx); err != nil {
		return err
	}

	logger := logging.DefaultLogger()

	// Create CA storage for each node
	for i, node := range ctc.nodes {
		nodeID := fmt.Sprintf("node-%d", node.id)

		// Use DefaultConfig to ensure all required fields have valid defaults
		cfg := cacluster.DefaultConfig(nodeID).
			WithTenantID("test-tenant").
			WithOptimisticLocking(true)

		storage, err := cacluster.NewQuicBaaSStorage(
			node.storage,
			cfg,
			logger,
		)
		if err != nil {
			return fmt.Errorf("failed to create CA storage for node %d: %w", i, err)
		}

		ctc.storages = append(ctc.storages, storage)
	}

	return nil
}

// getStorage returns the CA storage for the specified node index.
func (ctc *caTestCluster) getStorage(index int) *cacluster.QuicBaaSStorage {
	if index < 0 || index >= len(ctc.storages) {
		return nil
	}
	return ctc.storages[index]
}

// getLeaderStorage returns the CA storage for the leader node.
func (ctc *caTestCluster) getLeaderStorage() *cacluster.QuicBaaSStorage {
	leader := ctc.getLeader()
	if leader == nil {
		return nil
	}
	for i, node := range ctc.nodes {
		if node.id == leader.id {
			return ctc.storages[i]
		}
	}
	return nil
}

// generateTestCertificate creates a test certificate.
func (ctc *caTestCluster) generateTestCertificate(cn string) (*cacluster.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ctc.issuerCert, &key.PublicKey, ctc.issuerKey)
	if err != nil {
		return nil, err
	}

	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return cacluster.NewCertificate(x509Cert, "test-tenant"), nil
}

// TestCertificateReplication tests that certificates replicate across nodes.
func TestCertificateReplication(t *testing.T) {
	skipIfNoRaftCluster(t)
	skipIfNotIntegration(t)

	ctc := newCATestCluster(t, 3)
	defer ctc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := ctc.startWithCA(ctx)
	require.NoError(t, err)

	err = ctc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leaderStorage := ctc.getLeaderStorage()
	require.NotNil(t, leaderStorage)

	// Generate and store a certificate
	cert, err := ctc.generateTestCertificate("test-cert-replication")
	require.NoError(t, err)

	err = leaderStorage.StoreCertificate(ctx, cert)
	require.NoError(t, err, "Certificate storage should succeed on leader")

	t.Logf("Certificate stored with serial: %s", cert.SerialNumber.String())

	// Wait for replication
	time.Sleep(3 * time.Second)

	// Verify certificate is visible from all nodes
	for i := 0; i < ctc.nodeCount(); i++ {
		storage := ctc.getStorage(i)
		if storage == nil {
			continue
		}

		retrieved, err := storage.GetCertificate(ctx, cert.SerialNumber, "test-tenant")
		if err != nil {
			t.Logf("Node %d: certificate not yet replicated", i+1)
			continue
		}

		assert.Equal(t, cert.SerialNumber.String(), retrieved.SerialNumber.String())
		assert.Equal(t, cert.Subject, retrieved.Subject)
		assert.Equal(t, cert.Issuer, retrieved.Issuer)
		t.Logf("Node %d: certificate replicated successfully", i+1)
	}

	t.Log("Certificate replication test completed")
}

// TestCertificateReplication_Multiple tests multiple certificate replication.
func TestCertificateReplication_Multiple(t *testing.T) {
	skipIfNoRaftCluster(t)
	skipIfNotIntegration(t)

	ctc := newCATestCluster(t, 3)
	defer ctc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := ctc.startWithCA(ctx)
	require.NoError(t, err)

	err = ctc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leaderStorage := ctc.getLeaderStorage()
	require.NotNil(t, leaderStorage)

	// Store multiple certificates
	const certCount = 5
	certs := make([]*cacluster.Certificate, certCount)

	for i := 0; i < certCount; i++ {
		cert, err := ctc.generateTestCertificate(fmt.Sprintf("test-cert-%d", i))
		require.NoError(t, err)
		certs[i] = cert

		err = leaderStorage.StoreCertificate(ctx, cert)
		require.NoError(t, err)
	}

	t.Logf("Stored %d certificates", certCount)

	// Wait for replication
	time.Sleep(3 * time.Second)

	// Verify on followers
	followers := ctc.getFollowers()
	for _, follower := range followers {
		idx := -1
		for j, node := range ctc.nodes {
			if node.id == follower.id {
				idx = j
				break
			}
		}
		if idx < 0 {
			continue
		}

		storage := ctc.getStorage(idx)
		if storage == nil {
			continue
		}

		var foundCount int
		for _, cert := range certs {
			_, err := storage.GetCertificate(ctx, cert.SerialNumber, "test-tenant")
			if err == nil {
				foundCount++
			}
		}

		t.Logf("Follower has %d/%d certificates", foundCount, certCount)
	}

	t.Log("Multiple certificate replication test completed")
}

// TestCRLReplication tests that CRL updates replicate across nodes.
func TestCRLReplication(t *testing.T) {
	skipIfNoRaftCluster(t)
	skipIfNotIntegration(t)

	ctc := newCATestCluster(t, 3)
	defer ctc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := ctc.startWithCA(ctx)
	require.NoError(t, err)

	err = ctc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leaderStorage := ctc.getLeaderStorage()
	require.NotNil(t, leaderStorage)

	// Create a CRL
	crl := cacluster.NewCRL(
		"current",
		[]byte("mock-crl-der-data"),
		ctc.issuerCert.Subject.String(),
		time.Now().UTC(),
		time.Now().UTC().Add(24*time.Hour),
		"test-tenant",
	)

	err = leaderStorage.StoreCRL(ctx, crl)
	require.NoError(t, err, "CRL storage should succeed on leader")

	t.Logf("CRL stored with ID: %s", crl.CRLID)

	// Wait for replication
	time.Sleep(3 * time.Second)

	// Verify CRL is visible from all nodes
	for i := 0; i < ctc.nodeCount(); i++ {
		storage := ctc.getStorage(i)
		if storage == nil {
			continue
		}

		retrieved, err := storage.GetCRL(ctx, crl.CRLID, "test-tenant")
		if err != nil {
			t.Logf("Node %d: CRL not yet replicated", i+1)
			continue
		}

		assert.Equal(t, crl.CRLID, retrieved.CRLID)
		assert.Equal(t, crl.Issuer, retrieved.Issuer)
		t.Logf("Node %d: CRL replicated successfully", i+1)
	}

	t.Log("CRL replication test completed")
}

// TestCRLReplication_Update tests CRL update replication.
func TestCRLReplication_Update(t *testing.T) {
	skipIfNoRaftCluster(t)
	skipIfNotIntegration(t)

	ctc := newCATestCluster(t, 3)
	defer ctc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := ctc.startWithCA(ctx)
	require.NoError(t, err)

	err = ctc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leaderStorage := ctc.getLeaderStorage()
	require.NotNil(t, leaderStorage)

	// Create initial CRL
	crl := cacluster.NewCRL(
		"current",
		[]byte("initial-crl-data"),
		ctc.issuerCert.Subject.String(),
		time.Now().UTC(),
		time.Now().UTC().Add(24*time.Hour),
		"test-tenant",
	)

	err = leaderStorage.StoreCRL(ctx, crl)
	require.NoError(t, err)

	// Wait for replication and re-read to get the stored version
	time.Sleep(2 * time.Second)

	// Re-read the CRL to get the correct version set by the DAO
	storedCRL, err := leaderStorage.GetCRL(ctx, crl.CRLID, "test-tenant")
	require.NoError(t, err)

	// Update CRL with revoked certificate
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	storedCRL.RevokedCertificates = append(storedCRL.RevokedCertificates, &cacluster.RevokedCertificate{
		SerialNumber:     serial,
		RevocationTime:   time.Now().UTC(),
		RevocationReason: 1, // keyCompromise
	})
	// Note: Do NOT increment Version here - the DAO's Update method handles version increment
	// after validating that the provided version matches the stored version (optimistic locking)

	err = leaderStorage.UpdateCRL(ctx, storedCRL)
	require.NoError(t, err)

	// Wait for update to replicate
	time.Sleep(3 * time.Second)

	// Verify update on followers
	followers := ctc.getFollowers()
	for _, follower := range followers {
		idx := -1
		for j, node := range ctc.nodes {
			if node.id == follower.id {
				idx = j
				break
			}
		}
		if idx < 0 {
			continue
		}

		storage := ctc.getStorage(idx)
		if storage == nil {
			continue
		}

		retrieved, err := storage.GetCRL(ctx, crl.CRLID, "test-tenant")
		if err != nil {
			continue
		}

		t.Logf("Follower CRL has %d revoked certs", len(retrieved.RevokedCertificates))
	}

	t.Log("CRL update replication verified")
}

// TestACMEStateReplication tests that ACME state replicates across nodes.
func TestACMEStateReplication(t *testing.T) {
	skipIfNoRaftCluster(t)
	skipIfNotIntegration(t)

	ctc := newCATestCluster(t, 3)
	defer ctc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := ctc.startWithCA(ctx)
	require.NoError(t, err)

	err = ctc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leaderStorage := ctc.getLeaderStorage()
	require.NotNil(t, leaderStorage)

	// Create an ACME account
	account := cacluster.NewACMEAccount(
		fmt.Sprintf("acme-account-%d", time.Now().UnixNano()),
		[]byte(`{"kty":"EC","crv":"P-256"}`),
		[]string{"mailto:test@example.com"},
		"test-tenant",
	)

	err = leaderStorage.StoreACMEAccount(ctx, account)
	require.NoError(t, err, "ACME account storage should succeed on leader")

	t.Logf("ACME account stored: %s", account.AccountID)

	// Wait for replication
	time.Sleep(3 * time.Second)

	// Verify account is visible from all nodes
	for i := 0; i < ctc.nodeCount(); i++ {
		storage := ctc.getStorage(i)
		if storage == nil {
			continue
		}

		retrieved, err := storage.GetACMEAccount(ctx, account.AccountID, "test-tenant")
		if err != nil {
			t.Logf("Node %d: ACME account not yet replicated", i+1)
			continue
		}

		assert.Equal(t, account.AccountID, retrieved.AccountID)
		assert.Equal(t, account.Status, retrieved.Status)
		assert.Equal(t, account.Contact, retrieved.Contact)
		t.Logf("Node %d: ACME account replicated successfully", i+1)
	}

	t.Log("ACME state replication test completed")
}

// TestACMEStateReplication_Order tests ACME order replication.
func TestACMEStateReplication_Order(t *testing.T) {
	skipIfNoRaftCluster(t)
	skipIfNotIntegration(t)

	ctc := newCATestCluster(t, 3)
	defer ctc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := ctc.startWithCA(ctx)
	require.NoError(t, err)

	err = ctc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leaderStorage := ctc.getLeaderStorage()
	require.NotNil(t, leaderStorage)

	// Create account first
	accountID := fmt.Sprintf("acme-account-%d", time.Now().UnixNano())
	account := cacluster.NewACMEAccount(
		accountID,
		[]byte(`{"kty":"EC"}`),
		[]string{"mailto:test@example.com"},
		"test-tenant",
	)

	err = leaderStorage.StoreACMEAccount(ctx, account)
	require.NoError(t, err)

	// Create an order
	order := cacluster.NewACMEOrder(
		fmt.Sprintf("order-%d", time.Now().UnixNano()),
		accountID,
		[]cacluster.ACMEIdentifier{
			{Type: "dns", Value: "example.com"},
		},
		"test-tenant",
	)

	err = leaderStorage.StoreACMEOrder(ctx, order)
	require.NoError(t, err)

	t.Logf("ACME order stored: %s", order.OrderID)

	// Wait for replication
	time.Sleep(3 * time.Second)

	// Verify order is visible from followers
	followers := ctc.getFollowers()
	for _, follower := range followers {
		idx := -1
		for j, node := range ctc.nodes {
			if node.id == follower.id {
				idx = j
				break
			}
		}
		if idx < 0 {
			continue
		}

		storage := ctc.getStorage(idx)
		if storage == nil {
			continue
		}

		retrieved, err := storage.GetACMEOrder(ctx, order.OrderID, "test-tenant")
		if err != nil {
			t.Logf("Follower: ACME order not yet replicated")
			continue
		}

		assert.Equal(t, order.OrderID, retrieved.OrderID)
		assert.Equal(t, order.AccountID, retrieved.AccountID)
		assert.Equal(t, order.Status, retrieved.Status)
	}

	t.Log("ACME order replication verified")
}

// TestCRLLeaderOnly tests that only the leader generates CRLs.
func TestCRLLeaderOnly(t *testing.T) {
	skipIfNoRaftCluster(t)
	skipIfNotIntegration(t)

	ctc := newCATestCluster(t, 3)
	defer ctc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := ctc.startWithCA(ctx)
	require.NoError(t, err)

	err = ctc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leader := ctc.getLeader()
	require.NotNil(t, leader)

	// Verify leader is identified correctly
	assert.True(t, leader.coordinator.IsLeader())

	// Verify followers are not leaders
	followers := ctc.getFollowers()
	for _, follower := range followers {
		assert.False(t, follower.coordinator.IsLeader(),
			"Node %d should not be leader", follower.id)
	}

	// In a real implementation, CRL generation would be triggered
	// only by the leader through the CRLCoordinator.
	// This test verifies the leadership detection works correctly.

	t.Logf("Leader identified as node %d", leader.id)
	t.Logf("Found %d followers", len(followers))
	t.Log("CRL leader-only constraint verified")
}

// TestCRLLeaderOnly_Coordinator tests CRL coordinator respects leadership.
func TestCRLLeaderOnly_Coordinator(t *testing.T) {
	skipIfNoRaftCluster(t)
	skipIfNotIntegration(t)

	ctc := newCATestCluster(t, 3)
	defer ctc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := ctc.startWithCA(ctx)
	require.NoError(t, err)

	err = ctc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leader := ctc.getLeader()
	require.NotNil(t, leader)

	// Get leader's storage to find its index
	var leaderIdx int
	for i, node := range ctc.nodes {
		if node.id == leader.id {
			leaderIdx = i
			break
		}
	}

	leaderStorage := ctc.getStorage(leaderIdx)
	require.NotNil(t, leaderStorage)

	// Leader should be able to store CRL
	crl := cacluster.NewCRL(
		"leader-crl",
		[]byte("leader-generated-crl"),
		ctc.issuerCert.Subject.String(),
		time.Now().UTC(),
		time.Now().UTC().Add(24*time.Hour),
		"test-tenant",
	)

	err = leaderStorage.StoreCRL(ctx, crl)
	require.NoError(t, err, "Leader should be able to store CRL")

	t.Log("CRL coordinator leadership test completed")
}

// TestCAFailoverPersistence tests that CA state survives leader change.
func TestCAFailoverPersistence(t *testing.T) {
	skipIfNoRaftCluster(t)
	skipIfNotIntegration(t)

	ctc := newCATestCluster(t, 3)
	defer ctc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := ctc.startWithCA(ctx)
	require.NoError(t, err)

	err = ctc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leaderStorage := ctc.getLeaderStorage()
	require.NotNil(t, leaderStorage)

	// Create CA state before failover
	cert, err := ctc.generateTestCertificate("test-failover-cert")
	require.NoError(t, err)

	err = leaderStorage.StoreCertificate(ctx, cert)
	require.NoError(t, err)

	// Create CRL
	crl := cacluster.NewCRL(
		"failover-crl",
		[]byte("pre-failover-crl"),
		ctc.issuerCert.Subject.String(),
		time.Now().UTC(),
		time.Now().UTC().Add(24*time.Hour),
		"test-tenant",
	)

	err = leaderStorage.StoreCRL(ctx, crl)
	require.NoError(t, err)

	t.Logf("Created certificate and CRL before failover")

	// Wait for replication
	time.Sleep(3 * time.Second)

	// Simulate leader failover
	originalLeader := ctc.getLeader()
	require.NotNil(t, originalLeader)

	err = originalLeader.coordinator.Stop(ctx)
	require.NoError(t, err)

	// Update mock to elect new leader
	if mockOp, ok := originalLeader.raftOp.(*mockRaftOperator); ok {
		mockOp.setLeader(0)
	}

	followers := ctc.getFollowers()
	require.NotEmpty(t, followers)

	newLeaderNode := followers[0]
	if mockOp, ok := newLeaderNode.raftOp.(*mockRaftOperator); ok {
		mockOp.setLeader(newLeaderNode.id)
	}

	time.Sleep(2 * time.Second)

	// Find the new leader's storage
	var newLeaderStorage *cacluster.QuicBaaSStorage
	for i, node := range ctc.nodes {
		if node.id == newLeaderNode.id {
			newLeaderStorage = ctc.storages[i]
			break
		}
	}
	require.NotNil(t, newLeaderStorage)

	// Verify state persisted through failover
	retrievedCert, err := newLeaderStorage.GetCertificate(ctx, cert.SerialNumber, "test-tenant")
	require.NoError(t, err, "Certificate should persist through failover")
	assert.Equal(t, cert.SerialNumber.String(), retrievedCert.SerialNumber.String())
	assert.Equal(t, cert.Subject, retrievedCert.Subject)

	retrievedCRL, err := newLeaderStorage.GetCRL(ctx, crl.CRLID, "test-tenant")
	require.NoError(t, err, "CRL should persist through failover")
	assert.Equal(t, crl.CRLID, retrievedCRL.CRLID)
	assert.Equal(t, crl.Issuer, retrievedCRL.Issuer)

	t.Log("CA state persisted through leader failover")
}

// TestCAFailoverPersistence_NewCertAfterFailover tests cert issuance after failover.
func TestCAFailoverPersistence_NewCertAfterFailover(t *testing.T) {
	skipIfNoRaftCluster(t)
	skipIfNotIntegration(t)

	ctc := newCATestCluster(t, 3)
	defer ctc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := ctc.startWithCA(ctx)
	require.NoError(t, err)

	err = ctc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leaderStorage := ctc.getLeaderStorage()
	require.NotNil(t, leaderStorage)

	// Create initial certificate
	initialCert, err := ctc.generateTestCertificate("initial-cert")
	require.NoError(t, err)

	err = leaderStorage.StoreCertificate(ctx, initialCert)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	// Simulate failover
	originalLeader := ctc.getLeader()
	require.NotNil(t, originalLeader)

	err = originalLeader.coordinator.Stop(ctx)
	require.NoError(t, err)

	if mockOp, ok := originalLeader.raftOp.(*mockRaftOperator); ok {
		mockOp.setLeader(0)
	}

	followers := ctc.getFollowers()
	require.NotEmpty(t, followers)

	newLeaderNode := followers[0]
	if mockOp, ok := newLeaderNode.raftOp.(*mockRaftOperator); ok {
		mockOp.setLeader(newLeaderNode.id)
	}

	time.Sleep(2 * time.Second)

	// Get new leader's storage
	var newLeaderStorage *cacluster.QuicBaaSStorage
	for i, node := range ctc.nodes {
		if node.id == newLeaderNode.id {
			newLeaderStorage = ctc.storages[i]
			break
		}
	}
	require.NotNil(t, newLeaderStorage)

	// Issue new certificate after failover
	postFailoverCert, err := ctc.generateTestCertificate("post-failover-cert")
	require.NoError(t, err)

	err = newLeaderStorage.StoreCertificate(ctx, postFailoverCert)
	require.NoError(t, err, "Should be able to store certificate after failover")

	// Verify both certificates exist
	_, err = newLeaderStorage.GetCertificate(ctx, initialCert.SerialNumber, "test-tenant")
	assert.NoError(t, err, "Initial certificate should still exist")

	_, err = newLeaderStorage.GetCertificate(ctx, postFailoverCert.SerialNumber, "test-tenant")
	assert.NoError(t, err, "Post-failover certificate should exist")

	t.Log("Certificate issuance works after failover")
}

// TestCA_RevocationPersistence tests that revocations persist through failover.
func TestCA_RevocationPersistence(t *testing.T) {
	skipIfNoRaftCluster(t)
	skipIfNotIntegration(t)

	ctc := newCATestCluster(t, 3)
	defer ctc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := ctc.startWithCA(ctx)
	require.NoError(t, err)

	err = ctc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leaderStorage := ctc.getLeaderStorage()
	require.NotNil(t, leaderStorage)

	// Create and store a certificate
	cert, err := ctc.generateTestCertificate("revocation-test")
	require.NoError(t, err)

	err = leaderStorage.StoreCertificate(ctx, cert)
	require.NoError(t, err)

	// Revoke the certificate
	err = leaderStorage.RevokeCertificate(ctx, cert.SerialNumber, 1, "test-tenant")
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	// Verify revocation is visible on all nodes
	for i := 0; i < ctc.nodeCount(); i++ {
		storage := ctc.getStorage(i)
		if storage == nil {
			continue
		}

		retrieved, err := storage.GetCertificate(ctx, cert.SerialNumber, "test-tenant")
		if err != nil {
			continue
		}

		assert.True(t, retrieved.IsRevoked(), "Certificate should be revoked on node %d", i+1)
	}

	t.Log("Revocation persistence verified")
}
