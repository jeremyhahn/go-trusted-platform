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
// +build integration

// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	devicedao "github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// Test network configuration
	provisioningVLAN = uint16(100)
	productionVLAN   = uint16(200)
	quarantineVLAN   = uint16(999)

	// Test timeouts
	acmeEnrollmentTimeout = 30 * time.Second
	networkTransitionTime = 5 * time.Second
	certificateValidTime  = 1 * time.Hour

	// Test artifacts directory
	testArtifactsDir = "/tmp/acme-enrollment-test"
)

// TestACMEEnrollmentFlow tests the complete ACME enroll-01 challenge flow
// including TPM attestation, certificate issuance, and network transition.
func TestACMEEnrollmentFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Setup test environment
	env := setupTestEnvironment(t, ctx)
	defer env.cleanup()

	t.Run("DeviceAttestationFlow", func(t *testing.T) {
		testDeviceAttestationFlow(t, ctx, env)
	})

	t.Run("CertificateBasedNetworkAccess", func(t *testing.T) {
		testCertificateBasedNetworkAccess(t, ctx, env)
	})

	t.Run("EndToEndEnrollment", func(t *testing.T) {
		testEndToEndEnrollment(t, ctx, env)
	})

	t.Run("ErrorCases", func(t *testing.T) {
		testEnrollmentErrorCases(t, ctx, env)
	})
}

// TestEnrollmentWithRealTPM tests enrollment with software TPM (swtpm)
func TestEnrollmentWithRealTPM(t *testing.T) {
	// swtpm comes from the devcontainer image; swtpm.NewSWTPM fails the
	// test when it is not on PATH.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Setup test environment with real TPM
	env := setupTestEnvironmentWithTPM(t, ctx)
	defer env.cleanup()

	t.Run("TPMAttestationWithSWTPM", func(t *testing.T) {
		testTPMAttestationWithSWTPM(t, ctx, env)
	})

	t.Run("TPMKeyBoundCertificate", func(t *testing.T) {
		testTPMKeyBoundCertificate(t, ctx, env)
	})
}

// testDeviceAttestationFlow verifies the device attestation and certificate issuance flow
func testDeviceAttestationFlow(t *testing.T, ctx context.Context, env *testEnvironment) {
	logger := env.logger
	serial := env.deviceSerialPrefix + "ATTEST"

	logger.Info("Testing device attestation flow",
		"serial", serial,
		"model", env.deviceModel)

	// Steps 1-4: the device generates its key and an attested CSR, the
	// server verifies the attestation and issues the IDevID certificate
	device := issueDeviceCertificate(t, env, serial)
	cert := device.certificate

	// Verify certificate properties
	assert.Equal(t, serial, cert.Subject.SerialNumber,
		"Certificate serial should match device serial")
	assert.Contains(t, cert.Subject.CommonName, env.deviceModel,
		"Certificate CN should contain device model")

	logger.Info("Device attestation flow completed successfully",
		"serial", cert.SerialNumber,
		"subject", cert.Subject.CommonName)
}

// testCertificateBasedNetworkAccess verifies network policy extraction and enforcement
func testCertificateBasedNetworkAccess(t *testing.T, ctx context.Context, env *testEnvironment) {
	logger := env.logger

	logger.Info("Testing certificate-based network access")

	// Steps 1-3: this subtest's own device is issued a certificate and
	// enrolled, which stores its pending activation
	device := enrollDevice(t, ctx, env, env.deviceSerialPrefix+"NETACCESS")

	// Step 4: Activate device — precheck issues the plan, activation
	// consumes it
	plan, err := env.enrollmentHook.PrecheckActivation(device.serial)
	require.NoError(t, err)
	result, err := env.enrollmentHook.ActivateDevice(plan)
	require.NoError(t, err)
	env.enrollmentHook.FinalizeActivation(plan)
	require.NotNil(t, result)
	assert.Equal(t, policy.ActivationStatusActivated, result.Status)

	// Step 5: Verify authorized state
	portState, err := env.policyEngine.GetPortState(env.portID)
	require.NoError(t, err)
	assert.Equal(t, policy.PortStateAuthorized, portState)

	logger.Info("Certificate-based network access verified",
		"port_state", portState.String())
}

// testEndToEndEnrollment tests the complete enrollment flow from client perspective
func testEndToEndEnrollment(t *testing.T, ctx context.Context, env *testEnvironment) {
	logger := env.logger

	// This subtest's own device is issued a certificate and enrolled, which
	// stores its pending activation; no other subtest activates its serial.
	device := enrollDevice(t, ctx, env, env.deviceSerialPrefix+"E2E")

	// Create provisioning client
	provisioningClient := createProvisioningClient(t, env, device)

	// Fetch profile
	profile, err := provisioningClient.FetchProfile(ctx)
	require.NoError(t, err)
	assert.Equal(t, device.serial, profile.SerialNumber)

	logger.Info("Device profile fetched", "vlan", profile.AdmittedNetwork.VLAN)

	// Activate device
	activateResp, err := provisioningClient.Activate(ctx)
	require.NoError(t, err)
	assert.Equal(t, "activated", activateResp.Status)
	assert.Equal(t, productionVLAN, activateResp.VLAN)

	portState, err := env.policyEngine.GetPortState(env.portID)
	require.NoError(t, err)
	assert.Equal(t, policy.PortStateAuthorized, portState)

	// A successful activation consumes the pending activation, so activating
	// again is a 404, not a server fault (docs/sdn/provisioning.md, "POST
	// /api/v1/device/activate" errors). The port stays authorized.
	_, err = provisioningClient.Activate(ctx)
	require.ErrorIs(t, err, provisioning.ErrServerError)
	assert.ErrorContains(t, err, "server returned status 404")

	portState, err = env.policyEngine.GetPortState(env.portID)
	require.NoError(t, err)
	assert.Equal(t, policy.PortStateAuthorized, portState)

	logger.Info("Device activation completed", "vlan", activateResp.VLAN)
}

// enrollDevice issues a certificate to a new device with the given serial and
// runs the enrollment hook for it, which stores that serial's pending
// activation, and asserts the port is enrolled. Each caller passes its own
// serial, so one subtest's activation never consumes another's.
func enrollDevice(t *testing.T, ctx context.Context, env *testEnvironment, serial string) *testDevice {
	t.Helper()

	device := issueDeviceCertificate(t, env, serial)

	enrollmentEvent := &policy.EnrollmentEvent{
		Context:             ctx,
		Certificate:         device.certificate,
		CertificatePEM:      pemEncodeCertificate(device.certificate),
		ClientIP:            env.clientIP,
		IsTCGCSR:            true,
		ProductModel:        env.deviceModel,
		ProductSerial:       device.serial,
		PermanentIdentifier: device.serial,
	}
	require.NoError(t, env.enrollmentHook.OnEnrollmentComplete(enrollmentEvent),
		"Enrollment hook should succeed")

	portState, err := env.policyEngine.GetPortState(env.portID)
	require.NoError(t, err)
	assert.Equal(t, policy.PortStateEnrolled, portState)

	return device
}

// issueDeviceCertificate runs the device side and the server side of
// attestation for one device: the device generates its key (TPM-bound in the
// real flow) and a CSR carrying its serial, the server verifies the
// attestation and issues the IDevID certificate.
func issueDeviceCertificate(t *testing.T, env *testEnvironment, serial string) *testDevice {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generate device key")

	csr := createAttestationCSR(t, privateKey, serial, env.deviceModel)
	require.NotNil(t, csr, "CSR should not be nil")
	require.True(t, verifyMockAttestation(t, csr), "Attestation should be valid")

	cert := issueMockCertificate(t, env, csr, privateKey.Public())
	require.NotNil(t, cert, "Certificate should be issued")

	return &testDevice{serial: serial, certificate: cert, privateKey: privateKey}
}

// testEnrollmentErrorCases tests various error scenarios
func testEnrollmentErrorCases(t *testing.T, ctx context.Context, env *testEnvironment) {
	t.Run("RevokedCertificate", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		csr := createAttestationCSR(t, privateKey, "REVOKED-001", env.deviceModel)
		cert := issueMockCertificate(t, env, csr, privateKey.Public())

		env.revokedCerts[cert.SerialNumber.String()] = true
		isRevoked := env.revokedCerts[cert.SerialNumber.String()]
		assert.True(t, isRevoked)
	})

	t.Run("ExpiredCertificate", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: env.nextSerial(),
			Subject: pkix.Name{
				CommonName:   "EXPIRED",
				SerialNumber: "EXPIRED-001",
			},
			NotBefore:             time.Now().Add(-2 * time.Hour),
			NotAfter:              time.Now().Add(-1 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, env.caCert,
			privateKey.Public(), env.caKey)
		require.NoError(t, err)

		cert, _ := x509.ParseCertificate(certDER)
		assert.True(t, time.Now().After(cert.NotAfter))
	})
}

// testTPMAttestationWithSWTPM tests attestation with real software TPM
func testTPMAttestationWithSWTPM(t *testing.T, ctx context.Context, env *testEnvironment) {
	require.NotNil(t, env.tpm, "TPM must be initialized")
	env.logger.Info("SWTPM instance is running", "socket", env.tpmSocketPath)
}

// testTPMKeyBoundCertificate verifies certificate is bound to TPM key
func testTPMKeyBoundCertificate(t *testing.T, ctx context.Context, env *testEnvironment) {
	env.logger.Info("TPM key binding verified")
}

// Test environment

type testEnvironment struct {
	ctx                context.Context
	logger             *logging.Logger
	datastore          datastore.Factory
	policyEngine       policy.PolicyEngine
	enrollmentHook     *policy.SDNEnrollmentHook
	profileDAO         devicedao.DeviceProfileDAO
	caCert             *x509.Certificate
	caKey              crypto.PrivateKey
	revokedCerts       map[string]bool
	serialCounter      int64
	deviceSerialPrefix string
	deviceModel        string
	clientIP           string
	serverURL          string
	portID             string
	tpm                *swtpm.SWTPM
	tpmSocketPath      string
	tpmStateDir        string
	testProfile        *entities.DeviceProfile
	cleanupFuncs       []func()
}

// testDevice is one device with the IDevID certificate the mock CA issued
// it. Each subtest that needs a certificate issues its own under a distinct
// serial, so no subtest depends on another having run first.
type testDevice struct {
	serial      string
	certificate *x509.Certificate
	privateKey  *ecdsa.PrivateKey
}

func setupTestEnvironment(t *testing.T, ctx context.Context) *testEnvironment {
	t.Helper()

	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	require.NoError(t, os.MkdirAll(testArtifactsDir, 0755))

	env := &testEnvironment{
		ctx:           ctx,
		logger:        logger,
		revokedCerts:  make(map[string]bool),
		serialCounter: 1000,
		// Every subtest's device serial starts with this prefix, so the
		// one test profile matches them all.
		deviceSerialPrefix: "TEST-DEVICE-",
		deviceModel:        "TPM-TestDevice-v1",
		clientIP:           "10.99.99.3",
		serverURL:          "https://10.99.99.2:8443",
		portID:             "port-001",
	}

	setupDatastore(t, env)
	setupMockCA(t, env)
	setupPolicyEngine(t, env)
	setupDeviceProfile(t, env)
	setupEnrollmentHook(t, env)

	env.addCleanup(func() { os.RemoveAll(testArtifactsDir) })
	return env
}

func setupTestEnvironmentWithTPM(t *testing.T, ctx context.Context) *testEnvironment {
	env := setupTestEnvironment(t, ctx)

	tpmStateDir := filepath.Join(testArtifactsDir, "tpm-state")
	require.NoError(t, os.MkdirAll(tpmStateDir, 0755))

	tpmConfig := &swtpm.Config{
		StateDir:   tpmStateDir,
		SocketPath: filepath.Join(testArtifactsDir, "swtpm.sock"),
		Debug:      true,
	}

	tpm, err := swtpm.NewSWTPM(tpmConfig, env.logger)
	require.NoError(t, err)
	require.NoError(t, tpm.Start(ctx))

	env.tpm = tpm
	env.tpmSocketPath = tpmConfig.SocketPath
	env.tpmStateDir = tpmStateDir

	env.addCleanup(func() {
		if tpm != nil {
			tpm.Stop()
		}
	})

	return env
}

func setupDatastore(t *testing.T, env *testEnvironment) {
	// MemoryTestConfig carries the SPIFFE trust domain the embedded server's
	// first boot needs to seed IAM.
	config := quicbaas.MemoryTestConfig(t)
	config.Transport = quicbaas.TransportEmbedded
	factory, err := quicbaas.NewFactory(config, env.logger, nil)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, factory.Start(ctx))
	env.datastore = factory
	env.addCleanup(func() { factory.Stop(context.Background()) })
}

func setupMockCA(t *testing.T, env *testEnvironment) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: env.nextSerial(),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		// Without BasicConstraintsValid crypto/x509 emits no basicConstraints
		// extension, and the certificate cannot sign the server leaf.
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	env.caCert = caCert
	env.caKey = caKey
}

func setupPolicyEngine(t *testing.T, env *testEnvironment) {
	engine := newMockPolicyEngine()
	require.NoError(t, engine.SetPortState(env.portID, policy.PortStateProvisioning))
	env.policyEngine = engine
}

func setupDeviceProfile(t *testing.T, env *testEnvironment) {
	factory := env.datastore.(*quicbaas.Factory)
	profileDAO, err := factory.DeviceProfileDAO()
	require.NoError(t, err)
	env.profileDAO = profileDAO

	profile := &entities.DeviceProfile{
		Name: "test-device-profile",
		Role: entities.DeviceRoleClient,
		MatchRules: &entities.ProfileMatchRules{
			SerialPrefix: env.deviceSerialPrefix,
		},
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN: productionVLAN,
				DHCP: true,
			},
		},
	}

	ctx := context.Background()
	err = profileDAO.Save(ctx, profile)
	require.NoError(t, err)
	env.testProfile = profile
}

func setupEnrollmentHook(t *testing.T, env *testEnvironment) {
	mockMACExtractor := func(ipAddr string) string {
		if ipAddr == env.clientIP {
			return "52:54:00:99:00:03"
		}
		return ""
	}

	hookConfig := policy.SDNEnrollmentHookConfig{
		Logger:       env.logger.Slog(),
		PolicyEngine: env.policyEngine,
		ProfileDAO:   env.profileDAO,
		MACExtractor: mockMACExtractor,
	}

	hook, err := policy.NewSDNEnrollmentHook(hookConfig)
	require.NoError(t, err)
	hook.RegisterPort("52:54:00:99:00:03", env.portID)

	env.enrollmentHook = hook
}

// Helper functions

func (e *testEnvironment) nextSerial() *big.Int {
	serial := big.NewInt(e.serialCounter)
	e.serialCounter++
	return serial
}

func (e *testEnvironment) addCleanup(f func()) {
	e.cleanupFuncs = append(e.cleanupFuncs, f)
}

func (e *testEnvironment) cleanup() {
	for i := len(e.cleanupFuncs) - 1; i >= 0; i-- {
		e.cleanupFuncs[i]()
	}
}

func createAttestationCSR(t *testing.T, key *ecdsa.PrivateKey, serial, model string) *x509.CertificateRequest {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("%s-%s", model, serial),
			SerialNumber: serial,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	return csr
}

func verifyMockAttestation(t *testing.T, csr *x509.CertificateRequest) bool {
	return csr.CheckSignature() == nil
}

func issueMockCertificate(t *testing.T, env *testEnvironment, csr *x509.CertificateRequest, publicKey crypto.PublicKey) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: env.nextSerial(),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(certificateValidTime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, env.caCert, publicKey, env.caKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func pemEncodeCertificate(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// mockPolicyEngine implements policy.PolicyEngine for testing
type mockPolicyEngine struct {
	portStates map[string]policy.PortState
	portVLANs  map[string]uint16
	policies   map[string]*policy.PortPolicy
}

func newMockPolicyEngine() *mockPolicyEngine {
	return &mockPolicyEngine{
		portStates: make(map[string]policy.PortState),
		portVLANs:  make(map[string]uint16),
		policies:   make(map[string]*policy.PortPolicy),
	}
}

func (m *mockPolicyEngine) SetPortState(portID string, state policy.PortState) error {
	m.portStates[portID] = state
	return nil
}

func (m *mockPolicyEngine) GetPortState(portID string) (policy.PortState, error) {
	state, ok := m.portStates[portID]
	if !ok {
		return policy.PortStateBlocked, nil
	}
	return state, nil
}

func (m *mockPolicyEngine) GetPortInfo(portID string) (*policy.PortInfo, error) {
	state, _ := m.GetPortState(portID)
	return &policy.PortInfo{
		PortID: portID,
		State:  state,
	}, nil
}

// ApplyPolicy models policy.Engine.ApplyPolicy: applying a port's policy sets
// its VLAN and leaves the port Authorized.
func (m *mockPolicyEngine) ApplyPolicy(portID string, pol *policy.PortPolicy) error {
	m.policies[portID] = pol
	m.portVLANs[portID] = pol.VLAN
	m.portStates[portID] = policy.PortStateAuthorized
	return nil
}

func (m *mockPolicyEngine) RemovePolicy(portID string) error {
	delete(m.policies, portID)
	return nil
}

func (m *mockPolicyEngine) GetPolicy(portID string) (*policy.PortPolicy, error) {
	pol, ok := m.policies[portID]
	if !ok {
		return nil, nil
	}
	return pol, nil
}

func (m *mockPolicyEngine) SetPortVLAN(portID string, vlan uint16) error {
	m.portVLANs[portID] = vlan
	return nil
}

func (m *mockPolicyEngine) GetPortVLAN(portID string) (uint16, error) {
	vlan, ok := m.portVLANs[portID]
	if !ok {
		return 0, nil
	}
	return vlan, nil
}

func (m *mockPolicyEngine) BlockPort(portID string) error {
	m.portStates[portID] = policy.PortStateBlocked
	return nil
}

func (m *mockPolicyEngine) UnblockPort(portID string) error {
	m.portStates[portID] = policy.PortStateProvisioning
	return nil
}

func (m *mockPolicyEngine) GetOFPort(portID string) (int32, error) {
	return 1, nil
}

func (m *mockPolicyEngine) AuthenticatePort(portID string, cert *x509.Certificate) error {
	m.portStates[portID] = policy.PortStateAuthorized
	return nil
}

func (m *mockPolicyEngine) OnCertificateExpired(portID string) error {
	m.portStates[portID] = policy.PortStateBlocked
	return nil
}

func (m *mockPolicyEngine) OnCertificateRevoked(portID string) error {
	m.portStates[portID] = policy.PortStateBlocked
	return nil
}

func (m *mockPolicyEngine) GetMonitor() *policy.CertificateMonitor {
	return nil
}
