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

package policy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockDeviceProfileDAO is a mock implementation of DeviceProfileDAO for testing
type MockDeviceProfileDAO struct {
	mock.Mock
}

func (m *MockDeviceProfileDAO) Save(ctx context.Context, entity *entities.DeviceProfile) error {
	args := m.Called(ctx, entity)
	return args.Error(0)
}

func (m *MockDeviceProfileDAO) Get(ctx context.Context, id uint64) (*entities.DeviceProfile, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.DeviceProfile), args.Error(1)
}

func (m *MockDeviceProfileDAO) Delete(ctx context.Context, entity *entities.DeviceProfile) error {
	args := m.Called(ctx, entity)
	return args.Error(0)
}

func (m *MockDeviceProfileDAO) Count(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

func (m *MockDeviceProfileDAO) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.DeviceProfile], error) {
	args := m.Called(ctx, query)
	if args.Get(0) == nil {
		return datastore.PageResult[*entities.DeviceProfile]{}, args.Error(1)
	}
	return args.Get(0).(datastore.PageResult[*entities.DeviceProfile]), args.Error(1)
}

func (m *MockDeviceProfileDAO) ForEachPage(ctx context.Context, query datastore.PageQuery, fn datastore.PagerFunc[*entities.DeviceProfile]) error {
	args := m.Called(ctx, query, fn)
	return args.Error(0)
}

func (m *MockDeviceProfileDAO) FindByMACPrefix(ctx context.Context, macPrefix string) (*entities.DeviceProfile, error) {
	args := m.Called(ctx, macPrefix)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.DeviceProfile), args.Error(1)
}

func (m *MockDeviceProfileDAO) FindBySerialPrefix(ctx context.Context, serialPrefix string) (*entities.DeviceProfile, error) {
	args := m.Called(ctx, serialPrefix)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.DeviceProfile), args.Error(1)
}

func (m *MockDeviceProfileDAO) FindMatchingProfile(ctx context.Context, macAddr, serial, model string) (*entities.DeviceProfile, error) {
	args := m.Called(ctx, macAddr, serial, model)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.DeviceProfile), args.Error(1)
}

func (m *MockDeviceProfileDAO) FindByEKSerial(ctx context.Context, ekSerial string) (*entities.DeviceProfile, error) {
	args := m.Called(ctx, ekSerial)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.DeviceProfile), args.Error(1)
}

func (m *MockDeviceProfileDAO) FindByExactMAC(ctx context.Context, mac string) (*entities.DeviceProfile, error) {
	args := m.Called(ctx, mac)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.DeviceProfile), args.Error(1)
}

func (m *MockDeviceProfileDAO) FindConfigForDevice(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
	args := m.Called(ctx, ekSerial, mac)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.DeviceProfile), args.Error(1)
}

func createEnrollmentCertificate(t *testing.T, org string) *x509.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   "test-device",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// Helper function to create a test device profile
func createTestDeviceProfile(id uint64, name, macPrefix, serialPrefix string, vlan uint16) *entities.DeviceProfile {
	return &entities.DeviceProfile{
		ID:    id,
		Name:  name,
		Model: "TestModel",
		Role:  entities.DeviceRoleServer,
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN:       vlan,
				AuthMethod: entities.AuthMethod802_1X,
				ACLs: []entities.ACLConfig{
					{
						Priority: 100,
						Protocol: "tcp",
						SrcIP:    "0.0.0.0/0",
						DstIP:    "0.0.0.0/0",
						DstPort:  443,
						Action:   "allow",
					},
				},
			},
		},
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix:    macPrefix,
			SerialPrefix: serialPrefix,
		},
	}
}

// Test MAC extractor that returns a fixed MAC address
func testMACExtractor(mac string) MACExtractor {
	return func(ipAddr string) string {
		return mac
	}
}

func TestNewSDNEnrollmentHook(t *testing.T) {
	tests := []struct {
		name      string
		config    SDNEnrollmentHookConfig
		wantError bool
	}{
		{
			name: "valid configuration",
			config: SDNEnrollmentHookConfig{
				Logger:       slog.Default(),
				PolicyEngine: &MockPolicyEngine{},
				ProfileDAO:   &MockDeviceProfileDAO{},
			},
			wantError: false,
		},
		{
			name: "nil policy engine",
			config: SDNEnrollmentHookConfig{
				Logger:     slog.Default(),
				ProfileDAO: &MockDeviceProfileDAO{},
			},
			wantError: true,
		},
		{
			name: "nil profile DAO",
			config: SDNEnrollmentHookConfig{
				Logger:       slog.Default(),
				PolicyEngine: &MockPolicyEngine{},
			},
			wantError: true,
		},
		{
			name: "nil logger uses default",
			config: SDNEnrollmentHookConfig{
				PolicyEngine: &MockPolicyEngine{},
				ProfileDAO:   &MockDeviceProfileDAO{},
			},
			wantError: false,
		},
		{
			name: "custom MAC extractor",
			config: SDNEnrollmentHookConfig{
				Logger:       slog.Default(),
				PolicyEngine: &MockPolicyEngine{},
				ProfileDAO:   &MockDeviceProfileDAO{},
				MACExtractor: testMACExtractor("52:54:00:12:34:56"),
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook, err := NewSDNEnrollmentHook(tt.config)
			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, hook)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, hook)
				assert.NotNil(t, hook.macToPort)
				assert.NotNil(t, hook.macExtractor)
			}
		})
	}
}

func TestSDNEnrollmentHook_RegisterPort(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	tests := []struct {
		name     string
		mac      string
		portID   string
		expected string
	}{
		{
			name:     "standard MAC with colons",
			mac:      "52:54:00:12:34:56",
			portID:   "port1",
			expected: "52:54:00:12:34:56",
		},
		{
			name:     "MAC with dashes",
			mac:      "52-54-00-12-34-56",
			portID:   "port2",
			expected: "52:54:00:12:34:56",
		},
		{
			name:     "uppercase MAC",
			mac:      "52:54:00:AB:CD:EF",
			portID:   "port3",
			expected: "52:54:00:ab:cd:ef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook.RegisterPort(tt.mac, tt.portID)

			portID, ok := hook.GetPortByMAC(tt.mac)
			assert.True(t, ok)
			assert.Equal(t, tt.portID, portID)

			// Verify normalized format is used
			portID, ok = hook.GetPortByMAC(tt.expected)
			assert.True(t, ok)
			assert.Equal(t, tt.portID, portID)
		})
	}
}

func TestSDNEnrollmentHook_GetPortByMAC(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	// Register a port
	hook.RegisterPort("52:54:00:12:34:56", "port1")

	tests := []struct {
		name      string
		mac       string
		wantPort  string
		wantFound bool
	}{
		{
			name:      "existing MAC",
			mac:       "52:54:00:12:34:56",
			wantPort:  "port1",
			wantFound: true,
		},
		{
			name:      "existing MAC with dashes",
			mac:       "52-54-00-12-34-56",
			wantPort:  "port1",
			wantFound: true,
		},
		{
			name:      "non-existent MAC",
			mac:       "aa:bb:cc:dd:ee:ff",
			wantPort:  "",
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			portID, found := hook.GetPortByMAC(tt.mac)
			assert.Equal(t, tt.wantFound, found)
			if tt.wantFound {
				assert.Equal(t, tt.wantPort, portID)
			}
		})
	}
}

func TestSDNEnrollmentHook_FindProfileBySerial(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	profile1 := createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100)
	profile2 := createTestDeviceProfile(2, "IoT Profile", "", "IOT-", 200)

	tests := []struct {
		name          string
		serial        string
		setupMock     func(*MockDeviceProfileDAO)
		expectProfile *entities.DeviceProfile
		expectError   bool
		errorContains string
	}{
		{
			name:   "find by serial prefix",
			serial: "SRV-12345",
			setupMock: func(dao *MockDeviceProfileDAO) {
				dao.On("ForEachPage", mock.Anything, mock.Anything, mock.Anything).
					Run(func(args mock.Arguments) {
						fn := args.Get(2).(datastore.PagerFunc[*entities.DeviceProfile])
						_ = fn(datastore.PageResult[*entities.DeviceProfile]{Entities: []*entities.DeviceProfile{profile1, profile2}})
					}).
					Return(fmt.Errorf("found")).Once()
			},
			expectProfile: profile1,
			expectError:   false,
		},
		{
			name:   "no matching profile",
			serial: "XYZ-99999",
			setupMock: func(dao *MockDeviceProfileDAO) {
				dao.On("ForEachPage", mock.Anything, mock.Anything, mock.Anything).
					Run(func(args mock.Arguments) {
						fn := args.Get(2).(datastore.PagerFunc[*entities.DeviceProfile])
						_ = fn(datastore.PageResult[*entities.DeviceProfile]{Entities: []*entities.DeviceProfile{profile1, profile2}})
					}).
					Return(nil).Once()
			},
			expectProfile: nil,
			expectError:   true,
			errorContains: "no profile found",
		},
		{
			name:          "empty serial",
			serial:        "",
			setupMock:     func(dao *MockDeviceProfileDAO) {},
			expectProfile: nil,
			expectError:   true,
			errorContains: "serial number is empty",
		},
		{
			name:   "DAO error",
			serial: "SRV-12345",
			setupMock: func(dao *MockDeviceProfileDAO) {
				dao.On("ForEachPage", mock.Anything, mock.Anything, mock.Anything).
					Return(fmt.Errorf("database error")).Once()
			},
			expectProfile: nil,
			expectError:   true,
			errorContains: "failed to search profiles",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDAO.ExpectedCalls = nil
			tt.setupMock(mockDAO)

			profile, err := hook.findProfileBySerial(tt.serial)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, profile)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, profile)
				assert.Equal(t, tt.expectProfile.ID, profile.ID)
			}

			mockDAO.AssertExpectations(t)
		})
	}
}

func TestSDNEnrollmentHook_FindProfileByMAC(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	profile1 := createTestDeviceProfile(1, "Server Profile", "52:54:00", "", 100)
	profile2 := createTestDeviceProfile(2, "IoT Profile", "aa:bb:cc", "", 200)

	tests := []struct {
		name          string
		mac           string
		setupMock     func(*MockDeviceProfileDAO)
		expectProfile *entities.DeviceProfile
		expectError   bool
		errorContains string
	}{
		{
			name: "find by MAC prefix",
			mac:  "52:54:00:12:34:56",
			setupMock: func(dao *MockDeviceProfileDAO) {
				dao.On("ForEachPage", mock.Anything, mock.Anything, mock.Anything).
					Run(func(args mock.Arguments) {
						fn := args.Get(2).(datastore.PagerFunc[*entities.DeviceProfile])
						_ = fn(datastore.PageResult[*entities.DeviceProfile]{Entities: []*entities.DeviceProfile{profile1, profile2}})
					}).
					Return(fmt.Errorf("found")).Once()
			},
			expectProfile: profile1,
			expectError:   false,
		},
		{
			name: "no matching profile",
			mac:  "ff:ee:dd:cc:bb:aa",
			setupMock: func(dao *MockDeviceProfileDAO) {
				dao.On("ForEachPage", mock.Anything, mock.Anything, mock.Anything).
					Run(func(args mock.Arguments) {
						fn := args.Get(2).(datastore.PagerFunc[*entities.DeviceProfile])
						_ = fn(datastore.PageResult[*entities.DeviceProfile]{Entities: []*entities.DeviceProfile{profile1, profile2}})
					}).
					Return(nil).Once()
			},
			expectProfile: nil,
			expectError:   true,
			errorContains: "no profile found",
		},
		{
			name:          "empty MAC",
			mac:           "",
			setupMock:     func(dao *MockDeviceProfileDAO) {},
			expectProfile: nil,
			expectError:   true,
			errorContains: "MAC address is empty",
		},
		{
			name: "DAO error",
			mac:  "52:54:00:12:34:56",
			setupMock: func(dao *MockDeviceProfileDAO) {
				dao.On("ForEachPage", mock.Anything, mock.Anything, mock.Anything).
					Return(fmt.Errorf("database error")).Once()
			},
			expectProfile: nil,
			expectError:   true,
			errorContains: "failed to search profiles",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDAO.ExpectedCalls = nil
			tt.setupMock(mockDAO)

			profile, err := hook.findProfileByMAC(tt.mac)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, profile)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, profile)
				assert.Equal(t, tt.expectProfile.ID, profile.ID)
			}

			mockDAO.AssertExpectations(t)
		})
	}
}

func TestSDNEnrollmentHook_BuildPortPolicy(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	cert := createEnrollmentCertificate(t, "TestOrg")

	tests := []struct {
		name         string
		profile      *entities.DeviceProfile
		expectPolicy bool
		expectedVLAN uint16
		expectedACLs int
	}{
		{
			name:         "profile with production network",
			profile:      createTestDeviceProfile(1, "Server Profile", "52:54:00", "", 100),
			expectPolicy: true,
			expectedVLAN: 100,
			expectedACLs: 1,
		},
		{
			name: "profile without production network",
			profile: &entities.DeviceProfile{
				ID:   1,
				Name: "Incomplete Profile",
			},
			expectPolicy: false,
		},
		{
			name: "profile with invalid ACL",
			profile: &entities.DeviceProfile{
				ID:   2,
				Name: "Invalid ACL Profile",
				Networks: map[string]*entities.NetworkPhaseConfig{
					entities.DefaultPostEnrollmentNetwork: {
						VLAN: 200,
						ACLs: []entities.ACLConfig{
							{
								Priority: 100,
								Protocol: "invalid", // Invalid protocol
								Action:   "allow",
							},
						},
					},
				},
				MatchRules: &entities.ProfileMatchRules{
					MACPrefix: "52:54:00",
				},
			},
			expectPolicy: true,
			expectedVLAN: 200,
			expectedACLs: 0, // Invalid ACL should be skipped
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := hook.buildPortPolicy(tt.profile, cert)

			if tt.expectPolicy {
				assert.NotNil(t, policy)
				assert.Equal(t, tt.expectedVLAN, policy.VLAN)
				assert.Equal(t, "TestOrg", policy.TenantID)
				assert.Equal(t, cert.NotAfter, policy.ExpiresAt)
				assert.Equal(t, tt.expectedACLs, len(policy.ACLs))
				assert.NotNil(t, policy.Metadata)
			} else {
				assert.Nil(t, policy)
			}
		})
	}
}

func TestSDNEnrollmentHook_OnEnrollmentComplete(t *testing.T) {
	tests := []struct {
		name          string
		event         *EnrollmentEvent
		setupMocks    func(*MockPolicyEngine, *MockDeviceProfileDAO, *SDNEnrollmentHook)
		expectError   bool
		errorContains string
	}{
		{
			name: "successful enrollment with serial",
			event: &EnrollmentEvent{
				Context:             context.Background(),
				Certificate:         createEnrollmentCertificate(t, "TestOrg"),
				ClientIP:            "192.168.1.100",
				IsTCGCSR:            true,
				ProductSerial:       "SRV-12345",
				ProductModel:        "TestModel",
				PermanentIdentifier: "test-device-id",
			},
			setupMocks: func(engine *MockPolicyEngine, dao *MockDeviceProfileDAO, hook *SDNEnrollmentHook) {
				// Inject a test MAC extractor
				hook.macExtractor = testMACExtractor("52:54:00:12:34:56")

				profile := createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100)
				dao.On("ForEachPage", mock.Anything, mock.Anything, mock.Anything).
					Run(func(args mock.Arguments) {
						fn := args.Get(2).(datastore.PagerFunc[*entities.DeviceProfile])
						_ = fn(datastore.PageResult[*entities.DeviceProfile]{Entities: []*entities.DeviceProfile{profile}})
					}).
					Return(fmt.Errorf("found")).Once()

				hook.RegisterPort("52:54:00:12:34:56", "port1")

				engine.On("GetPortState", "port1").
					Return(PortStateProvisioning, nil).Once()
				engine.On("SetPortState", "port1", PortStateEnrolled).
					Return(nil).Once()
			},
			expectError: false,
		},
		{
			name:  "nil event",
			event: nil,
			setupMocks: func(engine *MockPolicyEngine, dao *MockDeviceProfileDAO, hook *SDNEnrollmentHook) {
			},
			expectError:   true,
			errorContains: "enrollment event is nil",
		},
		{
			name: "nil certificate",
			event: &EnrollmentEvent{
				Context:  context.Background(),
				ClientIP: "192.168.1.100",
				IsTCGCSR: true,
			},
			setupMocks: func(engine *MockPolicyEngine, dao *MockDeviceProfileDAO, hook *SDNEnrollmentHook) {
			},
			expectError:   true,
			errorContains: "invalid certificate",
		},
		{
			name: "profile not found",
			event: &EnrollmentEvent{
				Context:       context.Background(),
				Certificate:   createEnrollmentCertificate(t, "TestOrg"),
				ClientIP:      "192.168.1.100",
				ProductSerial: "UNKNOWN-12345",
			},
			setupMocks: func(engine *MockPolicyEngine, dao *MockDeviceProfileDAO, hook *SDNEnrollmentHook) {
				// Inject a test MAC extractor that returns empty
				hook.macExtractor = testMACExtractor("")

				// Expect serial lookup to fail
				dao.On("ForEachPage", mock.Anything, mock.Anything, mock.Anything).
					Run(func(args mock.Arguments) {
						fn := args.Get(2).(datastore.PagerFunc[*entities.DeviceProfile])
						_ = fn(datastore.PageResult[*entities.DeviceProfile]{Entities: []*entities.DeviceProfile{}})
					}).
					Return(nil).Once()
			},
			expectError:   true,
			errorContains: "unable to identify device",
		},
		{
			name: "state transition failure",
			event: &EnrollmentEvent{
				Context:       context.Background(),
				Certificate:   createEnrollmentCertificate(t, "TestOrg"),
				ClientIP:      "192.168.1.100",
				ProductSerial: "SRV-12345",
			},
			setupMocks: func(engine *MockPolicyEngine, dao *MockDeviceProfileDAO, hook *SDNEnrollmentHook) {
				// Inject a test MAC extractor
				hook.macExtractor = testMACExtractor("52:54:00:12:34:56")

				profile := createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100)
				dao.On("ForEachPage", mock.Anything, mock.Anything, mock.Anything).
					Run(func(args mock.Arguments) {
						fn := args.Get(2).(datastore.PagerFunc[*entities.DeviceProfile])
						_ = fn(datastore.PageResult[*entities.DeviceProfile]{Entities: []*entities.DeviceProfile{profile}})
					}).
					Return(fmt.Errorf("found")).Once()

				hook.RegisterPort("52:54:00:12:34:56", "port1")

				engine.On("GetPortState", "port1").
					Return(PortStateProvisioning, nil).Once()
				engine.On("SetPortState", "port1", PortStateEnrolled).
					Return(fmt.Errorf("flow installation failed")).Once()
			},
			expectError:   true,
			errorContains: "failed to transition port to enrolled state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockEngine := &MockPolicyEngine{}
			mockDAO := &MockDeviceProfileDAO{}

			hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
				Logger:       slog.Default(),
				PolicyEngine: mockEngine,
				ProfileDAO:   mockDAO,
			})
			require.NoError(t, err)

			tt.setupMocks(mockEngine, mockDAO, hook)

			err = hook.OnEnrollmentComplete(tt.event)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				// Verify pending activation was stored
				if tt.event != nil && tt.event.ProductSerial != "" {
					pending, ok := hook.GetPendingActivation(tt.event.ProductSerial)
					assert.True(t, ok)
					assert.NotNil(t, pending)
					assert.Equal(t, "port1", pending.PortID)
				}
			}

			mockEngine.AssertExpectations(t)
			mockDAO.AssertExpectations(t)
		})
	}
}

func TestSDNEnrollmentHook_ActivateDevice(t *testing.T) {
	tests := []struct {
		name          string
		serial        string
		setupMocks    func(*MockPolicyEngine, *MockDeviceProfileDAO, *SDNEnrollmentHook)
		expectError   bool
		errorContains string
	}{
		{
			name:   "successful activation",
			serial: "SRV-12345",
			setupMocks: func(engine *MockPolicyEngine, dao *MockDeviceProfileDAO, hook *SDNEnrollmentHook) {
				// Store a pending activation
				profile := createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100)
				cert := createEnrollmentCertificate(t, "TestOrg")
				pending := &PendingActivation{
					PortID:      "port1",
					Profile:     profile,
					Certificate: cert,
					EnrolledAt:  time.Now(),
				}
				hook.pendingActivations.Store("SRV-12345", pending)

				engine.On("ApplyPolicy", "port1", mock.AnythingOfType("*policy.PortPolicy")).
					Return(nil).Once()
			},
			expectError: false,
		},
		{
			name:   "no pending activation",
			serial: "UNKNOWN-12345",
			setupMocks: func(engine *MockPolicyEngine, dao *MockDeviceProfileDAO, hook *SDNEnrollmentHook) {
				// No pending activation stored
			},
			expectError:   true,
			errorContains: "no pending activation found",
		},
		{
			name:   "policy application failure",
			serial: "SRV-12345",
			setupMocks: func(engine *MockPolicyEngine, dao *MockDeviceProfileDAO, hook *SDNEnrollmentHook) {
				// Store a pending activation
				profile := createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100)
				cert := createEnrollmentCertificate(t, "TestOrg")
				pending := &PendingActivation{
					PortID:      "port1",
					Profile:     profile,
					Certificate: cert,
					EnrolledAt:  time.Now(),
				}
				hook.pendingActivations.Store("SRV-12345", pending)

				engine.On("ApplyPolicy", "port1", mock.AnythingOfType("*policy.PortPolicy")).
					Return(fmt.Errorf("flow installation failed")).Once()
			},
			expectError:   true,
			errorContains: "failed to apply production policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockEngine := &MockPolicyEngine{}
			mockDAO := &MockDeviceProfileDAO{}

			hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
				Logger:       slog.Default(),
				PolicyEngine: mockEngine,
				ProfileDAO:   mockDAO,
			})
			require.NoError(t, err)

			tt.setupMocks(mockEngine, mockDAO, hook)

			err = hook.ActivateDevice(tt.serial)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				// On error, pending activation should be restored
				if tt.errorContains == "failed to apply production policy" {
					_, ok := hook.pendingActivations.Load(tt.serial)
					assert.True(t, ok, "pending activation should be restored on failure")
				}
			} else {
				assert.NoError(t, err)
				// Verify pending activation was removed on success
				_, ok := hook.pendingActivations.Load(tt.serial)
				assert.False(t, ok, "pending activation should be removed on success")
			}

			mockEngine.AssertExpectations(t)
			mockDAO.AssertExpectations(t)
		})
	}
}

func TestSDNEnrollmentHook_GetPendingActivation(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	// Store a pending activation
	profile := createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100)
	cert := createEnrollmentCertificate(t, "TestOrg")
	pending := &PendingActivation{
		PortID:      "port1",
		Profile:     profile,
		Certificate: cert,
		EnrolledAt:  time.Now(),
	}
	hook.pendingActivations.Store("SRV-12345", pending)

	tests := []struct {
		name        string
		serial      string
		expectFound bool
	}{
		{
			name:        "existing pending activation",
			serial:      "SRV-12345",
			expectFound: true,
		},
		{
			name:        "non-existent pending activation",
			serial:      "UNKNOWN-12345",
			expectFound: false,
		},
		{
			name:        "already retrieved activation",
			serial:      "SRV-12345",
			expectFound: false, // Should be removed after first retrieval
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrieved, found := hook.GetPendingActivation(tt.serial)
			assert.Equal(t, tt.expectFound, found)
			if tt.expectFound {
				assert.NotNil(t, retrieved)
				assert.Equal(t, "port1", retrieved.PortID)
			} else {
				assert.Nil(t, retrieved)
			}
		})
	}
}

func TestSDNEnrollmentHook_ExtractMACFromARPTable(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	tests := []struct {
		name        string
		ipAddr      string
		expectEmpty bool
	}{
		{
			name:        "empty IP",
			ipAddr:      "",
			expectEmpty: true,
		},
		{
			name:        "invalid IP",
			ipAddr:      "not-an-ip",
			expectEmpty: true,
		},
		{
			name:   "valid IP (may or may not find MAC)",
			ipAddr: "192.168.1.1",
			// Don't assert on result since ARP table contents are system-dependent
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mac := hook.extractMACFromARPTable(tt.ipAddr)
			if tt.expectEmpty {
				assert.Empty(t, mac)
			}
			// For valid IPs, we can't assert the result as it depends on the system's ARP table
		})
	}
}

func TestSDNEnrollmentHook_BuildPortPolicy_ACLProtocols(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	cert := createEnrollmentCertificate(t, "TestOrg")

	tests := []struct {
		name            string
		protocol        string
		expectedIPProto uint8
	}{
		{
			name:            "TCP protocol",
			protocol:        "tcp",
			expectedIPProto: 6,
		},
		{
			name:            "UDP protocol",
			protocol:        "udp",
			expectedIPProto: 17,
		},
		{
			name:            "ICMP protocol",
			protocol:        "icmp",
			expectedIPProto: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := &entities.DeviceProfile{
				ID:   1,
				Name: "Test Profile",
				Networks: map[string]*entities.NetworkPhaseConfig{
					entities.DefaultPostEnrollmentNetwork: {
						VLAN: 100,
						ACLs: []entities.ACLConfig{
							{
								Priority: 100,
								Protocol: tt.protocol,
								SrcIP:    "10.0.0.0/8",
								DstIP:    "0.0.0.0/0",
								SrcPort:  8080,
								DstPort:  443,
								Action:   "allow",
							},
						},
					},
				},
				MatchRules: &entities.ProfileMatchRules{
					MACPrefix: "52:54:00",
				},
			}

			policy := hook.buildPortPolicy(profile, cert)
			require.NotNil(t, policy)
			require.Len(t, policy.ACLs, 1)

			assert.Equal(t, tt.expectedIPProto, policy.ACLs[0].Match.IPProto)
			assert.Equal(t, "10.0.0.0/8", policy.ACLs[0].Match.IPv4Src)
			assert.Equal(t, "0.0.0.0/0", policy.ACLs[0].Match.IPv4Dst)
		})
	}
}

func TestSDNEnrollmentHook_Concurrency(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	// Test concurrent port registration
	const numGoroutines = 100
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			mac := fmt.Sprintf("52:54:00:12:34:%02x", index%256)
			portID := fmt.Sprintf("port%d", index)
			hook.RegisterPort(mac, portID)

			// Verify registration
			retrievedPort, ok := hook.GetPortByMAC(mac)
			assert.True(t, ok)
			assert.Equal(t, portID, retrievedPort)

			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
} // MockPolicyEngine is a mock implementation of PolicyEngine for testing
type MockPolicyEngine struct {
	mock.Mock
}

func (m *MockPolicyEngine) SetPortState(portID string, state PortState) error {
	args := m.Called(portID, state)
	return args.Error(0)
}

func (m *MockPolicyEngine) GetPortState(portID string) (PortState, error) {
	args := m.Called(portID)
	return args.Get(0).(PortState), args.Error(1)
}

func (m *MockPolicyEngine) GetPortInfo(portID string) (*PortInfo, error) {
	args := m.Called(portID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*PortInfo), args.Error(1)
}

func (m *MockPolicyEngine) ApplyPolicy(portID string, policy *PortPolicy) error {
	args := m.Called(portID, policy)
	return args.Error(0)
}

func (m *MockPolicyEngine) RemovePolicy(portID string) error {
	args := m.Called(portID)
	return args.Error(0)
}

func (m *MockPolicyEngine) GetPolicy(portID string) (*PortPolicy, error) {
	args := m.Called(portID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*PortPolicy), args.Error(1)
}

func (m *MockPolicyEngine) SetPortVLAN(portID string, vlan uint16) error {
	args := m.Called(portID, vlan)
	return args.Error(0)
}

func (m *MockPolicyEngine) GetPortVLAN(portID string) (uint16, error) {
	args := m.Called(portID)
	return args.Get(0).(uint16), args.Error(1)
}

func (m *MockPolicyEngine) BlockPort(portID string) error {
	args := m.Called(portID)
	return args.Error(0)
}

func (m *MockPolicyEngine) UnblockPort(portID string) error {
	args := m.Called(portID)
	return args.Error(0)
}

func (m *MockPolicyEngine) GetOFPort(portID string) (int32, error) {
	args := m.Called(portID)
	return args.Get(0).(int32), args.Error(1)
}

func (m *MockPolicyEngine) AuthenticatePort(portID string, cert *x509.Certificate) error {
	args := m.Called(portID, cert)
	return args.Error(0)
}

func (m *MockPolicyEngine) OnCertificateExpired(portID string) error {
	args := m.Called(portID)
	return args.Error(0)
}

func (m *MockPolicyEngine) OnCertificateRevoked(portID string) error {
	args := m.Called(portID)
	return args.Error(0)
}

func (m *MockPolicyEngine) GetMonitor() *CertificateMonitor {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*CertificateMonitor)
}
