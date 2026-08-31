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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"testing"
	"time"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
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
					Return(&MessageError{Msg: "found"}).Once()
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
					Return(&MessageError{Msg: "database error"}).Once()
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
					Return(&MessageError{Msg: "found"}).Once()
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
					Return(&MessageError{Msg: "database error"}).Once()
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
			policy, _ := hook.buildPortPolicy(tt.profile, cert)

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
					Return(&MessageError{Msg: "found"}).Once()

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
					Return(&MessageError{Msg: "found"}).Once()

				hook.RegisterPort("52:54:00:12:34:56", "port1")

				engine.On("GetPortState", "port1").
					Return(PortStateProvisioning, nil).Once()
				engine.On("SetPortState", "port1", PortStateEnrolled).
					Return(&MessageError{Msg: "flow installation failed"}).Once()
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
					assert.Equal(t, "52:54:00:12:34:56", pending.MAC)
				}
			}

			mockEngine.AssertExpectations(t)
			mockDAO.AssertExpectations(t)
		})
	}
}

// TestSDNEnrollmentHook_OnEnrollmentComplete_PortMissDefers verifies that a
// missing MAC-to-port mapping does not fail enrollment: the certificate is
// issued, a WARN is logged, and a pending activation carrying the device MAC
// is recorded so the port transition can be applied once the device attaches
// to the fabric.
func TestSDNEnrollmentHook_OnEnrollmentComplete_PortMissDefers(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	var logBuf bytes.Buffer
	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.New(slog.NewTextHandler(&logBuf, nil)),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	hook.macExtractor = testMACExtractor("52:54:00:aa:bb:cc")

	profile := createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100)
	mockDAO.On("ForEachPage", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(datastore.PagerFunc[*entities.DeviceProfile])
			_ = fn(datastore.PageResult[*entities.DeviceProfile]{Entities: []*entities.DeviceProfile{profile}})
		}).
		Return(&MessageError{Msg: "found"}).Once()

	// No RegisterPort call: the device enrolled over the management LAN and
	// never attached to the fabric, so no MAC-to-port mapping exists.
	event := &EnrollmentEvent{
		Context:       context.Background(),
		Certificate:   createEnrollmentCertificate(t, "TestOrg"),
		ClientIP:      "192.168.100.50",
		IsTCGCSR:      true,
		ProductSerial: "SRV-99999",
	}

	err = hook.OnEnrollmentComplete(event)
	assert.NoError(t, err)

	assert.Contains(t, logBuf.String(), "port not registered for MAC address")

	pending, ok := hook.PeekPendingActivation("SRV-99999")
	require.True(t, ok, "pending activation should be recorded on port miss")
	assert.Empty(t, pending.PortID)
	assert.Equal(t, "52:54:00:aa:bb:cc", pending.MAC)
	assert.Equal(t, profile, pending.Profile)
	assert.NotNil(t, pending.Certificate)

	// No state transition may be attempted without a known port.
	mockEngine.AssertExpectations(t)
	mockDAO.AssertExpectations(t)
}

// TestSDNEnrollmentHook_ActivateDevice_DeferredPortResolved verifies that an
// activation for a device that enrolled without a port succeeds when a
// connect event has since registered the MAC-to-port mapping.
func TestSDNEnrollmentHook_ActivateDevice_DeferredPortResolved(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	hook.pendingActivations.Store("SRV-99999", &PendingActivation{
		MAC:         "52:54:00:aa:bb:cc",
		Profile:     createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100),
		Certificate: createEnrollmentCertificate(t, "TestOrg"),
		EnrolledAt:  time.Now(),
	})

	// The device attached to the fabric after enrollment.
	hook.RegisterPort("52:54:00:aa:bb:cc", "port7")

	mockEngine.On("ApplyPolicy", "port7", mock.AnythingOfType("*policy.PortPolicy")).
		Return(nil).Once()

	plan, err := hook.PrecheckActivation("SRV-99999")
	require.NoError(t, err)
	_, err = hook.ActivateDevice(plan)
	assert.NoError(t, err)

	// The reservation is held until the caller finalizes; releasing it
	// clears the slot.
	_, visible := hook.PeekPendingActivation("SRV-99999")
	assert.False(t, visible, "an in-flight reservation must not be visible as a pending activation")
	hook.FinalizeActivation(plan)
	_, loaded := hook.pendingActivations.Load("SRV-99999")
	assert.False(t, loaded, "pending activation should be removed after finalize")

	mockEngine.AssertExpectations(t)
}

// TestSDNEnrollmentHook_ActivateDevice_DeferredPortStillUnknown verifies that
// activation fails closed when the device still has no registered port, and
// that the pending activation is retained for a later attempt.
func TestSDNEnrollmentHook_ActivateDevice_DeferredPortStillUnknown(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	pending := &PendingActivation{
		MAC:         "52:54:00:aa:bb:cc",
		Profile:     createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100),
		Certificate: createEnrollmentCertificate(t, "TestOrg"),
		EnrolledAt:  time.Now(),
	}
	hook.pendingActivations.Store("SRV-99999", pending)

	// Build the plan directly: in the real flow the port was resolvable at
	// precheck time, but the mapping can be gone again by activation time —
	// ActivateDevice must fail closed on its own port resolution.
	pol, polErr := hook.buildPortPolicy(pending.Profile, pending.Certificate)
	require.NoError(t, polErr)
	require.NotNil(t, pol)
	plan := &activationPlan{serial: "SRV-99999", pending: pending, policy: pol}

	_, err = hook.ActivateDevice(plan)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no port registered for device MAC")

	_, loaded := hook.pendingActivations.Load("SRV-99999")
	assert.True(t, loaded, "pending activation should be retained when the port is still unknown")

	mockEngine.AssertExpectations(t)
}

// TestSDNEnrollmentHook_PrecheckActivation verifies the side-effect-free
// activation precheck: each failure class is reported without consuming or
// mutating the pending activation, and a clean pending activation passes.
func TestSDNEnrollmentHook_PrecheckActivation(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	// No pending activation for the serial.
	_, err = hook.PrecheckActivation("UNKNOWN-12345")
	var noPending ErrNoPendingActivation
	require.ErrorAs(t, err, &noPending)

	// Pending activation with a deferred, still-unregistered port.
	profile := createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100)
	cert := createEnrollmentCertificate(t, "TestOrg")
	pendingSRV := &PendingActivation{
		MAC:         "52:54:00:aa:bb:cc",
		Profile:     profile,
		Certificate: cert,
		EnrolledAt:  time.Now(),
	}
	hook.pendingActivations.Store("SRV-12345", pendingSRV)
	_, err = hook.PrecheckActivation("SRV-12345")
	var noPort ErrPortNotRegisteredForDevice
	require.ErrorAs(t, err, &noPort)
	assert.Equal(t, "52:54:00:aa:bb:cc", noPort.MAC)

	// The port becomes registered: the precheck passes and issues a plan
	// reserving the exact pending record it validated.
	hook.RegisterPort("52:54:00:aa:bb:cc", "port7")
	plan, err := hook.PrecheckActivation("SRV-12345")
	require.NoError(t, err)
	require.NotNil(t, plan)
	assert.Equal(t, "SRV-12345", plan.Serial())
	assert.False(t, plan.ExpectQuarantine())
	assert.Nil(t, plan.ZoneMismatch())
	// The VLAN snapshot is a value copy of the validated profile's
	// networks, taken at precheck time.
	vlans := plan.VLANs()
	assert.Equal(t, uint16(100), vlans.Trusted)

	// A profile without a production network cannot build a policy.
	noNetProfile := &entities.DeviceProfile{ID: 2, Name: "No Net"}
	hook.pendingActivations.Store("SRV-NONET", &PendingActivation{
		PortID:      "port9",
		MAC:         "52:54:00:dd:ee:ff",
		Profile:     noNetProfile,
		Certificate: cert,
		EnrolledAt:  time.Now(),
	})
	_, err = hook.PrecheckActivation("SRV-NONET")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to build port policy")

	// The precheck must not have consumed or replaced the pending record.
	got, ok := hook.PeekPendingActivation("SRV-12345")
	require.True(t, ok, "precheck must not consume the pending activation")
	assert.Same(t, pendingSRV, got, "precheck must leave the exact pending record in place")

	// A subsequent activation succeeds with the plan's reserved record.
	mockEngine.On("ApplyPolicy", "port7", mock.AnythingOfType("*policy.PortPolicy")).
		Return(nil).Once()
	_, err = hook.ActivateDevice(plan)
	require.NoError(t, err)

	mockEngine.AssertExpectations(t)
}

// TestSDNEnrollmentHook_ActivateDevice_FailureDoesNotClobberNewerPending
// verifies that a failed activation does not overwrite a pending activation
// stored concurrently (e.g. by a re-enrollment) between retrieval and restore.
func TestSDNEnrollmentHook_ActivateDevice_FailureDoesNotClobberNewerPending(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	stale := &PendingActivation{
		PortID:      "port1",
		MAC:         "52:54:00:aa:bb:cc",
		Profile:     createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100),
		Certificate: createEnrollmentCertificate(t, "TestOrg"),
		EnrolledAt:  time.Now(),
	}
	hook.pendingActivations.Store("SRV-12345", stale)

	newer := &PendingActivation{
		PortID:      "port2",
		MAC:         "52:54:00:aa:bb:cc",
		Profile:     createTestDeviceProfile(2, "Server Profile", "", "SRV-", 100),
		Certificate: createEnrollmentCertificate(t, "TestOrg"),
		EnrolledAt:  time.Now(),
	}

	mockEngine.On("ApplyPolicy", "port1", mock.AnythingOfType("*policy.PortPolicy")).
		Run(func(mock.Arguments) {
			// A re-enrollment lands while the activation is in flight.
			hook.pendingActivations.Store("SRV-12345", newer)
		}).
		Return(&MessageError{Msg: "flow installation failed"}).Once()

	plan, err := hook.PrecheckActivation("SRV-12345")
	require.NoError(t, err)
	_, err = hook.ActivateDevice(plan)
	assert.Error(t, err)

	got, loaded := hook.pendingActivations.Load("SRV-12345")
	require.True(t, loaded)
	assert.Same(t, newer, got, "the newer pending activation must survive a failed activation")

	mockEngine.AssertExpectations(t)
}

// TestSDNEnrollmentHook_FailedRestore_DoesNotResurrectConsumedRecord
// verifies the restore is anchored to the activation's own in-flight
// reservation: when a newer record was stored AND consumed while the
// failing activation was in flight, the now-empty slot stays empty — the
// stale record is never resurrected, so no later activation can apply a
// version that no longer reflects reality.
func TestSDNEnrollmentHook_FailedRestore_DoesNotResurrectConsumedRecord(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	stale := &PendingActivation{
		PortID:      "port1",
		MAC:         "52:54:00:aa:bb:cc",
		Profile:     createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100),
		Certificate: createEnrollmentCertificate(t, "TestOrg"),
		EnrolledAt:  time.Now(),
	}
	hook.pendingActivations.Store("SRV-12345", stale)

	newer := &PendingActivation{
		PortID:      "port2",
		MAC:         "52:54:00:aa:bb:cc",
		Profile:     createTestDeviceProfile(2, "Server Profile", "", "SRV-", 100),
		Certificate: createEnrollmentCertificate(t, "TestOrg"),
		EnrolledAt:  time.Now(),
	}

	mockEngine.On("ApplyPolicy", "port1", mock.AnythingOfType("*policy.PortPolicy")).
		Run(func(mock.Arguments) {
			// A re-enrollment stores a newer record AND another path
			// consumes it while this activation is in flight: the slot
			// has moved on and is now empty.
			hook.pendingActivations.Store("SRV-12345", newer)
			hook.pendingActivations.Delete("SRV-12345")
		}).
		Return(&MessageError{Msg: "flow installation failed"}).Once()

	plan, err := hook.PrecheckActivation("SRV-12345")
	require.NoError(t, err)
	_, err = hook.ActivateDevice(plan)
	assert.Error(t, err)

	_, loaded := hook.pendingActivations.Load("SRV-12345")
	assert.False(t, loaded, "a slot that moved on must never be repopulated with the stale record")

	mockEngine.AssertExpectations(t)
}

func TestSDNEnrollmentHook_ActivateDevice(t *testing.T) {
	// storePending stores a fresh pending activation for serial and
	// returns it.
	storePending := func(hook *SDNEnrollmentHook, serial string) *PendingActivation {
		pending := &PendingActivation{
			PortID:      "port1",
			Profile:     createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100),
			Certificate: createEnrollmentCertificate(t, "TestOrg"),
			EnrolledAt:  time.Now(),
		}
		hook.pendingActivations.Store(serial, pending)
		return pending
	}
	// mustPlan reserves the current pending activation via the real
	// precheck.
	mustPlan := func(hook *SDNEnrollmentHook, serial string) ActivationPlan {
		plan, err := hook.PrecheckActivation(serial)
		require.NoError(t, err)
		return plan
	}

	tests := []struct {
		name               string
		serial             string
		setup              func(*MockPolicyEngine, *SDNEnrollmentHook) ActivationPlan
		expectError        bool
		errorContains      string
		expectPendingAfter bool
	}{
		{
			name:   "successful activation",
			serial: "SRV-12345",
			setup: func(engine *MockPolicyEngine, hook *SDNEnrollmentHook) ActivationPlan {
				storePending(hook, "SRV-12345")
				engine.On("ApplyPolicy", "port1", mock.AnythingOfType("*policy.PortPolicy")).
					Return(nil).Once()
				return mustPlan(hook, "SRV-12345")
			},
			expectError:        false,
			expectPendingAfter: false,
		},
		{
			name:   "no pending activation",
			serial: "UNKNOWN-12345",
			setup: func(engine *MockPolicyEngine, hook *SDNEnrollmentHook) ActivationPlan {
				// A plan whose reserved record was never stored (or was
				// already consumed): nothing to consume, nothing applied.
				pending := &PendingActivation{
					PortID:      "port1",
					Profile:     createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100),
					Certificate: createEnrollmentCertificate(t, "TestOrg"),
					EnrolledAt:  time.Now(),
				}
				return &activationPlan{
					serial:  "UNKNOWN-12345",
					pending: pending,
					policy:  &PortPolicy{VLAN: 100},
				}
			},
			expectError:        true,
			errorContains:      "no pending activation found",
			expectPendingAfter: false,
		},
		{
			name:   "superseded by concurrent re-enrollment",
			serial: "SRV-12345",
			setup: func(engine *MockPolicyEngine, hook *SDNEnrollmentHook) ActivationPlan {
				storePending(hook, "SRV-12345")
				plan := mustPlan(hook, "SRV-12345")
				// A re-enrollment replaces the pending record after the
				// precheck: the plan's version is stale and must be
				// refused without applying anything (no engine
				// expectation is registered, so any ApplyPolicy call
				// fails the test).
				storePending(hook, "SRV-12345")
				return plan
			},
			expectError:        true,
			errorContains:      "superseded by a concurrent re-enrollment",
			expectPendingAfter: true,
		},
		{
			name:   "policy application failure",
			serial: "SRV-12345",
			setup: func(engine *MockPolicyEngine, hook *SDNEnrollmentHook) ActivationPlan {
				storePending(hook, "SRV-12345")
				engine.On("ApplyPolicy", "port1", mock.AnythingOfType("*policy.PortPolicy")).
					Return(&MessageError{Msg: "flow installation failed"}).Once()
				return mustPlan(hook, "SRV-12345")
			},
			expectError:        true,
			errorContains:      "failed to apply production policy",
			expectPendingAfter: true,
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

			plan := tt.setup(mockEngine, hook)

			_, err = hook.ActivateDevice(plan)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}

			_, ok := hook.PeekPendingActivation(tt.serial)
			assert.Equal(t, tt.expectPendingAfter, ok, "pending-activation retention mismatch")

			mockEngine.AssertExpectations(t)
			mockDAO.AssertExpectations(t)
		})
	}
}

// TestSDNEnrollmentHook_ReinstateActivation_RetryWithoutReenrollment is the
// transient-external-commit regression: a successful ActivateDevice whose
// caller's physical commit then fails is returned to a retryable state by
// ReinstateActivation — the next precheck sees the same pending record and
// the retry activates without re-enrollment. FinalizeActivation then
// releases the reservation for good.
func TestSDNEnrollmentHook_ReinstateActivation_RetryWithoutReenrollment(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	pending := &PendingActivation{
		PortID:      "port1",
		Profile:     createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100),
		Certificate: createEnrollmentCertificate(t, "TestOrg"),
		EnrolledAt:  time.Now(),
	}
	hook.pendingActivations.Store("SRV-RETRY", pending)

	mockEngine.On("ApplyPolicy", "port1", mock.AnythingOfType("*policy.PortPolicy")).
		Return(nil).Twice()

	// First attempt: SDN activation succeeds; the caller's physical commit
	// fails, so the plan is reinstated.
	plan1, err := hook.PrecheckActivation("SRV-RETRY")
	require.NoError(t, err)
	_, err = hook.ActivateDevice(plan1)
	require.NoError(t, err)
	hook.ReinstateActivation(plan1)

	// The same pending record is retryable — no re-enrollment happened.
	got, ok := hook.PeekPendingActivation("SRV-RETRY")
	require.True(t, ok, "the pending activation must be retryable after a failed external commit")
	assert.Same(t, pending, got)

	// Retry: precheck issues a fresh plan for the same record; activation
	// and finalize complete it.
	plan2, err := hook.PrecheckActivation("SRV-RETRY")
	require.NoError(t, err)
	_, err = hook.ActivateDevice(plan2)
	require.NoError(t, err)
	hook.FinalizeActivation(plan2)

	_, loaded := hook.pendingActivations.Load("SRV-RETRY")
	assert.False(t, loaded, "finalize must release the reservation")

	mockEngine.AssertExpectations(t)
}

// TestPrecheckActivation_MalformedZoneExtension_FailsClosed is the
// invalid-policy-input regression: a certificate whose OIDTPNetworkZone
// extension is present but unreadable must never fall back to the profile
// zone and receive the trusted policy — the precheck refuses to build any
// policy, so no plan is issued and no activation can be attempted.
func TestPrecheckActivation_MalformedZoneExtension_FailsClosed(t *testing.T) {
	zones, err := zone.Resolve(nil)
	require.NoError(t, err)
	extractor := NewX509PolicyExtractor(WithPolicyExtractorZones(zones))

	mockEngine := &MockPolicyEngine{}
	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   &MockDeviceProfileDAO{},
		Extractor:    extractor,
		Zones:        zones,
	})
	require.NoError(t, err)

	// A present-but-garbage zone extension.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(46),
		Subject:      pkix.Name{Organization: []string{"org"}, CommonName: "SRV-MALFORMED"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{
			Id:    quicbaasca.OIDTPNetworkZone,
			Value: []byte{0xff, 0x00, 0xba, 0xad},
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	pending := &PendingActivation{
		PortID: "port1",
		MAC:    "52:54:00:aa:bb:cc",
		Profile: &entities.DeviceProfile{
			ID:   4,
			Name: "malformed-profile",
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultPostEnrollmentNetwork: {VLAN: 200, Zone: "provisioning"},
				entities.DefaultFailureNetwork:        {VLAN: 666},
			},
		},
		Certificate: cert,
		EnrolledAt:  time.Now(),
	}
	hook.pendingActivations.Store("SRV-MALFORMED", pending)

	plan, err := hook.PrecheckActivation("SRV-MALFORMED")
	require.Nil(t, plan, "no plan may be issued for invalid policy input")
	var invalid ErrZoneExtensionInvalid
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "SRV-MALFORMED", invalid.Serial)

	// Nothing was applied and the pending activation is retained.
	got, ok := hook.PeekPendingActivation("SRV-MALFORMED")
	require.True(t, ok)
	assert.Same(t, pending, got)
	mockEngine.AssertExpectations(t)
}

// TestSDNEnrollmentHook_ActivateDevice_RejectsForeignAndNilPlans verifies
// that ActivateDevice consumes only plans produced by its own
// PrecheckActivation: a nil plan and a foreign ActivationPlan
// implementation are both refused before anything is touched.
func TestSDNEnrollmentHook_ActivateDevice_RejectsForeignAndNilPlans(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   &MockDeviceProfileDAO{},
	})
	require.NoError(t, err)

	_, err = hook.ActivateDevice(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil activation plan")

	_, err = hook.ActivateDevice(foreignActivationPlan{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not produced by this hook")

	mockEngine.AssertExpectations(t)
}

// foreignActivationPlan implements ActivationPlan outside the hook, to prove
// ActivateDevice refuses plans it did not issue.
type foreignActivationPlan struct{}

func (foreignActivationPlan) Serial() string                 { return "FOREIGN" }
func (foreignActivationPlan) VLANs() ActivationVLANs         { return ActivationVLANs{} }
func (foreignActivationPlan) ExpectQuarantine() bool         { return false }
func (foreignActivationPlan) ZoneMismatch() *ErrZoneMismatch { return nil }

// TestSDNEnrollmentHook_LockSerial_SerializesReenrollment is the concurrent
// re-enrollment regression: while an activation caller holds LockSerial —
// as the device activation handler does across its whole precheck ->
// switch move -> ActivateDevice sequence — OnEnrollmentComplete for the
// same serial must wait. The marker record stored under the lock proves the
// ordering: the enrollment's store lands strictly after it.
func TestSDNEnrollmentHook_LockSerial_SerializesReenrollment(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	profile := createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100)
	hook.macExtractor = testMACExtractor("52:54:00:12:34:56")
	mockDAO.On("ForEachPage", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(datastore.PagerFunc[*entities.DeviceProfile])
			_ = fn(datastore.PageResult[*entities.DeviceProfile]{Entities: []*entities.DeviceProfile{profile}})
		}).
		Return(&MessageError{Msg: "found"}).Once()
	hook.RegisterPort("52:54:00:12:34:56", "port1")
	mockEngine.On("GetPortState", "port1").Return(PortStateProvisioning, nil).Once()
	mockEngine.On("SetPortState", "port1", PortStateEnrolled).Return(nil).Once()

	event := &EnrollmentEvent{
		Context:       context.Background(),
		Certificate:   createEnrollmentCertificate(t, "TestOrg"),
		ClientIP:      "192.168.1.100",
		ProductSerial: "SRV-12345",
	}

	// Hold the serial lock the way the activation handler does.
	unlock := hook.LockSerial("SRV-12345")

	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- hook.OnEnrollmentComplete(event)
	}()
	<-started

	// Store the marker while holding the lock: a serialized enrollment can
	// only overwrite it after unlock.
	marker := &PendingActivation{PortID: "marker", EnrolledAt: time.Now()}
	hook.pendingActivations.Store("SRV-12345", marker)

	unlock()
	require.NoError(t, <-done)

	got, ok := hook.PeekPendingActivation("SRV-12345")
	require.True(t, ok)
	require.NotSame(t, marker, got,
		"the enrollment's store must land after the marker written under the lock")
	assert.Equal(t, "port1", got.PortID)

	mockEngine.AssertExpectations(t)
	mockDAO.AssertExpectations(t)
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

			policy, _ := hook.buildPortPolicy(profile, cert)
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

// TestSDNEnrollmentHook_ActivateDevice_PortBinderCalled verifies that a
// successful activation invokes the PortBinder callback with the correct serial
// and port ID so the device record is stamped.
func TestSDNEnrollmentHook_ActivateDevice_PortBinderCalled(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	var binderSerial, binderPortID string
	binder := func(ctx context.Context, serial, portID string) error {
		binderSerial = serial
		binderPortID = portID
		return nil
	}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
		PortBinder:   binder,
	})
	require.NoError(t, err)

	profile := createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100)
	cert := createEnrollmentCertificate(t, "TestOrg")
	hook.pendingActivations.Store("SRV-12345", &PendingActivation{
		PortID:      "tap0abc",
		Profile:     profile,
		Certificate: cert,
		EnrolledAt:  time.Now(),
	})

	mockEngine.On("ApplyPolicy", "tap0abc", mock.AnythingOfType("*policy.PortPolicy")).
		Return(nil).Once()

	plan, err := hook.PrecheckActivation("SRV-12345")
	require.NoError(t, err)
	_, err = hook.ActivateDevice(plan)
	require.NoError(t, err)

	if binderSerial != "SRV-12345" {
		t.Errorf("expected binder serial SRV-12345, got %q", binderSerial)
	}
	if binderPortID != "tap0abc" {
		t.Errorf("expected binder portID tap0abc, got %q", binderPortID)
	}
	mockEngine.AssertExpectations(t)
}

// TestSDNEnrollmentHook_ActivateDevice_PortBinderError verifies that a binder
// failure does not roll back the policy application — the device stays on the
// correct VLAN but activation still returns nil (binder errors are logged, not
// propagated, to avoid leaving the device in an ambiguous policy state).
func TestSDNEnrollmentHook_ActivateDevice_PortBinderError(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	binder := func(ctx context.Context, serial, portID string) error {
		return &MessageError{Msg: "storage unavailable"}
	}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
		PortBinder:   binder,
	})
	require.NoError(t, err)

	profile := createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100)
	cert := createEnrollmentCertificate(t, "TestOrg")
	hook.pendingActivations.Store("SRV-99999", &PendingActivation{
		PortID:      "tap99",
		Profile:     profile,
		Certificate: cert,
		EnrolledAt:  time.Now(),
	})

	mockEngine.On("ApplyPolicy", "tap99", mock.AnythingOfType("*policy.PortPolicy")).
		Return(nil).Once()

	// Binder failure must not propagate — device is on the correct VLAN.
	plan, err := hook.PrecheckActivation("SRV-99999")
	require.NoError(t, err)
	_, err = hook.ActivateDevice(plan)
	require.NoError(t, err, "binder error must not propagate")

	// Pending activation was consumed (success path); finalize releases
	// the reservation.
	hook.FinalizeActivation(plan)
	_, ok := hook.pendingActivations.Load("SRV-99999")
	assert.False(t, ok, "pending activation should be removed even when binder fails")

	mockEngine.AssertExpectations(t)
}

// TestBuildPortPolicy_ZoneCrossCheck verifies zone authoritative behaviour
// and mismatch quarantine in buildPortPolicy.
// TestActivateDevice_ZoneMismatch_RealEngineNoZoneFlowManager is the
// regression the fail-open finding asked for: with the REAL Engine and no
// ZoneFlowManager (the daemon's tolerated degraded state), a zone mismatch
// must never end with the port authorized on the trusted VLAN. The engine
// refuses the quarantine-zone policy outright (ErrZoneEnforcementUnavailable)
// and the hook turns that into a hard activation failure; with a real
// ZoneFlowManager the quarantine is enforced and the port reads as
// quarantined; a profile with no quarantine or provisioning VLAN fails
// closed before anything is committed.
func TestActivateDevice_ZoneMismatch_RealEngineNoZoneFlowManager(t *testing.T) {
	zones, err := zone.Resolve(nil)
	require.NoError(t, err)
	extractor := NewX509PolicyExtractor(WithPolicyExtractorZones(zones))

	certWithZone := func(t *testing.T, zoneName string) *x509.Certificate {
		t.Helper()
		ext, err := quicbaasca.CreateNetworkZoneExtension(zoneName)
		require.NoError(t, err)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := x509.Certificate{
			SerialNumber:    big.NewInt(44),
			Subject:         pkix.Name{Organization: []string{"org"}, CommonName: "SRV-MISMATCH"},
			NotBefore:       time.Now().Add(-time.Minute),
			NotAfter:        time.Now().Add(24 * time.Hour),
			ExtraExtensions: []pkix.Extension{ext},
		}
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert
	}

	newRealEngineHook := func(t *testing.T) (*SDNEnrollmentHook, *Engine) {
		t.Helper()
		engine, err := NewEngine(Config{
			BridgeName:     "br0",
			FlowController: newMockFlowController(),
			// No ZoneFlowManager: the VLAN-direct fallback is in force.
		})
		require.NoError(t, err)
		hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
			Logger:       slog.Default(),
			PolicyEngine: engine,
			ProfileDAO:   &MockDeviceProfileDAO{},
			Extractor:    extractor,
			Zones:        zones,
		})
		require.NoError(t, err)
		return hook, engine
	}

	// Cert says "trusted", profile says "provisioning": a zone mismatch.
	cert := certWithZone(t, "trusted")

	mismatchProfile := &entities.DeviceProfile{
		ID:   1,
		Name: "mismatch-profile",
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {VLAN: 200, Zone: "provisioning"},
			entities.DefaultFailureNetwork:        {VLAN: 666},
		},
	}

	t.Run("no zone flow manager - mismatch is a hard failure, port never authorized", func(t *testing.T) {
		hook, engine := newRealEngineHook(t)
		require.NoError(t, engine.SetPortState("port1", PortStateProvisioning))
		hook.pendingActivations.Store("SRV-MISMATCH", &PendingActivation{
			PortID:      "port1",
			MAC:         "52:54:00:aa:bb:cc",
			Profile:     mismatchProfile,
			Certificate: cert,
			EnrolledAt:  time.Now(),
		})

		plan, err := hook.PrecheckActivation("SRV-MISMATCH")
		require.NoError(t, err)
		require.True(t, plan.ExpectQuarantine(), "the precheck must predict the quarantine")

		_, err = hook.ActivateDevice(plan)
		var unavailable ErrZoneEnforcementUnavailable
		require.ErrorAs(t, err, &unavailable, "the engine must refuse a quarantine policy it cannot enforce")
		var mismatch ErrZoneMismatch
		assert.False(t, errors.As(err, &mismatch), "the failure must not read as a successful quarantine")

		// No policy was applied and the port never became authorized.
		_, err = engine.GetPortVLAN("port1")
		require.Error(t, err)
		state, err := engine.GetPortState("port1")
		require.NoError(t, err)
		assert.Equal(t, PortStateProvisioning, state)

		// The pending activation is retained.
		_, ok := hook.PeekPendingActivation("SRV-MISMATCH")
		assert.True(t, ok)
	})

	t.Run("with zone flow manager - mismatch is enforced as quarantine", func(t *testing.T) {
		engine := createTestEngineWithZones(t)
		hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
			Logger:       slog.Default(),
			PolicyEngine: engine,
			ProfileDAO:   &MockDeviceProfileDAO{},
			Extractor:    extractor,
			Zones:        zones,
		})
		require.NoError(t, err)
		hook.pendingActivations.Store("SRV-MISMATCH", &PendingActivation{
			PortID:      "port1",
			MAC:         "52:54:00:aa:bb:cc",
			Profile:     mismatchProfile,
			Certificate: cert,
			EnrolledAt:  time.Now(),
		})

		plan, err := hook.PrecheckActivation("SRV-MISMATCH")
		require.NoError(t, err)
		require.True(t, plan.ExpectQuarantine(), "the precheck must predict the quarantine")

		result, err := hook.ActivateDevice(plan)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, ActivationStatusQuarantined, result.Status)
		require.NotNil(t, result.ZoneMismatch)

		// The datapath VLAN is the zone-resolved quarantine VLAN, never the
		// trusted one; the result reports that VLAN; the port reads as
		// quarantined.
		vlan, err := engine.GetPortVLAN("port1")
		require.NoError(t, err)
		assert.NotEqual(t, uint16(200), vlan)
		assert.Equal(t, vlan, result.VLAN, "the result must report the VLAN actually applied")
		state, err := engine.GetPortState("port1")
		require.NoError(t, err)
		assert.Equal(t, PortStateQuarantined, state)
	})

	t.Run("mismatch without a quarantine or provisioning VLAN fails closed", func(t *testing.T) {
		hook, engine := newRealEngineHook(t)
		profile := &entities.DeviceProfile{
			ID:   2,
			Name: "no-quarantine-profile",
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultPostEnrollmentNetwork: {VLAN: 200, Zone: "provisioning"},
			},
		}
		require.NoError(t, engine.SetPortState("port1", PortStateProvisioning))
		hook.pendingActivations.Store("SRV-MISMATCH", &PendingActivation{
			PortID:      "port1",
			MAC:         "52:54:00:aa:bb:cc",
			Profile:     profile,
			Certificate: cert,
			EnrolledAt:  time.Now(),
		})

		// The precheck already refuses it — no plan is issued, so nothing
		// external can be committed on the strength of a quarantine that
		// cannot be applied, and no activation can even be attempted.
		plan, err := hook.PrecheckActivation("SRV-MISMATCH")
		var unavailable ErrQuarantineVLANUnavailable
		require.ErrorAs(t, err, &unavailable)
		require.Nil(t, plan)

		// No policy was applied and the port never became authorized.
		_, err = engine.GetPortVLAN("port1")
		require.Error(t, err)
		state, err := engine.GetPortState("port1")
		require.NoError(t, err)
		assert.Equal(t, PortStateProvisioning, state)

		// The pending activation is retained for a corrected profile.
		_, ok := hook.PeekPendingActivation("SRV-MISMATCH")
		assert.True(t, ok)
	})
}

// TestActivateDevice_QuarantineStateFailure_IsIndeterminate verifies that a
// quarantine policy applied to the datapath whose port cannot then be marked
// quarantined is reported as ErrQuarantineStateIndeterminate — never as a
// successful quarantine — and that the pending activation is retained.
func TestActivateDevice_QuarantineStateFailure_IsIndeterminate(t *testing.T) {
	zones, err := zone.Resolve(nil)
	require.NoError(t, err)
	extractor := NewX509PolicyExtractor(WithPolicyExtractorZones(zones))

	ext, err := quicbaasca.CreateNetworkZoneExtension("trusted")
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber:    big.NewInt(45),
		Subject:         pkix.Name{Organization: []string{"org"}, CommonName: "SRV-STATE"},
		NotBefore:       time.Now().Add(-time.Minute),
		NotAfter:        time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	mockEngine := &MockPolicyEngine{}
	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   &MockDeviceProfileDAO{},
		Extractor:    extractor,
		Zones:        zones,
	})
	require.NoError(t, err)

	pending := &PendingActivation{
		PortID: "port1",
		MAC:    "52:54:00:aa:bb:cc",
		Profile: &entities.DeviceProfile{
			ID:   3,
			Name: "state-profile",
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultPostEnrollmentNetwork: {VLAN: 200, Zone: "provisioning"},
				entities.DefaultFailureNetwork:        {VLAN: 666},
			},
		},
		Certificate: cert,
		EnrolledAt:  time.Now(),
	}
	hook.pendingActivations.Store("SRV-STATE", pending)

	// The quarantine policy applies, but the state machine refuses the
	// transition (e.g. a concurrent change moved the port elsewhere).
	mockEngine.On("ApplyPolicy", "port1", mock.AnythingOfType("*policy.PortPolicy")).Return(nil).Once()
	mockEngine.On("SetPortState", "port1", PortStateQuarantined).
		Return(&MessageError{Msg: "invalid state transition"}).Once()

	plan, err := hook.PrecheckActivation("SRV-STATE")
	require.NoError(t, err)
	result, err := hook.ActivateDevice(plan)
	require.Nil(t, result, "no outcome may be reported for an indeterminate state")
	var indeterminate ErrQuarantineStateIndeterminate
	require.ErrorAs(t, err, &indeterminate)
	assert.Equal(t, "port1", indeterminate.PortID)

	got, ok := hook.PeekPendingActivation("SRV-STATE")
	require.True(t, ok, "the pending activation must be retained")
	assert.Same(t, pending, got)

	mockEngine.AssertExpectations(t)
}

func TestBuildPortPolicy_ZoneCrossCheck(t *testing.T) {
	t.Parallel()

	zones, err := zone.Resolve(nil)
	require.NoError(t, err)

	extractor := NewX509PolicyExtractor(WithPolicyExtractorZones(zones))

	buildHook := func(t *testing.T) *SDNEnrollmentHook {
		t.Helper()
		mockEngine := &MockPolicyEngine{}
		mockDAO := &MockDeviceProfileDAO{}
		hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
			Logger:       slog.Default(),
			PolicyEngine: mockEngine,
			ProfileDAO:   mockDAO,
			Extractor:    extractor,
			Zones:        zones,
		})
		require.NoError(t, err)
		return hook
	}

	certWithZone := func(t *testing.T, org, zoneName string) *x509.Certificate {
		t.Helper()
		ext, err := quicbaasca.CreateNetworkZoneExtension(zoneName)
		require.NoError(t, err)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := x509.Certificate{
			SerialNumber:    big.NewInt(42),
			Subject:         pkix.Name{Organization: []string{org}, CommonName: "device-sn"},
			NotBefore:       time.Now().Add(-time.Minute),
			NotAfter:        time.Now().Add(24 * time.Hour),
			ExtraExtensions: []pkix.Extension{ext},
		}
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert
	}

	certNoZone := func(t *testing.T, org string) *x509.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := x509.Certificate{
			SerialNumber: big.NewInt(43),
			Subject:      pkix.Name{Organization: []string{org}},
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert
	}

	// profileWithZone creates a profile whose post-enrollment network is stored
	// under the default key "trusted" (entities.DefaultPostEnrollmentNetwork)
	// and whose failure network (the quarantine VLAN) is 666.
	profileWithZone := func(profileZone string) *entities.DeviceProfile {
		return &entities.DeviceProfile{
			ID:   1,
			Name: "test-profile",
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultPostEnrollmentNetwork: {
					VLAN: 200,
					Zone: profileZone,
					ACLs: []entities.ACLConfig{
						{Priority: 100, Protocol: "tcp", SrcIP: "0.0.0.0/0", DstIP: "0.0.0.0/0", DstPort: 443, Action: "allow"},
					},
				},
				entities.DefaultFailureNetwork: {
					VLAN: 666,
				},
			},
		}
	}

	t.Run("cert zone matches profile zone - cert is authoritative", func(t *testing.T) {
		hook := buildHook(t)
		cert := certWithZone(t, "org", "trusted")
		profile := profileWithZone("trusted")

		policy, err := hook.buildPortPolicy(profile, cert)
		require.NoError(t, err)
		require.NotNil(t, policy)
		assert.Equal(t, zone.Zone("trusted"), policy.Zone)
	})

	t.Run("cert zone differs from profile zone - quarantine applied", func(t *testing.T) {
		hook := buildHook(t)
		// Cert says "trusted" but profile says "provisioning" → mismatch
		cert := certWithZone(t, "org", "trusted")
		profile := profileWithZone("provisioning")

		policy, err := hook.buildPortPolicy(profile, cert)
		require.NotNil(t, policy)
		require.Error(t, err)
		var mismatch ErrZoneMismatch
		assert.ErrorAs(t, err, &mismatch)
		assert.Equal(t, zone.Zone("trusted"), mismatch.CertZone)
		assert.Equal(t, zone.Zone("provisioning"), mismatch.ProfileZone)
		// Policy zone is set to quarantine
		quarantine, _ := zone.ZoneForRole(zones, zone.LifecycleRoleQuarantine)
		assert.Equal(t, quarantine, policy.Zone)
		// The policy carries the failure-network VLAN and no production
		// ACLs, so the engine's VLAN-direct path still isolates the port.
		assert.Equal(t, uint16(666), policy.VLAN)
		assert.Empty(t, policy.ACLs)
	})

	t.Run("cert zone differs and no failure network - quarantine falls back to the provisioning VLAN", func(t *testing.T) {
		hook := buildHook(t)
		cert := certWithZone(t, "org", "trusted")
		profile := profileWithZone("provisioning")
		delete(profile.Networks, entities.DefaultFailureNetwork)
		profile.Networks[entities.DefaultEnrollmentNetwork] = &entities.NetworkPhaseConfig{VLAN: 998}

		policy, err := hook.buildPortPolicy(profile, cert)
		require.NotNil(t, policy)
		var mismatch ErrZoneMismatch
		require.ErrorAs(t, err, &mismatch)
		assert.Equal(t, uint16(998), policy.VLAN)
		assert.Empty(t, policy.ACLs)
	})

	t.Run("cert zone differs and quarantine VLAN equals trusted VLAN - contradiction", func(t *testing.T) {
		hook := buildHook(t)
		cert := certWithZone(t, "org", "trusted")
		profile := profileWithZone("provisioning")
		profile.Networks[entities.DefaultFailureNetwork].VLAN = 200

		policy, err := hook.buildPortPolicy(profile, cert)
		require.Nil(t, policy, "a quarantine that shares the trusted VLAN isolates nothing")
		var contradiction ErrQuarantinePolicyContradiction
		require.ErrorAs(t, err, &contradiction)
		assert.Equal(t, uint16(200), contradiction.VLAN)
	})

	t.Run("cert zone differs and no quarantine or provisioning VLAN - fails closed", func(t *testing.T) {
		hook := buildHook(t)
		cert := certWithZone(t, "org", "trusted")
		profile := profileWithZone("provisioning")
		delete(profile.Networks, entities.DefaultFailureNetwork)

		policy, err := hook.buildPortPolicy(profile, cert)
		require.Nil(t, policy, "no policy may be built when quarantine cannot be enforced")
		var unavailable ErrQuarantineVLANUnavailable
		require.ErrorAs(t, err, &unavailable)
		assert.Equal(t, "test-profile", unavailable.Profile)
	})

	t.Run("cert without zone extension falls back to profile zone", func(t *testing.T) {
		hook := buildHook(t)
		cert := certNoZone(t, "org")
		profile := profileWithZone("trusted")

		policy, err := hook.buildPortPolicy(profile, cert)
		require.NoError(t, err)
		require.NotNil(t, policy)
		// Backward-compat: profile zone is used
		assert.Equal(t, zone.Zone("trusted"), policy.Zone)
	})

	t.Run("no extractor configured - profile zone used unconditionally", func(t *testing.T) {
		mockEngine := &MockPolicyEngine{}
		mockDAO := &MockDeviceProfileDAO{}
		hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
			Logger:       slog.Default(),
			PolicyEngine: mockEngine,
			ProfileDAO:   mockDAO,
			// No Extractor — zone cross-check is skipped
		})
		require.NoError(t, err)

		cert := certWithZone(t, "org", "trusted")
		profile := profileWithZone("production")

		// Without extractor there is no cross-check even if zones differ
		policy, pErr := hook.buildPortPolicy(profile, cert)
		require.NoError(t, pErr)
		require.NotNil(t, policy)
		assert.Equal(t, zone.Zone("production"), policy.Zone)
	})
}
