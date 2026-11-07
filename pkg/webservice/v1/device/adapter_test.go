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

package device

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockDeviceService is a mock implementation of DeviceServiceInterface
type MockDeviceService struct {
	mock.Mock
}

func (m *MockDeviceService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.Device], error) {
	args := m.Called(ctx, query)
	return args.Get(0).(datastore.PageResult[*entities.Device]), args.Error(1)
}

// MockDeviceProfileService is a mock implementation of DeviceProfileServiceInterface
type MockDeviceProfileService struct {
	mock.Mock
}

func (m *MockDeviceProfileService) FindMatchingProfile(ctx context.Context, macAddr, serial, model string) (*entities.DeviceProfile, error) {
	args := m.Called(ctx, macAddr, serial, model)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.DeviceProfile), args.Error(1)
}

func (m *MockDeviceProfileService) FindProfileForDevice(ctx context.Context, dev *entities.Device) (*entities.DeviceProfile, error) {
	args := m.Called(ctx, dev)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.DeviceProfile), args.Error(1)
}

func TestNewProfileServiceAdapter(t *testing.T) {
	// Test with nil services - should not panic
	adapter := NewProfileServiceAdapter(nil, nil)
	require.NotNil(t, adapter)

	// Compile-time check: adapter is already ProfileService via return type
	_ = adapter
}

func TestNewProfileServiceAdapterWithInterfaces(t *testing.T) {
	mockDeviceService := &MockDeviceService{}
	mockProfileService := &MockDeviceProfileService{}

	adapter := NewProfileServiceAdapterWithInterfaces(mockDeviceService, mockProfileService)
	require.NotNil(t, adapter)

	// Compile-time check: adapter is already ProfileService via return type
	_ = adapter
}

func TestProfileServiceAdapter_GetBySerial_Success(t *testing.T) {
	mockDeviceService := &MockDeviceService{}
	mockProfileService := &MockDeviceProfileService{}
	ctx := context.Background()

	// Create test data
	testDevice := &entities.Device{
		ID:     1,
		Serial: "TEST-DEVICE-001",
		Model:  "TestModel",
	}

	testProfile := &entities.DeviceProfile{
		ID:   1,
		Name: "production-profile",
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN: 200,
				DHCP: true,
				DNS:  []string{"10.100.1.2"},
			},
		},
	}

	// Setup expectations
	mockDeviceService.On("Page", mock.Anything, mock.MatchedBy(func(q datastore.PageQuery) bool {
		return q.Page == 1 && q.PageSize == 100
	})).Return(datastore.PageResult[*entities.Device]{
		Entities: []*entities.Device{testDevice},
		Page:     1,
		PageSize: 100,
		HasMore:  false,
	}, nil)

	mockProfileService.On("FindMatchingProfile", mock.Anything, "", "TEST-DEVICE-001", "TestModel").
		Return(testProfile, nil)

	// Create adapter
	adapter := NewProfileServiceAdapterWithInterfaces(mockDeviceService, mockProfileService)

	// Execute
	result, err := adapter.GetBySerial(ctx, "TEST-DEVICE-001")

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "TEST-DEVICE-001", result.SerialNumber)
	assert.Equal(t, uint16(200), result.AdmittedNetwork.VLAN)
	assert.True(t, result.AdmittedNetwork.UseDHCP)

	mockDeviceService.AssertExpectations(t)
	mockProfileService.AssertExpectations(t)
}

func TestProfileServiceAdapter_GetBySerial_EmptySerial(t *testing.T) {
	mockDeviceService := &MockDeviceService{}
	mockProfileService := &MockDeviceProfileService{}
	ctx := context.Background()

	adapter := NewProfileServiceAdapterWithInterfaces(mockDeviceService, mockProfileService)

	// Execute
	result, err := adapter.GetBySerial(ctx, "")

	// Assert
	assert.ErrorIs(t, err, ErrProfileNotFoundBySerial)
	assert.Nil(t, result)

	// No calls should be made with empty serial
	mockDeviceService.AssertNotCalled(t, "Page")
	mockProfileService.AssertNotCalled(t, "FindMatchingProfile")
}

func TestProfileServiceAdapter_GetBySerial_DeviceNotFound(t *testing.T) {
	mockDeviceService := &MockDeviceService{}
	mockProfileService := &MockDeviceProfileService{}
	ctx := context.Background()

	// Setup expectations - no devices found
	mockDeviceService.On("Page", mock.Anything, mock.Anything).Return(
		datastore.PageResult[*entities.Device]{
			Entities: []*entities.Device{},
			Page:     1,
			PageSize: 100,
			HasMore:  false,
		}, nil)

	adapter := NewProfileServiceAdapterWithInterfaces(mockDeviceService, mockProfileService)

	// Execute
	result, err := adapter.GetBySerial(ctx, "NON-EXISTENT")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to find device by serial")

	mockDeviceService.AssertExpectations(t)
	mockProfileService.AssertNotCalled(t, "FindMatchingProfile")
}

func TestProfileServiceAdapter_GetBySerial_ProfileNotFound(t *testing.T) {
	mockDeviceService := &MockDeviceService{}
	mockProfileService := &MockDeviceProfileService{}
	ctx := context.Background()

	testDevice := &entities.Device{
		ID:     1,
		Serial: "DEVICE-WITHOUT-PROFILE",
		Model:  "TestModel",
	}

	// Setup expectations
	mockDeviceService.On("Page", mock.Anything, mock.Anything).Return(
		datastore.PageResult[*entities.Device]{
			Entities: []*entities.Device{testDevice},
			Page:     1,
			PageSize: 100,
			HasMore:  false,
		}, nil)

	mockProfileService.On("FindMatchingProfile", mock.Anything, "", "DEVICE-WITHOUT-PROFILE", "TestModel").
		Return(nil, datastore.ErrRecordNotFound)

	adapter := NewProfileServiceAdapterWithInterfaces(mockDeviceService, mockProfileService)

	// Execute
	result, err := adapter.GetBySerial(ctx, "DEVICE-WITHOUT-PROFILE")

	// Assert
	assert.ErrorIs(t, err, ErrProfileNotFoundBySerial)
	assert.Nil(t, result)

	mockDeviceService.AssertExpectations(t)
	mockProfileService.AssertExpectations(t)
}

func TestProfileServiceAdapter_GetBySerial_PageError(t *testing.T) {
	mockDeviceService := &MockDeviceService{}
	mockProfileService := &MockDeviceProfileService{}
	ctx := context.Background()

	// Setup expectations - page operation fails
	mockDeviceService.On("Page", mock.Anything, mock.Anything).Return(
		datastore.PageResult[*entities.Device]{}, assert.AnError)

	adapter := NewProfileServiceAdapterWithInterfaces(mockDeviceService, mockProfileService)

	// Execute
	result, err := adapter.GetBySerial(ctx, "DEVICE-001")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to find device by serial")

	mockDeviceService.AssertExpectations(t)
	mockProfileService.AssertNotCalled(t, "FindMatchingProfile")
}

func TestProfileServiceAdapter_GetBySerial_MultiplePages(t *testing.T) {
	mockDeviceService := &MockDeviceService{}
	mockProfileService := &MockDeviceProfileService{}
	ctx := context.Background()

	// Create devices for first page
	page1Devices := make([]*entities.Device, 100)
	for i := 0; i < 100; i++ {
		page1Devices[i] = &entities.Device{
			ID:     uint64(i + 1),
			Serial: "DEVICE-" + string(rune('A'+i)),
			Model:  "Model1",
		}
	}

	// Create devices for second page with our target device
	targetDevice := &entities.Device{
		ID:     101,
		Serial: "TARGET-DEVICE",
		Model:  "TargetModel",
	}
	page2Devices := []*entities.Device{targetDevice}

	testProfile := &entities.DeviceProfile{
		ID:   1,
		Name: "target-profile",
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN: 300,
				DHCP: false,
			},
		},
	}

	// Setup expectations for page 1
	mockDeviceService.On("Page", mock.Anything, mock.MatchedBy(func(q datastore.PageQuery) bool {
		return q.Page == 1
	})).Return(datastore.PageResult[*entities.Device]{
		Entities: page1Devices,
		Page:     1,
		PageSize: 100,
		HasMore:  true,
	}, nil).Once()

	// Setup expectations for page 2
	mockDeviceService.On("Page", mock.Anything, mock.MatchedBy(func(q datastore.PageQuery) bool {
		return q.Page == 2
	})).Return(datastore.PageResult[*entities.Device]{
		Entities: page2Devices,
		Page:     2,
		PageSize: 100,
		HasMore:  false,
	}, nil).Once()

	mockProfileService.On("FindMatchingProfile", mock.Anything, "", "TARGET-DEVICE", "TargetModel").
		Return(testProfile, nil)

	adapter := NewProfileServiceAdapterWithInterfaces(mockDeviceService, mockProfileService)

	// Execute
	result, err := adapter.GetBySerial(ctx, "TARGET-DEVICE")

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "TARGET-DEVICE", result.SerialNumber)
	assert.Equal(t, uint16(300), result.AdmittedNetwork.VLAN)

	mockDeviceService.AssertExpectations(t)
	mockProfileService.AssertExpectations(t)
}

func TestProfileServiceAdapter_GetBySerial_FindMatchingProfileError(t *testing.T) {
	mockDeviceService := &MockDeviceService{}
	mockProfileService := &MockDeviceProfileService{}
	ctx := context.Background()

	testDevice := &entities.Device{
		ID:     1,
		Serial: "DEVICE-001",
		Model:  "TestModel",
	}

	mockDeviceService.On("Page", mock.Anything, mock.Anything).Return(
		datastore.PageResult[*entities.Device]{
			Entities: []*entities.Device{testDevice},
			Page:     1,
			PageSize: 100,
			HasMore:  false,
		}, nil)

	// Profile service returns an error other than ErrRecordNotFound
	mockProfileService.On("FindMatchingProfile", mock.Anything, "", "DEVICE-001", "TestModel").
		Return(nil, assert.AnError)

	adapter := NewProfileServiceAdapterWithInterfaces(mockDeviceService, mockProfileService)

	// Execute
	result, err := adapter.GetBySerial(ctx, "DEVICE-001")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to find matching profile")

	mockDeviceService.AssertExpectations(t)
	mockProfileService.AssertExpectations(t)
}

func TestProfileServiceAdapter_GetBySerial_WithACLs(t *testing.T) {
	mockDeviceService := &MockDeviceService{}
	mockProfileService := &MockDeviceProfileService{}
	ctx := context.Background()

	testDevice := &entities.Device{
		ID:     1,
		Serial: "DEVICE-WITH-ACLS",
		Model:  "SecureModel",
	}

	testProfile := &entities.DeviceProfile{
		ID:   1,
		Name: "secure-profile",
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN: 500,
				DHCP: true,
				ACLs: []entities.ACLConfig{
					{
						Priority: 100,
						Protocol: "tcp",
						DstPort:  443,
						Action:   "allow",
					},
					{
						Priority: 90,
						Protocol: "udp",
						DstPort:  53,
						Action:   "allow",
					},
					{
						Priority: 10,
						Protocol: "any",
						Action:   "deny",
					},
				},
			},
		},
	}

	mockDeviceService.On("Page", mock.Anything, mock.Anything).Return(
		datastore.PageResult[*entities.Device]{
			Entities: []*entities.Device{testDevice},
			Page:     1,
			PageSize: 100,
			HasMore:  false,
		}, nil)

	mockProfileService.On("FindMatchingProfile", mock.Anything, "", "DEVICE-WITH-ACLS", "SecureModel").
		Return(testProfile, nil)

	adapter := NewProfileServiceAdapterWithInterfaces(mockDeviceService, mockProfileService)

	// Execute
	result, err := adapter.GetBySerial(ctx, "DEVICE-WITH-ACLS")

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "DEVICE-WITH-ACLS", result.SerialNumber)
	assert.Equal(t, uint16(500), result.AdmittedNetwork.VLAN)
	assert.Len(t, result.ACLs, 3)
	assert.Equal(t, "acl-0", result.ACLs[0].Name)
	assert.Equal(t, 100, result.ACLs[0].Priority)
	assert.Equal(t, "allow", result.ACLs[0].Action)

	mockDeviceService.AssertExpectations(t)
	mockProfileService.AssertExpectations(t)
}

func TestProfileServiceAdapter_GetBySerial_WithStaticIP(t *testing.T) {
	mockDeviceService := &MockDeviceService{}
	mockProfileService := &MockDeviceProfileService{}
	ctx := context.Background()

	testDevice := &entities.Device{
		ID:     1,
		Serial: "DEVICE-STATIC",
		Model:  "StaticModel",
	}

	testProfile := &entities.DeviceProfile{
		ID:   1,
		Name: "static-profile",
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN:     250,
				DHCP:     false,
				StaticIP: "10.200.50.100",
				Gateway:  "10.200.50.1",
				DNS:      []string{"10.200.50.2", "8.8.8.8"},
			},
		},
	}

	mockDeviceService.On("Page", mock.Anything, mock.Anything).Return(
		datastore.PageResult[*entities.Device]{
			Entities: []*entities.Device{testDevice},
			Page:     1,
			PageSize: 100,
			HasMore:  false,
		}, nil)

	mockProfileService.On("FindMatchingProfile", mock.Anything, "", "DEVICE-STATIC", "StaticModel").
		Return(testProfile, nil)

	adapter := NewProfileServiceAdapterWithInterfaces(mockDeviceService, mockProfileService)

	// Execute
	result, err := adapter.GetBySerial(ctx, "DEVICE-STATIC")

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "DEVICE-STATIC", result.SerialNumber)
	assert.Equal(t, uint16(250), result.AdmittedNetwork.VLAN)
	assert.False(t, result.AdmittedNetwork.UseDHCP)
	assert.Equal(t, "10.200.50.100", result.AdmittedNetwork.StaticIP)
	assert.Equal(t, "10.200.50.1", result.AdmittedNetwork.Gateway)
	assert.Equal(t, []string{"10.200.50.2", "8.8.8.8"}, result.AdmittedNetwork.DNS)

	mockDeviceService.AssertExpectations(t)
	mockProfileService.AssertExpectations(t)
}

func TestProfileServiceAdapter_GetBySerial_FirstDeviceMatches(t *testing.T) {
	mockDeviceService := &MockDeviceService{}
	mockProfileService := &MockDeviceProfileService{}
	ctx := context.Background()

	targetDevice := &entities.Device{
		ID:     1,
		Serial: "FIRST-DEVICE",
		Model:  "FirstModel",
	}

	otherDevices := []*entities.Device{
		targetDevice,
		{ID: 2, Serial: "SECOND-DEVICE", Model: "Model2"},
		{ID: 3, Serial: "THIRD-DEVICE", Model: "Model3"},
	}

	testProfile := &entities.DeviceProfile{
		ID:   1,
		Name: "first-profile",
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN: 100,
				DHCP: true,
			},
		},
	}

	mockDeviceService.On("Page", mock.Anything, mock.Anything).Return(
		datastore.PageResult[*entities.Device]{
			Entities: otherDevices,
			Page:     1,
			PageSize: 100,
			HasMore:  false,
		}, nil)

	mockProfileService.On("FindMatchingProfile", mock.Anything, "", "FIRST-DEVICE", "FirstModel").
		Return(testProfile, nil)

	adapter := NewProfileServiceAdapterWithInterfaces(mockDeviceService, mockProfileService)

	// Execute
	result, err := adapter.GetBySerial(ctx, "FIRST-DEVICE")

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "FIRST-DEVICE", result.SerialNumber)

	mockDeviceService.AssertExpectations(t)
	mockProfileService.AssertExpectations(t)
}

func TestProfileServiceAdapter_GetBySerial_LastDeviceMatches(t *testing.T) {
	mockDeviceService := &MockDeviceService{}
	mockProfileService := &MockDeviceProfileService{}
	ctx := context.Background()

	targetDevice := &entities.Device{
		ID:     3,
		Serial: "LAST-DEVICE",
		Model:  "LastModel",
	}

	devices := []*entities.Device{
		{ID: 1, Serial: "FIRST-DEVICE", Model: "Model1"},
		{ID: 2, Serial: "SECOND-DEVICE", Model: "Model2"},
		targetDevice,
	}

	testProfile := &entities.DeviceProfile{
		ID:   1,
		Name: "last-profile",
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN: 999,
				DHCP: false,
			},
		},
	}

	mockDeviceService.On("Page", mock.Anything, mock.Anything).Return(
		datastore.PageResult[*entities.Device]{
			Entities: devices,
			Page:     1,
			PageSize: 100,
			HasMore:  false,
		}, nil)

	mockProfileService.On("FindMatchingProfile", mock.Anything, "", "LAST-DEVICE", "LastModel").
		Return(testProfile, nil)

	adapter := NewProfileServiceAdapterWithInterfaces(mockDeviceService, mockProfileService)

	// Execute
	result, err := adapter.GetBySerial(ctx, "LAST-DEVICE")

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "LAST-DEVICE", result.SerialNumber)
	assert.Equal(t, uint16(999), result.AdmittedNetwork.VLAN)

	mockDeviceService.AssertExpectations(t)
	mockProfileService.AssertExpectations(t)
}
