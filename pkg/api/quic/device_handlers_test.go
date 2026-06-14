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

//go:build codec_msgpack

package quic

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// init initializes the codec for Device handler tests
func init() {
	// Set the default codec to MsgPack for encoding/decoding payloads
	_ = SetDefaultCodecType(codec.MsgPack)
}

// =============================================================================
// Mock Device Service
// =============================================================================

// mockDeviceService implements DeviceService for testing
type mockDeviceService struct {
	devices     map[uint64]*entities.Device
	saveError   error
	getError    error
	deleteError error
	updateError error
	countError  error
	pageError   error
	findError   error
}

func newMockDeviceService() *mockDeviceService {
	return &mockDeviceService{
		devices: make(map[uint64]*entities.Device),
	}
}

func (m *mockDeviceService) Save(ctx context.Context, device *entities.Device) error {
	if m.saveError != nil {
		return m.saveError
	}
	m.devices[device.ID] = device
	return nil
}

func (m *mockDeviceService) Get(ctx context.Context, id uint64) (*entities.Device, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	device, ok := m.devices[id]
	if !ok {
		return nil, errors.New("device not found")
	}
	return device, nil
}

func (m *mockDeviceService) Delete(ctx context.Context, device *entities.Device) error {
	if m.deleteError != nil {
		return m.deleteError
	}
	delete(m.devices, device.ID)
	return nil
}

func (m *mockDeviceService) Update(ctx context.Context, device *entities.Device) error {
	if m.updateError != nil {
		return m.updateError
	}
	m.devices[device.ID] = device
	return nil
}

func (m *mockDeviceService) Count(ctx context.Context) (int, error) {
	if m.countError != nil {
		return 0, m.countError
	}
	return len(m.devices), nil
}

func (m *mockDeviceService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.Device], error) {
	if m.pageError != nil {
		return datastore.PageResult[*entities.Device]{}, m.pageError
	}

	result := make([]*entities.Device, 0, len(m.devices))
	for _, d := range m.devices {
		result = append(result, d)
	}

	return datastore.PageResult[*entities.Device]{
		Entities: result,
		Page:     query.Page,
		PageSize: query.PageSize,
		Total:    len(result),
		HasMore:  false,
	}, nil
}

func (m *mockDeviceService) FindBySerial(ctx context.Context, serial string) (*entities.Device, error) {
	if m.findError != nil {
		return nil, m.findError
	}
	for _, d := range m.devices {
		if d.Serial == serial {
			return d, nil
		}
	}
	return nil, errors.New("device not found")
}

// FindByHostname finds a device by its IDevID hostname.
func (m *mockDeviceService) FindByHostname(ctx context.Context, hostname string) (*entities.Device, error) {
	for _, d := range m.devices {
		if d.Hostname == hostname {
			return d, nil
		}
	}
	return nil, errors.New("device not found by hostname")
}

// =============================================================================
// Mock Profile Service
// =============================================================================

// mockProfileService implements ProfileService for testing
type mockProfileService struct {
	profiles    map[uint64]*entities.DeviceProfile
	saveError   error
	getError    error
	deleteError error
	updateError error
	countError  error
	pageError   error
	findError   error
}

func newMockProfileService() *mockProfileService {
	return &mockProfileService{
		profiles: make(map[uint64]*entities.DeviceProfile),
	}
}

func (m *mockProfileService) Save(ctx context.Context, profile *entities.DeviceProfile) error {
	if m.saveError != nil {
		return m.saveError
	}
	m.profiles[profile.ID] = profile
	return nil
}

func (m *mockProfileService) Get(ctx context.Context, id uint64) (*entities.DeviceProfile, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	profile, ok := m.profiles[id]
	if !ok {
		return nil, errors.New("profile not found")
	}
	return profile, nil
}

func (m *mockProfileService) Delete(ctx context.Context, profile *entities.DeviceProfile) error {
	if m.deleteError != nil {
		return m.deleteError
	}
	delete(m.profiles, profile.ID)
	return nil
}

func (m *mockProfileService) Update(ctx context.Context, profile *entities.DeviceProfile) error {
	if m.updateError != nil {
		return m.updateError
	}
	m.profiles[profile.ID] = profile
	return nil
}

func (m *mockProfileService) Count(ctx context.Context) (int, error) {
	if m.countError != nil {
		return 0, m.countError
	}
	return len(m.profiles), nil
}

func (m *mockProfileService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.DeviceProfile], error) {
	if m.pageError != nil {
		return datastore.PageResult[*entities.DeviceProfile]{}, m.pageError
	}

	result := make([]*entities.DeviceProfile, 0, len(m.profiles))
	for _, p := range m.profiles {
		result = append(result, p)
	}

	return datastore.PageResult[*entities.DeviceProfile]{
		Entities: result,
		Page:     query.Page,
		PageSize: query.PageSize,
		Total:    len(result),
		HasMore:  false,
	}, nil
}

func (m *mockProfileService) FindByMACAddress(ctx context.Context, macAddr string) (*entities.DeviceProfile, error) {
	if m.findError != nil {
		return nil, m.findError
	}
	for _, p := range m.profiles {
		if p.MatchRules != nil && p.MatchRules.MACPrefix == macAddr {
			return p, nil
		}
	}
	return nil, errors.New("profile not found")
}

func (m *mockProfileService) FindBySerial(ctx context.Context, serial string) (*entities.DeviceProfile, error) {
	if m.findError != nil {
		return nil, m.findError
	}
	for _, p := range m.profiles {
		if p.MatchRules != nil && p.MatchRules.SerialPrefix == serial {
			return p, nil
		}
	}
	return nil, errors.New("profile not found")
}

func (m *mockProfileService) FindMatchingProfile(ctx context.Context, macAddr, serial, model string) (*entities.DeviceProfile, error) {
	if m.findError != nil {
		return nil, m.findError
	}
	for _, p := range m.profiles {
		if p.Model == model {
			return p, nil
		}
	}
	return nil, errors.New("profile not found")
}

// =============================================================================
// Test Helpers
// =============================================================================

func newDeviceTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelInfo, nil)
}

func createTestDeviceHandler() (*DeviceHandler, *mockDeviceService, *mockProfileService) {
	logger := newDeviceTestLogger()
	deviceService := newMockDeviceService()
	profileService := newMockProfileService()
	handler := NewDeviceHandler(logger, deviceService, profileService)
	return handler, deviceService, profileService
}

// createTestDevice creates a device in the registered state (ready for activation)
func createTestDevice(service *mockDeviceService, id uint64, serial string) *entities.Device {
	device := &entities.Device{
		ID:         id,
		Serial:     serial,
		Model:      "test-model",
		AttestPub:  "test-attest-pub",
		SigningPub: "test-signing-pub",
		EKCert:     "test-ek-cert",
		EventLog:   []byte("test-event-log"),
		HashAlgoId: 11,
		State:      entities.DeviceStateRegistered, // Set state for activation
	}
	service.devices[id] = device
	return device
}

// createActivatedTestDevice creates a device in the activated state (ready for attestation)
func createActivatedTestDevice(service *mockDeviceService, id uint64, serial string) *entities.Device {
	device := &entities.Device{
		ID:         id,
		Serial:     serial,
		Model:      "test-model",
		AttestPub:  "test-attest-pub",
		SigningPub: "test-signing-pub",
		EKCert:     "test-ek-cert",
		EventLog:   []byte("test-event-log"),
		HashAlgoId: 11,
		State:      entities.DeviceStateActivated, // Set state for attestation
	}
	service.devices[id] = device
	return device
}

func createTestProfile(service *mockProfileService, id uint64, name string) *entities.DeviceProfile {
	profile := &entities.DeviceProfile{
		ID:       id,
		Name:     name,
		Model:    "test-model",
		Role:     entities.DeviceRoleServer,
		EventLog: []byte("test-event-log"),
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
				VLAN:       100,
				StaticIP:   "192.168.1.10",
				Gateway:    "192.168.1.1",
				DNS:        []string{"8.8.8.8"},
				AuthMethod: entities.AuthMethod802_1X,
			},
		},
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix:    "52:54:00",
			SerialPrefix: "TEST",
			Model:        "test-model",
		},
	}
	service.profiles[id] = profile
	return profile
}

// =============================================================================
// Test: NewDeviceHandler
// =============================================================================

func TestNewDeviceHandler(t *testing.T) {
	t.Run("creates handler with valid inputs", func(t *testing.T) {
		logger := newDeviceTestLogger()
		deviceService := newMockDeviceService()
		profileService := newMockProfileService()
		handler := NewDeviceHandler(logger, deviceService, profileService)

		assert.NotNil(t, handler)
		assert.Equal(t, logger, handler.logger)
		assert.Equal(t, deviceService, handler.deviceService)
		assert.Equal(t, profileService, handler.profileService)
	})

	t.Run("creates handler with nil services", func(t *testing.T) {
		logger := newDeviceTestLogger()
		handler := NewDeviceHandler(logger, nil, nil)

		assert.NotNil(t, handler)
		assert.Nil(t, handler.deviceService)
		assert.Nil(t, handler.profileService)
	})
}

// =============================================================================
// Test: HandleRequest
// =============================================================================

func TestDeviceHandleRequest(t *testing.T) {
	t.Run("returns error for nil request", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()
		resp := handler.HandleRequest(context.Background(), nil)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error for unknown opcode", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()
		resp := handler.HandleRequest(context.Background(), &Request{Opcode: 0xFF})

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: Handle Device Register
// =============================================================================

func TestHandleRegisterDevice(t *testing.T) {
	ctx := context.Background()

	t.Run("registers device successfully", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		registerReq := &DeviceRegisterRequest{
			Serial:     "TEST-SERIAL-001",
			Model:      "test-model",
			AttestPub:  "attest-pub-key",
			SigningPub: "signing-pub-key",
			EKCert:     "ek-certificate",
			EventLog:   []byte("event-log-data"),
			HashAlgoID: 11,
		}

		payload, err := EncodePayload(registerReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceRegister,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var registerResp DeviceRegisterResponse
		err = DecodePayload(resp.Payload, &registerResp)
		require.NoError(t, err)

		assert.NotNil(t, registerResp.Device)
		assert.Equal(t, "TEST-SERIAL-001", registerResp.Device.Serial)
		assert.Equal(t, "test-model", registerResp.Device.Model)
		assert.Greater(t, registerResp.Timestamp, int64(0))
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewDeviceHandler(newDeviceTestLogger(), nil, nil)

		registerReq := &DeviceRegisterRequest{
			Serial: "TEST-SERIAL-001",
		}

		payload, err := EncodePayload(registerReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceRegister,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
		assert.Contains(t, string(resp.Payload), "not available")
	})

	t.Run("returns error for missing serial", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		registerReq := &DeviceRegisterRequest{
			Model: "test-model",
		}

		payload, err := EncodePayload(registerReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceRegister,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		req := &Request{
			Opcode:  OpDeviceRegister,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when save fails", func(t *testing.T) {
		handler, deviceService, _ := createTestDeviceHandler()
		deviceService.saveError = errors.New("database error")

		registerReq := &DeviceRegisterRequest{
			Serial: "TEST-SERIAL-001",
		}

		payload, err := EncodePayload(registerReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceRegister,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: Handle Device Get
// =============================================================================

func TestHandleGetDevice(t *testing.T) {
	ctx := context.Background()

	t.Run("gets device successfully", func(t *testing.T) {
		handler, deviceService, _ := createTestDeviceHandler()
		device := createTestDevice(deviceService, 1, "TEST-SERIAL-001")

		getReq := &DeviceGetRequest{ID: device.ID}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var getResp DeviceGetResponse
		err = DecodePayload(resp.Payload, &getResp)
		require.NoError(t, err)

		assert.NotNil(t, getResp.Device)
		assert.Equal(t, device.ID, getResp.Device.ID)
		assert.Equal(t, device.Serial, getResp.Device.Serial)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewDeviceHandler(newDeviceTestLogger(), nil, nil)

		getReq := &DeviceGetRequest{ID: 1}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		getReq := &DeviceGetRequest{}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for device not found", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		getReq := &DeviceGetRequest{ID: 999}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		req := &Request{
			Opcode:  OpDeviceGet,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: Handle Device List
// =============================================================================

func TestHandleListDevices(t *testing.T) {
	ctx := context.Background()

	t.Run("lists devices successfully", func(t *testing.T) {
		handler, deviceService, _ := createTestDeviceHandler()
		createTestDevice(deviceService, 1, "TEST-001")
		createTestDevice(deviceService, 2, "TEST-002")

		listReq := &DeviceListRequest{Page: 1, PageSize: 10}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp DeviceListResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.Devices, 2)
		assert.Equal(t, int32(2), listResp.Total)
	})

	t.Run("lists empty devices", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		listReq := &DeviceListRequest{Page: 1, PageSize: 10}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp DeviceListResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.Devices, 0)
		assert.Equal(t, int32(0), listResp.Total)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewDeviceHandler(newDeviceTestLogger(), nil, nil)

		listReq := &DeviceListRequest{Page: 1, PageSize: 10}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		req := &Request{
			Opcode:  OpDeviceList,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("uses default pagination when not specified", func(t *testing.T) {
		handler, deviceService, _ := createTestDeviceHandler()
		createTestDevice(deviceService, 1, "TEST-001")

		listReq := &DeviceListRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp DeviceListResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, int32(1), listResp.Page)
		assert.Equal(t, int32(deviceDefaultLimit), listResp.PageSize)
	})

	t.Run("caps page size at max", func(t *testing.T) {
		handler, deviceService, _ := createTestDeviceHandler()
		createTestDevice(deviceService, 1, "TEST-001")

		listReq := &DeviceListRequest{Page: 1, PageSize: 10000}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp DeviceListResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, int32(deviceMaxLimit), listResp.PageSize)
	})
}

// =============================================================================
// Test: Handle Device Update
// =============================================================================

func TestHandleUpdateDevice(t *testing.T) {
	ctx := context.Background()

	t.Run("updates device successfully", func(t *testing.T) {
		handler, deviceService, _ := createTestDeviceHandler()
		device := createTestDevice(deviceService, 1, "TEST-001")

		updateReq := &DeviceUpdateRequest{
			ID:    device.ID,
			Model: "updated-model",
		}

		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceUpdate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var updateResp DeviceUpdateResponse
		err = DecodePayload(resp.Payload, &updateResp)
		require.NoError(t, err)

		assert.NotNil(t, updateResp.Device)
		assert.Equal(t, "updated-model", updateResp.Device.Model)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewDeviceHandler(newDeviceTestLogger(), nil, nil)

		updateReq := &DeviceUpdateRequest{ID: 1, Model: "test"}

		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceUpdate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		updateReq := &DeviceUpdateRequest{Model: "test"}

		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceUpdate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for device not found", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		updateReq := &DeviceUpdateRequest{ID: 999, Model: "test"}

		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceUpdate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		req := &Request{
			Opcode:  OpDeviceUpdate,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: Handle Device Delete
// =============================================================================

func TestHandleDeleteDevice(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes device successfully", func(t *testing.T) {
		handler, deviceService, _ := createTestDeviceHandler()
		device := createTestDevice(deviceService, 1, "TEST-001")

		deleteReq := &DeviceDeleteRequest{ID: device.ID}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceUnregister,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		// Verify device is deleted
		_, exists := deviceService.devices[device.ID]
		assert.False(t, exists)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewDeviceHandler(newDeviceTestLogger(), nil, nil)

		deleteReq := &DeviceDeleteRequest{ID: 1}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceUnregister,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		deleteReq := &DeviceDeleteRequest{}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceUnregister,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for device not found", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		deleteReq := &DeviceDeleteRequest{ID: 999}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceUnregister,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		req := &Request{
			Opcode:  OpDeviceUnregister,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: Handle Device Activate
// =============================================================================

func TestDeviceHandleActivateDevice(t *testing.T) {
	ctx := context.Background()

	t.Run("activates device successfully", func(t *testing.T) {
		handler, deviceService, _ := createTestDeviceHandler()
		// Device must be in registered state to be activated
		device := createTestDevice(deviceService, 1, "TEST-001")

		activateReq := &DeviceActivateRequest{ID: device.ID}

		payload, err := EncodePayload(activateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceActivate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var activateResp DeviceActivateResponse
		err = DecodePayload(resp.Payload, &activateResp)
		require.NoError(t, err)

		assert.True(t, activateResp.Activated)

		// Verify device state was updated
		updatedDevice := deviceService.devices[device.ID]
		assert.Equal(t, entities.DeviceStateActivated, updatedDevice.State)
	})

	t.Run("returns error for device already activated", func(t *testing.T) {
		handler, deviceService, _ := createTestDeviceHandler()
		// Device in activated state cannot be activated again
		device := createActivatedTestDevice(deviceService, 1, "TEST-001")

		activateReq := &DeviceActivateRequest{ID: device.ID}

		payload, err := EncodePayload(activateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceActivate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		// Should fail because device is already activated
		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewDeviceHandler(newDeviceTestLogger(), nil, nil)

		activateReq := &DeviceActivateRequest{ID: 1}

		payload, err := EncodePayload(activateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceActivate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		activateReq := &DeviceActivateRequest{}

		payload, err := EncodePayload(activateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceActivate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for device not found", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		activateReq := &DeviceActivateRequest{ID: 999}

		payload, err := EncodePayload(activateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceActivate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		req := &Request{
			Opcode:  OpDeviceActivate,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: Handle Device Attest
// =============================================================================

func TestDeviceHandleAttestDevice(t *testing.T) {
	ctx := context.Background()

	t.Run("attests device successfully", func(t *testing.T) {
		handler, deviceService, _ := createTestDeviceHandler()
		// Device must be in activated state to be attested
		device := createActivatedTestDevice(deviceService, 1, "TEST-001")

		// Attestation requires nonce, quote, and signature
		attestReq := &DeviceAttestRequest{
			ID:        device.ID,
			Nonce:     []byte("test-nonce-12345"),
			Quote:     []byte("test-quote-data"),
			Signature: []byte("test-signature"),
			PCRValues: []byte("pcr-values"),
			EventLog:  []byte("event-log"),
		}

		payload, err := EncodePayload(attestReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var attestResp DeviceAttestResponse
		err = DecodePayload(resp.Payload, &attestResp)
		require.NoError(t, err)

		assert.True(t, attestResp.Attested)

		// Verify device state was updated
		updatedDevice := deviceService.devices[device.ID]
		assert.Equal(t, entities.DeviceStateAttested, updatedDevice.State)
	})

	t.Run("returns error for device not activated", func(t *testing.T) {
		handler, deviceService, _ := createTestDeviceHandler()
		// Device in registered state cannot be attested
		device := createTestDevice(deviceService, 1, "TEST-001")

		attestReq := &DeviceAttestRequest{
			ID:        device.ID,
			Nonce:     []byte("test-nonce"),
			Quote:     []byte("test-quote"),
			Signature: []byte("test-sig"),
		}

		payload, err := EncodePayload(attestReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		// Should fail because device is not activated
		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing attestation data", func(t *testing.T) {
		handler, deviceService, _ := createTestDeviceHandler()
		device := createActivatedTestDevice(deviceService, 1, "TEST-001")

		// Missing nonce, quote, signature
		attestReq := &DeviceAttestRequest{ID: device.ID}

		payload, err := EncodePayload(attestReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewDeviceHandler(newDeviceTestLogger(), nil, nil)

		attestReq := &DeviceAttestRequest{ID: 1}

		payload, err := EncodePayload(attestReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		attestReq := &DeviceAttestRequest{}

		payload, err := EncodePayload(attestReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for device not found", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		attestReq := &DeviceAttestRequest{ID: 999}

		payload, err := EncodePayload(attestReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		req := &Request{
			Opcode:  OpDeviceAttest,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: Handle Get Device State
// =============================================================================

func TestDeviceHandleGetDeviceState(t *testing.T) {
	ctx := context.Background()

	t.Run("gets device state successfully", func(t *testing.T) {
		handler, deviceService, _ := createTestDeviceHandler()
		device := createTestDevice(deviceService, 1, "TEST-001")

		stateReq := &DeviceStateRequest{ID: device.ID}

		payload, err := EncodePayload(stateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceGetState,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var stateResp DeviceStateResponse
		err = DecodePayload(resp.Payload, &stateResp)
		require.NoError(t, err)

		assert.NotEmpty(t, stateResp.State)
		assert.Equal(t, entities.DeviceStateRegistered.String(), stateResp.State)
	})

	t.Run("gets activated device state", func(t *testing.T) {
		handler, deviceService, _ := createTestDeviceHandler()
		device := createActivatedTestDevice(deviceService, 1, "TEST-001")

		stateReq := &DeviceStateRequest{ID: device.ID}

		payload, err := EncodePayload(stateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceGetState,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var stateResp DeviceStateResponse
		err = DecodePayload(resp.Payload, &stateResp)
		require.NoError(t, err)

		assert.Equal(t, entities.DeviceStateActivated.String(), stateResp.State)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewDeviceHandler(newDeviceTestLogger(), nil, nil)

		stateReq := &DeviceStateRequest{ID: 1}

		payload, err := EncodePayload(stateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceGetState,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		stateReq := &DeviceStateRequest{}

		payload, err := EncodePayload(stateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceGetState,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for device not found", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		stateReq := &DeviceStateRequest{ID: 999}

		payload, err := EncodePayload(stateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceGetState,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		req := &Request{
			Opcode:  OpDeviceGetState,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: Handle Profile Create
// =============================================================================

func TestDeviceHandleCreateProfile(t *testing.T) {
	ctx := context.Background()

	t.Run("creates profile successfully", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		createReq := &ProfileCreateRequest{
			Name:  "TEST-PROFILE-001",
			Model: "test-model",
			Role:  "server",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceCreateProfile,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var createResp ProfileCreateResponse
		err = DecodePayload(resp.Payload, &createResp)
		require.NoError(t, err)

		assert.NotNil(t, createResp.Profile)
		assert.Equal(t, "TEST-PROFILE-001", createResp.Profile.Name)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewDeviceHandler(newDeviceTestLogger(), nil, nil)

		createReq := &ProfileCreateRequest{
			Name: "TEST-PROFILE-001",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceCreateProfile,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		createReq := &ProfileCreateRequest{
			Model: "test-model",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceCreateProfile,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		req := &Request{
			Opcode:  OpDeviceCreateProfile,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: Handle Profile Get
// =============================================================================

func TestDeviceHandleGetProfile(t *testing.T) {
	ctx := context.Background()

	t.Run("gets profile successfully", func(t *testing.T) {
		handler, _, profileService := createTestDeviceHandler()
		profile := createTestProfile(profileService, 1, "TEST-PROFILE-001")

		getReq := &ProfileGetRequest{ID: profile.ID}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceGetProfile,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var getResp ProfileGetResponse
		err = DecodePayload(resp.Payload, &getResp)
		require.NoError(t, err)

		assert.NotNil(t, getResp.Profile)
		assert.Equal(t, profile.ID, getResp.Profile.ID)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewDeviceHandler(newDeviceTestLogger(), nil, nil)

		getReq := &ProfileGetRequest{ID: 1}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceGetProfile,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		getReq := &ProfileGetRequest{}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceGetProfile,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for profile not found", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		getReq := &ProfileGetRequest{ID: 999}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceGetProfile,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		req := &Request{
			Opcode:  OpDeviceGetProfile,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: Handle Profile List
// =============================================================================

func TestDeviceHandleListProfiles(t *testing.T) {
	ctx := context.Background()

	t.Run("lists profiles successfully", func(t *testing.T) {
		handler, _, profileService := createTestDeviceHandler()
		createTestProfile(profileService, 1, "PROFILE-001")
		createTestProfile(profileService, 2, "PROFILE-002")

		listReq := &ProfileListRequest{Page: 1, PageSize: 10}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceListProfiles,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp ProfileListResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.Profiles, 2)
		assert.Equal(t, int32(2), listResp.Total)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewDeviceHandler(newDeviceTestLogger(), nil, nil)

		listReq := &ProfileListRequest{Page: 1, PageSize: 10}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceListProfiles,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		req := &Request{
			Opcode:  OpDeviceListProfiles,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: Handle Profile Update
// =============================================================================

func TestDeviceHandleUpdateProfile(t *testing.T) {
	ctx := context.Background()

	t.Run("updates profile successfully", func(t *testing.T) {
		handler, _, profileService := createTestDeviceHandler()
		profile := createTestProfile(profileService, 1, "TEST-PROFILE-001")

		updateReq := &ProfileUpdateRequest{
			ID:    profile.ID,
			Name:  "UPDATED-PROFILE",
			Model: "updated-model",
		}

		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceSetProfile,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var updateResp ProfileUpdateResponse
		err = DecodePayload(resp.Payload, &updateResp)
		require.NoError(t, err)

		assert.NotNil(t, updateResp.Profile)
		assert.Equal(t, "UPDATED-PROFILE", updateResp.Profile.Name)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewDeviceHandler(newDeviceTestLogger(), nil, nil)

		updateReq := &ProfileUpdateRequest{ID: 1, Name: "test"}

		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceSetProfile,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		updateReq := &ProfileUpdateRequest{Name: "test"}

		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceSetProfile,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for profile not found", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		updateReq := &ProfileUpdateRequest{ID: 999, Name: "test"}

		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceSetProfile,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		req := &Request{
			Opcode:  OpDeviceSetProfile,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: Handle Profile Delete
// =============================================================================

func TestDeviceHandleDeleteProfile(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes profile successfully", func(t *testing.T) {
		handler, _, profileService := createTestDeviceHandler()
		profile := createTestProfile(profileService, 1, "TEST-PROFILE-001")

		deleteReq := &ProfileDeleteRequest{ID: profile.ID}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceDeleteProfile,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		// Verify profile is deleted
		_, exists := profileService.profiles[profile.ID]
		assert.False(t, exists)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewDeviceHandler(newDeviceTestLogger(), nil, nil)

		deleteReq := &ProfileDeleteRequest{ID: 1}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceDeleteProfile,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		deleteReq := &ProfileDeleteRequest{}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceDeleteProfile,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for profile not found", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		deleteReq := &ProfileDeleteRequest{ID: 999}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDeviceDeleteProfile,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()

		req := &Request{
			Opcode:  OpDeviceDeleteProfile,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: Error Types
// =============================================================================

func TestDeviceErrorTypes(t *testing.T) {
	t.Run("ErrDeviceServiceNotAvailable", func(t *testing.T) {
		err := ErrDeviceServiceNotAvailable{}
		assert.Contains(t, err.Error(), "not available")
	})

	t.Run("ErrProfileServiceNotAvailable", func(t *testing.T) {
		err := ErrProfileServiceNotAvailable{}
		assert.Contains(t, err.Error(), "not available")
	})

	t.Run("ErrDeviceMissingID", func(t *testing.T) {
		err := ErrDeviceMissingID{}
		assert.Contains(t, err.Error(), "ID")
	})

	t.Run("ErrDeviceMissingSerial", func(t *testing.T) {
		err := ErrDeviceMissingSerial{}
		assert.Contains(t, err.Error(), "serial")
	})

	t.Run("ErrProfileMissingID", func(t *testing.T) {
		err := ErrProfileMissingID{}
		assert.Contains(t, err.Error(), "ID")
	})

	t.Run("ErrProfileMissingName", func(t *testing.T) {
		err := ErrProfileMissingName{}
		assert.Contains(t, err.Error(), "name")
	})

	t.Run("ErrDeviceEncodingFailed", func(t *testing.T) {
		err := ErrDeviceEncodingFailed{Cause: errors.New("test")}
		assert.Contains(t, err.Error(), "encode")
		assert.Equal(t, errors.New("test"), err.Unwrap())
	})

	t.Run("ErrDeviceDecodingFailed", func(t *testing.T) {
		err := ErrDeviceDecodingFailed{Cause: errors.New("test")}
		assert.Contains(t, err.Error(), "decode")
		assert.Equal(t, errors.New("test"), err.Unwrap())
	})

	t.Run("ErrDeviceOperationFailed", func(t *testing.T) {
		err := ErrDeviceOperationFailed{Operation: "test", Cause: errors.New("test")}
		assert.Contains(t, err.Error(), "test")
		assert.Equal(t, errors.New("test"), err.Unwrap())
	})

	t.Run("ErrProfileOperationFailed", func(t *testing.T) {
		err := ErrProfileOperationFailed{Operation: "test", Cause: errors.New("test")}
		assert.Contains(t, err.Error(), "test")
		assert.Equal(t, errors.New("test"), err.Unwrap())
	})

	t.Run("ErrDeviceActivationFailed", func(t *testing.T) {
		err := ErrDeviceActivationFailed{DeviceID: 1, Reason: "test reason"}
		assert.Contains(t, err.Error(), "activation failed")
		assert.Contains(t, err.Error(), "test reason")
	})

	t.Run("ErrDeviceNotActivated", func(t *testing.T) {
		err := ErrDeviceNotActivated{DeviceID: 1}
		assert.Contains(t, err.Error(), "not activated")
	})

	t.Run("ErrAttestationFailed", func(t *testing.T) {
		err := ErrAttestationFailed{DeviceID: 1, Reason: "test reason"}
		assert.Contains(t, err.Error(), "attestation verification failed")
	})

	t.Run("ErrMissingAttestationData", func(t *testing.T) {
		err := ErrMissingAttestationData{Field: "nonce"}
		assert.Contains(t, err.Error(), "missing required attestation data")
		assert.Contains(t, err.Error(), "nonce")
	})
}

// =============================================================================
// Test: Device to Info Conversion
// =============================================================================

func TestDeviceToInfo(t *testing.T) {
	t.Run("converts device to info", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()
		device := &entities.Device{
			ID:         1,
			Serial:     "TEST-001",
			Model:      "test-model",
			AttestPub:  "attest-pub",
			SigningPub: "signing-pub",
			EKCert:     "ek-cert",
			EventLog:   []byte("event-log"),
			HashAlgoId: 11,
		}

		info := handler.deviceToInfo(device)

		assert.Equal(t, device.ID, info.ID)
		assert.Equal(t, device.Serial, info.Serial)
		assert.Equal(t, device.Model, info.Model)
		assert.Equal(t, device.AttestPub, info.AttestPub)
		assert.Equal(t, device.SigningPub, info.SigningPub)
		assert.Equal(t, device.EKCert, info.EKCert)
		assert.Equal(t, device.EventLog, info.EventLog)
		assert.Equal(t, device.HashAlgoId, info.HashAlgoID)
	})

	t.Run("handles nil device", func(t *testing.T) {
		handler, _, _ := createTestDeviceHandler()
		info := handler.deviceToInfo(nil)
		assert.Nil(t, info)
	})
}

// =============================================================================
// Test: Pagination Constants
// =============================================================================

func TestDevicePaginationConstants(t *testing.T) {
	assert.Equal(t, int32(50), deviceDefaultLimit)
	assert.Equal(t, int32(1000), deviceMaxLimit)
}

// =============================================================================
// Test: Error Response Mapping
// =============================================================================

func TestDeviceErrorResponseMapping(t *testing.T) {
	handler, _, _ := createTestDeviceHandler()

	t.Run("not found error", func(t *testing.T) {
		resp := handler.deviceErrorResponse(errors.New("not found"))
		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("already exists error", func(t *testing.T) {
		resp := handler.deviceErrorResponse(errors.New("already exists"))
		assert.Equal(t, StatusAlreadyExists, resp.Status)
	})

	t.Run("duplicate error", func(t *testing.T) {
		resp := handler.deviceErrorResponse(errors.New("duplicate"))
		assert.Equal(t, StatusAlreadyExists, resp.Status)
	})

	t.Run("invalid error", func(t *testing.T) {
		resp := handler.deviceErrorResponse(errors.New("invalid"))
		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("generic error", func(t *testing.T) {
		resp := handler.deviceErrorResponse(errors.New("some error"))
		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: Complete Flow - Device Lifecycle
// =============================================================================

func TestDeviceLifecycleFlow(t *testing.T) {
	ctx := context.Background()
	handler, _, _ := createTestDeviceHandler()

	// 1. Register device
	registerReq := &DeviceRegisterRequest{
		Serial:    "LIFECYCLE-TEST-001",
		Model:     "test-model",
		AttestPub: "test-attest-pub", // Required for attestation
	}
	payload, err := EncodePayload(registerReq)
	require.NoError(t, err, "failed to encode register request")

	resp := handler.HandleRequest(ctx, &Request{Opcode: OpDeviceRegister, Payload: payload})
	require.Equal(t, StatusOK, resp.Status, "register device failed: %s", string(resp.Payload))

	var registerResp DeviceRegisterResponse
	err = DecodePayload(resp.Payload, &registerResp)
	require.NoError(t, err, "failed to decode register response")
	require.NotNil(t, registerResp.Device, "register response device is nil")

	deviceID := registerResp.Device.ID

	// 2. Get device
	getReq := &DeviceGetRequest{ID: deviceID}
	payload, err = EncodePayload(getReq)
	require.NoError(t, err)

	resp = handler.HandleRequest(ctx, &Request{Opcode: OpDeviceGet, Payload: payload})
	require.Equal(t, StatusOK, resp.Status)

	// 3. Update device
	updateReq := &DeviceUpdateRequest{ID: deviceID, Model: "updated-model"}
	payload, err = EncodePayload(updateReq)
	require.NoError(t, err)

	resp = handler.HandleRequest(ctx, &Request{Opcode: OpDeviceUpdate, Payload: payload})
	require.Equal(t, StatusOK, resp.Status)

	// 4. Activate device
	activateReq := &DeviceActivateRequest{ID: deviceID}
	payload, err = EncodePayload(activateReq)
	require.NoError(t, err)

	resp = handler.HandleRequest(ctx, &Request{Opcode: OpDeviceActivate, Payload: payload})
	require.Equal(t, StatusOK, resp.Status)

	// 5. Attest device (requires nonce, quote, signature)
	attestReq := &DeviceAttestRequest{
		ID:        deviceID,
		Nonce:     []byte("lifecycle-test-nonce"),
		Quote:     []byte("lifecycle-test-quote"),
		Signature: []byte("lifecycle-test-sig"),
	}
	payload, err = EncodePayload(attestReq)
	require.NoError(t, err)

	resp = handler.HandleRequest(ctx, &Request{Opcode: OpDeviceAttest, Payload: payload})
	require.Equal(t, StatusOK, resp.Status)

	// 6. Get device state
	stateReq := &DeviceStateRequest{ID: deviceID}
	payload, err = EncodePayload(stateReq)
	require.NoError(t, err)

	resp = handler.HandleRequest(ctx, &Request{Opcode: OpDeviceGetState, Payload: payload})
	require.Equal(t, StatusOK, resp.Status)

	var stateResp DeviceStateResponse
	err = DecodePayload(resp.Payload, &stateResp)
	require.NoError(t, err)
	assert.Equal(t, entities.DeviceStateAttested.String(), stateResp.State)

	// 7. List devices
	listReq := &DeviceListRequest{Page: 1, PageSize: 10}
	payload, err = EncodePayload(listReq)
	require.NoError(t, err)

	resp = handler.HandleRequest(ctx, &Request{Opcode: OpDeviceList, Payload: payload})
	require.Equal(t, StatusOK, resp.Status)

	// 8. Delete device
	deleteReq := &DeviceDeleteRequest{ID: deviceID}
	payload, err = EncodePayload(deleteReq)
	require.NoError(t, err)

	resp = handler.HandleRequest(ctx, &Request{Opcode: OpDeviceUnregister, Payload: payload})
	require.Equal(t, StatusOK, resp.Status)

	// 9. Verify deletion
	payload, err = EncodePayload(getReq)
	require.NoError(t, err)

	resp = handler.HandleRequest(ctx, &Request{Opcode: OpDeviceGet, Payload: payload})
	assert.Equal(t, StatusNotFound, resp.Status)
}

// =============================================================================
// Test: Complete Flow - Profile Lifecycle
// =============================================================================

func TestProfileLifecycleFlow(t *testing.T) {
	ctx := context.Background()
	handler, _, _ := createTestDeviceHandler()

	// 1. Create profile
	createReq := &ProfileCreateRequest{
		Name:  "LIFECYCLE-PROFILE-001",
		Model: "test-model",
		Role:  "server",
	}
	payload, err := EncodePayload(createReq)
	require.NoError(t, err, "failed to encode create request")

	resp := handler.HandleRequest(ctx, &Request{Opcode: OpDeviceCreateProfile, Payload: payload})
	require.Equal(t, StatusOK, resp.Status, "create profile failed: %s", string(resp.Payload))

	var createResp ProfileCreateResponse
	err = DecodePayload(resp.Payload, &createResp)
	require.NoError(t, err, "failed to decode create response")
	require.NotNil(t, createResp.Profile, "create response profile is nil")

	profileID := createResp.Profile.ID

	// 2. Get profile
	getReq := &ProfileGetRequest{ID: profileID}
	payload, err = EncodePayload(getReq)
	require.NoError(t, err)

	resp = handler.HandleRequest(ctx, &Request{Opcode: OpDeviceGetProfile, Payload: payload})
	require.Equal(t, StatusOK, resp.Status)

	// 3. Update profile
	updateReq := &ProfileUpdateRequest{ID: profileID, Name: "UPDATED-PROFILE", Model: "updated-model"}
	payload, err = EncodePayload(updateReq)
	require.NoError(t, err)

	resp = handler.HandleRequest(ctx, &Request{Opcode: OpDeviceSetProfile, Payload: payload})
	require.Equal(t, StatusOK, resp.Status)

	// 4. List profiles
	listReq := &ProfileListRequest{Page: 1, PageSize: 10}
	payload, err = EncodePayload(listReq)
	require.NoError(t, err)

	resp = handler.HandleRequest(ctx, &Request{Opcode: OpDeviceListProfiles, Payload: payload})
	require.Equal(t, StatusOK, resp.Status)

	// 5. Delete profile
	deleteReq := &ProfileDeleteRequest{ID: profileID}
	payload, err = EncodePayload(deleteReq)
	require.NoError(t, err)

	resp = handler.HandleRequest(ctx, &Request{Opcode: OpDeviceDeleteProfile, Payload: payload})
	require.Equal(t, StatusOK, resp.Status)

	// 6. Verify deletion
	payload, err = EncodePayload(getReq)
	require.NoError(t, err)

	resp = handler.HandleRequest(ctx, &Request{Opcode: OpDeviceGetProfile, Payload: payload})
	assert.Equal(t, StatusNotFound, resp.Status)
}

// =============================================================================
// Test: Network Config Conversions
// =============================================================================

func TestNetworkInfoToEntity(t *testing.T) {
	t.Parallel()
	handler, _, _ := createTestDeviceHandler()

	t.Run("converts network info to entity with all fields", func(t *testing.T) {
		t.Parallel()
		info := &NetworkPhaseConfigInfo{
			VLAN:       100,
			StaticIP:   "192.168.1.10",
			Gateway:    "192.168.1.1",
			DNS:        []string{"8.8.8.8", "8.8.4.4"},
			AuthMethod: "802.1X",
		}

		entity := handler.networkInfoToEntity(info)

		assert.NotNil(t, entity)
		assert.Equal(t, uint16(100), entity.VLAN)
		assert.Equal(t, "192.168.1.10", entity.StaticIP)
		assert.Equal(t, "192.168.1.1", entity.Gateway)
		assert.Equal(t, []string{"8.8.8.8", "8.8.4.4"}, entity.DNS)
		assert.Equal(t, entities.AuthMethod("802.1X"), entity.AuthMethod)
	})

	t.Run("handles nil input", func(t *testing.T) {
		t.Parallel()
		entity := handler.networkInfoToEntity(nil)
		assert.Nil(t, entity)
	})

	t.Run("converts empty network info to entity", func(t *testing.T) {
		t.Parallel()
		info := &NetworkPhaseConfigInfo{}

		entity := handler.networkInfoToEntity(info)

		assert.NotNil(t, entity)
		assert.Equal(t, uint16(0), entity.VLAN)
		assert.Equal(t, "", entity.StaticIP)
		assert.Equal(t, "", entity.Gateway)
		assert.Nil(t, entity.DNS)
		assert.Equal(t, entities.AuthMethod(""), entity.AuthMethod)
	})

	t.Run("converts network info with empty DNS slice", func(t *testing.T) {
		t.Parallel()
		info := &NetworkPhaseConfigInfo{
			VLAN:       200,
			StaticIP:   "10.0.0.5",
			Gateway:    "10.0.0.1",
			DNS:        []string{},
			AuthMethod: "PSK",
		}

		entity := handler.networkInfoToEntity(info)

		assert.NotNil(t, entity)
		assert.Equal(t, uint16(200), entity.VLAN)
		assert.Equal(t, []string{}, entity.DNS)
	})
}

func TestNetworkEntityToInfo(t *testing.T) {
	t.Parallel()
	handler, _, _ := createTestDeviceHandler()

	t.Run("converts network entity to info with all fields", func(t *testing.T) {
		t.Parallel()
		entity := &entities.NetworkPhaseConfig{
			VLAN:       100,
			StaticIP:   "192.168.1.10",
			Gateway:    "192.168.1.1",
			DNS:        []string{"8.8.8.8", "8.8.4.4"},
			AuthMethod: entities.AuthMethod802_1X,
		}

		info := handler.networkEntityToInfo(entity)

		assert.NotNil(t, info)
		assert.Equal(t, uint16(100), info.VLAN)
		assert.Equal(t, "192.168.1.10", info.StaticIP)
		assert.Equal(t, "192.168.1.1", info.Gateway)
		assert.Equal(t, []string{"8.8.8.8", "8.8.4.4"}, info.DNS)
		assert.Equal(t, string(entities.AuthMethod802_1X), info.AuthMethod)
	})

	t.Run("handles nil input", func(t *testing.T) {
		t.Parallel()
		info := handler.networkEntityToInfo(nil)
		assert.Nil(t, info)
	})

	t.Run("converts empty network entity to info", func(t *testing.T) {
		t.Parallel()
		entity := &entities.NetworkPhaseConfig{}

		info := handler.networkEntityToInfo(entity)

		assert.NotNil(t, info)
		assert.Equal(t, uint16(0), info.VLAN)
		assert.Equal(t, "", info.StaticIP)
		assert.Equal(t, "", info.Gateway)
		assert.Nil(t, info.DNS)
		assert.Equal(t, "", info.AuthMethod)
	})
}

func TestNetworkConversionRoundTrip(t *testing.T) {
	t.Parallel()
	handler, _, _ := createTestDeviceHandler()

	t.Run("info to entity to info preserves data", func(t *testing.T) {
		t.Parallel()
		originalInfo := &NetworkPhaseConfigInfo{
			VLAN:       150,
			StaticIP:   "172.16.0.50",
			Gateway:    "172.16.0.1",
			DNS:        []string{"1.1.1.1"},
			AuthMethod: "PSK",
		}

		entity := handler.networkInfoToEntity(originalInfo)
		roundTripInfo := handler.networkEntityToInfo(entity)

		assert.Equal(t, originalInfo.VLAN, roundTripInfo.VLAN)
		assert.Equal(t, originalInfo.StaticIP, roundTripInfo.StaticIP)
		assert.Equal(t, originalInfo.Gateway, roundTripInfo.Gateway)
		assert.Equal(t, originalInfo.DNS, roundTripInfo.DNS)
		assert.Equal(t, originalInfo.AuthMethod, roundTripInfo.AuthMethod)
	})
}
