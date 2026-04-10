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

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// Mock device service for testing
type mockDeviceService struct {
	devices         map[uint64]*entities.Device
	saveErr         error
	getErr          error
	deleteErr       error
	updateErr       error
	countErr        error
	pageErr         error
	findBySerialErr error
}

func newMockDeviceService() *mockDeviceService {
	return &mockDeviceService{
		devices: make(map[uint64]*entities.Device),
	}
}

func (m *mockDeviceService) Save(ctx context.Context, device *entities.Device) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.devices[device.ID] = device
	return nil
}

func (m *mockDeviceService) Get(ctx context.Context, id uint64) (*entities.Device, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	device, ok := m.devices[id]
	if !ok {
		return nil, errors.New("device not found")
	}
	return device, nil
}

func (m *mockDeviceService) Delete(ctx context.Context, device *entities.Device) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.devices, device.ID)
	return nil
}

func (m *mockDeviceService) Update(ctx context.Context, device *entities.Device) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	if _, ok := m.devices[device.ID]; !ok {
		return errors.New("failed to get device for update")
	}
	m.devices[device.ID] = device
	return nil
}

func (m *mockDeviceService) Count(ctx context.Context) (int, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	return len(m.devices), nil
}

func (m *mockDeviceService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.Device], error) {
	if m.pageErr != nil {
		return datastore.PageResult[*entities.Device]{}, m.pageErr
	}
	result := datastore.PageResult[*entities.Device]{
		Entities: make([]*entities.Device, 0, len(m.devices)),
		Page:     query.Page,
		PageSize: query.PageSize,
		Total:    len(m.devices),
	}
	for _, d := range m.devices {
		result.Entities = append(result.Entities, d)
	}
	return result, nil
}

func (m *mockDeviceService) FindBySerial(ctx context.Context, serial string) (*entities.Device, error) {
	if m.findBySerialErr != nil {
		return nil, m.findBySerialErr
	}
	for _, d := range m.devices {
		if d.Serial == serial {
			return d, nil
		}
	}
	return nil, errors.New("device not found")
}

// Mock profile service for testing
type mockProfileService struct {
	profiles               map[uint64]*entities.DeviceProfile
	saveErr                error
	getErr                 error
	deleteErr              error
	updateErr              error
	countErr               error
	pageErr                error
	findByMACErr           error
	findBySerialErr        error
	findMatchingProfileErr error
}

func newMockProfileService() *mockProfileService {
	return &mockProfileService{
		profiles: make(map[uint64]*entities.DeviceProfile),
	}
}

func (m *mockProfileService) Save(ctx context.Context, profile *entities.DeviceProfile) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.profiles[profile.ID] = profile
	return nil
}

func (m *mockProfileService) Get(ctx context.Context, id uint64) (*entities.DeviceProfile, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	profile, ok := m.profiles[id]
	if !ok {
		return nil, errors.New("profile not found")
	}
	return profile, nil
}

func (m *mockProfileService) Delete(ctx context.Context, profile *entities.DeviceProfile) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.profiles, profile.ID)
	return nil
}

func (m *mockProfileService) Update(ctx context.Context, profile *entities.DeviceProfile) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	if _, ok := m.profiles[profile.ID]; !ok {
		return errors.New("failed to get profile for update")
	}
	m.profiles[profile.ID] = profile
	return nil
}

func (m *mockProfileService) Count(ctx context.Context) (int, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	return len(m.profiles), nil
}

func (m *mockProfileService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.DeviceProfile], error) {
	if m.pageErr != nil {
		return datastore.PageResult[*entities.DeviceProfile]{}, m.pageErr
	}
	result := datastore.PageResult[*entities.DeviceProfile]{
		Entities: make([]*entities.DeviceProfile, 0, len(m.profiles)),
		Page:     query.Page,
		PageSize: query.PageSize,
		Total:    len(m.profiles),
	}
	for _, p := range m.profiles {
		result.Entities = append(result.Entities, p)
	}
	return result, nil
}

func (m *mockProfileService) FindByMACAddress(ctx context.Context, macAddr string) (*entities.DeviceProfile, error) {
	if m.findByMACErr != nil {
		return nil, m.findByMACErr
	}
	for _, p := range m.profiles {
		if p.MatchRules != nil && p.MatchRules.MACPrefix == macAddr {
			return p, nil
		}
	}
	return nil, errors.New("profile not found")
}

func (m *mockProfileService) FindBySerial(ctx context.Context, serial string) (*entities.DeviceProfile, error) {
	if m.findBySerialErr != nil {
		return nil, m.findBySerialErr
	}
	for _, p := range m.profiles {
		if p.MatchRules != nil && p.MatchRules.SerialPrefix == serial {
			return p, nil
		}
	}
	return nil, errors.New("profile not found")
}

func (m *mockProfileService) FindMatchingProfile(ctx context.Context, macAddr, serial, model string) (*entities.DeviceProfile, error) {
	if m.findMatchingProfileErr != nil {
		return nil, m.findMatchingProfileErr
	}
	for _, p := range m.profiles {
		if p.MatchRules != nil {
			if p.MatchRules.Model == model || p.MatchRules.SerialPrefix == serial {
				return p, nil
			}
		}
	}
	return nil, errors.New("profile not found")
}

func TestNewDeviceGRPCService(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	logger := slog.Default()

	svc := NewDeviceGRPCService(deviceSvc, profileSvc, logger)
	require.NotNil(t, svc)
	assert.NotNil(t, svc.deviceService)
	assert.NotNil(t, svc.profileService)
	assert.NotNil(t, svc.logger)
}

func TestNewDeviceGRPCService_NilLogger(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()

	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)
	require.NotNil(t, svc)
	assert.NotNil(t, svc.logger)
}

func TestDeviceGRPCService_CreateDevice(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.CreateDeviceRequest{
		Device: &platformv1.Device{
			Id:     1,
			Model:  "TestTPM",
			Serial: "SN001",
		},
	}

	resp, err := svc.CreateDevice(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, uint64(1), resp.Device.Id)
	assert.Equal(t, "TestTPM", resp.Device.Model)
}

func TestDeviceGRPCService_CreateDevice_NilDevice(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.CreateDeviceRequest{Device: nil}

	resp, err := svc.CreateDevice(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDeviceGRPCService_CreateDevice_SaveError(t *testing.T) {
	deviceSvc := newMockDeviceService()
	deviceSvc.saveErr = errors.New("save failed")
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.CreateDeviceRequest{
		Device: &platformv1.Device{Id: 1},
	}

	resp, err := svc.CreateDevice(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDeviceGRPCService_GetDevice(t *testing.T) {
	deviceSvc := newMockDeviceService()
	deviceSvc.devices[1] = &entities.Device{
		ID:     1,
		Model:  "TestTPM",
		Serial: "SN001",
	}
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.GetDeviceRequest{Id: 1}

	resp, err := svc.GetDevice(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, uint64(1), resp.Device.Id)
	assert.Equal(t, "TestTPM", resp.Device.Model)
}

func TestDeviceGRPCService_GetDevice_ZeroID(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.GetDeviceRequest{Id: 0}

	resp, err := svc.GetDevice(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDeviceGRPCService_GetDevice_NotFound(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.GetDeviceRequest{Id: 999}

	resp, err := svc.GetDevice(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestDeviceGRPCService_UpdateDevice(t *testing.T) {
	deviceSvc := newMockDeviceService()
	deviceSvc.devices[1] = &entities.Device{
		ID:     1,
		Model:  "OldModel",
		Serial: "SN001",
	}
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.UpdateDeviceRequest{
		Device: &platformv1.Device{
			Id:     1,
			Model:  "NewModel",
			Serial: "SN001",
		},
	}

	resp, err := svc.UpdateDevice(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, "NewModel", resp.Device.Model)
}

func TestDeviceGRPCService_UpdateDevice_NilDevice(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.UpdateDeviceRequest{Device: nil}

	resp, err := svc.UpdateDevice(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDeviceGRPCService_UpdateDevice_UpdateError(t *testing.T) {
	deviceSvc := newMockDeviceService()
	deviceSvc.devices[1] = &entities.Device{ID: 1}
	deviceSvc.updateErr = errors.New("update failed")
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.UpdateDeviceRequest{
		Device: &platformv1.Device{Id: 1},
	}

	resp, err := svc.UpdateDevice(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDeviceGRPCService_DeleteDevice(t *testing.T) {
	deviceSvc := newMockDeviceService()
	deviceSvc.devices[1] = &entities.Device{ID: 1}
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.DeleteDeviceRequest{Id: 1}

	resp, err := svc.DeleteDevice(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)

	// Verify device is deleted
	_, exists := deviceSvc.devices[1]
	assert.False(t, exists)
}

func TestDeviceGRPCService_DeleteDevice_ZeroID(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.DeleteDeviceRequest{Id: 0}

	resp, err := svc.DeleteDevice(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDeviceGRPCService_DeleteDevice_NotFound(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.DeleteDeviceRequest{Id: 999}

	resp, err := svc.DeleteDevice(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestDeviceGRPCService_DeleteDevice_DeleteError(t *testing.T) {
	deviceSvc := newMockDeviceService()
	deviceSvc.devices[1] = &entities.Device{ID: 1}
	deviceSvc.deleteErr = errors.New("delete failed")
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.DeleteDeviceRequest{Id: 1}

	resp, err := svc.DeleteDevice(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDeviceGRPCService_ListDevices(t *testing.T) {
	deviceSvc := newMockDeviceService()
	for i := uint64(1); i <= 5; i++ {
		deviceSvc.devices[i] = &entities.Device{
			ID:     i,
			Model:  "TPM",
			Serial: "SN",
		}
	}
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.ListDevicesRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:     1,
			PageSize: 10,
		},
	}

	resp, err := svc.ListDevices(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Devices, 5)
}

func TestDeviceGRPCService_ListDevices_PageError(t *testing.T) {
	deviceSvc := newMockDeviceService()
	deviceSvc.pageErr = errors.New("page failed")
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.ListDevicesRequest{}

	resp, err := svc.ListDevices(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDeviceGRPCService_FindDeviceBySerial(t *testing.T) {
	deviceSvc := newMockDeviceService()
	deviceSvc.devices[1] = &entities.Device{
		ID:     1,
		Model:  "TPM",
		Serial: "SN001",
	}
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.FindDeviceBySerialRequest{Serial: "SN001"}

	resp, err := svc.FindDeviceBySerial(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, uint64(1), resp.Device.Id)
}

func TestDeviceGRPCService_FindDeviceBySerial_EmptySerial(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.FindDeviceBySerialRequest{Serial: ""}

	resp, err := svc.FindDeviceBySerial(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDeviceGRPCService_FindDeviceBySerial_NotFound(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.FindDeviceBySerialRequest{Serial: "NONEXISTENT"}

	resp, err := svc.FindDeviceBySerial(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDeviceGRPCService_CountDevices(t *testing.T) {
	deviceSvc := newMockDeviceService()
	deviceSvc.devices[1] = &entities.Device{ID: 1}
	deviceSvc.devices[2] = &entities.Device{ID: 2}
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.CountDevicesRequest{}

	resp, err := svc.CountDevices(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, int32(2), resp.Count)
}

func TestDeviceGRPCService_CountDevices_Error(t *testing.T) {
	deviceSvc := newMockDeviceService()
	deviceSvc.countErr = errors.New("count failed")
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.CountDevicesRequest{}

	resp, err := svc.CountDevices(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDeviceGRPCService_CreateProfile(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.CreateProfileRequest{
		Profile: &platformv1.DeviceProfile{
			Id:   1,
			Name: "TestProfile",
		},
	}

	resp, err := svc.CreateProfile(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, "TestProfile", resp.Profile.Name)
}

func TestDeviceGRPCService_CreateProfile_NilProfile(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.CreateProfileRequest{Profile: nil}

	resp, err := svc.CreateProfile(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDeviceGRPCService_CreateProfile_SaveError(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	profileSvc.saveErr = errors.New("save failed")
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.CreateProfileRequest{
		Profile: &platformv1.DeviceProfile{Id: 1, Name: "Test"},
	}

	resp, err := svc.CreateProfile(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDeviceGRPCService_GetProfile(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	profileSvc.profiles[1] = &entities.DeviceProfile{
		ID:   1,
		Name: "TestProfile",
	}
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.GetProfileRequest{Id: 1}

	resp, err := svc.GetProfile(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "TestProfile", resp.Profile.Name)
}

func TestDeviceGRPCService_GetProfile_ZeroID(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.GetProfileRequest{Id: 0}

	resp, err := svc.GetProfile(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDeviceGRPCService_GetProfile_NotFound(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.GetProfileRequest{Id: 999}

	resp, err := svc.GetProfile(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDeviceGRPCService_UpdateProfile(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	profileSvc.profiles[1] = &entities.DeviceProfile{
		ID:   1,
		Name: "OldName",
	}
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.UpdateProfileRequest{
		Profile: &platformv1.DeviceProfile{
			Id:   1,
			Name: "NewName",
		},
	}

	resp, err := svc.UpdateProfile(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, "NewName", resp.Profile.Name)
}

func TestDeviceGRPCService_UpdateProfile_NilProfile(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.UpdateProfileRequest{Profile: nil}

	resp, err := svc.UpdateProfile(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDeviceGRPCService_UpdateProfile_UpdateError(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	profileSvc.profiles[1] = &entities.DeviceProfile{ID: 1}
	profileSvc.updateErr = errors.New("update failed")
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.UpdateProfileRequest{
		Profile: &platformv1.DeviceProfile{Id: 1},
	}

	resp, err := svc.UpdateProfile(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDeviceGRPCService_DeleteProfile(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	profileSvc.profiles[1] = &entities.DeviceProfile{ID: 1}
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.DeleteProfileRequest{Id: 1}

	resp, err := svc.DeleteProfile(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
}

func TestDeviceGRPCService_DeleteProfile_ZeroID(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.DeleteProfileRequest{Id: 0}

	resp, err := svc.DeleteProfile(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDeviceGRPCService_DeleteProfile_NotFound(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.DeleteProfileRequest{Id: 999}

	resp, err := svc.DeleteProfile(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDeviceGRPCService_DeleteProfile_DeleteError(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	profileSvc.profiles[1] = &entities.DeviceProfile{ID: 1}
	profileSvc.deleteErr = errors.New("delete failed")
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.DeleteProfileRequest{Id: 1}

	resp, err := svc.DeleteProfile(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDeviceGRPCService_ListProfiles(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	profileSvc.profiles[1] = &entities.DeviceProfile{ID: 1, Name: "P1"}
	profileSvc.profiles[2] = &entities.DeviceProfile{ID: 2, Name: "P2"}
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.ListProfilesRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:     1,
			PageSize: 10,
		},
	}

	resp, err := svc.ListProfiles(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Profiles, 2)
}

func TestDeviceGRPCService_ListProfiles_PageError(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	profileSvc.pageErr = errors.New("page failed")
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.ListProfilesRequest{}

	resp, err := svc.ListProfiles(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDeviceGRPCService_FindProfileByMACAddress(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	profileSvc.profiles[1] = &entities.DeviceProfile{
		ID:   1,
		Name: "TestProfile",
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix: "AA:BB:CC",
		},
	}
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.FindProfileByMACAddressRequest{MacAddress: "AA:BB:CC"}

	resp, err := svc.FindProfileByMACAddress(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "TestProfile", resp.Profile.Name)
}

func TestDeviceGRPCService_FindProfileByMACAddress_EmptyMAC(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.FindProfileByMACAddressRequest{MacAddress: ""}

	resp, err := svc.FindProfileByMACAddress(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDeviceGRPCService_FindProfileByMACAddress_NotFound(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.FindProfileByMACAddressRequest{MacAddress: "FF:FF:FF"}

	resp, err := svc.FindProfileByMACAddress(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDeviceGRPCService_FindProfileBySerial(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	profileSvc.profiles[1] = &entities.DeviceProfile{
		ID:   1,
		Name: "TestProfile",
		MatchRules: &entities.ProfileMatchRules{
			SerialPrefix: "SN001",
		},
	}
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.FindProfileBySerialRequest{Serial: "SN001"}

	resp, err := svc.FindProfileBySerial(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "TestProfile", resp.Profile.Name)
}

func TestDeviceGRPCService_FindProfileBySerial_EmptySerial(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.FindProfileBySerialRequest{Serial: ""}

	resp, err := svc.FindProfileBySerial(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDeviceGRPCService_FindProfileBySerial_NotFound(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.FindProfileBySerialRequest{Serial: "NONEXISTENT"}

	resp, err := svc.FindProfileBySerial(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDeviceGRPCService_FindMatchingProfile(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	profileSvc.profiles[1] = &entities.DeviceProfile{
		ID:   1,
		Name: "TestProfile",
		MatchRules: &entities.ProfileMatchRules{
			Model: "TestModel",
		},
	}
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.FindMatchingProfileRequest{
		Model: "TestModel",
	}

	resp, err := svc.FindMatchingProfile(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "TestProfile", resp.Profile.Name)
}

func TestDeviceGRPCService_FindMatchingProfile_NotFound(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.FindMatchingProfileRequest{
		Model: "NonexistentModel",
	}

	resp, err := svc.FindMatchingProfile(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDeviceGRPCService_CountProfiles(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	profileSvc.profiles[1] = &entities.DeviceProfile{ID: 1}
	profileSvc.profiles[2] = &entities.DeviceProfile{ID: 2}
	profileSvc.profiles[3] = &entities.DeviceProfile{ID: 3}
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.CountProfilesRequest{}

	resp, err := svc.CountProfiles(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, int32(3), resp.Count)
}

func TestDeviceGRPCService_CountProfiles_Error(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	profileSvc.countErr = errors.New("count failed")
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.CountProfilesRequest{}

	resp, err := svc.CountProfiles(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDeviceGRPCService_ActivateDevice(t *testing.T) {
	deviceSvc := newMockDeviceService()
	deviceSvc.devices[1] = &entities.Device{
		ID:     1,
		Model:  "TestModel",
		Serial: "SN001",
	}
	profileSvc := newMockProfileService()
	profileSvc.profiles[1] = &entities.DeviceProfile{
		ID:   1,
		Name: "TestProfile",
		MatchRules: &entities.ProfileMatchRules{
			Model: "TestModel",
		},
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN: 100,
			},
		},
	}
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.ActivateDeviceRequest{Serial: "SN001"}

	resp, err := svc.ActivateDevice(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, "activated", resp.ActivationStatus)
	assert.Equal(t, uint32(100), resp.Vlan)
}

func TestDeviceGRPCService_ActivateDevice_EmptySerial(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.ActivateDeviceRequest{Serial: ""}

	resp, err := svc.ActivateDevice(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDeviceGRPCService_ActivateDevice_DeviceNotFound(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.ActivateDeviceRequest{Serial: "NONEXISTENT"}

	resp, err := svc.ActivateDevice(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDeviceGRPCService_ActivateDevice_ProfileNotFound(t *testing.T) {
	deviceSvc := newMockDeviceService()
	deviceSvc.devices[1] = &entities.Device{
		ID:     1,
		Model:  "TestModel",
		Serial: "SN001",
	}
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.ActivateDeviceRequest{Serial: "SN001"}

	resp, err := svc.ActivateDevice(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDeviceGRPCService_ActivateDevice_NoProductionNetwork(t *testing.T) {
	deviceSvc := newMockDeviceService()
	deviceSvc.devices[1] = &entities.Device{
		ID:     1,
		Model:  "TestModel",
		Serial: "SN001",
	}
	profileSvc := newMockProfileService()
	profileSvc.profiles[1] = &entities.DeviceProfile{
		ID:   1,
		Name: "TestProfile",
		MatchRules: &entities.ProfileMatchRules{
			Model: "TestModel",
		},
		// No ProductionNetwork set
	}
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	req := &platformv1.ActivateDeviceRequest{Serial: "SN001"}

	resp, err := svc.ActivateDevice(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, uint32(0), resp.Vlan) // No VLAN when no production network
}

func TestDeviceGRPCService_ConversionHelpers(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	t.Run("pbToDevice_nil", func(t *testing.T) {
		result := svc.pbToDevice(nil)
		assert.Nil(t, result)
	})

	t.Run("deviceToPb_nil", func(t *testing.T) {
		result := svc.deviceToPb(nil)
		assert.Nil(t, result)
	})

	t.Run("pbToProfile_nil", func(t *testing.T) {
		result := svc.pbToProfile(nil)
		assert.Nil(t, result)
	})

	t.Run("profileToPb_nil", func(t *testing.T) {
		result := svc.profileToPb(nil)
		assert.Nil(t, result)
	})

	t.Run("calculateTotalPages", func(t *testing.T) {
		assert.Equal(t, 0, svc.calculateTotalPages(10, 0))
		assert.Equal(t, 2, svc.calculateTotalPages(10, 5))
		assert.Equal(t, 3, svc.calculateTotalPages(11, 5))
		assert.Equal(t, 1, svc.calculateTotalPages(5, 10))
	})

	t.Run("toGRPCError_nil", func(t *testing.T) {
		result := svc.toGRPCError(nil)
		assert.Nil(t, result)
	})

	t.Run("deviceRoleToPb", func(t *testing.T) {
		assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_SERVER, svc.deviceRoleToPb(entities.DeviceRoleServer))
		assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_CLIENT, svc.deviceRoleToPb(entities.DeviceRoleClient))
		assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_WORKSTATION, svc.deviceRoleToPb(entities.DeviceRoleWorkstation))
		assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_EDGE, svc.deviceRoleToPb(entities.DeviceRoleEdge))
		assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_IOT, svc.deviceRoleToPb(entities.DeviceRoleIoT))
		assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_GATEWAY, svc.deviceRoleToPb(entities.DeviceRoleGateway))
		assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER, svc.deviceRoleToPb(entities.DeviceRoleLoadBalancer))
		assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_UNKNOWN, svc.deviceRoleToPb(entities.DeviceRoleUnknown))
	})

	t.Run("pbToDeviceRole_all_cases", func(t *testing.T) {
		assert.Equal(t, entities.DeviceRoleServer, svc.pbToDeviceRole(platformv1.DeviceRole_DEVICE_ROLE_SERVER))
		assert.Equal(t, entities.DeviceRoleClient, svc.pbToDeviceRole(platformv1.DeviceRole_DEVICE_ROLE_CLIENT))
		assert.Equal(t, entities.DeviceRoleWorkstation, svc.pbToDeviceRole(platformv1.DeviceRole_DEVICE_ROLE_WORKSTATION))
		assert.Equal(t, entities.DeviceRoleEdge, svc.pbToDeviceRole(platformv1.DeviceRole_DEVICE_ROLE_EDGE))
		assert.Equal(t, entities.DeviceRoleIoT, svc.pbToDeviceRole(platformv1.DeviceRole_DEVICE_ROLE_IOT))
		assert.Equal(t, entities.DeviceRoleGateway, svc.pbToDeviceRole(platformv1.DeviceRole_DEVICE_ROLE_GATEWAY))
		assert.Equal(t, entities.DeviceRoleLoadBalancer, svc.pbToDeviceRole(platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER))
		assert.Equal(t, entities.DeviceRoleUnknown, svc.pbToDeviceRole(platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED))
		assert.Equal(t, entities.DeviceRoleUnknown, svc.pbToDeviceRole(platformv1.DeviceRole_DEVICE_ROLE_UNKNOWN))
	})

	t.Run("authMethodToPb", func(t *testing.T) {
		assert.Equal(t, platformv1.AuthMethod_AUTH_METHOD_802_1X, svc.authMethodToPb(entities.AuthMethod802_1X))
		assert.Equal(t, platformv1.AuthMethod_AUTH_METHOD_NONE, svc.authMethodToPb(entities.AuthMethodNone))
	})

	t.Run("pbToAuthMethod", func(t *testing.T) {
		assert.Equal(t, entities.AuthMethod802_1X, svc.pbToAuthMethod(platformv1.AuthMethod_AUTH_METHOD_802_1X))
		assert.Equal(t, entities.AuthMethodNone, svc.pbToAuthMethod(platformv1.AuthMethod_AUTH_METHOD_UNSPECIFIED))
	})
}

func TestDeviceGRPCService_pbToDevice_WithAllFields(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	pb := &platformv1.Device{
		Id:         123,
		AttestPub:  "attest-pub-data",
		EkCert:     "ek-cert-data",
		EventLog:   []byte{0x01, 0x02, 0x03},
		HashAlgoId: 11,
		Model:      "TestModel",
		Serial:     "SN12345",
		SigningPub: "signing-pub-data",
	}

	result := svc.pbToDevice(pb)
	require.NotNil(t, result)
	assert.Equal(t, uint64(123), result.ID)
	assert.Equal(t, "attest-pub-data", result.AttestPub)
	assert.Equal(t, "ek-cert-data", result.EKCert)
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, result.EventLog)
	assert.Equal(t, uint32(11), result.HashAlgoId)
	assert.Equal(t, "TestModel", result.Model)
	assert.Equal(t, "SN12345", result.Serial)
	assert.Equal(t, "signing-pub-data", result.SigningPub)
}

func TestDeviceGRPCService_deviceToPb_WithAllFields(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	device := &entities.Device{
		ID:         456,
		AttestPub:  "attest-pub",
		EKCert:     "ek-cert",
		EventLog:   []byte{0x04, 0x05},
		HashAlgoId: 7,
		Model:      "Model123",
		Serial:     "Serial456",
		SigningPub: "signing-pub",
	}

	result := svc.deviceToPb(device)
	require.NotNil(t, result)
	assert.Equal(t, uint64(456), result.Id)
	assert.Equal(t, "attest-pub", result.AttestPub)
	assert.Equal(t, "ek-cert", result.EkCert)
	assert.Equal(t, []byte{0x04, 0x05}, result.EventLog)
	assert.Equal(t, uint32(7), result.HashAlgoId)
	assert.Equal(t, "Model123", result.Model)
	assert.Equal(t, "Serial456", result.Serial)
	assert.Equal(t, "signing-pub", result.SigningPub)
}

func TestDeviceGRPCService_pbToProfile_WithAllNetworkConfigs(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	pb := &platformv1.DeviceProfile{
		Id:       100,
		Name:     "FullProfile",
		Model:    "TestModel",
		Role:     platformv1.DeviceRole_DEVICE_ROLE_SERVER,
		EventLog: []byte{0x10, 0x20},
		ProvisioningNetwork: &platformv1.NetworkPhaseConfig{
			Vlan:       10,
			StaticIp:   "192.168.1.100",
			Gateway:    "192.168.1.1",
			AuthMethod: platformv1.AuthMethod_AUTH_METHOD_802_1X,
			Subnet:     "192.168.1.0/24",
			Dhcp:       true,
			DhcpPool: &platformv1.DHCPPoolConfig{
				Network:    "192.168.1.0/24",
				RangeStart: "192.168.1.10",
				RangeEnd:   "192.168.1.50",
				LeaseTime:  3600,
			},
			Acls: []*platformv1.ACLConfig{
				{
					Priority: 1,
					Protocol: "tcp",
					SrcIp:    "192.168.1.0/24",
					DstIp:    "0.0.0.0/0",
					SrcPort:  0,
					DstPort:  443,
					Action:   "allow",
				},
			},
		},
		ProductionNetwork: &platformv1.NetworkPhaseConfig{
			Vlan:    20,
			Gateway: "10.0.0.1",
		},
		QuarantineNetwork: &platformv1.NetworkPhaseConfig{
			Vlan:         999,
			FirewallZone: "quarantine",
		},
		PlatformdConfig: &platformv1.PlatformdConfigRef{
			ConfigType: "reference",
			Reference:  "/etc/platformd/config.yaml",
			ConfigName: "default",
			ConfigPath: "/configs",
			Version:    "1.0.0",
		},
		MatchRules: &platformv1.ProfileMatchRules{
			MacPrefix:         "AA:BB:CC",
			SerialPrefix:      "SN",
			Model:             "TestModel",
			ModelPattern:      "Test*",
			SerialPattern:     "SN*",
			ManufacturerMatch: "Acme",
			TpmVendor:         "TPM2.0",
			CustomAttributes:  map[string]string{"env": "prod"},
		},
	}

	result := svc.pbToProfile(pb)
	require.NotNil(t, result)
	assert.Equal(t, uint64(100), result.ID)
	assert.Equal(t, "FullProfile", result.Name)
	assert.Equal(t, "TestModel", result.Model)
	assert.Equal(t, entities.DeviceRoleServer, result.Role)
	assert.Equal(t, []byte{0x10, 0x20}, result.EventLog)

	// Check provisioning network
	require.NotNil(t, result.GetEnrollmentNetworkConfig())
	assert.Equal(t, uint16(10), result.GetEnrollmentNetworkConfig().VLAN)
	assert.Equal(t, "192.168.1.100", result.GetEnrollmentNetworkConfig().StaticIP)
	assert.Equal(t, "192.168.1.1", result.GetEnrollmentNetworkConfig().Gateway)
	assert.Equal(t, entities.AuthMethod802_1X, result.GetEnrollmentNetworkConfig().AuthMethod)
	assert.True(t, result.GetEnrollmentNetworkConfig().DHCP)
	require.NotNil(t, result.GetEnrollmentNetworkConfig().DHCPPool)
	assert.Equal(t, "192.168.1.0/24", result.GetEnrollmentNetworkConfig().DHCPPool.Network)
	assert.Equal(t, 3600, result.GetEnrollmentNetworkConfig().DHCPPool.LeaseTime)
	require.Len(t, result.GetEnrollmentNetworkConfig().ACLs, 1)
	assert.Equal(t, 1, result.GetEnrollmentNetworkConfig().ACLs[0].Priority)
	assert.Equal(t, "allow", result.GetEnrollmentNetworkConfig().ACLs[0].Action)

	// Check production network
	require.NotNil(t, result.GetPostEnrollmentNetworkConfig())
	assert.Equal(t, uint16(20), result.GetPostEnrollmentNetworkConfig().VLAN)

	// Check quarantine network
	require.NotNil(t, result.GetFailureNetworkConfig())
	assert.Equal(t, uint16(999), result.GetFailureNetworkConfig().VLAN)
	assert.Equal(t, "quarantine", result.GetFailureNetworkConfig().FirewallZone)

	// Check platformd config
	require.NotNil(t, result.PlatformdConfig)
	assert.Equal(t, "reference", result.PlatformdConfig.ConfigType)
	assert.Equal(t, "/etc/platformd/config.yaml", result.PlatformdConfig.Reference)

	// Check match rules
	require.NotNil(t, result.MatchRules)
	assert.Equal(t, "AA:BB:CC", result.MatchRules.MACPrefix)
	assert.Equal(t, "SN", result.MatchRules.SerialPrefix)
	assert.Equal(t, "TestModel", result.MatchRules.Model)
	assert.Equal(t, "Acme", result.MatchRules.ManufacturerMatch)
	assert.Equal(t, "TPM2.0", result.MatchRules.TPMVendor)
	assert.Equal(t, "prod", result.MatchRules.CustomAttributes["env"])
}

func TestDeviceGRPCService_profileToPb_WithAllNetworkConfigs(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	profile := &entities.DeviceProfile{
		ID:       200,
		Name:     "CompleteProfile",
		Model:    "CompleteModel",
		Role:     entities.DeviceRoleGateway,
		EventLog: []byte{0x30, 0x40},
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
				VLAN:       30,
				StaticIP:   "10.0.0.100",
				Gateway:    "10.0.0.1",
				DNS:        []string{"8.8.8.8"},
				AuthMethod: entities.AuthMethod802_1X,
				Subnet:     "10.0.0.0/24",
				DNSServers: []string{"8.8.4.4"},
				DHCP:       false,
				DHCPPool: &entities.DHCPPoolConfig{
					Network:    "10.0.0.0/24",
					RangeStart: "10.0.0.10",
					RangeEnd:   "10.0.0.100",
					LeaseTime:  7200,
				},
				ACLs: []entities.ACLConfig{
					{
						Priority: 10,
						Protocol: "udp",
						SrcIP:    "10.0.0.0/24",
						DstIP:    "0.0.0.0/0",
						SrcPort:  0,
						DstPort:  53,
						Action:   "allow",
					},
				},
				FirewallZone: "trusted",
			},
			entities.DefaultPostEnrollmentNetwork: {
				VLAN:    40,
				Gateway: "172.16.0.1",
			},
			entities.DefaultFailureNetwork: {
				VLAN:         888,
				FirewallZone: "isolated",
			},
		},
		PlatformdConfig: &entities.PlatformdConfigRef{
			ConfigType: "inline",
			Reference:  "/config/platformd.yaml",
			ConfigName: "production",
			ConfigPath: "/etc/platformd",
			Version:    "2.0.0",
		},
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix:         "DD:EE:FF",
			SerialPrefix:      "DEV",
			Model:             "CompleteModel",
			ModelPattern:      "Complete*",
			SerialPattern:     "DEV*",
			ManufacturerMatch: "Corp",
			TPMVendor:         "Infineon",
			CustomAttributes:  map[string]string{"tier": "premium"},
		},
	}

	result := svc.profileToPb(profile)
	require.NotNil(t, result)
	assert.Equal(t, uint64(200), result.Id)
	assert.Equal(t, "CompleteProfile", result.Name)
	assert.Equal(t, "CompleteModel", result.Model)
	assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_GATEWAY, result.Role)
	assert.Equal(t, []byte{0x30, 0x40}, result.EventLog)

	// Check provisioning network
	require.NotNil(t, result.ProvisioningNetwork)
	assert.Equal(t, uint32(30), result.ProvisioningNetwork.Vlan)
	assert.Equal(t, "10.0.0.100", result.ProvisioningNetwork.StaticIp)
	assert.Equal(t, entities.AuthMethod802_1X.String(), svc.pbToAuthMethod(result.ProvisioningNetwork.AuthMethod).String())
	require.NotNil(t, result.ProvisioningNetwork.DhcpPool)
	assert.Equal(t, "10.0.0.0/24", result.ProvisioningNetwork.DhcpPool.Network)
	require.Len(t, result.ProvisioningNetwork.Acls, 1)
	assert.Equal(t, "allow", result.ProvisioningNetwork.Acls[0].Action)

	// Check production network
	require.NotNil(t, result.ProductionNetwork)
	assert.Equal(t, uint32(40), result.ProductionNetwork.Vlan)

	// Check quarantine network
	require.NotNil(t, result.QuarantineNetwork)
	assert.Equal(t, uint32(888), result.QuarantineNetwork.Vlan)

	// Check platformd config
	require.NotNil(t, result.PlatformdConfig)
	assert.Equal(t, "inline", result.PlatformdConfig.ConfigType)

	// Check match rules
	require.NotNil(t, result.MatchRules)
	assert.Equal(t, "DD:EE:FF", result.MatchRules.MacPrefix)
	assert.Equal(t, "premium", result.MatchRules.CustomAttributes["tier"])
}

func TestDeviceGRPCService_pbToNetworkPhaseConfig_Nil(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	result := svc.pbToNetworkPhaseConfig(nil)
	assert.Nil(t, result)
}

func TestDeviceGRPCService_pbToNetworkPhaseConfig_WithDHCPPool(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	pb := &platformv1.NetworkPhaseConfig{
		Vlan:       50,
		StaticIp:   "198.18.1.10",
		Gateway:    "198.18.1.1",
		Dns:        []string{"8.8.8.8", "8.8.4.4"},
		AuthMethod: platformv1.AuthMethod_AUTH_METHOD_802_1X,
		Subnet:     "198.18.1.0/24",
		DnsServers: []string{"1.1.1.1"},
		Dhcp:       true,
		DhcpPool: &platformv1.DHCPPoolConfig{
			Network:    "198.18.1.0/24",
			RangeStart: "198.18.1.100",
			RangeEnd:   "198.18.1.200",
			LeaseTime:  43200,
		},
		FirewallZone: "dmz",
		Acls: []*platformv1.ACLConfig{
			{
				Priority: 5,
				Protocol: "tcp",
				SrcIp:    "198.18.1.0/24",
				DstIp:    "10.0.0.0/8",
				SrcPort:  1024,
				DstPort:  80,
				Action:   "deny",
			},
		},
	}

	result := svc.pbToNetworkPhaseConfig(pb)
	require.NotNil(t, result)
	assert.Equal(t, uint16(50), result.VLAN)
	assert.Equal(t, "198.18.1.10", result.StaticIP)
	assert.Equal(t, "198.18.1.1", result.Gateway)
	assert.Equal(t, []string{"8.8.8.8", "8.8.4.4"}, result.DNS)
	assert.Equal(t, entities.AuthMethod802_1X, result.AuthMethod)
	assert.Equal(t, "198.18.1.0/24", result.Subnet)
	assert.True(t, result.DHCP)
	assert.Equal(t, "dmz", result.FirewallZone)

	require.NotNil(t, result.DHCPPool)
	assert.Equal(t, "198.18.1.0/24", result.DHCPPool.Network)
	assert.Equal(t, "198.18.1.100", result.DHCPPool.RangeStart)
	assert.Equal(t, "198.18.1.200", result.DHCPPool.RangeEnd)
	assert.Equal(t, 43200, result.DHCPPool.LeaseTime)

	require.Len(t, result.ACLs, 1)
	assert.Equal(t, 5, result.ACLs[0].Priority)
	assert.Equal(t, "tcp", result.ACLs[0].Protocol)
	assert.Equal(t, "198.18.1.0/24", result.ACLs[0].SrcIP)
	assert.Equal(t, "10.0.0.0/8", result.ACLs[0].DstIP)
	assert.Equal(t, uint16(1024), result.ACLs[0].SrcPort)
	assert.Equal(t, uint16(80), result.ACLs[0].DstPort)
	assert.Equal(t, "deny", result.ACLs[0].Action)
}

func TestDeviceGRPCService_networkPhaseConfigToPb_Nil(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	result := svc.networkPhaseConfigToPb(nil)
	assert.Nil(t, result)
}

func TestDeviceGRPCService_networkPhaseConfigToPb_WithDHCPPool(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	config := &entities.NetworkPhaseConfig{
		VLAN:       60,
		StaticIP:   "172.16.60.10",
		Gateway:    "172.16.60.1",
		DNS:        []string{"8.8.8.8"},
		AuthMethod: entities.AuthMethodNone,
		Subnet:     "172.16.60.0/24",
		DNSServers: []string{"1.1.1.1", "1.0.0.1"},
		DHCP:       false,
		DHCPPool: &entities.DHCPPoolConfig{
			Network:    "172.16.60.0/24",
			RangeStart: "172.16.60.50",
			RangeEnd:   "172.16.60.150",
			LeaseTime:  86400,
		},
		FirewallZone: "internal",
		ACLs: []entities.ACLConfig{
			{
				Priority: 100,
				Protocol: "icmp",
				SrcIP:    "0.0.0.0/0",
				DstIP:    "172.16.60.0/24",
				SrcPort:  0,
				DstPort:  0,
				Action:   "allow",
			},
		},
	}

	result := svc.networkPhaseConfigToPb(config)
	require.NotNil(t, result)
	assert.Equal(t, uint32(60), result.Vlan)
	assert.Equal(t, "172.16.60.10", result.StaticIp)
	assert.Equal(t, "172.16.60.1", result.Gateway)
	assert.Equal(t, platformv1.AuthMethod_AUTH_METHOD_NONE, result.AuthMethod)
	assert.False(t, result.Dhcp)
	assert.Equal(t, "internal", result.FirewallZone)

	require.NotNil(t, result.DhcpPool)
	assert.Equal(t, "172.16.60.0/24", result.DhcpPool.Network)
	assert.Equal(t, int32(86400), result.DhcpPool.LeaseTime)

	require.Len(t, result.Acls, 1)
	assert.Equal(t, int32(100), result.Acls[0].Priority)
	assert.Equal(t, "icmp", result.Acls[0].Protocol)
}

func TestDeviceGRPCService_pbToPlatformdConfigRef_Nil(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	result := svc.pbToPlatformdConfigRef(nil)
	assert.Nil(t, result)
}

func TestDeviceGRPCService_pbToPlatformdConfigRef_WithData(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	pb := &platformv1.PlatformdConfigRef{
		ConfigType: "reference",
		Reference:  "/etc/platformd/main.yaml",
		ConfigName: "main",
		ConfigPath: "/etc/platformd",
		Version:    "3.1.4",
	}

	result := svc.pbToPlatformdConfigRef(pb)
	require.NotNil(t, result)
	assert.Equal(t, "reference", result.ConfigType)
	assert.Equal(t, "/etc/platformd/main.yaml", result.Reference)
	assert.Equal(t, "main", result.ConfigName)
	assert.Equal(t, "/etc/platformd", result.ConfigPath)
	assert.Equal(t, "3.1.4", result.Version)
}

func TestDeviceGRPCService_platformdConfigRefToPb_Nil(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	result := svc.platformdConfigRefToPb(nil)
	assert.Nil(t, result)
}

func TestDeviceGRPCService_platformdConfigRefToPb_WithData(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	config := &entities.PlatformdConfigRef{
		ConfigType: "inline",
		Reference:  "/config/inline.yaml",
		ConfigName: "inline-config",
		ConfigPath: "/config",
		Version:    "1.2.3",
	}

	result := svc.platformdConfigRefToPb(config)
	require.NotNil(t, result)
	assert.Equal(t, "inline", result.ConfigType)
	assert.Equal(t, "/config/inline.yaml", result.Reference)
	assert.Equal(t, "inline-config", result.ConfigName)
	assert.Equal(t, "/config", result.ConfigPath)
	assert.Equal(t, "1.2.3", result.Version)
}

func TestDeviceGRPCService_pbToProfileMatchRules_Nil(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	result := svc.pbToProfileMatchRules(nil)
	assert.Nil(t, result)
}

func TestDeviceGRPCService_pbToProfileMatchRules_WithData(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	pb := &platformv1.ProfileMatchRules{
		MacPrefix:         "11:22:33",
		SerialPrefix:      "TEST",
		Model:             "TestDevice",
		ModelPattern:      "Test*",
		SerialPattern:     "TEST*",
		ManufacturerMatch: "TestCorp",
		TpmVendor:         "TestTPM",
		CustomAttributes:  map[string]string{"type": "test", "env": "dev"},
	}

	result := svc.pbToProfileMatchRules(pb)
	require.NotNil(t, result)
	assert.Equal(t, "11:22:33", result.MACPrefix)
	assert.Equal(t, "TEST", result.SerialPrefix)
	assert.Equal(t, "TestDevice", result.Model)
	assert.Equal(t, "Test*", result.ModelPattern)
	assert.Equal(t, "TEST*", result.SerialPattern)
	assert.Equal(t, "TestCorp", result.ManufacturerMatch)
	assert.Equal(t, "TestTPM", result.TPMVendor)
	assert.Len(t, result.CustomAttributes, 2)
	assert.Equal(t, "test", result.CustomAttributes["type"])
	assert.Equal(t, "dev", result.CustomAttributes["env"])
}

func TestDeviceGRPCService_profileMatchRulesToPb_Nil(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	result := svc.profileMatchRulesToPb(nil)
	assert.Nil(t, result)
}

func TestDeviceGRPCService_profileMatchRulesToPb_WithData(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	rules := &entities.ProfileMatchRules{
		MACPrefix:         "AA:BB:CC",
		SerialPrefix:      "PROD",
		Model:             "ProdDevice",
		ModelPattern:      "Prod*",
		SerialPattern:     "PROD*",
		ManufacturerMatch: "ProdCorp",
		TPMVendor:         "ProdTPM",
		CustomAttributes:  map[string]string{"region": "us-west"},
	}

	result := svc.profileMatchRulesToPb(rules)
	require.NotNil(t, result)
	assert.Equal(t, "AA:BB:CC", result.MacPrefix)
	assert.Equal(t, "PROD", result.SerialPrefix)
	assert.Equal(t, "ProdDevice", result.Model)
	assert.Equal(t, "Prod*", result.ModelPattern)
	assert.Equal(t, "PROD*", result.SerialPattern)
	assert.Equal(t, "ProdCorp", result.ManufacturerMatch)
	assert.Equal(t, "ProdTPM", result.TpmVendor)
	assert.Equal(t, "us-west", result.CustomAttributes["region"])
}

func TestDeviceGRPCService_PaginationToQuery(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	t.Run("nil pagination", func(t *testing.T) {
		query := svc.paginationToQuery(nil)
		assert.Equal(t, 1, query.Page)
		assert.Equal(t, 25, query.PageSize)
	})

	t.Run("with pagination", func(t *testing.T) {
		pagination := &platformv1.PaginationRequest{
			Page:      2,
			PageSize:  50,
			Ascending: true,
		}
		query := svc.paginationToQuery(pagination)
		assert.Equal(t, 2, query.Page)
		assert.Equal(t, 50, query.PageSize)
		assert.Equal(t, datastore.SortAscending, query.SortOrder)
	})

	t.Run("descending order", func(t *testing.T) {
		pagination := &platformv1.PaginationRequest{
			Ascending: false,
		}
		query := svc.paginationToQuery(pagination)
		assert.Equal(t, datastore.SortDescending, query.SortOrder)
	})

	t.Run("zero page uses default", func(t *testing.T) {
		pagination := &platformv1.PaginationRequest{
			Page:     0,
			PageSize: 0,
		}
		query := svc.paginationToQuery(pagination)
		assert.Equal(t, 1, query.Page)
		assert.Equal(t, 25, query.PageSize)
	})
}

func TestDeviceGRPCService_toGRPCError(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	t.Run("nil error", func(t *testing.T) {
		result := svc.toGRPCError(nil)
		assert.Nil(t, result)
	})

	t.Run("invalid device ID error", func(t *testing.T) {
		err := errors.New("invalid device ID")
		result := svc.toGRPCError(err)
		st, ok := status.FromError(result)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("invalid profile ID error", func(t *testing.T) {
		err := errors.New("invalid profile ID")
		result := svc.toGRPCError(err)
		st, ok := status.FromError(result)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("not found error", func(t *testing.T) {
		err := errors.New("device not found")
		result := svc.toGRPCError(err)
		st, ok := status.FromError(result)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("failed to get error", func(t *testing.T) {
		err := errors.New("failed to get device")
		result := svc.toGRPCError(err)
		st, ok := status.FromError(result)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("already exists error", func(t *testing.T) {
		err := errors.New("device already exists")
		result := svc.toGRPCError(err)
		st, ok := status.FromError(result)
		require.True(t, ok)
		assert.Equal(t, codes.AlreadyExists, st.Code())
	})

	t.Run("generic error", func(t *testing.T) {
		err := errors.New("some internal error")
		result := svc.toGRPCError(err)
		st, ok := status.FromError(result)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

func TestContainsSubstring(t *testing.T) {
	assert.True(t, containsSubstring("hello world", "world"))
	assert.True(t, containsSubstring("hello", "hello"))
	assert.False(t, containsSubstring("hello", "world"))
	assert.False(t, containsSubstring("hi", "hello"))
}

func TestContains(t *testing.T) {
	assert.True(t, contains("hello world", "world"))
	assert.True(t, contains("hello", "hello"))
	assert.False(t, contains("hello", "world"))
	assert.False(t, contains("hi", "hello"))
}

func TestContainsNotFound(t *testing.T) {
	assert.True(t, containsNotFound("device not found"))
	assert.True(t, containsNotFound("failed to get device"))
	assert.False(t, containsNotFound("device created"))
}

func TestContainsAlreadyExists(t *testing.T) {
	assert.True(t, containsAlreadyExists("device already exists"))
	assert.False(t, containsAlreadyExists("device not found"))
}
