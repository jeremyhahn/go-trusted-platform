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
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
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

// Create mirrors the real service: mint an ID when the caller has none,
// then take the ordinary Save path (#525).
func (m *mockDeviceService) Create(ctx context.Context, dev *entities.Device) error {
	if dev == nil {
		return device.ErrNilDevice
	}
	if dev.ID == 0 {
		dev.ID = device.NewID()
	}
	return m.Save(ctx, dev)
}

func (m *mockDeviceService) Save(ctx context.Context, dev *entities.Device) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	// Save refuses a zero ID exactly as the real service does. Without
	// this the mock accepted the create path that production refused, so
	// the unit tests passed while every transport's create was broken
	// (#525).
	if dev == nil || dev.ID == 0 {
		return device.ErrInvalidDeviceID
	}
	m.devices[dev.ID] = dev
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

// FindByHostname finds a device by its IDevID hostname.
func (m *mockDeviceService) FindByHostname(ctx context.Context, hostname string) (*entities.Device, error) {
	for _, d := range m.devices {
		if d.Hostname == hostname {
			return d, nil
		}
	}
	return nil, errors.New("device not found by hostname")
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
	assignErr              error
	unassignErr            error
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

func (m *mockProfileService) AssignToDeviceWithEK(ctx context.Context, profileID uint64, ekSerial, mac, ekCertPEM string) error {
	if m.assignErr != nil {
		return m.assignErr
	}
	profile, ok := m.profiles[profileID]
	if !ok {
		return errors.New("profile not found")
	}
	if ekSerial != "" {
		profile.EKSerial = ekSerial
	}
	if mac != "" {
		profile.MACAddress = mac
	}
	if ekCertPEM != "" {
		profile.EKCert = ekCertPEM
	}
	profile.Assigned = true
	profile.AssignedAt = time.Now().UTC()
	return nil
}

func (m *mockProfileService) UnassignFromDevice(ctx context.Context, profileID uint64) error {
	if m.unassignErr != nil {
		return m.unassignErr
	}
	profile, ok := m.profiles[profileID]
	if !ok {
		return errors.New("profile not found")
	}
	profile.EKSerial = ""
	profile.MACAddress = ""
	profile.EKCert = ""
	profile.Assigned = false
	profile.AssignedAt = time.Time{}
	return nil
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

// TestDeviceGRPCService_CreateDevice_WithoutAnID is the #525 regression.
// A caller creating a device has no ID to supply, which is what creation
// means; CreateDevice called Save, which requires one, so every create
// on gRPC, Unix and QUIC — all three reach this method — came back
// InvalidArgument "invalid device ID". Measured at 67 refusals in one
// integration run.
func TestDeviceGRPCService_CreateDevice_WithoutAnID(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	resp, err := svc.CreateDevice(ctx, &platformv1.CreateDeviceRequest{
		Device: &platformv1.Device{
			Model:  "TestTPM",
			Serial: "SN-NO-ID",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.NotZero(t, resp.Device.Id, "the response must carry the assigned ID")

	// The created device is readable afterwards under that ID, which is
	// the acceptance condition the device integration suite asserts on
	// every transport.
	got, err := svc.GetDevice(ctx, &platformv1.GetDeviceRequest{Id: resp.Device.Id})
	require.NoError(t, err)
	assert.Equal(t, "SN-NO-ID", got.Device.Serial)
}

// TestDeviceGRPCService_CreateDevice_TwoCreatesGetDistinctIDs guards the
// other half: assigned identity must be unique, or the second create
// silently replaces the first.
func TestDeviceGRPCService_CreateDevice_TwoCreatesGetDistinctIDs(t *testing.T) {
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(deviceSvc, profileSvc, nil)

	ctx := context.Background()
	first, err := svc.CreateDevice(ctx, &platformv1.CreateDeviceRequest{
		Device: &platformv1.Device{Serial: "SN-DISTINCT-1"},
	})
	require.NoError(t, err)
	second, err := svc.CreateDevice(ctx, &platformv1.CreateDeviceRequest{
		Device: &platformv1.Device{Serial: "SN-DISTINCT-2"},
	})
	require.NoError(t, err)

	assert.NotEqual(t, first.Device.Id, second.Device.Id)
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
		result, err := svc.pbToProfile(nil)
		assert.NoError(t, err)
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

	t.Run("deviceRole_roundTripsThroughSharedMapping", func(t *testing.T) {
		for _, role := range []entities.DeviceRole{
			entities.DeviceRoleControlPlane, entities.DeviceRoleWorker, entities.DeviceRoleGateway,
			entities.DeviceRoleServer, entities.DeviceRoleLoadBalancer, entities.DeviceRoleUnknown,
		} {
			profile, err := svc.pbToProfile(svc.profileToPb(&entities.DeviceProfile{ID: 1, Role: role}))
			require.NoError(t, err)
			assert.Equal(t, role, profile.Role)
		}
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
		Networks: map[string]*platformv1.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
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
			entities.DefaultPostEnrollmentNetwork: {
				Vlan:    20,
				Gateway: "10.0.0.1",
			},
			entities.DefaultFailureNetwork: {
				Vlan: 999,
				Zone: "quarantine",
			},
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

	result, err := svc.pbToProfile(pb)
	require.NoError(t, err)
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
	assert.Equal(t, "quarantine", result.GetFailureNetworkConfig().Zone)

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
				Zone: "control-plane",
			},
			entities.DefaultPostEnrollmentNetwork: {
				VLAN:    40,
				Gateway: "172.16.0.1",
			},
			entities.DefaultFailureNetwork: {
				VLAN: 888,
				Zone: "isolated",
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

	// Check networks map
	require.NotNil(t, result.Networks)
	provNet := result.Networks[entities.DefaultEnrollmentNetwork]
	require.NotNil(t, provNet)
	assert.Equal(t, uint32(30), provNet.Vlan)
	assert.Equal(t, "10.0.0.100", provNet.StaticIp)
	assert.Equal(t, entities.AuthMethod802_1X.String(), svc.pbToAuthMethod(provNet.AuthMethod).String())
	require.NotNil(t, provNet.DhcpPool)
	assert.Equal(t, "10.0.0.0/24", provNet.DhcpPool.Network)
	require.Len(t, provNet.Acls, 1)
	assert.Equal(t, "allow", provNet.Acls[0].Action)

	// Check trusted (post-enrollment) network
	prodNet := result.Networks[entities.DefaultPostEnrollmentNetwork]
	require.NotNil(t, prodNet)
	assert.Equal(t, uint32(40), prodNet.Vlan)

	// Check quarantine network
	quarNet := result.Networks[entities.DefaultFailureNetwork]
	require.NotNil(t, quarNet)
	assert.Equal(t, uint32(888), quarNet.Vlan)

	// Check platformd config
	require.NotNil(t, result.PlatformdConfig)
	assert.Equal(t, "inline", result.PlatformdConfig.ConfigType)

	// Check match rules
	require.NotNil(t, result.MatchRules)
	assert.Equal(t, "DD:EE:FF", result.MatchRules.MacPrefix)
	assert.Equal(t, "premium", result.MatchRules.CustomAttributes["tier"])
}

// TestDeviceGRPCService_profileToPb_IdentityAndConfigFields verifies the
// converter populates the device-identity, assignment, and config fields so
// gRPC/QUIC responses carry the same profile data as REST/MCP.
func TestDeviceGRPCService_profileToPb_IdentityAndConfigFields(t *testing.T) {
	svc := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)

	assignedAt := time.Date(2026, 8, 1, 12, 30, 0, 0, time.UTC)
	profile := &entities.DeviceProfile{
		ID:         300,
		Name:       "IdentityProfile",
		EKSerial:   "EK-SERIAL-300",
		MACAddress: "aa:bb:cc:dd:ee:00",
		Assigned:   true,
		AssignedAt: assignedAt,
		Config: map[string]any{
			"hostname": "node-02",
			"secure-boot": map[string]any{
				"enabled": true,
			},
		},
	}

	result := svc.profileToPb(profile)
	require.NotNil(t, result)
	assert.Equal(t, "EK-SERIAL-300", result.EkSerial)
	assert.Equal(t, "aa:bb:cc:dd:ee:00", result.MacAddress)
	assert.True(t, result.Assigned)
	require.NotNil(t, result.AssignedAt)
	assert.Equal(t, assignedAt, result.AssignedAt.AsTime())

	require.NotEmpty(t, result.Config)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(result.Config, &decoded))
	assert.Equal(t, "node-02", decoded["hostname"])

	// The domain entity carries no created/updated timestamps, so the pb
	// fields must stay unset.
	assert.Nil(t, result.CreatedAt)
	assert.Nil(t, result.UpdatedAt)
}

// TestDeviceGRPCService_profileToPb_ZeroAndInvalidOptionalFields verifies the
// converter omits the assignment timestamp when unassigned, omits config when
// absent, and degrades gracefully (omitting only the config bytes) when the
// config value cannot be JSON-serialized.
func TestDeviceGRPCService_profileToPb_ZeroAndInvalidOptionalFields(t *testing.T) {
	svc := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)

	t.Run("nil config and zero assigned_at stay unset", func(t *testing.T) {
		result := svc.profileToPb(&entities.DeviceProfile{ID: 301, Name: "Bare"})
		require.NotNil(t, result)
		assert.Nil(t, result.Config)
		assert.Nil(t, result.AssignedAt)
		assert.False(t, result.Assigned)
		assert.Empty(t, result.EkSerial)
		assert.Empty(t, result.MacAddress)
	})

	t.Run("unserializable config is omitted without failing conversion", func(t *testing.T) {
		result := svc.profileToPb(&entities.DeviceProfile{
			ID:       302,
			Name:     "BadConfig",
			EKSerial: "EK-302",
			Config:   make(chan int),
		})
		require.NotNil(t, result)
		assert.Nil(t, result.Config)
		assert.Equal(t, "EK-302", result.EkSerial)
	})
}

// TestDeviceGRPCService_pbToProfile_IdentityAndConfigFields verifies the
// inbound converter preserves the device-identity, assignment, and config
// fields so a profile round-trips through the gRPC surface without data
// loss (the seeding path used by pre-enrollment config delivery).
func TestDeviceGRPCService_pbToProfile_IdentityAndConfigFields(t *testing.T) {
	svc := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)

	assignedAt := time.Date(2026, 8, 1, 12, 30, 0, 0, time.UTC)
	pb := &platformv1.DeviceProfile{
		Id:         400,
		Name:       "IdentityProfile",
		EkSerial:   "EK-SERIAL-400",
		MacAddress: "aa:bb:cc:dd:ee:40",
		Assigned:   true,
		AssignedAt: timestamppb.New(assignedAt),
		Config:     []byte(`{"hostname":"node-04","secure-boot":{"enabled":true}}`),
	}

	result, err := svc.pbToProfile(pb)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "EK-SERIAL-400", result.EKSerial)
	assert.Equal(t, "aa:bb:cc:dd:ee:40", result.MACAddress)
	assert.True(t, result.Assigned)
	assert.Equal(t, assignedAt, result.AssignedAt)

	config, ok := result.Config.(map[string]any)
	require.True(t, ok, "config must decode to a JSON object, got %T", result.Config)
	assert.Equal(t, "node-04", config["hostname"])

	// Round-trip: converting back to pb must reproduce the same identity
	// and config payload.
	roundTrip := svc.profileToPb(result)
	require.NotNil(t, roundTrip)
	assert.Equal(t, pb.EkSerial, roundTrip.EkSerial)
	assert.Equal(t, pb.MacAddress, roundTrip.MacAddress)
	assert.True(t, roundTrip.Assigned)
	var original, restored map[string]any
	require.NoError(t, json.Unmarshal(pb.Config, &original))
	require.NoError(t, json.Unmarshal(roundTrip.Config, &restored))
	assert.Equal(t, original, restored)
}

// TestDeviceGRPCService_pbToProfile_InvalidConfig verifies malformed config
// bytes are rejected with the typed ErrProfileConfigInvalid instead of being
// silently dropped.
func TestDeviceGRPCService_pbToProfile_InvalidConfig(t *testing.T) {
	svc := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)

	result, err := svc.pbToProfile(&platformv1.DeviceProfile{
		Id:     401,
		Name:   "BadConfig",
		Config: []byte("{not-json"),
	})
	require.Error(t, err)
	assert.Nil(t, result)

	var configErr ErrProfileConfigInvalid
	require.ErrorAs(t, err, &configErr)
	require.NotNil(t, configErr.Unwrap())
}

// TestDeviceGRPCService_pbToProfile_EmptyOptionalFields verifies the zero
// values stay zero: no config, no assignment timestamp, empty identity.
func TestDeviceGRPCService_pbToProfile_EmptyOptionalFields(t *testing.T) {
	svc := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)

	result, err := svc.pbToProfile(&platformv1.DeviceProfile{Id: 402, Name: "Bare"})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Nil(t, result.Config)
	assert.True(t, result.AssignedAt.IsZero())
	assert.False(t, result.Assigned)
	assert.Empty(t, result.EKSerial)
	assert.Empty(t, result.MACAddress)
}

// TestDeviceGRPCService_CreateProfile_InvalidConfig verifies CreateProfile
// maps malformed profile config bytes to an InvalidArgument status.
func TestDeviceGRPCService_CreateProfile_InvalidConfig(t *testing.T) {
	svc := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)

	resp, err := svc.CreateProfile(context.Background(), &platformv1.CreateProfileRequest{
		Profile: &platformv1.DeviceProfile{
			Name:   "BadConfigProfile",
			Config: []byte("not json at all"),
		},
	})
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// TestDeviceGRPCService_UpdateProfile_InvalidConfig verifies UpdateProfile
// maps malformed profile config bytes to an InvalidArgument status.
func TestDeviceGRPCService_UpdateProfile_InvalidConfig(t *testing.T) {
	svc := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)

	resp, err := svc.UpdateProfile(context.Background(), &platformv1.UpdateProfileRequest{
		Profile: &platformv1.DeviceProfile{
			Id:     403,
			Name:   "BadConfigProfile",
			Config: []byte("{"),
		},
	})
	require.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// TestDeviceGRPCService_CreateProfile_PersistsIdentityAndConfig verifies the
// create path persists the identity and config fields end-to-end through the
// service layer (the regression that previously dropped them silently).
func TestDeviceGRPCService_CreateProfile_PersistsIdentityAndConfig(t *testing.T) {
	profileSvc := newMockProfileService()
	svc := NewDeviceGRPCService(newMockDeviceService(), profileSvc, nil)

	resp, err := svc.CreateProfile(context.Background(), &platformv1.CreateProfileRequest{
		Profile: &platformv1.DeviceProfile{
			Name:       "SeededProfile",
			EkSerial:   "EK-SEEDED-1",
			MacAddress: "aa:bb:cc:00:00:01",
			Config:     []byte(`{"platform":{"hostname":"seeded"}}`),
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotZero(t, resp.Profile.Id)
	assert.Equal(t, "EK-SEEDED-1", resp.Profile.EkSerial)
	assert.Equal(t, "aa:bb:cc:00:00:01", resp.Profile.MacAddress)

	var config map[string]any
	require.NoError(t, json.Unmarshal(resp.Profile.Config, &config))
	platform, ok := config["platform"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "seeded", platform["hostname"])
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
		StaticIp:   "10.4.2.10",
		Gateway:    "10.4.2.1",
		Dns:        []string{"8.8.8.8", "8.8.4.4"},
		AuthMethod: platformv1.AuthMethod_AUTH_METHOD_802_1X,
		Subnet:     "10.4.2.0/24",
		DnsServers: []string{"1.1.1.1"},
		Dhcp:       true,
		DhcpPool: &platformv1.DHCPPoolConfig{
			Network:    "10.4.2.0/24",
			RangeStart: "10.4.2.100",
			RangeEnd:   "10.4.2.200",
			LeaseTime:  43200,
		},
		Zone: "dmz",
		Acls: []*platformv1.ACLConfig{
			{
				Priority: 5,
				Protocol: "tcp",
				SrcIp:    "10.4.2.0/24",
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
	assert.Equal(t, "10.4.2.10", result.StaticIP)
	assert.Equal(t, "10.4.2.1", result.Gateway)
	assert.Equal(t, []string{"8.8.8.8", "8.8.4.4"}, result.DNS)
	assert.Equal(t, entities.AuthMethod802_1X, result.AuthMethod)
	assert.Equal(t, "10.4.2.0/24", result.Subnet)
	assert.True(t, result.DHCP)
	assert.Equal(t, "dmz", result.Zone)

	require.NotNil(t, result.DHCPPool)
	assert.Equal(t, "10.4.2.0/24", result.DHCPPool.Network)
	assert.Equal(t, "10.4.2.100", result.DHCPPool.RangeStart)
	assert.Equal(t, "10.4.2.200", result.DHCPPool.RangeEnd)
	assert.Equal(t, 43200, result.DHCPPool.LeaseTime)

	require.Len(t, result.ACLs, 1)
	assert.Equal(t, 5, result.ACLs[0].Priority)
	assert.Equal(t, "tcp", result.ACLs[0].Protocol)
	assert.Equal(t, "10.4.2.0/24", result.ACLs[0].SrcIP)
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
		Zone: "internal",
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
	assert.Equal(t, "internal", result.Zone)

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

// FindProfileForDevice mirrors the real resolver's precedence: a profile
// bound to the device's EK identity first, else the match rules.
func (m *mockProfileService) FindProfileForDevice(ctx context.Context, dev *entities.Device) (*entities.DeviceProfile, error) {
	if dev == nil {
		return nil, device.ErrDeviceRequired{}
	}
	ekSerial := ""
	if dev.EKCert != "" {
		if serial, err := entities.EKSerialFromCertPEM(dev.EKCert); err == nil {
			ekSerial = serial
		}
	}
	if ekSerial != "" {
		for _, p := range m.profiles {
			if p.EKSerial == ekSerial {
				return p, nil
			}
		}
	}
	profile, err := m.FindMatchingProfile(ctx, "", dev.Serial, dev.Model)
	if err != nil {
		return nil, device.ErrNoProfileForDevice{DeviceID: dev.ID, Serial: dev.Serial, EKSerial: ekSerial}
	}
	return profile, nil
}
