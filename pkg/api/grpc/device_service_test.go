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

package grpc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockDeviceService implements DeviceService for testing.
type mockDeviceService struct {
	devices      map[uint64]*entities.Device
	saveErr      error
	getErr       error
	deleteErr    error
	updateErr    error
	countErr     error
	pageErr      error
	findBySerErr error
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
	if device.ID == 0 {
		device.ID = uint64(len(m.devices) + 1)
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
		return nil, datastore.ErrRecordNotFound
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
		return datastore.ErrRecordNotFound
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
	result := datastore.NewPageResultFromQuery[*entities.Device](query)
	for _, d := range m.devices {
		result.Entities = append(result.Entities, d)
	}
	result.Total = len(m.devices)
	return result, nil
}

func (m *mockDeviceService) FindBySerial(ctx context.Context, serial string) (*entities.Device, error) {
	if m.findBySerErr != nil {
		return nil, m.findBySerErr
	}
	for _, d := range m.devices {
		if d.Serial == serial {
			return d, nil
		}
	}
	return nil, datastore.ErrRecordNotFound
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

// Ensure mockDeviceService implements DeviceService.
var _ DeviceService = (*mockDeviceService)(nil)

// mockProfileService implements DeviceProfileService for testing.
type mockProfileService struct {
	profiles        map[uint64]*entities.DeviceProfile
	saveErr         error
	getErr          error
	deleteErr       error
	updateErr       error
	countErr        error
	pageErr         error
	findByMACErr    error
	findBySerialErr error
	findMatchingErr error
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
	if profile.ID == 0 {
		profile.ID = uint64(len(m.profiles) + 1)
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
		return nil, datastore.ErrRecordNotFound
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
		return datastore.ErrRecordNotFound
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
	result := datastore.NewPageResultFromQuery[*entities.DeviceProfile](query)
	for _, p := range m.profiles {
		result.Entities = append(result.Entities, p)
	}
	result.Total = len(m.profiles)
	return result, nil
}

func (m *mockProfileService) FindByMACAddress(ctx context.Context, macAddr string) (*entities.DeviceProfile, error) {
	if m.findByMACErr != nil {
		return nil, m.findByMACErr
	}
	for _, p := range m.profiles {
		if p.MatchRules != nil && p.MatchRules.MACPrefix != "" {
			if len(macAddr) >= len(p.MatchRules.MACPrefix) &&
				macAddr[:len(p.MatchRules.MACPrefix)] == p.MatchRules.MACPrefix {
				return p, nil
			}
		}
	}
	return nil, datastore.ErrRecordNotFound
}

func (m *mockProfileService) FindBySerial(ctx context.Context, serial string) (*entities.DeviceProfile, error) {
	if m.findBySerialErr != nil {
		return nil, m.findBySerialErr
	}
	for _, p := range m.profiles {
		if p.MatchRules != nil && p.MatchRules.SerialPrefix != "" {
			if len(serial) >= len(p.MatchRules.SerialPrefix) &&
				serial[:len(p.MatchRules.SerialPrefix)] == p.MatchRules.SerialPrefix {
				return p, nil
			}
		}
	}
	return nil, datastore.ErrRecordNotFound
}

func (m *mockProfileService) FindMatchingProfile(ctx context.Context, macAddr, serial, model string) (*entities.DeviceProfile, error) {
	if m.findMatchingErr != nil {
		return nil, m.findMatchingErr
	}
	for _, p := range m.profiles {
		if p.MatchRules != nil && p.MatchRules.Matches(macAddr, serial, model) {
			return p, nil
		}
		if p.Model == model {
			return p, nil
		}
	}
	return nil, datastore.ErrRecordNotFound
}

func (m *mockProfileService) AssignToDeviceWithEK(ctx context.Context, profileID uint64, ekSerial, mac, ekCertPEM string) error {
	profile, ok := m.profiles[profileID]
	if !ok {
		return datastore.ErrRecordNotFound
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
	profile, ok := m.profiles[profileID]
	if !ok {
		return datastore.ErrRecordNotFound
	}
	profile.EKSerial = ""
	profile.MACAddress = ""
	profile.EKCert = ""
	profile.Assigned = false
	profile.AssignedAt = time.Time{}
	return nil
}

// Ensure mockProfileService implements DeviceProfileService.
var _ DeviceProfileService = (*mockProfileService)(nil)

func newTestDeviceService() (*DeviceGRPCService, *mockDeviceService, *mockProfileService) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	deviceMock := newMockDeviceService()
	profileMock := newMockProfileService()
	service := NewDeviceGRPCService(logger, deviceMock, profileMock)
	return service, deviceMock, profileMock
}

// Device CRUD Tests

func TestDeviceGRPCService_CreateDevice_Success(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.CreateDeviceRequest{
		Device: &platformv1.Device{
			Id:         1,
			Serial:     "TEST-SERIAL-001",
			Model:      "Test Model",
			AttestPub:  "attest-pub-key",
			SigningPub: "signing-pub-key",
			EkCert:     "ek-certificate",
			HashAlgoId: 11, // SHA256
		},
	}

	resp, err := service.CreateDevice(ctx, req)
	if err != nil {
		t.Fatalf("CreateDevice failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetDevice() == nil {
		t.Error("Expected device in response")
	}

	if resp.GetDevice().GetSerial() != "TEST-SERIAL-001" {
		t.Errorf("Expected serial 'TEST-SERIAL-001', got '%s'", resp.GetDevice().GetSerial())
	}
}

func TestDeviceGRPCService_CreateDevice_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDeviceGRPCService(logger, nil, nil)
	ctx := context.Background()

	req := &platformv1.CreateDeviceRequest{
		Device: &platformv1.Device{Serial: "TEST"},
	}

	_, err := service.CreateDevice(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestDeviceGRPCService_CreateDevice_MissingDevice(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.CreateDeviceRequest{}

	_, err := service.CreateDevice(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing device")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDeviceGRPCService_CreateDevice_SaveError(t *testing.T) {
	service, deviceMock, _ := newTestDeviceService()
	deviceMock.saveErr = errors.New("save failed")
	ctx := context.Background()

	req := &platformv1.CreateDeviceRequest{
		Device: &platformv1.Device{Id: 1, Serial: "TEST"},
	}

	_, err := service.CreateDevice(ctx, req)
	if err == nil {
		t.Fatal("Expected error from save")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal, got %v", st.Code())
	}
}

func TestDeviceGRPCService_GetDevice_Success(t *testing.T) {
	service, deviceMock, _ := newTestDeviceService()
	ctx := context.Background()

	// Pre-populate a device
	deviceMock.devices[1] = &entities.Device{
		ID:     1,
		Serial: "TEST-001",
		Model:  "Model X",
	}

	req := &platformv1.GetDeviceRequest{Id: 1}

	resp, err := service.GetDevice(ctx, req)
	if err != nil {
		t.Fatalf("GetDevice failed: %v", err)
	}

	if resp.GetDevice() == nil {
		t.Error("Expected device in response")
	}

	if resp.GetDevice().GetSerial() != "TEST-001" {
		t.Errorf("Expected serial 'TEST-001', got '%s'", resp.GetDevice().GetSerial())
	}
}

func TestDeviceGRPCService_GetDevice_MissingID(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.GetDeviceRequest{}

	_, err := service.GetDevice(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDeviceGRPCService_GetDevice_NotFound(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.GetDeviceRequest{Id: 999}

	_, err := service.GetDevice(ctx, req)
	if err == nil {
		t.Fatal("Expected error for not found")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got %v", st.Code())
	}
}

func TestDeviceGRPCService_UpdateDevice_Success(t *testing.T) {
	service, deviceMock, _ := newTestDeviceService()
	ctx := context.Background()

	// Pre-populate a device
	deviceMock.devices[1] = &entities.Device{
		ID:     1,
		Serial: "TEST-001",
		Model:  "Model X",
	}

	req := &platformv1.UpdateDeviceRequest{
		Device: &platformv1.Device{
			Id:     1,
			Serial: "TEST-001-UPDATED",
			Model:  "Model X Updated",
		},
	}

	resp, err := service.UpdateDevice(ctx, req)
	if err != nil {
		t.Fatalf("UpdateDevice failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestDeviceGRPCService_UpdateDevice_MissingDevice(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.UpdateDeviceRequest{}

	_, err := service.UpdateDevice(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing device")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDeviceGRPCService_UpdateDevice_MissingID(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.UpdateDeviceRequest{
		Device: &platformv1.Device{Serial: "TEST"},
	}

	_, err := service.UpdateDevice(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDeviceGRPCService_DeleteDevice_Success(t *testing.T) {
	service, deviceMock, _ := newTestDeviceService()
	ctx := context.Background()

	// Pre-populate a device
	deviceMock.devices[1] = &entities.Device{ID: 1, Serial: "TEST-001"}

	req := &platformv1.DeleteDeviceRequest{Id: 1}

	resp, err := service.DeleteDevice(ctx, req)
	if err != nil {
		t.Fatalf("DeleteDevice failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	// Verify device was deleted
	if _, ok := deviceMock.devices[1]; ok {
		t.Error("Expected device to be deleted")
	}
}

func TestDeviceGRPCService_DeleteDevice_MissingID(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.DeleteDeviceRequest{}

	_, err := service.DeleteDevice(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDeviceGRPCService_DeleteDevice_NotFound(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.DeleteDeviceRequest{Id: 999}

	_, err := service.DeleteDevice(ctx, req)
	if err == nil {
		t.Fatal("Expected error for not found")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got %v", st.Code())
	}
}

func TestDeviceGRPCService_ListDevices_Success(t *testing.T) {
	service, deviceMock, _ := newTestDeviceService()
	ctx := context.Background()

	// Pre-populate devices
	deviceMock.devices[1] = &entities.Device{ID: 1, Serial: "TEST-001"}
	deviceMock.devices[2] = &entities.Device{ID: 2, Serial: "TEST-002"}

	req := &platformv1.ListDevicesRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:     1,
			PageSize: 10,
		},
	}

	resp, err := service.ListDevices(ctx, req)
	if err != nil {
		t.Fatalf("ListDevices failed: %v", err)
	}

	if len(resp.GetDevices()) != 2 {
		t.Errorf("Expected 2 devices, got %d", len(resp.GetDevices()))
	}

	if resp.GetPagination().GetTotalItems() != 2 {
		t.Errorf("Expected total items 2, got %d", resp.GetPagination().GetTotalItems())
	}
}

func TestDeviceGRPCService_ListDevices_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDeviceGRPCService(logger, nil, nil)
	ctx := context.Background()

	req := &platformv1.ListDevicesRequest{}

	_, err := service.ListDevices(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestDeviceGRPCService_FindDeviceBySerial_Success(t *testing.T) {
	service, deviceMock, _ := newTestDeviceService()
	ctx := context.Background()

	deviceMock.devices[1] = &entities.Device{ID: 1, Serial: "UNIQUE-SERIAL"}

	req := &platformv1.FindDeviceBySerialRequest{Serial: "UNIQUE-SERIAL"}

	resp, err := service.FindDeviceBySerial(ctx, req)
	if err != nil {
		t.Fatalf("FindDeviceBySerial failed: %v", err)
	}

	if resp.GetDevice() == nil {
		t.Error("Expected device in response")
	}

	if resp.GetDevice().GetSerial() != "UNIQUE-SERIAL" {
		t.Errorf("Expected serial 'UNIQUE-SERIAL', got '%s'", resp.GetDevice().GetSerial())
	}
}

func TestDeviceGRPCService_FindDeviceBySerial_MissingSerial(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.FindDeviceBySerialRequest{}

	_, err := service.FindDeviceBySerial(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing serial")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDeviceGRPCService_FindDeviceBySerial_NotFound(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.FindDeviceBySerialRequest{Serial: "NONEXISTENT"}

	_, err := service.FindDeviceBySerial(ctx, req)
	if err == nil {
		t.Fatal("Expected error for not found")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got %v", st.Code())
	}
}

func TestDeviceGRPCService_CountDevices_Success(t *testing.T) {
	service, deviceMock, _ := newTestDeviceService()
	ctx := context.Background()

	deviceMock.devices[1] = &entities.Device{ID: 1}
	deviceMock.devices[2] = &entities.Device{ID: 2}
	deviceMock.devices[3] = &entities.Device{ID: 3}

	req := &platformv1.CountDevicesRequest{}

	resp, err := service.CountDevices(ctx, req)
	if err != nil {
		t.Fatalf("CountDevices failed: %v", err)
	}

	if resp.GetCount() != 3 {
		t.Errorf("Expected count 3, got %d", resp.GetCount())
	}
}

func TestDeviceGRPCService_CountDevices_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDeviceGRPCService(logger, nil, nil)
	ctx := context.Background()

	req := &platformv1.CountDevicesRequest{}

	_, err := service.CountDevices(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

// Profile CRUD Tests

func TestDeviceGRPCService_CreateProfile_Success(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.CreateProfileRequest{
		Profile: &platformv1.DeviceProfile{
			Id:    1,
			Name:  "Test Profile",
			Model: "Test Model",
			Role:  platformv1.DeviceRole_DEVICE_ROLE_SERVER,
		},
	}

	resp, err := service.CreateProfile(ctx, req)
	if err != nil {
		t.Fatalf("CreateProfile failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetProfile().GetName() != "Test Profile" {
		t.Errorf("Expected name 'Test Profile', got '%s'", resp.GetProfile().GetName())
	}
}

func TestDeviceGRPCService_CreateProfile_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDeviceGRPCService(logger, newMockDeviceService(), nil)
	ctx := context.Background()

	req := &platformv1.CreateProfileRequest{
		Profile: &platformv1.DeviceProfile{Name: "Test"},
	}

	_, err := service.CreateProfile(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestDeviceGRPCService_CreateProfile_MissingProfile(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.CreateProfileRequest{}

	_, err := service.CreateProfile(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing profile")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDeviceGRPCService_GetProfile_Success(t *testing.T) {
	service, _, profileMock := newTestDeviceService()
	ctx := context.Background()

	profileMock.profiles[1] = &entities.DeviceProfile{
		ID:   1,
		Name: "Test Profile",
		Role: entities.DeviceRoleServer,
	}

	req := &platformv1.GetProfileRequest{Id: 1}

	resp, err := service.GetProfile(ctx, req)
	if err != nil {
		t.Fatalf("GetProfile failed: %v", err)
	}

	if resp.GetProfile() == nil {
		t.Error("Expected profile in response")
	}

	if resp.GetProfile().GetName() != "Test Profile" {
		t.Errorf("Expected name 'Test Profile', got '%s'", resp.GetProfile().GetName())
	}
}

func TestDeviceGRPCService_GetProfile_MissingID(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.GetProfileRequest{}

	_, err := service.GetProfile(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDeviceGRPCService_GetProfile_NotFound(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.GetProfileRequest{Id: 999}

	_, err := service.GetProfile(ctx, req)
	if err == nil {
		t.Fatal("Expected error for not found")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got %v", st.Code())
	}
}

func TestDeviceGRPCService_UpdateProfile_Success(t *testing.T) {
	service, _, profileMock := newTestDeviceService()
	ctx := context.Background()

	profileMock.profiles[1] = &entities.DeviceProfile{ID: 1, Name: "Original"}

	req := &platformv1.UpdateProfileRequest{
		Profile: &platformv1.DeviceProfile{
			Id:   1,
			Name: "Updated",
		},
	}

	resp, err := service.UpdateProfile(ctx, req)
	if err != nil {
		t.Fatalf("UpdateProfile failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestDeviceGRPCService_UpdateProfile_MissingProfile(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.UpdateProfileRequest{}

	_, err := service.UpdateProfile(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing profile")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDeviceGRPCService_UpdateProfile_MissingID(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.UpdateProfileRequest{
		Profile: &platformv1.DeviceProfile{Name: "Test"},
	}

	_, err := service.UpdateProfile(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDeviceGRPCService_DeleteProfile_Success(t *testing.T) {
	service, _, profileMock := newTestDeviceService()
	ctx := context.Background()

	profileMock.profiles[1] = &entities.DeviceProfile{ID: 1, Name: "Test"}

	req := &platformv1.DeleteProfileRequest{Id: 1}

	resp, err := service.DeleteProfile(ctx, req)
	if err != nil {
		t.Fatalf("DeleteProfile failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestDeviceGRPCService_DeleteProfile_MissingID(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.DeleteProfileRequest{}

	_, err := service.DeleteProfile(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDeviceGRPCService_ListProfiles_Success(t *testing.T) {
	service, _, profileMock := newTestDeviceService()
	ctx := context.Background()

	profileMock.profiles[1] = &entities.DeviceProfile{ID: 1, Name: "Profile 1"}
	profileMock.profiles[2] = &entities.DeviceProfile{ID: 2, Name: "Profile 2"}

	req := &platformv1.ListProfilesRequest{
		Pagination: &platformv1.PaginationRequest{Page: 1, PageSize: 10},
	}

	resp, err := service.ListProfiles(ctx, req)
	if err != nil {
		t.Fatalf("ListProfiles failed: %v", err)
	}

	if len(resp.GetProfiles()) != 2 {
		t.Errorf("Expected 2 profiles, got %d", len(resp.GetProfiles()))
	}
}

func TestDeviceGRPCService_FindProfileByMACAddress_Success(t *testing.T) {
	service, _, profileMock := newTestDeviceService()
	ctx := context.Background()

	profileMock.profiles[1] = &entities.DeviceProfile{
		ID:   1,
		Name: "MAC Profile",
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix: "52:54:00",
		},
	}

	req := &platformv1.FindProfileByMACAddressRequest{MacAddress: "52:54:00:12:34:56"}

	resp, err := service.FindProfileByMACAddress(ctx, req)
	if err != nil {
		t.Fatalf("FindProfileByMACAddress failed: %v", err)
	}

	if resp.GetProfile() == nil {
		t.Error("Expected profile in response")
	}
}

func TestDeviceGRPCService_FindProfileByMACAddress_MissingMAC(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.FindProfileByMACAddressRequest{}

	_, err := service.FindProfileByMACAddress(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing MAC address")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDeviceGRPCService_FindProfileBySerial_Success(t *testing.T) {
	service, _, profileMock := newTestDeviceService()
	ctx := context.Background()

	profileMock.profiles[1] = &entities.DeviceProfile{
		ID:   1,
		Name: "Serial Profile",
		MatchRules: &entities.ProfileMatchRules{
			SerialPrefix: "ABC",
		},
	}

	req := &platformv1.FindProfileBySerialRequest{Serial: "ABC12345"}

	resp, err := service.FindProfileBySerial(ctx, req)
	if err != nil {
		t.Fatalf("FindProfileBySerial failed: %v", err)
	}

	if resp.GetProfile() == nil {
		t.Error("Expected profile in response")
	}
}

func TestDeviceGRPCService_FindProfileBySerial_MissingSerial(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.FindProfileBySerialRequest{}

	_, err := service.FindProfileBySerial(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing serial")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDeviceGRPCService_FindMatchingProfile_Success(t *testing.T) {
	service, _, profileMock := newTestDeviceService()
	ctx := context.Background()

	profileMock.profiles[1] = &entities.DeviceProfile{
		ID:    1,
		Name:  "Model Profile",
		Model: "TestModel",
	}

	req := &platformv1.FindMatchingProfileRequest{
		MacAddress: "52:54:00:12:34:56",
		Serial:     "ABC123",
		Model:      "TestModel",
	}

	resp, err := service.FindMatchingProfile(ctx, req)
	if err != nil {
		t.Fatalf("FindMatchingProfile failed: %v", err)
	}

	if resp.GetProfile() == nil {
		t.Error("Expected profile in response")
	}
}

func TestDeviceGRPCService_FindMatchingProfile_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDeviceGRPCService(logger, newMockDeviceService(), nil)
	ctx := context.Background()

	req := &platformv1.FindMatchingProfileRequest{Model: "Test"}

	_, err := service.FindMatchingProfile(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestDeviceGRPCService_CountProfiles_Success(t *testing.T) {
	service, _, profileMock := newTestDeviceService()
	ctx := context.Background()

	profileMock.profiles[1] = &entities.DeviceProfile{ID: 1}
	profileMock.profiles[2] = &entities.DeviceProfile{ID: 2}

	req := &platformv1.CountProfilesRequest{}

	resp, err := service.CountProfiles(ctx, req)
	if err != nil {
		t.Fatalf("CountProfiles failed: %v", err)
	}

	if resp.GetCount() != 2 {
		t.Errorf("Expected count 2, got %d", resp.GetCount())
	}
}

// ActivateDevice Tests

func TestDeviceGRPCService_ActivateDevice_Success(t *testing.T) {
	service, deviceMock, profileMock := newTestDeviceService()
	ctx := context.Background()

	deviceMock.devices[1] = &entities.Device{
		ID:     1,
		Serial: "TEST-SERIAL",
		Model:  "TestModel",
	}

	profileMock.profiles[1] = &entities.DeviceProfile{
		ID:    1,
		Name:  "Test Profile",
		Model: "TestModel",
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN: 100,
			},
		},
	}

	req := &platformv1.ActivateDeviceRequest{
		Serial:     "TEST-SERIAL",
		MacAddress: "52:54:00:12:34:56",
	}

	resp, err := service.ActivateDevice(ctx, req)
	if err != nil {
		t.Fatalf("ActivateDevice failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetActivationStatus() != "activated" {
		t.Errorf("Expected activation status 'activated', got '%s'", resp.GetActivationStatus())
	}

	if resp.GetVlan() != 100 {
		t.Errorf("Expected VLAN 100, got %d", resp.GetVlan())
	}

	if resp.GetTransitionedAt() == nil {
		t.Error("Expected transitioned_at timestamp")
	}
}

func TestDeviceGRPCService_ActivateDevice_MissingSerial(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.ActivateDeviceRequest{}

	_, err := service.ActivateDevice(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing serial")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDeviceGRPCService_ActivateDevice_DeviceNotFound(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.ActivateDeviceRequest{Serial: "NONEXISTENT"}

	_, err := service.ActivateDevice(ctx, req)
	if err == nil {
		t.Fatal("Expected error for device not found")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got %v", st.Code())
	}
}

func TestDeviceGRPCService_ActivateDevice_NilDeviceService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDeviceGRPCService(logger, nil, newMockProfileService())
	ctx := context.Background()

	req := &platformv1.ActivateDeviceRequest{Serial: "TEST"}

	_, err := service.ActivateDevice(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil device service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestDeviceGRPCService_ActivateDevice_NilProfileService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDeviceGRPCService(logger, newMockDeviceService(), nil)
	ctx := context.Background()

	req := &platformv1.ActivateDeviceRequest{Serial: "TEST"}

	_, err := service.ActivateDevice(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil profile service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

// Role Conversion Tests

func TestDeviceRoleConversions(t *testing.T) {
	testCases := []struct {
		protoRole  platformv1.DeviceRole
		entityRole entities.DeviceRole
	}{
		{platformv1.DeviceRole_DEVICE_ROLE_SERVER, entities.DeviceRoleServer},
		{platformv1.DeviceRole_DEVICE_ROLE_CLIENT, entities.DeviceRoleClient},
		{platformv1.DeviceRole_DEVICE_ROLE_WORKSTATION, entities.DeviceRoleWorkstation},
		{platformv1.DeviceRole_DEVICE_ROLE_EDGE, entities.DeviceRoleEdge},
		{platformv1.DeviceRole_DEVICE_ROLE_IOT, entities.DeviceRoleIoT},
		{platformv1.DeviceRole_DEVICE_ROLE_GATEWAY, entities.DeviceRoleGateway},
		{platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER, entities.DeviceRoleLoadBalancer},
		{platformv1.DeviceRole_DEVICE_ROLE_UNKNOWN, entities.DeviceRoleUnknown},
	}

	for _, tc := range testCases {
		t.Run(tc.protoRole.String(), func(t *testing.T) {
			// Test proto to entity
			entity := protoRoleToEntity(tc.protoRole)
			if entity != tc.entityRole {
				t.Errorf("protoRoleToEntity: expected %s, got %s", tc.entityRole, entity)
			}

			// Test entity to proto
			proto := entityRoleToProto(tc.entityRole)
			if proto != tc.protoRole {
				t.Errorf("entityRoleToProto: expected %s, got %s", tc.protoRole, proto)
			}
		})
	}
}

// AuthMethod Conversion Tests

func TestDeviceAuthMethodConversions(t *testing.T) {
	testCases := []struct {
		protoAuth  platformv1.AuthMethod
		entityAuth entities.AuthMethod
	}{
		{platformv1.AuthMethod_AUTH_METHOD_NONE, entities.AuthMethodNone},
		{platformv1.AuthMethod_AUTH_METHOD_802_1X, entities.AuthMethod802_1X},
	}

	for _, tc := range testCases {
		t.Run(tc.protoAuth.String(), func(t *testing.T) {
			// Test proto to entity
			entity := protoAuthMethodToEntity(tc.protoAuth)
			if entity != tc.entityAuth {
				t.Errorf("protoAuthMethodToEntity: expected %s, got %s", tc.entityAuth, entity)
			}

			// Test entity to proto
			proto := entityAuthMethodToProto(tc.entityAuth)
			if proto != tc.protoAuth {
				t.Errorf("entityAuthMethodToProto: expected %s, got %s", tc.protoAuth, proto)
			}
		})
	}
}

// NetworkConfig Conversion Tests

func TestDeviceNetworkConfigConversion(t *testing.T) {
	protoConfig := &platformv1.NetworkPhaseConfig{
		Vlan:     100,
		StaticIp: "192.168.1.10",
		Gateway:  "192.168.1.1",
		Dns:      []string{"8.8.8.8", "8.8.4.4"},
		DhcpPool: &platformv1.DHCPPoolConfig{
			Network:    "192.168.1.0/24",
			RangeStart: "192.168.1.100",
			RangeEnd:   "192.168.1.200",
			LeaseTime:  3600,
		},
		Acls: []*platformv1.ACLConfig{
			{
				Priority: 1,
				Protocol: "tcp",
				SrcIp:    "192.168.1.0/24",
				DstIp:    "0.0.0.0/0",
				DstPort:  443,
				Action:   "allow",
			},
		},
		AuthMethod: platformv1.AuthMethod_AUTH_METHOD_802_1X,
		Subnet:     "192.168.1.0/24",
		DnsServers: []string{"8.8.8.8"},
		Dhcp:       true,
		Zone:       "trusted",
	}

	entity := protoNetworkConfigToEntity(protoConfig)
	if entity == nil {
		t.Fatal("Expected entity config")
	}

	if entity.VLAN != 100 {
		t.Errorf("Expected VLAN 100, got %d", entity.VLAN)
	}

	if entity.StaticIP != "192.168.1.10" {
		t.Errorf("Expected StaticIP '192.168.1.10', got '%s'", entity.StaticIP)
	}

	if entity.DHCPPool == nil {
		t.Error("Expected DHCP pool config")
	} else if entity.DHCPPool.LeaseTime != 3600 {
		t.Errorf("Expected lease time 3600, got %d", entity.DHCPPool.LeaseTime)
	}

	if len(entity.ACLs) != 1 {
		t.Errorf("Expected 1 ACL, got %d", len(entity.ACLs))
	}

	// Test reverse conversion
	protoBack := entityNetworkConfigToProto(entity)
	if protoBack == nil {
		t.Fatal("Expected proto config")
	}

	if protoBack.GetVlan() != 100 {
		t.Errorf("Expected VLAN 100, got %d", protoBack.GetVlan())
	}
}

// PlatformdConfig Conversion Tests

func TestDevicePlatformdConfigConversion(t *testing.T) {
	protoConfig := &platformv1.PlatformdConfigRef{
		ConfigType: "reference",
		Reference:  "/etc/platformd/config.yaml",
		ConfigName: "production",
		ConfigPath: "/etc/platformd",
		Version:    "1.0.0",
	}

	entity := protoPlatformdConfigToEntity(protoConfig)
	if entity == nil {
		t.Fatal("Expected entity config")
	}

	if entity.ConfigType != "reference" {
		t.Errorf("Expected ConfigType 'reference', got '%s'", entity.ConfigType)
	}

	if entity.Version != "1.0.0" {
		t.Errorf("Expected Version '1.0.0', got '%s'", entity.Version)
	}

	// Test reverse conversion
	protoBack := entityPlatformdConfigToProto(entity)
	if protoBack == nil {
		t.Fatal("Expected proto config")
	}

	if protoBack.GetConfigType() != "reference" {
		t.Errorf("Expected ConfigType 'reference', got '%s'", protoBack.GetConfigType())
	}
}

// MatchRules Conversion Tests

func TestDeviceMatchRulesConversion(t *testing.T) {
	protoRules := &platformv1.ProfileMatchRules{
		MacPrefix:         "52:54:00",
		SerialPrefix:      "ABC",
		Model:             "TestModel",
		ModelPattern:      "Test*",
		SerialPattern:     "ABC*",
		ManufacturerMatch: "TestCorp",
		TpmVendor:         "IFX",
		CustomAttributes: map[string]string{
			"region": "us-west",
		},
	}

	entity := protoMatchRulesToEntity(protoRules)
	if entity == nil {
		t.Fatal("Expected entity rules")
	}

	if entity.MACPrefix != "52:54:00" {
		t.Errorf("Expected MACPrefix '52:54:00', got '%s'", entity.MACPrefix)
	}

	if entity.TPMVendor != "IFX" {
		t.Errorf("Expected TPMVendor 'IFX', got '%s'", entity.TPMVendor)
	}

	if entity.CustomAttributes["region"] != "us-west" {
		t.Errorf("Expected CustomAttributes['region'] = 'us-west', got '%s'", entity.CustomAttributes["region"])
	}

	// Test reverse conversion
	protoBack := entityMatchRulesToProto(entity)
	if protoBack == nil {
		t.Fatal("Expected proto rules")
	}

	if protoBack.GetMacPrefix() != "52:54:00" {
		t.Errorf("Expected MACPrefix '52:54:00', got '%s'", protoBack.GetMacPrefix())
	}
}

// Pagination Tests

func TestDevicePaginationConversion(t *testing.T) {
	protoReq := &platformv1.PaginationRequest{
		Page:      2,
		PageSize:  50,
		Ascending: false,
	}

	query := protoDevicePaginationToQuery(protoReq)

	if query.Page != 2 {
		t.Errorf("Expected Page 2, got %d", query.Page)
	}

	if query.PageSize != 50 {
		t.Errorf("Expected PageSize 50, got %d", query.PageSize)
	}

	if query.SortOrder != datastore.SortDescending {
		t.Errorf("Expected SortDescending, got %d", query.SortOrder)
	}

	// Test nil pagination request
	nilQuery := protoDevicePaginationToQuery(nil)
	if nilQuery.Page != 1 || nilQuery.PageSize != 25 {
		t.Error("Expected default pagination for nil request")
	}
}

// Error Type Tests

func TestDeviceErrNilDeviceService_Error(t *testing.T) {
	err := ErrNilDeviceService{}
	expected := "device service is nil"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestDeviceErrNilProfileService_Error(t *testing.T) {
	err := ErrNilProfileService{}
	expected := "profile service is nil"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestDeviceErrMissingDeviceID_Error(t *testing.T) {
	err := ErrMissingDeviceID{}
	expected := "device ID is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestDeviceErrMissingProfileID_Error(t *testing.T) {
	err := ErrMissingProfileID{}
	expected := "profile ID is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestDeviceErrMissingDevice_Error(t *testing.T) {
	err := ErrMissingDevice{}
	expected := "device data is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestDeviceErrMissingProfile_Error(t *testing.T) {
	err := ErrMissingProfile{}
	expected := "profile data is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestDeviceErrMissingDeviceSerial_Error(t *testing.T) {
	err := ErrMissingDeviceSerial{}
	expected := "device serial number is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestDeviceErrMissingDeviceMACAddress_Error(t *testing.T) {
	err := ErrMissingDeviceMACAddress{}
	expected := "MAC address is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestDeviceErrDeviceOperationFailed_Error(t *testing.T) {
	err := ErrDeviceOperationFailed{Operation: "CreateDevice", Reason: "database error"}
	expected := "device operation CreateDevice failed: database error"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestDeviceErrProfileOperationFailed_Error(t *testing.T) {
	err := ErrProfileOperationFailed{Operation: "CreateProfile", Reason: "validation error"}
	expected := "profile operation CreateProfile failed: validation error"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

// Nil Conversion Tests

func TestDeviceNilConversions(t *testing.T) {
	// Test nil device conversions
	if protoDeviceToEntity(nil) != nil {
		t.Error("Expected nil for nil device proto")
	}
	if entityDeviceToProto(nil) != nil {
		t.Error("Expected nil for nil device entity")
	}

	// Test nil profile conversions
	if protoProfileToEntity(nil) != nil {
		t.Error("Expected nil for nil profile proto")
	}
	if entityProfileToProto(nil) != nil {
		t.Error("Expected nil for nil profile entity")
	}

	// Test nil network config conversions
	if protoNetworkConfigToEntity(nil) != nil {
		t.Error("Expected nil for nil network config proto")
	}
	if entityNetworkConfigToProto(nil) != nil {
		t.Error("Expected nil for nil network config entity")
	}

	// Test nil platformd config conversions
	if protoPlatformdConfigToEntity(nil) != nil {
		t.Error("Expected nil for nil platformd config proto")
	}
	if entityPlatformdConfigToProto(nil) != nil {
		t.Error("Expected nil for nil platformd config entity")
	}

	// Test nil match rules conversions
	if protoMatchRulesToEntity(nil) != nil {
		t.Error("Expected nil for nil match rules proto")
	}
	if entityMatchRulesToProto(nil) != nil {
		t.Error("Expected nil for nil match rules entity")
	}
}

// Profile with Full Configuration Test

func TestDeviceGRPCService_CreateProfile_FullConfiguration(t *testing.T) {
	service, _, _ := newTestDeviceService()
	ctx := context.Background()

	req := &platformv1.CreateProfileRequest{
		Profile: &platformv1.DeviceProfile{
			Id:    1,
			Name:  "Full Config Profile",
			Model: "Enterprise Server",
			Role:  platformv1.DeviceRole_DEVICE_ROLE_SERVER,
			Networks: map[string]*platformv1.NetworkPhaseConfig{
				"provisioning": {
					Vlan:    10,
					Dhcp:    true,
					Gateway: "192.168.10.1",
				},
				"trusted": {
					Vlan:     100,
					StaticIp: "10.0.0.100",
					Gateway:  "10.0.0.1",
				},
				"quarantine": {
					Vlan:    999,
					Gateway: "192.168.99.1",
				},
			},
			PlatformdConfig: &platformv1.PlatformdConfigRef{
				ConfigType: "reference",
				Reference:  "/etc/platformd/server.yaml",
			},
			MatchRules: &platformv1.ProfileMatchRules{
				Model:        "Enterprise Server",
				SerialPrefix: "ENT",
			},
		},
	}

	resp, err := service.CreateProfile(ctx, req)
	if err != nil {
		t.Fatalf("CreateProfile failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	profile := resp.GetProfile()
	if profile == nil {
		t.Fatal("Expected profile in response")
	}

	if profile.GetNetworks() == nil {
		t.Error("Expected networks map")
	}
	if profile.GetNetworks()["provisioning"] == nil {
		t.Error("Expected provisioning network")
	}
	if profile.GetNetworks()["trusted"] == nil {
		t.Error("Expected trusted network")
	}
	if profile.GetNetworks()["quarantine"] == nil {
		t.Error("Expected quarantine network")
	}

	if profile.GetPlatformdConfig() == nil {
		t.Error("Expected platformd config")
	}

	if profile.GetMatchRules() == nil {
		t.Error("Expected match rules")
	}
}

// Service Error Handling Tests

func TestDeviceGRPCService_ServiceErrors(t *testing.T) {
	service, deviceMock, profileMock := newTestDeviceService()
	ctx := context.Background()

	// Test count error
	deviceMock.countErr = errors.New("count failed")
	_, err := service.CountDevices(ctx, &platformv1.CountDevicesRequest{})
	if err == nil {
		t.Error("Expected error from count")
	}
	deviceMock.countErr = nil

	// Test page error
	deviceMock.pageErr = errors.New("page failed")
	_, err = service.ListDevices(ctx, &platformv1.ListDevicesRequest{})
	if err == nil {
		t.Error("Expected error from page")
	}
	deviceMock.pageErr = nil

	// Test profile count error
	profileMock.countErr = errors.New("count failed")
	_, err = service.CountProfiles(ctx, &platformv1.CountProfilesRequest{})
	if err == nil {
		t.Error("Expected error from profile count")
	}
	profileMock.countErr = nil

	// Test profile page error
	profileMock.pageErr = errors.New("page failed")
	_, err = service.ListProfiles(ctx, &platformv1.ListProfilesRequest{})
	if err == nil {
		t.Error("Expected error from profile page")
	}
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestDeviceErrorTypes(t *testing.T) {
	t.Parallel()

	t.Run("ErrDeviceNotFound", func(t *testing.T) {
		err := ErrDeviceNotFound{ID: 12345}
		expected := "device not found: 12345"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrProfileNotFound", func(t *testing.T) {
		err := ErrProfileNotFound{ID: 67890}
		expected := "profile not found: 67890"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

// TestDeviceGRPCService_AssignProfileToDevice_Success verifies the
// assignment RPC binds the EK identity and returns the updated profile.
func TestDeviceGRPCService_AssignProfileToDevice_Success(t *testing.T) {
	service, _, profileMock := newTestDeviceService()
	ctx := context.Background()

	profileMock.profiles[900] = &entities.DeviceProfile{ID: 900, Name: "assign-me"}

	resp, err := service.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{
		ProfileId:  900,
		EkSerial:   "EK-9009",
		MacAddress: "00:25:90:11:22:33",
	})
	if err != nil {
		t.Fatalf("AssignProfileToDevice: %v", err)
	}
	if resp.GetProfile() == nil {
		t.Fatal("response profile is nil")
	}
	if !resp.GetProfile().GetAssigned() {
		t.Error("profile not marked assigned")
	}
	if resp.GetProfile().GetEkSerial() != "EK-9009" {
		t.Errorf("EkSerial = %q, want EK-9009", resp.GetProfile().GetEkSerial())
	}
}

// TestDeviceGRPCService_AssignProfileToDevice_Errors verifies the
// boundary validation error paths of the assignment RPC.
func TestDeviceGRPCService_AssignProfileToDevice_Errors(t *testing.T) {
	service, _, profileMock := newTestDeviceService()
	ctx := context.Background()
	profileMock.profiles[901] = &entities.DeviceProfile{ID: 901}

	if _, err := service.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{EkSerial: "EK-1"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing profile_id: code = %v, want InvalidArgument", status.Code(err))
	}

	if _, err := service.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{ProfileId: 901}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing identity: code = %v, want InvalidArgument", status.Code(err))
	}

	if _, err := service.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{
		ProfileId: 901, EkSerial: "EK-1", EkCert: "not-a-pem",
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("invalid ek_cert: code = %v, want InvalidArgument", status.Code(err))
	}

	nilSvc := NewDeviceGRPCService(logging.NewLogger(slog.LevelError, io.Discard), nil, nil)
	if _, err := nilSvc.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{
		ProfileId: 901, EkSerial: "EK-1",
	}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("nil service: code = %v, want FailedPrecondition", status.Code(err))
	}
}

// TestDeviceGRPCService_UnassignProfileFromDevice verifies the
// unassignment RPC clears the binding, plus its error paths.
func TestDeviceGRPCService_UnassignProfileFromDevice(t *testing.T) {
	service, _, profileMock := newTestDeviceService()
	ctx := context.Background()

	profileMock.profiles[910] = &entities.DeviceProfile{
		ID: 910, EKSerial: "EK-9109", Assigned: true,
	}

	resp, err := service.UnassignProfileFromDevice(ctx, &platformv1.UnassignProfileFromDeviceRequest{
		ProfileId: 910,
	})
	if err != nil {
		t.Fatalf("UnassignProfileFromDevice: %v", err)
	}
	if resp.GetProfile().GetAssigned() {
		t.Error("profile still marked assigned")
	}
	if resp.GetProfile().GetEkSerial() != "" {
		t.Errorf("EkSerial = %q, want empty", resp.GetProfile().GetEkSerial())
	}

	if _, err := service.UnassignProfileFromDevice(ctx, &platformv1.UnassignProfileFromDeviceRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing profile_id: code = %v, want InvalidArgument", status.Code(err))
	}

	if _, err := service.UnassignProfileFromDevice(ctx, &platformv1.UnassignProfileFromDeviceRequest{ProfileId: 777777}); status.Code(err) != codes.NotFound {
		t.Errorf("unknown profile: code = %v, want NotFound", status.Code(err))
	}
}
