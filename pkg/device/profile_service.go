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
	"fmt"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// ErrInvalidProfileID indicates an invalid or zero profile ID was provided.
type ErrInvalidProfileID struct{}

func (e ErrInvalidProfileID) Error() string { return "device: invalid profile ID" }

// ProfileService provides business logic for device profile management.
type ProfileService struct {
	profileDAO dao.DeviceProfileDAO
}

// NewProfileService creates a new profile service using the provided Datastore.
// The Datastore should be initialized with QuicBaaS storage.
func NewProfileService(ds *Datastore) (*ProfileService, error) {
	profileDAO, err := ds.ProfileDAO()
	if err != nil {
		return nil, fmt.Errorf("failed to get profile DAO: %w", err)
	}

	return &ProfileService{
		profileDAO: profileDAO,
	}, nil
}

// DAO returns the underlying DeviceProfileDAO. It is used by the SDN
// enrollment hook constructor which requires direct DAO access for
// profile matching during device enrollment.
func (s *ProfileService) DAO() dao.DeviceProfileDAO {
	return s.profileDAO
}

// Save persists a device profile.
func (s *ProfileService) Save(ctx context.Context, profile *entities.DeviceProfile) error {

	if profile.ID == 0 {
		return ErrInvalidProfileID{}
	}

	if err := s.profileDAO.Save(ctx, profile); err != nil {
		return fmt.Errorf("failed to save profile: %w", err)
	}

	return nil
}

// Get retrieves a device profile by ID.
func (s *ProfileService) Get(ctx context.Context, id uint64) (*entities.DeviceProfile, error) {
	if id == 0 {
		return nil, ErrInvalidProfileID{}
	}

	profile, err := s.profileDAO.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get profile: %w", err)
	}

	return profile, nil
}

// Delete removes a device profile.
func (s *ProfileService) Delete(ctx context.Context, profile *entities.DeviceProfile) error {
	if profile == nil || profile.ID == 0 {
		return ErrInvalidProfileID{}
	}

	if err := s.profileDAO.Delete(ctx, profile); err != nil {
		return fmt.Errorf("failed to delete profile: %w", err)
	}

	return nil
}

// Update updates an existing device profile.
func (s *ProfileService) Update(ctx context.Context, profile *entities.DeviceProfile) error {
	if profile == nil || profile.ID == 0 {
		return ErrInvalidProfileID{}
	}

	// Verify profile exists before updating
	_, err := s.profileDAO.Get(ctx, profile.ID)
	if err != nil {
		return fmt.Errorf("failed to get profile for update: %w", err)
	}

	if err := s.profileDAO.Save(ctx, profile); err != nil {
		return fmt.Errorf("failed to update profile: %w", err)
	}

	return nil
}

// Count returns the total number of device profiles.
func (s *ProfileService) Count(ctx context.Context) (int, error) {
	count, err := s.profileDAO.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to count profiles: %w", err)
	}
	return count, nil
}

// Page returns a paginated list of device profiles.
func (s *ProfileService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.DeviceProfile], error) {
	result, err := s.profileDAO.Page(ctx, query)
	if err != nil {
		return datastore.PageResult[*entities.DeviceProfile]{}, fmt.Errorf("failed to page profiles: %w", err)
	}
	return result, nil
}

// FindByMACAddress finds a profile matching the given MAC address prefix.
func (s *ProfileService) FindByMACAddress(ctx context.Context, macAddr string) (*entities.DeviceProfile, error) {
	profile, err := s.profileDAO.FindByMACPrefix(ctx, macAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to find profile by MAC address: %w", err)
	}
	return profile, nil
}

// FindBySerial finds a profile matching the given serial number prefix.
func (s *ProfileService) FindBySerial(ctx context.Context, serial string) (*entities.DeviceProfile, error) {
	profile, err := s.profileDAO.FindBySerialPrefix(ctx, serial)
	if err != nil {
		return nil, fmt.Errorf("failed to find profile by serial: %w", err)
	}
	return profile, nil
}

// FindMatchingProfile finds a profile that matches the given device characteristics.
func (s *ProfileService) FindMatchingProfile(ctx context.Context, macAddr, serial, model string) (*entities.DeviceProfile, error) {
	profile, err := s.profileDAO.FindMatchingProfile(ctx, macAddr, serial, model)
	if err != nil {
		return nil, fmt.Errorf("failed to find matching profile: %w", err)
	}
	return profile, nil
}

// FindConfigForDevice finds a profile for a device using resolution priority:
// EK serial -> exact MAC -> prefix match rules.
func (s *ProfileService) FindConfigForDevice(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
	if ekSerial == "" && mac == "" {
		return nil, ErrDeviceIdentityRequired{}
	}

	profile, err := s.profileDAO.FindConfigForDevice(ctx, ekSerial, mac)
	if err != nil {
		return nil, ErrNoMatchingConfig{EKSerial: ekSerial, MAC: mac}
	}

	return profile, nil
}

// AssignToDevice binds a profile to a specific device by setting its EK serial
// and/or MAC address and marking it as assigned.
func (s *ProfileService) AssignToDevice(ctx context.Context, profileID uint64, ekSerial, mac string) error {
	if ekSerial == "" && mac == "" {
		return ErrDeviceIdentityRequired{}
	}

	if profileID == 0 {
		return ErrInvalidProfileID{}
	}

	profile, err := s.profileDAO.Get(ctx, profileID)
	if err != nil {
		return fmt.Errorf("failed to get profile for assignment: %w", err)
	}

	if ekSerial != "" {
		profile.EKSerial = ekSerial
	}
	if mac != "" {
		profile.MACAddress = mac
	}

	profile.Assigned = true
	profile.AssignedAt = time.Now().UTC()

	if err := s.profileDAO.Save(ctx, profile); err != nil {
		return fmt.Errorf("failed to save profile assignment: %w", err)
	}

	return nil
}
