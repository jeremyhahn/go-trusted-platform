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

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

var (
	ErrInvalidDeviceID = fmt.Errorf("invalid device ID")
)

type Service struct {
	deviceDAO dao.DeviceDAO
}

// NewService creates a new device service using the provided Datastore.
// The Datastore should be initialized with QuicBaaS storage.
func NewService(ds *Datastore) (*Service, error) {
	deviceDAO, err := ds.DeviceDAO()
	if err != nil {
		return nil, fmt.Errorf("failed to get device DAO: %w", err)
	}

	return &Service{
		deviceDAO: deviceDAO,
	}, nil
}

func (s *Service) Save(ctx context.Context, device *entities.Device) error {

	if device.ID == 0 {
		return ErrInvalidDeviceID
	}

	if err := s.deviceDAO.Save(ctx, device); err != nil {
		return fmt.Errorf("failed to save device: %w", err)
	}

	return nil
}

func (s *Service) Get(ctx context.Context, id uint64) (*entities.Device, error) {
	if id == 0 {
		return nil, ErrInvalidDeviceID
	}

	device, err := s.deviceDAO.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	return device, nil
}

func (s *Service) Delete(ctx context.Context, device *entities.Device) error {
	if device == nil || device.ID == 0 {
		return ErrInvalidDeviceID
	}

	if err := s.deviceDAO.Delete(ctx, device); err != nil {
		return fmt.Errorf("failed to delete device: %w", err)
	}

	return nil
}

func (s *Service) Update(ctx context.Context, device *entities.Device) error {
	if device == nil || device.ID == 0 {
		return ErrInvalidDeviceID
	}

	// Verify device exists before updating
	_, err := s.deviceDAO.Get(ctx, device.ID)
	if err != nil {
		return fmt.Errorf("failed to get device for update: %w", err)
	}

	if err := s.deviceDAO.Save(ctx, device); err != nil {
		return fmt.Errorf("failed to update device: %w", err)
	}

	return nil
}

func (s *Service) Count(ctx context.Context) (int, error) {
	count, err := s.deviceDAO.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to count devices: %w", err)
	}
	return count, nil
}

func (s *Service) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.Device], error) {
	result, err := s.deviceDAO.Page(ctx, query)
	if err != nil {
		return datastore.PageResult[*entities.Device]{}, fmt.Errorf("failed to page devices: %w", err)
	}
	return result, nil
}

// FindBySerial finds a device by its serial number.
func (s *Service) FindBySerial(ctx context.Context, serial string) (*entities.Device, error) {
	device, err := s.deviceDAO.FindBySerial(ctx, serial)
	if err != nil {
		return nil, fmt.Errorf("failed to find device by serial: %w", err)
	}
	return device, nil
}

// FindByHostname finds a device by its IDevID hostname (CN).
func (s *Service) FindByHostname(ctx context.Context, hostname string) (*entities.Device, error) {
	device, err := s.deviceDAO.FindByHostname(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to find device by hostname: %w", err)
	}
	return device, nil
}
