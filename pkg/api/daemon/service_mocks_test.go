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
	"sync"

	devicepkg "github.com/jeremyhahn/go-trusted-platform/pkg/device"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// =============================================================================
// Mock Device Service shared by the device attestation tests
// =============================================================================

type spMockDeviceService struct {
	mu          sync.RWMutex
	devices     map[uint64]*deviceentities.Device
	nextID      uint64
	shouldError bool
	errorMsg    string
}

func newSPMockDeviceService() *spMockDeviceService {
	return &spMockDeviceService{
		devices: make(map[uint64]*deviceentities.Device),
		nextID:  1,
	}
}

// Create mints an ID when the caller has none, then takes the ordinary
// Save path, mirroring the real service (#525).
func (m *spMockDeviceService) Create(ctx context.Context, dev *deviceentities.Device) error {
	if dev == nil {
		return devicepkg.ErrNilDevice
	}
	m.mu.Lock()
	if dev.ID == 0 {
		dev.ID = m.nextID
		m.nextID++
	}
	m.mu.Unlock()
	return m.Save(ctx, dev)
}

func (m *spMockDeviceService) Save(ctx context.Context, device *deviceentities.Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	// Save refuses a zero ID exactly as the real service does; minting
	// one here is what let the create path look healthy while production
	// refused it (#525). Create below does the minting.
	if device == nil || device.ID == 0 {
		return devicepkg.ErrInvalidDeviceID
	}
	m.devices[device.ID] = device
	return nil
}

func (m *spMockDeviceService) Get(ctx context.Context, id uint64) (*deviceentities.Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	if device, ok := m.devices[id]; ok {
		return device, nil
	}
	return nil, ErrDeviceNotFound{DeviceID: "not found"}
}

func (m *spMockDeviceService) Delete(ctx context.Context, device *deviceentities.Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	delete(m.devices, device.ID)
	return nil
}

func (m *spMockDeviceService) Update(ctx context.Context, device *deviceentities.Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	if _, ok := m.devices[device.ID]; !ok {
		return ErrDeviceNotFound{DeviceID: "not found"}
	}
	m.devices[device.ID] = device
	return nil
}

func (m *spMockDeviceService) Count(ctx context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.shouldError {
		return 0, errors.New(m.errorMsg)
	}
	return len(m.devices), nil
}

func (m *spMockDeviceService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*deviceentities.Device], error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.shouldError {
		return datastore.PageResult[*deviceentities.Device]{}, errors.New(m.errorMsg)
	}
	devices := make([]*deviceentities.Device, 0, len(m.devices))
	for _, d := range m.devices {
		devices = append(devices, d)
	}
	return datastore.PageResult[*deviceentities.Device]{
		Entities: devices,
		Total:    len(devices),
	}, nil
}

func (m *spMockDeviceService) FindBySerial(ctx context.Context, serial string) (*deviceentities.Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	for _, d := range m.devices {
		if d.Serial == serial {
			return d, nil
		}
	}
	return nil, ErrDeviceNotFound{DeviceID: serial}
}

// FindByHostname finds a device by its IDevID hostname.
func (m *spMockDeviceService) FindByHostname(ctx context.Context, hostname string) (*deviceentities.Device, error) {
	for _, d := range m.devices {
		if d.Hostname == hostname {
			return d, nil
		}
	}
	return nil, errors.New("device not found by hostname")
}
