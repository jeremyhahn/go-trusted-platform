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
	"errors"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

var (
	ErrInvalidDeviceID = &MessageError{Msg: "invalid device ID"}

	// ErrHeartbeatIdentityRequired is returned when RecordHeartbeat is
	// called without the certificate-derived identity.
	ErrHeartbeatIdentityRequired = &MessageError{Msg: "heartbeat identity is required"}
)

// writeLockStripes sizes the striped write-lock table. Device write
// contention is per-device and rare (heartbeats, activation, admin
// edits); 64 stripes keeps unrelated devices from serializing while
// bounding memory.
const writeLockStripes = 64

type Service struct {
	deviceDAO dao.DeviceDAO
	// writeLocks serialize service-layer read-modify-write cycles per
	// device (striped by ID) so a heartbeat racing an activation or
	// admin edit cannot resurrect stale fields via a whole-entity Save.
	// Writers that bypass the service and use the DAO directly are NOT
	// covered — the service is the platform's device write path.
	writeLocks [writeLockStripes]sync.Mutex
}

// writeLock returns the stripe lock for a device ID.
func (s *Service) writeLock(id uint64) *sync.Mutex {
	return &s.writeLocks[id%writeLockStripes]
}

// NewService creates a new device service using the provided Datastore.
// The Datastore should be initialized with QuicBaaS storage.
func NewService(ds *Datastore) (*Service, error) {
	deviceDAO, err := ds.DeviceDAO()
	if err != nil {
		return nil, &WrappedError{Msg: "failed to get device DAO", Err: err}
	}

	return &Service{
		deviceDAO: deviceDAO,
	}, nil
}

func (s *Service) Save(ctx context.Context, device *entities.Device) error {

	if device.ID == 0 {
		return ErrInvalidDeviceID
	}

	lock := s.writeLock(device.ID)
	lock.Lock()
	defer lock.Unlock()
	if err := s.deviceDAO.Save(ctx, device); err != nil {
		return &WrappedError{Msg: "failed to save device", Err: err}
	}

	return nil
}

func (s *Service) Get(ctx context.Context, id uint64) (*entities.Device, error) {
	if id == 0 {
		return nil, ErrInvalidDeviceID
	}

	device, err := s.deviceDAO.Get(ctx, id)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to get device", Err: err}
	}

	return device, nil
}

func (s *Service) Delete(ctx context.Context, device *entities.Device) error {
	if device == nil || device.ID == 0 {
		return ErrInvalidDeviceID
	}

	lock := s.writeLock(device.ID)
	lock.Lock()
	defer lock.Unlock()
	if err := s.deviceDAO.Delete(ctx, device); err != nil {
		return &WrappedError{Msg: "failed to delete device", Err: err}
	}

	return nil
}

func (s *Service) Update(ctx context.Context, device *entities.Device) error {
	if device == nil || device.ID == 0 {
		return ErrInvalidDeviceID
	}

	lock := s.writeLock(device.ID)
	lock.Lock()
	defer lock.Unlock()
	existing, err := s.deviceDAO.Get(ctx, device.ID)
	if err != nil {
		return &WrappedError{Msg: "failed to get device for update", Err: err}
	}
	// Server-owned fields survive a caller update: API update requests
	// do not carry lifecycle or liveness state, so saving the incoming
	// entity verbatim silently erased LastHeartbeatAt, State, Hostname
	// and the enrollment timestamps on every ordinary edit. Zero-valued
	// incoming fields inherit the stored values; a caller that really
	// owns one of these transitions goes through its dedicated flow
	// (activation, quarantine, heartbeat), never a generic update.
	if device.State == "" {
		device.State = existing.State
		device.StateReason = existing.StateReason
	}
	if device.Hostname == "" {
		device.Hostname = existing.Hostname
	}
	if device.NetworkPortID == "" {
		// Clearing this would make the quarantine observer treat an
		// SDN-activated device as never-activated and skip enforcement.
		device.NetworkPortID = existing.NetworkPortID
	}
	if device.SwitchName == "" {
		device.SwitchName = existing.SwitchName
	}
	if device.SwitchPort == "" {
		device.SwitchPort = existing.SwitchPort
	}
	if device.LastHeartbeatAt.IsZero() {
		device.LastHeartbeatAt = existing.LastHeartbeatAt
	}
	if device.LastAttestedAt.IsZero() {
		device.LastAttestedAt = existing.LastAttestedAt
	}
	if device.ActivatedAt.IsZero() {
		device.ActivatedAt = existing.ActivatedAt
	}
	if device.CreatedAt.IsZero() {
		device.CreatedAt = existing.CreatedAt
	}
	if device.PriorState == "" {
		device.PriorState = existing.PriorState
	}
	if device.PriorZone == "" {
		device.PriorZone = existing.PriorZone
	}
	if device.BMCEnrollment == nil {
		device.BMCEnrollment = existing.BMCEnrollment
	}
	device.UpdatedAt = time.Now().UTC()

	if err := s.deviceDAO.Save(ctx, device); err != nil {
		return &WrappedError{Msg: "failed to update device", Err: err}
	}

	return nil
}

func (s *Service) Count(ctx context.Context) (int, error) {
	count, err := s.deviceDAO.Count(ctx)
	if err != nil {
		return 0, &WrappedError{Msg: "failed to count devices", Err: err}
	}
	return count, nil
}

func (s *Service) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.Device], error) {
	result, err := s.deviceDAO.Page(ctx, query)
	if err != nil {
		return datastore.PageResult[*entities.Device]{}, &WrappedError{Msg: "failed to page devices", Err: err}
	}
	return result, nil
}

// FindBySerial finds a device by its serial number.
func (s *Service) FindBySerial(ctx context.Context, serial string) (*entities.Device, error) {
	device, err := s.deviceDAO.FindBySerial(ctx, serial)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to find device by serial", Err: err}
	}
	return device, nil
}

// FindByHostname finds a device by its IDevID hostname (CN).
func (s *Service) FindByHostname(ctx context.Context, hostname string) (*entities.Device, error) {
	device, err := s.deviceDAO.FindByHostname(ctx, hostname)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to find device by hostname", Err: err}
	}
	return device, nil
}

// isLookupMiss reports whether a DAO lookup error means "no such
// record" (as opposed to a storage fault). The quicbaas DAO answers a
// miss with its typed not-found errors; anything else is operational.
func isLookupMiss(err error) bool {
	var byIndex quicbaas.ErrNotFoundByIndex
	if errors.As(err, &byIndex) {
		return true
	}
	var byID quicbaas.ErrNotFound
	return errors.As(err, &byID)
}

// RecordHeartbeat stamps the device's liveness timestamp. The identity
// argument is the value extracted from the caller's verified mTLS
// client certificate: it is matched against the device serial first and
// the enrollment hostname (the IDevID common name) second, because
// enrolled nodes authenticate with certificates naming their FQDN
// rather than the hardware serial. Only LastHeartbeatAt and UpdatedAt
// change — a heartbeat never moves the lifecycle state machine.
func (s *Service) RecordHeartbeat(ctx context.Context, identity string) (*entities.Device, error) {
	if identity == "" {
		return nil, ErrHeartbeatIdentityRequired
	}
	resolved, serialErr := s.deviceDAO.FindBySerial(ctx, identity)
	if serialErr != nil || resolved == nil || resolved.Serial != identity {
		// A storage fault during the serial lookup must surface as a
		// server error, never masquerade as an unknown device.
		if serialErr != nil && !isLookupMiss(serialErr) {
			return nil, &WrappedError{Msg: "heartbeat device lookup failed", Err: serialErr}
		}
		var hostErr error
		resolved, hostErr = s.deviceDAO.FindByHostname(ctx, identity)
		if hostErr != nil {
			if isLookupMiss(hostErr) {
				return nil, &HeartbeatDeviceNotFoundError{Identity: identity, Cause: hostErr}
			}
			return nil, &WrappedError{Msg: "heartbeat device lookup failed", Err: hostErr}
		}
		// Post-condition, independent of any DAO/index behavior: the
		// record a heartbeat stamps MUST carry the authenticated
		// identity — stamping a near-miss would report another node
		// alive.
		if resolved == nil || resolved.Hostname != identity {
			return nil, &HeartbeatDeviceNotFoundError{Identity: identity,
				Cause: &MessageError{Msg: "resolved device does not match heartbeat identity"}}
		}
	}
	// Serialize against every other service-layer device write and
	// RE-READ under the lock: stamping the copy resolved above would
	// write back whatever that copy held, resurrecting fields a
	// concurrent activation or admin edit just changed.
	lock := s.writeLock(resolved.ID)
	lock.Lock()
	defer lock.Unlock()
	device, err := s.deviceDAO.Get(ctx, resolved.ID)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to re-read device for heartbeat", Err: err}
	}
	// Re-validate after the locked re-read: a concurrent Update may have
	// renamed the record between lookup and lock, and the post-condition
	// is on the record actually stamped, not the one first resolved.
	if device.Serial != identity && device.Hostname != identity {
		return nil, &HeartbeatDeviceNotFoundError{Identity: identity,
			Cause: &MessageError{Msg: "device no longer carries the heartbeat identity"}}
	}
	now := time.Now().UTC()
	device.LastHeartbeatAt = now
	device.UpdatedAt = now
	if err := s.deviceDAO.Save(ctx, device); err != nil {
		return nil, &WrappedError{Msg: "failed to record device heartbeat", Err: err}
	}
	return device, nil
}
