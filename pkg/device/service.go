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
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

var (
	ErrInvalidDeviceID = &MessageError{Msg: "invalid device ID"}

	// ErrNilDevice is returned when a write is handed no device at all.
	ErrNilDevice = &MessageError{Msg: "device is required"}

	// ErrIdentityRequired is returned when an identity lookup
	// (RecordHeartbeat, ResolveIdentity) is called without the
	// certificate-derived identity.
	ErrIdentityRequired = &MessageError{Msg: "device identity is required"}
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
	// createLock serializes creates so two racing for one serial cannot
	// both pass the uniqueness check.
	createLock sync.Mutex
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

// Create persists a device that does not exist yet, assigning its
// identity when the caller has none to supply.
//
// This is the create verb every transport adapter calls. Save is the
// unrestricted write primitive and doubles as the update primitive, so
// it requires a non-zero ID; a caller that is creating a device has no
// ID yet, which is what creation means. Routing creates through Save
// therefore refused every one of them (#525).
//
// Identity is minted by NewID(), the platform's single device-id
// allocator — the same one Register uses on the enrollment path — so
// this adds a create path, not a second way of minting an id. Adapters
// no longer mint their own: assignment lives behind the service
// boundary where it can be relied upon by all six transports.
//
// A caller-supplied non-zero ID is honoured rather than refused, which
// is what the REST create handler has always done and what an operator
// restoring a known record needs. Create is therefore an upsert on that
// path exactly as Save is; it is not a claim that the ID is unused.
func (s *Service) Create(ctx context.Context, device *entities.Device) error {
	if device == nil {
		return ErrNilDevice
	}

	if device.ID == 0 {
		device.ID = NewID()
	}
	// A created device starts registered with both timestamps set, whichever
	// transport created it, so the same request persists the same entity on
	// every listener (#484).
	if device.State == "" {
		device.State = entities.DeviceStateRegistered
	}
	if device.CreatedAt.IsZero() {
		device.CreatedAt = time.Now()
	}
	if device.UpdatedAt.IsZero() {
		device.UpdatedAt = device.CreatedAt
	}

	s.createLock.Lock()
	defer s.createLock.Unlock()
	if err := s.refuseTakenSerial(ctx, device.Serial); err != nil {
		return err
	}
	return s.Save(ctx, device)
}

// refuseTakenSerial fails with ErrDeviceSerialExists when another device
// already holds serial. An empty serial is not checked: no device is
// matched by it.
func (s *Service) refuseTakenSerial(ctx context.Context, serial string) error {
	if serial == "" {
		return nil
	}
	existing, err := s.deviceDAO.FindBySerial(ctx, serial)
	if err != nil {
		if isLookupMiss(err) {
			return nil
		}
		return &WrappedError{Msg: "failed to check device serial", Err: err}
	}
	if existing != nil && existing.Serial == serial {
		return ErrDeviceSerialExists{Serial: serial}
	}
	return nil
}

func (s *Service) Save(ctx context.Context, device *entities.Device) error {

	if device == nil {
		return ErrNilDevice
	}

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
	if device.LastHeartbeatAddr == "" {
		device.LastHeartbeatAddr = existing.LastHeartbeatAddr
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
	if device.PriorPortClass == "" {
		device.PriorPortClass = existing.PriorPortClass
	}
	if device.BMCEnrollment == nil {
		device.BMCEnrollment = existing.BMCEnrollment
	}

	// Identity and enrollment material survive a caller update for the same
	// reason the lifecycle fields above do, and the omission was worse: a PUT
	// that did not name them erased the device's TPM identity binding with no
	// error and no audit trail. A machine that had been attested could no
	// longer prove it, and nothing said so (issue #252).
	//
	// TenantID is the sharpest case. device.Request has no tenant field at
	// all, so a REST update CANNOT populate it — every update erased it,
	// not merely the partial ones, detaching the device from its tenant.
	if device.TenantID == "" {
		device.TenantID = existing.TenantID
	}
	if device.EKCert == "" {
		device.EKCert = existing.EKCert
	}
	if device.AttestPub == "" {
		device.AttestPub = existing.AttestPub
	}
	if device.AttestCert == "" {
		device.AttestCert = existing.AttestCert
	}
	if device.IDevIDCert == "" {
		device.IDevIDCert = existing.IDevIDCert
	}
	if device.SigningPub == "" {
		device.SigningPub = existing.SigningPub
	}
	if len(device.EventLog) == 0 {
		device.EventLog = existing.EventLog
	}
	if device.HashAlgoId == 0 {
		device.HashAlgoId = existing.HashAlgoId
	}
	// Model and Serial are legitimately editable, and remain so: a caller
	// that sends a new value still wins. Restoring only the zero value stops
	// an omission from erasing the device's identifier.
	if device.Model == "" {
		device.Model = existing.Model
	}
	if device.Serial == "" {
		device.Serial = existing.Serial
	}

	device.UpdatedAt = time.Now().UTC()

	if err := s.deviceDAO.Save(ctx, device); err != nil {
		return &WrappedError{Msg: "failed to update device", Err: err}
	}

	return nil
}

// ClearAttestCert removes the device's attestation certificate while the
// record still holds expected. It is the one write that may empty the field:
// Update keeps a stored certificate when the incoming one is empty (#252).
// The comparison runs under the device's write lock, so a certificate
// recorded concurrently is never cleared; that case is
// ErrAttestCertClearConflict.
func (s *Service) ClearAttestCert(ctx context.Context, id uint64, expected string) error {
	if id == 0 {
		return ErrInvalidDeviceID
	}

	lock := s.writeLock(id)
	lock.Lock()
	defer lock.Unlock()
	existing, err := s.deviceDAO.Get(ctx, id)
	if err != nil {
		return &WrappedError{Msg: "failed to get device for attestation certificate clear", Err: err}
	}
	if strings.TrimSpace(existing.AttestCert) != strings.TrimSpace(expected) {
		return ErrAttestCertClearConflict{DeviceID: id}
	}
	existing.AttestCert = ""
	existing.UpdatedAt = time.Now().UTC()
	if err := s.deviceDAO.Save(ctx, existing); err != nil {
		return &WrappedError{Msg: "failed to clear device attestation certificate", Err: err}
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

// ResolveIdentity finds the device a verified certificate identity names.
// The identity is matched against the device serial first and the
// enrollment hostname (the IDevID common name) second, because enrolled
// nodes authenticate with certificates naming their FQDN rather than the
// hardware serial. A miss is an *IdentityNotFoundError; a storage fault is
// never reported as one.
func (s *Service) ResolveIdentity(ctx context.Context, identity string) (*entities.Device, error) {
	if identity == "" {
		return nil, ErrIdentityRequired
	}
	resolved, serialErr := s.deviceDAO.FindBySerial(ctx, identity)
	if serialErr == nil && resolved != nil && resolved.Serial == identity {
		return resolved, nil
	}
	// A storage fault during the serial lookup must surface as a server
	// error, never masquerade as an unknown device.
	if serialErr != nil && !isLookupMiss(serialErr) {
		return nil, &WrappedError{Msg: "device identity lookup failed", Err: serialErr}
	}
	resolved, hostErr := s.deviceDAO.FindByHostname(ctx, identity)
	if hostErr != nil {
		if isLookupMiss(hostErr) {
			return nil, &IdentityNotFoundError{Identity: identity, Cause: hostErr}
		}
		return nil, &WrappedError{Msg: "device identity lookup failed", Err: hostErr}
	}
	// Post-condition, independent of any DAO/index behavior: the record
	// returned MUST carry the authenticated identity — answering with a
	// near-miss would act on another node.
	if resolved == nil || resolved.Hostname != identity {
		return nil, &IdentityNotFoundError{Identity: identity,
			Cause: &MessageError{Msg: "resolved device does not match identity"}}
	}
	return resolved, nil
}

// RecordHeartbeat stamps the device's liveness timestamp. The identity
// argument is the value extracted from the caller's verified mTLS
// client certificate, resolved by ResolveIdentity. Only LastHeartbeatAt
// and UpdatedAt change — a heartbeat never moves the lifecycle state
// machine.
func (s *Service) RecordHeartbeat(ctx context.Context, identity string, peerAddr string) (*entities.Device, error) {
	resolved, err := s.ResolveIdentity(ctx, identity)
	if err != nil {
		return nil, err
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
		return nil, &IdentityNotFoundError{Identity: identity,
			Cause: &MessageError{Msg: "device no longer carries the heartbeat identity"}}
	}
	now := time.Now().UTC()
	device.LastHeartbeatAt = now
	device.UpdatedAt = now
	if addr := heartbeatPeerAddr(peerAddr); addr != "" {
		device.LastHeartbeatAddr = addr
	}
	if err := s.deviceDAO.Save(ctx, device); err != nil {
		return nil, &WrappedError{Msg: "failed to record device heartbeat", Err: err}
	}
	return device, nil
}

// heartbeatPeerAddr normalises a transport peer address for the device
// record. Only an IP literal (with or without port) is accepted: the value
// is dialled by the attestation collector, and anything that is not a
// verified transport address must never reach it. An empty result leaves
// the previously recorded address in place.
func heartbeatPeerAddr(peerAddr string) string {
	peerAddr = strings.TrimSpace(peerAddr)
	if peerAddr == "" {
		return ""
	}
	host := peerAddr
	if h, _, err := net.SplitHostPort(peerAddr); err == nil {
		host = h
	}
	if net.ParseIP(host) == nil {
		return ""
	}
	return peerAddr
}
