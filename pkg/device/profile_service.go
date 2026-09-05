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
	"strconv"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// ErrInvalidProfileID indicates an invalid or zero profile ID was provided.
type ErrInvalidProfileID struct{}

func (e ErrInvalidProfileID) Error() string { return "device: invalid profile ID" }

// ErrProfileVLANsNotDistinct is returned when a profile's provisioning
// (enrollment) network and trusted (post-enrollment) network share a VLAN.
// The provisioning VLAN is the fail-closed revert target for physical port
// activation; if it equalled the trusted VLAN, "closed" would mean "open".
type ErrProfileVLANsNotDistinct struct {
	VLAN uint16
}

func (e ErrProfileVLANsNotDistinct) Error() string {
	return "device: invalid profile: provisioning and trusted networks share VLAN " +
		strconv.FormatUint(uint64(e.VLAN), 10) +
		"; the provisioning VLAN is the fail-closed revert target and must differ"
}

// validateNetworkPhases rejects a profile whose provisioning and trusted
// networks share a VLAN. It is reached only through saveValidated, which
// every profile-persisting method funnels into, so it is the one
// enforcement point behind every transport (REST, gRPC, QUIC, MCP, CLI).
func validateNetworkPhases(profile *entities.DeviceProfile) error {
	provisioning := profile.GetEnrollmentNetworkConfig()
	trusted := profile.GetPostEnrollmentNetworkConfig()
	if provisioning == nil || trusted == nil {
		return nil
	}
	if provisioning.VLAN == trusted.VLAN {
		return ErrProfileVLANsNotDistinct{VLAN: provisioning.VLAN}
	}
	return nil
}

// ProfileService provides business logic for device profile management.
type ProfileService struct {
	profileDAO dao.DeviceProfileDAO
}

// NewProfileService creates a new profile service using the provided Datastore.
// The Datastore should be initialized with QuicBaaS storage.
func NewProfileService(ds *Datastore) (*ProfileService, error) {
	profileDAO, err := ds.ProfileDAO()
	if err != nil {
		return nil, &WrappedError{Msg: "failed to get profile DAO", Err: err}
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

	return s.saveValidated(ctx, profile, "failed to save profile")
}

// saveValidated is the seam through which every profile mutation that can
// INTRODUCE invalid network state reaches the DAO. It runs
// validateNetworkPhases first, so no such path can persist a profile whose
// provisioning and trusted networks share a VLAN — including the paths that
// do not themselves touch the network config and would otherwise write back
// an invalid profile they merely loaded.
func (s *ProfileService) saveValidated(ctx context.Context, profile *entities.DeviceProfile, msg string) error {
	if err := validateNetworkPhases(profile); err != nil {
		return err
	}

	return s.save(ctx, profile, msg)
}

// save is the one call to profileDAO.Save in this file, which is what makes
// the enforcement claim above checkable rather than aspirational: to reach
// the DAO at all you go through save, and everything that can introduce
// invalid state goes through saveValidated first.
//
// Call save directly ONLY from a path that REMOVES state. See
// UnassignFromDevice for the one such caller and the reasoning.
func (s *ProfileService) save(ctx context.Context, profile *entities.DeviceProfile, msg string) error {
	if err := s.profileDAO.Save(ctx, profile); err != nil {
		return &WrappedError{Msg: msg, Err: err}
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
		return nil, &WrappedError{Msg: "failed to get profile", Err: err}
	}

	return profile, nil
}

// Delete removes a device profile.
func (s *ProfileService) Delete(ctx context.Context, profile *entities.DeviceProfile) error {
	if profile == nil || profile.ID == 0 {
		return ErrInvalidProfileID{}
	}

	if err := s.profileDAO.Delete(ctx, profile); err != nil {
		return &WrappedError{Msg: "failed to delete profile", Err: err}
	}

	return nil
}

// Update updates an existing device profile.
func (s *ProfileService) Update(ctx context.Context, profile *entities.DeviceProfile) error {
	if profile == nil || profile.ID == 0 {
		return ErrInvalidProfileID{}
	}

	// Validated up front, ahead of the existence check, so an invalid
	// profile reports the validation failure rather than a lookup failure.
	// saveValidated validates again; the repetition is deliberate and keeps
	// the seam the single enforcement point.
	if err := validateNetworkPhases(profile); err != nil {
		return err
	}

	// Verify profile exists before updating
	existing, err := s.profileDAO.Get(ctx, profile.ID)
	if err != nil {
		return &WrappedError{Msg: "failed to get profile for update", Err: err}
	}

	// Server-owned profile state survives a caller update, for the same
	// reason the device service restores its own (#252, #374): the REST
	// handler builds its entity from the request alone, and ProfileRequest
	// deliberately cannot carry these fields. Without this, an ordinary
	// profile edit erased the PCR baseline the verifier captured (#373) and
	// the next quote re-seeded one from whichever device attested first —
	// security state lost with no error and no audit trail (#446).
	//
	// Assigned is cleared only by UnassignFromDevice, which bypasses Update
	// on purpose, so a zero value here is an omission, never a request.
	if profile.PCRBaseline == nil {
		profile.PCRBaseline = existing.PCRBaseline
	}
	// TLSServerName is operator-set, but every write path that reaches this
	// service either merges onto the stored record or, on the live REST
	// PUT, rebuilds the entity from a request the console fills from its
	// form. A console edit that does not know the field must not erase the
	// name the attestation collector verifies node certificates against
	// (#430): without it the collector fails closed for every device on the
	// profile. Omission fills from the stored record; a supplied value wins.
	if profile.TLSServerName == "" {
		profile.TLSServerName = existing.TLSServerName
	}
	if !profile.Assigned && existing.Assigned {
		profile.Assigned = existing.Assigned
		profile.AssignedAt = existing.AssignedAt
	}

	return s.saveValidated(ctx, profile, "failed to update profile")
}

// Count returns the total number of device profiles.
func (s *ProfileService) Count(ctx context.Context) (int, error) {
	count, err := s.profileDAO.Count(ctx)
	if err != nil {
		return 0, &WrappedError{Msg: "failed to count profiles", Err: err}
	}
	return count, nil
}

// Page returns a paginated list of device profiles.
func (s *ProfileService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.DeviceProfile], error) {
	result, err := s.profileDAO.Page(ctx, query)
	if err != nil {
		return datastore.PageResult[*entities.DeviceProfile]{}, &WrappedError{Msg: "failed to page profiles", Err: err}
	}
	return result, nil
}

// FindByMACAddress finds a profile matching the given MAC address prefix.
func (s *ProfileService) FindByMACAddress(ctx context.Context, macAddr string) (*entities.DeviceProfile, error) {
	profile, err := s.profileDAO.FindByMACPrefix(ctx, macAddr)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to find profile by MAC address", Err: err}
	}
	return profile, nil
}

// FindBySerial finds a profile matching the given serial number prefix.
func (s *ProfileService) FindBySerial(ctx context.Context, serial string) (*entities.DeviceProfile, error) {
	profile, err := s.profileDAO.FindBySerialPrefix(ctx, serial)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to find profile by serial", Err: err}
	}
	return profile, nil
}

// FindMatchingProfile finds a profile that matches the given device characteristics.
func (s *ProfileService) FindMatchingProfile(ctx context.Context, macAddr, serial, model string) (*entities.DeviceProfile, error) {
	profile, err := s.profileDAO.FindMatchingProfile(ctx, macAddr, serial, model)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to find matching profile", Err: err}
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
// and/or MAC address and marking it as assigned. It is a back-compatible
// wrapper around AssignToDeviceWithEK that prestages no EK certificate.
func (s *ProfileService) AssignToDevice(ctx context.Context, profileID uint64, ekSerial, mac string) error {
	return s.AssignToDeviceWithEK(ctx, profileID, ekSerial, mac, "")
}

// AssignToDeviceWithEK binds a profile to a specific device by setting its EK
// serial and/or MAC address, optionally prestaging the device's PEM-encoded EK
// certificate for hardware-EK verification, and marking the profile assigned.
//
// When ekCertPEM is non-empty it is stored on the profile so pre-enrollment
// config delivery (paradigm B) can cryptographically bind the delivered config
// to the hardware EK. An empty ekCertPEM leaves any existing EKCert untouched,
// preserving back-compatibility for callers that only know the EK serial/MAC.
func (s *ProfileService) AssignToDeviceWithEK(ctx context.Context, profileID uint64, ekSerial, mac, ekCertPEM string) error {
	if ekSerial == "" && mac == "" {
		return ErrDeviceIdentityRequired{}
	}

	if profileID == 0 {
		return ErrInvalidProfileID{}
	}

	profile, err := s.profileDAO.Get(ctx, profileID)
	if err != nil {
		return &WrappedError{Msg: "failed to get profile for assignment", Err: err}
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

	return s.saveValidated(ctx, profile, "failed to save profile assignment")
}

// UnassignFromDevice clears a profile's device binding: the EK serial, MAC
// address, prestaged EK certificate, and assignment state are all reset so
// the profile returns to the unassigned pool. It is the symmetric inverse
// of AssignToDeviceWithEK.
func (s *ProfileService) UnassignFromDevice(ctx context.Context, profileID uint64) error {
	if profileID == 0 {
		return ErrInvalidProfileID{}
	}

	profile, err := s.profileDAO.Get(ctx, profileID)
	if err != nil {
		return &WrappedError{Msg: "failed to get profile for unassignment", Err: err}
	}

	profile.EKSerial = ""
	profile.MACAddress = ""
	profile.EKCert = ""
	profile.Assigned = false
	profile.AssignedAt = time.Time{}

	// Unassign deliberately does NOT run validateNetworkPhases.
	//
	// Validation guards the INTRODUCTION of invalid state; unassign is the
	// REMOVAL path. Refusing to unassign a profile whose VLANs are already
	// invalid strands the operator: the device cannot be detached from a
	// profile it is trying to stop using until someone repairs a profile
	// nobody wants any more — precisely the wrong constraint during an
	// incident. Delete does not validate either, so refusing here would
	// protect an inconsistency in which paths validate rather than an
	// invariant.
	//
	// The failure mode this permits (an invalid profile briefly stays
	// stored) is strictly less bad than the one it avoids (an operator
	// cannot detach a bad profile), and activation is independently
	// protected by the runtime guard in transitionSwitchPort. Do not
	// "restore consistency" by routing this through saveValidated.
	return s.save(ctx, profile, "failed to save profile unassignment")
}
