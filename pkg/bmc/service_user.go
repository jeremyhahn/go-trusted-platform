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

package bmc

import (
	"context"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// userManagerFor builds a ManagedUserManager for the given profile by
// opening a fresh IPMI 2.0 RMCP+ session against the BMC. Callers MUST
// Close the returned manager when finished to release the session.
func (s *Service) userManagerFor(ctx context.Context, profileID uint64) (ManagedUserManager, error) {
	if s.profiles == nil {
		return nil, ErrProfileNotFound{ProfileID: profileID}
	}
	cfg, err := s.profiles.Get(ctx, profileID)
	if err != nil {
		return nil, ErrProfileNotFound{ProfileID: profileID}
	}
	return NewUserManager(ctx, cfg, s.logger)
}

// ListUsers returns the populated BMC user slots for the given profile.
func (s *Service) ListUsers(ctx context.Context, profileID uint64) ([]User, error) {
	mgr, err := s.userManagerFor(ctx, profileID)
	if err != nil {
		return nil, err
	}
	defer mgr.Close()
	return mgr.ListUsers(ctx)
}

// CreateUser creates a new BMC user in the slot specified by user.Slot.
// The plaintext password is wrapped in a *memguard.MemoryEnclave for the
// duration of the call. An Enabled user needs a password; a name-only entry
// (empty password) must have Enabled false. An Enabled user with an empty
// password is refused before any session is opened or lock taken.
func (s *Service) CreateUser(ctx context.Context, profileID uint64, user User, password string) error {
	if user.Enabled && password == "" {
		return ErrInvalidConfig{Field: "password", Reason: "an enabled user needs a password"}
	}
	mgr, err := s.userManagerFor(ctx, profileID)
	if err != nil {
		return err
	}
	defer mgr.Close()

	// Hold the profile's user lock from the slot check through the write.
	lock, _ := s.userLocks.LoadOrStore(profileID, &sync.Mutex{})
	mu := lock.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	// Refuse a slot that already holds an account: writing it would silently
	// overwrite that account (on most BMCs slot 1 or 2 is the administrator).
	existing, err := mgr.ListUsers(ctx)
	if err != nil {
		return err
	}
	for _, u := range existing {
		if u.Slot == user.Slot {
			return ErrSlotOccupied{Slot: user.Slot}
		}
	}

	pwSecret := memguard.NewMemoryEnclaveFromString(password)
	defer pwSecret.Destroy()

	return mgr.CreateUser(ctx, user, pwSecret)
}

// DeleteUser removes the BMC user at the given slot.
func (s *Service) DeleteUser(ctx context.Context, profileID uint64, slot uint8) error {
	mgr, err := s.userManagerFor(ctx, profileID)
	if err != nil {
		return err
	}
	defer mgr.Close()
	return mgr.DeleteUser(ctx, slot)
}

// SetUserPassword updates the password for the BMC user at the given slot.
func (s *Service) SetUserPassword(ctx context.Context, profileID uint64, slot uint8, password string) error {
	mgr, err := s.userManagerFor(ctx, profileID)
	if err != nil {
		return err
	}
	defer mgr.Close()

	pwSecret := memguard.NewMemoryEnclaveFromString(password)
	defer pwSecret.Destroy()

	return mgr.SetUserPassword(ctx, slot, pwSecret)
}

// SetUserPrivilege updates the channel privilege for the BMC user at the
// given slot. The channel argument selects the IPMI logical channel;
// pass 0 to use the package default LAN channel.
func (s *Service) SetUserPrivilege(ctx context.Context, profileID uint64, slot, channel uint8, privilege Privilege) error {
	mgr, err := s.userManagerFor(ctx, profileID)
	if err != nil {
		return err
	}
	defer mgr.Close()
	return mgr.SetUserPrivilege(ctx, slot, channel, privilege)
}
