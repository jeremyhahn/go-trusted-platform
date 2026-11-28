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
	cfg, err := s.profileConfig(ctx, profileID)
	if err != nil {
		return nil, err
	}
	return NewUserManager(ctx, cfg, s.logger)
}

// profileConfig loads the stored BMC config of the given profile; a missing
// store or profile is ErrProfileNotFound.
func (s *Service) profileConfig(ctx context.Context, profileID uint64) (*Config, error) {
	if s.profiles == nil {
		return nil, ErrProfileNotFound{ProfileID: profileID}
	}
	cfg, err := s.profiles.Get(ctx, profileID)
	if err != nil {
		return nil, ErrProfileNotFound{ProfileID: profileID}
	}
	return cfg, nil
}

// refuseLoginAccount refuses a write to the account the profile logs in as,
// because the stored profile credential would no longer open a management
// session. It returns ErrInvalidConfig on the slot, with reason, when the
// user in slot has the profile's username. A failed user list is returned,
// so the check fails closed.
func refuseLoginAccount(ctx context.Context, mgr ManagedUserManager, cfg *Config, slot uint8, reason string) error {
	users, err := mgr.ListUsers(ctx)
	if err != nil {
		return err
	}
	for _, u := range users {
		if u.Slot == slot && u.Username == cfg.Username {
			return ErrInvalidConfig{Field: "slot", Reason: reason}
		}
	}
	return nil
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

// DeleteUser removes the BMC user at the given slot. It refuses the account
// the profile logs in as and writes nothing then.
func (s *Service) DeleteUser(ctx context.Context, profileID uint64, slot uint8) error {
	cfg, err := s.profileConfig(ctx, profileID)
	if err != nil {
		return err
	}
	mgr, err := NewUserManager(ctx, cfg, s.logger)
	if err != nil {
		return err
	}
	defer mgr.Close()
	if err := refuseLoginAccount(ctx, mgr, cfg, slot, "the slot holds the account this profile logs in as; deleting it would leave the stored credential unable to open a session"); err != nil {
		return err
	}
	return mgr.DeleteUser(ctx, slot)
}

// SetUserPassword updates the password for the BMC user at the given slot.
// It refuses the account the profile logs in as, because the stored profile
// password would no longer open a session (no rotation path updates it yet);
// it writes nothing then.
func (s *Service) SetUserPassword(ctx context.Context, profileID uint64, slot uint8, password string) error {
	cfg, err := s.profileConfig(ctx, profileID)
	if err != nil {
		return err
	}
	mgr, err := NewUserManager(ctx, cfg, s.logger)
	if err != nil {
		return err
	}
	defer mgr.Close()

	if err := refuseLoginAccount(ctx, mgr, cfg, slot, "the slot holds the account this profile logs in as; its password cannot be changed until the stored credential is rotated with it"); err != nil {
		return err
	}

	pwSecret := memguard.NewMemoryEnclaveFromString(password)
	defer pwSecret.Destroy()

	return mgr.SetUserPassword(ctx, slot, pwSecret)
}

// SetUserPrivilege updates the channel privilege for the BMC user at the
// given slot. The channel argument selects the IPMI logical channel;
// pass 0 to use the package default LAN channel. Any privilege change on the
// account the profile logs in as is refused (fail closed), even to its
// current level, and nothing is written then.
func (s *Service) SetUserPrivilege(ctx context.Context, profileID uint64, slot, channel uint8, privilege Privilege) error {
	cfg, err := s.profileConfig(ctx, profileID)
	if err != nil {
		return err
	}
	mgr, err := NewUserManager(ctx, cfg, s.logger)
	if err != nil {
		return err
	}
	defer mgr.Close()
	if err := refuseLoginAccount(ctx, mgr, cfg, slot, "the slot holds the account this profile logs in as; its privilege cannot be changed while the profile manages the BMC through it"); err != nil {
		return err
	}
	return mgr.SetUserPrivilege(ctx, slot, channel, privilege)
}
