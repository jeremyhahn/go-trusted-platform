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

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// userManagerFor builds a ManagedUserManager for the given profile by
// opening a fresh IPMI 2.0 RMCP+ session against the BMC. Callers MUST
// Close the returned manager when finished to release the session.
func (s *Service) userManagerFor(ctx context.Context, profileID uint64) (ManagedUserManager, *Config, error) {
	cfg, err := s.profileConfig(ctx, profileID)
	if err != nil {
		return nil, nil, err
	}
	mgr, err := NewUserManager(ctx, cfg, s.logger)
	if err != nil {
		return nil, nil, err
	}
	return mgr, cfg, nil
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

// lockUsers takes the profile's user lock stripe, a 1-slot channel, and
// returns its release. It waits in a select on ctx.Done(): when ctx ends
// first it returns ctx.Err() without the lock. A select picks at random when
// both are ready, so ctx is checked once more after the lock is taken, and
// on error the lock is released and the error returned.
func (s *Service) lockUsers(ctx context.Context, profileID uint64) (func(), error) {
	ch := s.userLock(profileID)
	select {
	case ch <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	release := func() { <-ch }
	if err := ctx.Err(); err != nil {
		release()
		return nil, err
	}
	return release, nil
}

// refuseConnectionAccount returns ErrConnectionAccount when the user in slot
// is the account the profile itself connects with: changing it or deleting
// it would leave the stored profile credential unable to authenticate, so
// every later request on the profile would fail. A profile with an empty
// Username connects through the null (anonymous) user, which ListUsers
// omits because its name is empty: for it, slot 1 (the built-in anonymous
// account) is always refused, and so is every slot no listed user holds,
// since the anonymous login may resolve to any null-named slot. A failed
// user list is returned, so the check fails closed.
func refuseConnectionAccount(ctx context.Context, mgr ManagedUserManager, cfg *Config, profileID uint64, slot uint8) error {
	login, err := loginAccountSlot(ctx, mgr, cfg, slot)
	if err != nil {
		return err
	}
	if login {
		return ErrConnectionAccount{ProfileID: profileID, Slot: slot}
	}
	return nil
}

// refuseLoginAccount is refuseConnectionAccount answering ErrInvalidConfig
// on the slot, with reason, instead of ErrConnectionAccount.
func refuseLoginAccount(ctx context.Context, mgr ManagedUserManager, cfg *Config, slot uint8, reason string) error {
	login, err := loginAccountSlot(ctx, mgr, cfg, slot)
	if err != nil {
		return err
	}
	if login {
		return ErrInvalidConfig{Field: "slot", Reason: reason}
	}
	return nil
}

// loginAccountSlot reports whether slot may hold the account the profile
// logs in as (see refuseConnectionAccount). A failed user list is returned.
func loginAccountSlot(ctx context.Context, mgr ManagedUserManager, cfg *Config, slot uint8) (bool, error) {
	users, err := mgr.ListUsers(ctx)
	if err != nil {
		return false, err
	}
	anonymous := cfg.Username == ""
	if anonymous && slot == ipmiAnonymousUserSlot {
		return true, nil
	}
	listed := false
	for _, u := range users {
		if u.Slot != slot {
			continue
		}
		listed = true
		if u.Username == cfg.Username {
			return true, nil
		}
	}
	return anonymous && !listed, nil
}

// ListUsers returns the populated BMC user slots for the given profile.
func (s *Service) ListUsers(ctx context.Context, profileID uint64) ([]User, error) {
	mgr, _, err := s.userManagerFor(ctx, profileID)
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
//
// A slot that already holds a user is refused with ErrSlotOccupied: the
// IPMI create overwrites whatever is in the slot. The occupancy check and
// the create run under the profile's user lock, taken before the BMC
// session opens, so two concurrent creates on one free slot cannot both
// succeed. It returns ctx.Err(), writing nothing, when ctx ends while it
// waits for the lock or before the write.
//
// A profile with an empty Username connects through the IPMI null-name
// (anonymous) user, which is always user ID 1 and which ListUsers omits, so
// the occupancy check cannot see it: CreateUser refuses slot 1 on such a
// profile with ErrConnectionAccount, since overwriting it would lock the
// profile out (#2145).
func (s *Service) CreateUser(ctx context.Context, profileID uint64, user User, password string) error {
	if user.Enabled && password == "" {
		return ErrInvalidConfig{Field: "password", Reason: "an enabled user needs a password"}
	}
	// Hold the profile's user lock from the session open through the write.
	unlock, err := s.lockUsers(ctx, profileID)
	if err != nil {
		return err
	}
	defer unlock()
	mgr, cfg, err := s.userManagerFor(ctx, profileID)
	if err != nil {
		return err
	}
	defer mgr.Close()

	if cfg.Username == "" && user.Slot == ipmiAnonymousUserSlot {
		return ErrConnectionAccount{ProfileID: profileID, Slot: user.Slot}
	}

	// Refuse a slot that already holds an account: writing it would silently
	// overwrite that account (on most BMCs slot 1 or 2 is the administrator).
	users, err := mgr.ListUsers(ctx)
	if err != nil {
		return err
	}
	for _, u := range users {
		if u.Slot == user.Slot && u.Username != "" {
			return ErrSlotOccupied{ProfileID: profileID, Slot: user.Slot}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	pwSecret := memguard.NewMemoryEnclaveFromString(password)
	defer pwSecret.Destroy()

	return mgr.CreateUser(ctx, user, pwSecret)
}

// DeleteUser removes the BMC user at the given slot. It refuses the account
// the profile logs in as and writes nothing then.
func (s *Service) DeleteUser(ctx context.Context, profileID uint64, slot uint8) error {
	mgr, cfg, err := s.userManagerFor(ctx, profileID)
	if err != nil {
		return err
	}
	defer mgr.Close()
	if err := refuseConnectionAccount(ctx, mgr, cfg, profileID, slot); err != nil {
		return err
	}
	return mgr.DeleteUser(ctx, slot)
}

// SetUserPassword updates the password for the BMC user at the given slot.
// It refuses the account the profile logs in as, because the stored profile
// password would no longer open a session (no rotation path updates it yet);
// it writes nothing then.
func (s *Service) SetUserPassword(ctx context.Context, profileID uint64, slot uint8, password string) error {
	mgr, cfg, err := s.userManagerFor(ctx, profileID)
	if err != nil {
		return err
	}
	defer mgr.Close()
	if err := refuseConnectionAccount(ctx, mgr, cfg, profileID, slot); err != nil {
		return err
	}

	if err := refuseConnectionAccount(ctx, mgr, cfg, profileID, slot); err != nil {
		return err
	}

	pwSecret := memguard.NewMemoryEnclaveFromString(password)
	defer pwSecret.Destroy()

	return mgr.SetUserPassword(ctx, slot, pwSecret)
}

// SetUserPrivilege updates the channel privilege for the BMC user at the
// given slot. The channel argument selects the IPMI logical channel;
// pass 0 to use the package default LAN channel.
//
// Any privilege change on the profile's connection account is refused with
// ErrConnectionAccount (fail closed), even to its current level, and nothing
// is written then: no-access disables the account's IPMI login, and a lower
// privilege leaves the profile unable to manage its own BMC.
func (s *Service) SetUserPrivilege(ctx context.Context, profileID uint64, slot, channel uint8, privilege Privilege) error {
	mgr, cfg, err := s.userManagerFor(ctx, profileID)
	if err != nil {
		return err
	}
	defer mgr.Close()
	if err := refuseConnectionAccount(ctx, mgr, cfg, profileID, slot); err != nil {
		return err
	}
	return mgr.SetUserPrivilege(ctx, slot, channel, privilege)
}
