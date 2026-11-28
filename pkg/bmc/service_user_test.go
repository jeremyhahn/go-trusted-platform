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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// listOnlyUserManager is a ManagedUserManager whose ListUsers returns a fixed
// list; every write is recorded and succeeds.
type listOnlyUserManager struct {
	users  []User
	writes []string
}

func (f *listOnlyUserManager) ListUsers(context.Context) ([]User, error) {
	return f.users, nil
}

func (f *listOnlyUserManager) CreateUser(context.Context, User, *memguard.MemoryEnclave) error {
	f.writes = append(f.writes, "create")
	return nil
}

func (f *listOnlyUserManager) SetUserPassword(context.Context, uint8, *memguard.MemoryEnclave) error {
	f.writes = append(f.writes, "password")
	return nil
}

func (f *listOnlyUserManager) SetUserPrivilege(context.Context, uint8, uint8, Privilege) error {
	f.writes = append(f.writes, "privilege")
	return nil
}

func (f *listOnlyUserManager) DeleteUser(context.Context, uint8) error {
	f.writes = append(f.writes, "delete")
	return nil
}

func (f *listOnlyUserManager) MaxUsers(context.Context) (uint8, error) { return 16, nil }

func (f *listOnlyUserManager) Close() error { return nil }

func wantSlotRefusal(t *testing.T, err error, slot uint8) {
	t.Helper()
	var ic ErrInvalidConfig
	if !errors.As(err, &ic) || ic.Field != "slot" {
		t.Errorf("slot %d: err = %v, want ErrInvalidConfig on slot", slot, err)
	}
}

// TestRefuseLoginAccount_AnonymousProfile: a profile that logs in as the
// null (anonymous) user must not write slot 1, which ListUsers hides because
// its name is empty, nor any other slot no listed user holds.
func TestRefuseLoginAccount_AnonymousProfile(t *testing.T) {
	ctx := context.Background()
	mgr := &listOnlyUserManager{users: []User{
		{Slot: 2, Username: "admin"},
		{Slot: 3, Username: "op"},
	}}
	cfg := &Config{Username: ""}
	wantSlotRefusal(t, refuseLoginAccount(ctx, mgr, cfg, ipmiAnonymousUserSlot, "r"), ipmiAnonymousUserSlot)
	wantSlotRefusal(t, refuseLoginAccount(ctx, mgr, cfg, 7, "r"), 7)
	if err := refuseLoginAccount(ctx, mgr, cfg, 3, "r"); err != nil {
		t.Errorf("slot 3 (named op): err = %v, want nil", err)
	}

	// Slot 1 stays refused for an anonymous profile even if a BMC lists it.
	listed := &listOnlyUserManager{users: []User{{Slot: ipmiAnonymousUserSlot, Username: "x"}}}
	wantSlotRefusal(t, refuseLoginAccount(ctx, listed, cfg, ipmiAnonymousUserSlot, "r"), ipmiAnonymousUserSlot)
	if len(mgr.writes)+len(listed.writes) != 0 {
		t.Errorf("the guard wrote: %v %v", mgr.writes, listed.writes)
	}
}

// TestRefuseLoginAccount_NamedProfile: a named profile refuses only the slot
// that holds its username.
func TestRefuseLoginAccount_NamedProfile(t *testing.T) {
	ctx := context.Background()
	mgr := &listOnlyUserManager{users: []User{
		{Slot: 2, Username: "admin"},
		{Slot: 3, Username: "op"},
	}}
	cfg := &Config{Username: "admin"}
	wantSlotRefusal(t, refuseLoginAccount(ctx, mgr, cfg, 2, "r"), 2)
	for _, slot := range []uint8{1, 3} {
		if err := refuseLoginAccount(ctx, mgr, cfg, slot, "r"); err != nil {
			t.Errorf("slot %d: err = %v, want nil", slot, err)
		}
	}
}
