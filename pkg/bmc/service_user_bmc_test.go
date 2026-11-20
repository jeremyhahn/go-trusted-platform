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

package bmc_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// simProfiles serves one profile per ID from a fixed map.
type simProfiles map[uint64]*bmc.Config

func (p simProfiles) Get(_ context.Context, id uint64) (*bmc.Config, error) {
	cfg, ok := p[id]
	if !ok {
		return nil, bmc.ErrProfileNotFound{ProfileID: id}
	}
	return cfg, nil
}

// newSimUserService returns a Service whose profile 1 points at a running
// RMCP+ simulator, so every user call opens a real IPMI 2.0 session.
func newSimUserService(t *testing.T) *bmc.Service {
	t.Helper()
	sim := startSim(t, "admin", simPassword)
	svc, err := bmc.NewService(bmc.ServiceParams{
		Factory: bmc.NewIPMIClientFactory(slog.Default()),
		Profiles: simProfiles{1: {
			Address:  sim.LocalAddr().IP.String(),
			Port:     sim.LocalAddr().Port,
			Username: "admin",
			Password: simPassword,
			Protocol: bmc.ProtocolIPMI,
		}},
		Logger: slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

// userInSlot lists the BMC users and returns the one in slot, if any.
func userInSlot(t *testing.T, svc *bmc.Service, slot uint8) (bmc.User, bool) {
	t.Helper()
	users, err := svc.ListUsers(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	for _, u := range users {
		if u.Slot == slot {
			return u, true
		}
	}
	return bmc.User{}, false
}

// Every Service user call opens its own RMCP+ session, and each session
// open costs one read timeout on the simulator (it does not answer the
// IPMI 1.5 Get Channel Authentication Capabilities probe). The subtests
// therefore run in parallel, each against its own simulator, with the
// fewest calls that still observe the change on the BMC.
func TestService_UserMethods_Simulator(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("CreateUser", func(t *testing.T) {
		t.Parallel()
		svc := newSimUserService(t)
		operator := bmc.User{Slot: 3, Username: "operator1", Enabled: true, Privilege: bmc.PrivilegeOperator}
		if err := svc.CreateUser(ctx, 1, operator, "s3cret-pass"); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		got, ok := userInSlot(t, svc, 3)
		operator.Channel = 1
		if !ok || got != operator {
			t.Errorf("slot 3 = %+v (found %v), want %+v", got, ok, operator)
		}
	})

	t.Run("SetUserPrivilege", func(t *testing.T) {
		t.Parallel()
		svc := newSimUserService(t)
		if err := svc.CreateUser(ctx, 1, bmc.User{Slot: 3, Username: "operator1", Enabled: true, Privilege: bmc.PrivilegeUser}, "s3cret-pass"); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if err := svc.SetUserPrivilege(ctx, 1, 3, 1, bmc.PrivilegeOperator); err != nil {
			t.Fatalf("SetUserPrivilege: %v", err)
		}
		got, ok := userInSlot(t, svc, 3)
		if !ok || got.Username != "operator1" || got.Privilege != bmc.PrivilegeOperator {
			t.Errorf("slot 3 = %+v (found %v), want operator1 at operator", got, ok)
		}
	})

	t.Run("SetUserPassword", func(t *testing.T) {
		t.Parallel()
		svc := newSimUserService(t)
		if err := svc.SetUserPassword(ctx, 1, 2, "n3w-secret-pass"); err != nil {
			t.Fatalf("SetUserPassword: %v", err)
		}
	})

	t.Run("DeleteUser", func(t *testing.T) {
		t.Parallel()
		svc := newSimUserService(t)
		if err := svc.CreateUser(ctx, 1, bmc.User{Slot: 4, Username: "temp", Privilege: bmc.PrivilegeUser}, ""); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if err := svc.DeleteUser(ctx, 1, 4); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		if got, ok := userInSlot(t, svc, 4); ok {
			t.Errorf("slot 4 after delete = %+v, want no user", got)
		}
	})
}

// The profile connects as "admin" (slot 1 on the simulator). Changing that
// account's password or deleting it would lock the profile out of its own
// BMC, so the service refuses both and leaves the account as it was.
func TestService_ConnectionAccount_Refused_Simulator(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	assertRefused := func(t *testing.T, err error) {
		t.Helper()
		var refused bmc.ErrConnectionAccount
		if !errors.As(err, &refused) {
			t.Fatalf("err = %v, want ErrConnectionAccount", err)
		}
		if refused.ProfileID != 1 || refused.Slot != 1 {
			t.Errorf("refused = %+v, want profile 1 slot 1", refused)
		}
	}

	t.Run("SetUserPassword", func(t *testing.T) {
		t.Parallel()
		svc := newSimUserService(t)
		assertRefused(t, svc.SetUserPassword(ctx, 1, 1, "n3w-secret-pass"))
		// The profile still authenticates with its stored password.
		if got, ok := userInSlot(t, svc, 1); !ok || got.Username != "admin" {
			t.Errorf("slot 1 = %+v (found %v), want admin", got, ok)
		}
	})

	t.Run("DeleteUser", func(t *testing.T) {
		t.Parallel()
		svc := newSimUserService(t)
		assertRefused(t, svc.DeleteUser(ctx, 1, 1))
		if got, ok := userInSlot(t, svc, 1); !ok || got.Username != "admin" {
			t.Errorf("slot 1 after refused delete = %+v (found %v), want admin", got, ok)
		}
	})

	// Setting no-access, or any privilege below administrator, on the
	// connection account would disable or weaken the profile's own login.
	for _, priv := range []bmc.Privilege{bmc.PrivilegeNoAccess, bmc.PrivilegeOperator} {
		t.Run("SetUserPrivilege_"+priv.String(), func(t *testing.T) {
			t.Parallel()
			svc := newSimUserService(t)
			assertRefused(t, svc.SetUserPrivilege(ctx, 1, 1, 1, priv))
			got, ok := userInSlot(t, svc, 1)
			if !ok || got.Username != "admin" || got.Privilege != bmc.PrivilegeAdministrator {
				t.Errorf("slot 1 after refused privilege = %+v (found %v), want admin at administrator", got, ok)
			}
		})
	}
}

// CreateUser must not overwrite a slot that already holds a user: the page
// checks occupancy against a listing that may be stale, so the service
// checks again under a per-profile lock.
func TestService_CreateUser_SlotOccupied_Simulator(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	assertOccupied := func(t *testing.T, err error, slot uint8) {
		t.Helper()
		var occupied bmc.ErrSlotOccupied
		if !errors.As(err, &occupied) {
			t.Fatalf("err = %v, want ErrSlotOccupied", err)
		}
		if occupied.ProfileID != 1 || occupied.Slot != slot {
			t.Errorf("occupied = %+v, want profile 1 slot %d", occupied, slot)
		}
	}

	t.Run("Occupied", func(t *testing.T) {
		t.Parallel()
		svc := newSimUserService(t)
		err := svc.CreateUser(ctx, 1, bmc.User{Slot: 1, Username: "intruder", Enabled: true, Privilege: bmc.PrivilegeUser}, "s3cret-pass")
		assertOccupied(t, err, 1)
		if got, ok := userInSlot(t, svc, 1); !ok || got.Username != "admin" {
			t.Errorf("slot 1 after refused create = %+v (found %v), want admin", got, ok)
		}
	})

	t.Run("Concurrent", func(t *testing.T) {
		t.Parallel()
		svc := newSimUserService(t)
		names := []string{"first", "second"}
		start := make(chan struct{})
		errs := make([]error, len(names))
		var wg sync.WaitGroup
		for i, name := range names {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = svc.CreateUser(ctx, 1, bmc.User{Slot: 5, Username: name, Enabled: true, Privilege: bmc.PrivilegeUser}, "s3cret-pass")
			}()
		}
		close(start)
		wg.Wait()

		winner := -1
		for i, err := range errs {
			if err == nil {
				if winner >= 0 {
					t.Fatalf("both creates succeeded on slot 5")
				}
				winner = i
				continue
			}
			assertOccupied(t, err, 5)
		}
		if winner < 0 {
			t.Fatalf("no create succeeded: %v", errs)
		}
		if got, ok := userInSlot(t, svc, 5); !ok || got.Username != names[winner] {
			t.Errorf("slot 5 = %+v (found %v), want %s", got, ok, names[winner])
		}
	})
}

// TestService_CreateUser_UnknownProfiles_LocksBounded checks that creates
// refused for nonexistent profiles do not grow the user-slot lock storage,
// and that one profile always maps to the same mutex.
func TestService_CreateUser_UnknownProfiles_LocksBounded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := newSimUserService(t)

	const maxLocks = 64
	for id := uint64(1000); id < 2000; id++ {
		err := svc.CreateUser(ctx, id, bmc.User{Slot: 5, Username: "ghost", Enabled: true, Privilege: bmc.PrivilegeUser}, "s3cret-pass")
		var notFound bmc.ErrProfileNotFound
		if !errors.As(err, &notFound) {
			t.Fatalf("CreateUser(profile %d) err = %v, want ErrProfileNotFound", id, err)
		}
	}
	if n := svc.UserLockCount(); n > maxLocks {
		t.Errorf("user-slot locks after 1000 unknown profiles = %d, want <= %d", n, maxLocks)
	}
	for _, id := range []uint64{1, 1000, 1999, 1 << 40} {
		if svc.UserLockFor(id) != svc.UserLockFor(id) {
			t.Errorf("profile %d maps to different mutexes", id)
		}
	}
}
