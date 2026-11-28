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
	"time"

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

	t.Run("CreateUserRefusesOccupiedSlot", func(t *testing.T) {
		t.Parallel()
		svc := newSimUserService(t)
		err := svc.CreateUser(ctx, 1, bmc.User{Slot: 1, Username: "intruder", Privilege: bmc.PrivilegeUser}, "x-pass-1")
		var occupied bmc.ErrSlotOccupied
		if !errors.As(err, &occupied) {
			t.Fatalf("CreateUser into slot 1 = %v, want ErrSlotOccupied", err)
		}
		if occupied.Slot != 1 {
			t.Errorf("ErrSlotOccupied.Slot = %d, want 1", occupied.Slot)
		}
		got, ok := userInSlot(t, svc, 1)
		if !ok || got.Username != "admin" {
			t.Errorf("slot 1 after refused create = %+v (found %v), want admin", got, ok)
		}
	})

	t.Run("CreateUserEnabledWithoutPasswordIsRefused", func(t *testing.T) {
		t.Parallel()
		svc := newSimUserService(t)
		err := svc.CreateUser(ctx, 1, bmc.User{Slot: 5, Username: "nopass", Enabled: true, Privilege: bmc.PrivilegeUser}, "")
		var cfgErr bmc.ErrInvalidConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "password" {
			t.Fatalf("CreateUser enabled without password = %v, want ErrInvalidConfig on password", err)
		}
		if got, ok := userInSlot(t, svc, 5); ok {
			t.Errorf("slot 5 after refused create = %+v, want no user", got)
		}
	})

	t.Run("ConcurrentCreatesSameSlotOneWins", func(t *testing.T) {
		t.Parallel()
		svc := newSimUserService(t)
		names := []string{"racer-a", "racer-b", "racer-c", "racer-d", "racer-e", "racer-f", "racer-g", "racer-h"}
		errs := make([]error, len(names))
		var wg sync.WaitGroup
		for i, name := range names {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = svc.CreateUser(ctx, 1, bmc.User{Slot: 6, Username: name, Privilege: bmc.PrivilegeUser}, "x-pass-1")
			}()
		}
		wg.Wait()

		var ok, occupied int
		for _, err := range errs {
			var slotErr bmc.ErrSlotOccupied
			switch {
			case err == nil:
				ok++
			case errors.As(err, &slotErr):
				occupied++
			default:
				t.Fatalf("CreateUser: unexpected error %v", err)
			}
		}
		if ok != 1 || occupied != len(names)-1 {
			t.Fatalf("concurrent creates: %d succeeded, %d refused as occupied; want 1 and %d", ok, occupied, len(names)-1)
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

	t.Run("SetUserPasswordRefusesTheProfileLoginAccount", func(t *testing.T) {
		t.Parallel()
		svc := newSimUserService(t)
		err := svc.SetUserPassword(ctx, 1, 1, "n3w-secret-pass")
		var cfgErr bmc.ErrInvalidConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "slot" {
			t.Fatalf("SetUserPassword on the login account = %v, want ErrInvalidConfig on slot", err)
		}
		// A fresh session with the stored password must still open.
		got, ok := userInSlot(t, svc, 1)
		if !ok || got.Username != "admin" {
			t.Errorf("slot 1 after the refusal = %+v (found %v), want admin", got, ok)
		}
	})

	t.Run("DeleteUserRefusesTheProfileLoginAccount", func(t *testing.T) {
		t.Parallel()
		svc := newSimUserService(t)
		err := svc.DeleteUser(ctx, 1, 1)
		var cfgErr bmc.ErrInvalidConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "slot" {
			t.Fatalf("DeleteUser on the login account = %v, want ErrInvalidConfig on slot", err)
		}
		// A fresh session with the stored credential must still open.
		got, ok := userInSlot(t, svc, 1)
		if !ok || got.Username != "admin" || !got.Enabled {
			t.Errorf("slot 1 after the refusal = %+v (found %v), want admin enabled", got, ok)
		}
	})

	t.Run("SetUserPrivilegeRefusesTheProfileLoginAccount", func(t *testing.T) {
		t.Parallel()
		svc := newSimUserService(t)
		err := svc.SetUserPrivilege(ctx, 1, 1, 1, bmc.PrivilegeNoAccess)
		var cfgErr bmc.ErrInvalidConfig
		if !errors.As(err, &cfgErr) || cfgErr.Field != "slot" {
			t.Fatalf("SetUserPrivilege on the login account = %v, want ErrInvalidConfig on slot", err)
		}
		// A fresh session with the stored credential must still open.
		got, ok := userInSlot(t, svc, 1)
		if !ok || got.Username != "admin" || got.Privilege != bmc.PrivilegeAdministrator {
			t.Errorf("slot 1 after the refusal = %+v (found %v), want admin at administrator", got, ok)
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

// TestService_CreateUserEnabledWithoutPasswordOpensNoSession pins that the
// refusal comes before the profile lookup and the BMC session: the service
// has no profile at all, so any later check would answer ErrProfileNotFound.
func TestService_CreateUserEnabledWithoutPasswordOpensNoSession(t *testing.T) {
	t.Parallel()
	svc, err := bmc.NewService(bmc.ServiceParams{
		Factory:  bmc.NewIPMIClientFactory(slog.Default()),
		Profiles: simProfiles{},
		Logger:   slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	err = svc.CreateUser(context.Background(), 7, bmc.User{Slot: 5, Username: "nopass", Enabled: true, Privilege: bmc.PrivilegeUser}, "")
	var cfgErr bmc.ErrInvalidConfig
	if !errors.As(err, &cfgErr) {
		t.Fatalf("CreateUser = %v, want ErrInvalidConfig", err)
	}
	if cfgErr.Field != "password" {
		t.Errorf("Field = %q, want password", cfgErr.Field)
	}
}

// TestService_CreateUserCancelledWhileWaitingWritesNothing: a create that
// waits on the profile's user lock and whose context ends meanwhile returns
// the context error, opens no BMC session and writes no user (Codex #2199
// round 18).
func TestService_CreateUserCancelledWhileWaitingWritesNothing(t *testing.T) {
	cases := []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		want error
	}{
		{
			name: "cancelled",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, cancel
			},
			want: context.Canceled,
		},
		{
			name: "deadline_while_waiting",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 50*time.Millisecond)
			},
			want: context.DeadlineExceeded,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := newSimUserService(t)
			release := bmc.HoldUserLock(svc, 1)
			ctx, cancel := tc.ctx()
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- svc.CreateUser(ctx, 1, bmc.User{Slot: 7, Username: "late", Enabled: true, Privilege: bmc.PrivilegeOperator}, "s3cret-pass")
			}()
			var err error
			select {
			case err = <-done:
				release()
			case <-time.After(15 * time.Second):
				release()
				err = <-done
				t.Fatalf("CreateUser waited on the held user lock after its context ended, then returned %v", err)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("CreateUser err = %v, want %v", err, tc.want)
			}
			var connFailed bmc.ErrConnectionFailed
			if errors.As(err, &connFailed) {
				t.Errorf("a cancelled create opened a BMC session before taking the lock: %v", err)
			}
			if got, ok := userInSlot(t, svc, 7); ok {
				t.Errorf("slot 7 = %+v, want no user: a cancelled create wrote the BMC", got)
			}
		})
	}
}

// TestService_CreateUserLockTableStaysBounded checks that the per-profile
// user lock table drops an entry once no holder or waiter remains, so
// caller-supplied profile IDs cannot grow it without bound.
func TestService_CreateUserLockTableStaysBounded(t *testing.T) {
	user := bmc.User{Slot: 7, Username: "ghost", Enabled: true, Privilege: bmc.PrivilegeOperator}
	t.Run("unknown_profiles", func(t *testing.T) {
		t.Parallel()
		svc := newSimUserService(t)
		for id := uint64(100); id < 164; id++ {
			err := svc.CreateUser(context.Background(), id, user, "s3cret-pass")
			var nf bmc.ErrProfileNotFound
			if !errors.As(err, &nf) {
				t.Fatalf("CreateUser(profile %d) err = %v, want ErrProfileNotFound", id, err)
			}
		}
		if got := bmc.UserLockCount(svc); got != 0 {
			t.Errorf("UserLockCount = %d after creates on unknown profiles, want 0", got)
		}
	})
	t.Run("cancelled_context", func(t *testing.T) {
		t.Parallel()
		svc := newSimUserService(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := svc.CreateUser(ctx, 200, user, "s3cret-pass"); !errors.Is(err, context.Canceled) {
			t.Fatalf("CreateUser err = %v, want %v", err, context.Canceled)
		}
		if got := bmc.UserLockCount(svc); got != 0 {
			t.Errorf("UserLockCount = %d after a cancelled create, want 0", got)
		}
	})
	t.Run("waiter_gives_up_then_release", func(t *testing.T) {
		t.Parallel()
		svc := newSimUserService(t)
		release := bmc.HoldUserLock(svc, 1)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			done <- svc.CreateUser(ctx, 1, user, "s3cret-pass")
		}()
		var err error
		select {
		case err = <-done:
		case <-time.After(15 * time.Second):
			release()
			err = <-done
			t.Fatalf("CreateUser waited on the held user lock after its context ended, then returned %v", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			release()
			t.Fatalf("CreateUser err = %v, want %v", err, context.DeadlineExceeded)
		}
		if got := bmc.UserLockCount(svc); got != 1 {
			t.Errorf("UserLockCount = %d while the lock is held, want 1", got)
		}
		release()
		if got := bmc.UserLockCount(svc); got != 0 {
			t.Errorf("UserLockCount = %d after release, want 0", got)
		}
	})
}
