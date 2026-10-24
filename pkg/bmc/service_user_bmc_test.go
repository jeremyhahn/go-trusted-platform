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
	"log/slog"
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
		if err := svc.SetUserPrivilege(ctx, 1, 1, 1, bmc.PrivilegeOperator); err != nil {
			t.Fatalf("SetUserPrivilege: %v", err)
		}
		got, ok := userInSlot(t, svc, 1)
		if !ok || got.Username != "admin" || got.Privilege != bmc.PrivilegeOperator {
			t.Errorf("slot 1 = %+v (found %v), want admin at operator", got, ok)
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
