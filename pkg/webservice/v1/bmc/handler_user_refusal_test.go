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
	"net/http"
	"testing"

	bmcpkg "github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// TestBMCUserRefusal_HTTPConflict checks that the deliberate BMC user-slot
// refusals answer 409 Conflict, not 500 (#2145 Codex round 2).
func TestBMCUserRefusal_HTTPConflict(t *testing.T) {
	createPick := func(h RestHandler) http.HandlerFunc { return h.CreateUser }
	deletePick := func(h RestHandler) http.HandlerFunc { return h.DeleteUser }
	const createBody = `{"username":"u","password":"p","privilege":"user"}`

	createWith := func(err error) *mockBMCService {
		return &mockBMCService{createUserFn: func(context.Context, uint64, bmcpkg.User, string) error { return err }}
	}

	cases := []struct {
		name   string
		svc    *mockBMCService
		method string
		route  string
		path   string
		body   string
		pick   func(h RestHandler) http.HandlerFunc
	}{
		{"create_slot_occupied", createWith(bmcpkg.ErrSlotOccupied{ProfileID: 5, Slot: 2}),
			http.MethodPost, "/bmc/{profileID}/users", "/bmc/5/users", createBody, createPick},
		{"create_connection_account", createWith(bmcpkg.ErrConnectionAccount{ProfileID: 5, Slot: 1}),
			http.MethodPost, "/bmc/{profileID}/users", "/bmc/5/users", createBody, createPick},
		{"delete_connection_account", &mockBMCService{deleteUserFn: func(context.Context, uint64, uint8) error {
			return bmcpkg.ErrConnectionAccount{ProfileID: 5, Slot: 2}
		}}, http.MethodDelete, "/bmc/{profileID}/users/{slot}", "/bmc/5/users/2", "", deletePick},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rw := serveBMC(t, tc.svc, tc.method, tc.route, tc.path, tc.body, tc.pick)
			if rw.lastStatus != http.StatusConflict {
				t.Fatalf("status = %d, want 409", rw.lastStatus)
			}
		})
	}
}
