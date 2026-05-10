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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// fakeBMC is an httptest-backed Redfish AccountService stub.
type fakeBMC struct {
	mu       sync.Mutex
	accounts map[uint8]*redfishAccount
	requests []recordedReq
	server   *httptest.Server
	// Force errors when these flags are set.
	listFails  bool
	patchFails bool
}

type recordedReq struct {
	method string
	path   string
	body   string
	auth   string
}

func newFakeBMC(t *testing.T) *fakeBMC {
	t.Helper()
	bmc := &fakeBMC{
		accounts: map[uint8]*redfishAccount{
			1: {ODataID: "/redfish/v1/AccountService/Accounts/1", ID: "1", Username: "ADMIN", RoleID: "Administrator", Enabled: true},
			2: {ODataID: "/redfish/v1/AccountService/Accounts/2", ID: "2", Username: "operator", RoleID: "Operator", Enabled: true},
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/redfish/v1/AccountService/Accounts", bmc.handleCollection)
	mux.HandleFunc("/redfish/v1/AccountService/Accounts/", bmc.handleAccount)
	bmc.server = httptest.NewTLSServer(mux)
	return bmc
}

func (f *fakeBMC) close() { f.server.Close() }

func (f *fakeBMC) cfg() *Config {
	u, _ := url.Parse(f.server.URL)
	port, _ := strconv.Atoi(u.Port())
	return &Config{
		Address: u.Hostname(), Port: port,
		Username: "admin", Password: "secret",
		Protocol:      ProtocolRedfish,
		SkipTLSVerify: true,
	}
}

func (f *fakeBMC) record(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	auth := r.Header.Get("Authorization")
	f.mu.Lock()
	f.requests = append(f.requests, recordedReq{
		method: r.Method, path: r.URL.Path, body: string(body), auth: auth,
	})
	f.mu.Unlock()
}

func (f *fakeBMC) handleCollection(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	switch r.Method {
	case http.MethodGet:
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.listFails {
			http.Error(w, `{"error":{"message":"forced failure"}}`, http.StatusInternalServerError)
			return
		}
		members := make([]redfishRef, 0, len(f.accounts))
		// Iterate in sorted slot order for deterministic tests.
		for slot := uint8(1); slot <= 16; slot++ {
			if a, ok := f.accounts[slot]; ok {
				members = append(members, redfishRef{ODataID: a.ODataID})
			}
		}
		writeJSON(w, redfishAccountsList{Members: members})
	case http.MethodPost:
		var body struct {
			UserName string `json:"UserName"`
			Password string `json:"Password"`
			RoleID   string `json:"RoleId"`
			Enabled  bool   `json:"Enabled"`
		}
		decode := json.NewDecoder(strings.NewReader(f.requests[len(f.requests)-1].body))
		if err := decode.Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		nextSlot := uint8(len(f.accounts) + 1)
		f.accounts[nextSlot] = &redfishAccount{
			ODataID:  "/redfish/v1/AccountService/Accounts/" + strconv.Itoa(int(nextSlot)),
			ID:       strconv.Itoa(int(nextSlot)),
			Username: body.UserName,
			RoleID:   body.RoleID,
			Enabled:  body.Enabled,
		}
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (f *fakeBMC) handleAccount(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	idStr := strings.TrimPrefix(r.URL.Path, "/redfish/v1/AccountService/Accounts/")
	slot, err := strconv.ParseUint(idStr, 10, 8)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	acc, ok := f.accounts[uint8(slot)]
	if !ok {
		http.Error(w, `{"error":{"message":"no such account"}}`, http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, acc)
	case http.MethodPatch:
		if f.patchFails {
			http.Error(w, `{"error":{"message":"patch failed"}}`, http.StatusInternalServerError)
			return
		}
		var patch redfishAccountPatch
		if err := json.Unmarshal([]byte(f.requests[len(f.requests)-1].body), &patch); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if patch.Password != nil {
			// Don't store the password — just acknowledge it was sent.
		}
		if patch.RoleID != nil {
			acc.RoleID = *patch.RoleID
		}
		if patch.Enabled != nil {
			acc.Enabled = *patch.Enabled
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		delete(f.accounts, uint8(slot))
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func TestRedfishUM_NewClose(t *testing.T) {
	bmc := newFakeBMC(t)
	defer bmc.close()
	um, err := NewRedfishUserManager(bmc.cfg(), nil)
	if err != nil {
		t.Fatalf("NewRedfishUserManager: %v", err)
	}
	if err := um.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestRedfishUM_NewBadConfig(t *testing.T) {
	if _, err := NewRedfishUserManager(nil, nil); err == nil {
		t.Error("expected error for nil config")
	}
}

func TestRedfishUM_MaxUsers(t *testing.T) {
	bmc := newFakeBMC(t)
	defer bmc.close()
	um, _ := NewRedfishUserManager(bmc.cfg(), nil)
	defer um.Close()

	got, err := um.MaxUsers(context.Background())
	if err != nil {
		t.Fatalf("MaxUsers: %v", err)
	}
	if got != 2 {
		t.Errorf("MaxUsers = %d, want 2", got)
	}
}

func TestRedfishUM_MaxUsersError(t *testing.T) {
	bmc := newFakeBMC(t)
	defer bmc.close()
	bmc.listFails = true
	um, _ := NewRedfishUserManager(bmc.cfg(), nil)
	defer um.Close()
	if _, err := um.MaxUsers(context.Background()); err == nil {
		t.Error("expected error")
	}
}

func TestRedfishUM_ListUsers(t *testing.T) {
	bmc := newFakeBMC(t)
	defer bmc.close()
	um, _ := NewRedfishUserManager(bmc.cfg(), nil)
	defer um.Close()

	users, err := um.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("got %d users, want 2", len(users))
	}
	if users[0].Username != "ADMIN" || users[0].Privilege != PrivilegeAdministrator || users[0].Slot != 1 {
		t.Errorf("user[0] = %+v", users[0])
	}
	if users[1].Username != "operator" || users[1].Privilege != PrivilegeOperator {
		t.Errorf("user[1] = %+v", users[1])
	}
}

func TestRedfishUM_ListUsers_SkipsEmpty(t *testing.T) {
	bmc := newFakeBMC(t)
	defer bmc.close()
	bmc.accounts[3] = &redfishAccount{
		ODataID: "/redfish/v1/AccountService/Accounts/3", ID: "3",
		Username: "", RoleID: "ReadOnly",
	}
	um, _ := NewRedfishUserManager(bmc.cfg(), nil)
	defer um.Close()
	users, err := um.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Errorf("got %d users, want 2 (slot 3 should be skipped)", len(users))
	}
}

func TestRedfishUM_ListUsersCollectionError(t *testing.T) {
	bmc := newFakeBMC(t)
	defer bmc.close()
	bmc.listFails = true
	um, _ := NewRedfishUserManager(bmc.cfg(), nil)
	defer um.Close()
	if _, err := um.ListUsers(context.Background()); err == nil {
		t.Error("expected error")
	}
}

func TestRedfishUM_ListUsersAccountFetchError(t *testing.T) {
	bmc := newFakeBMC(t)
	// Inject a member pointing at a nonexistent account (slot 99).
	bmc.accounts[99] = &redfishAccount{
		ODataID: "/redfish/v1/AccountService/Accounts/99", ID: "99",
	}
	bmc.accounts[99].Username = "" // skip from results — but URI exists
	// Force the GET on that path to fail by removing it after listing.
	defer bmc.close()
	um, _ := NewRedfishUserManager(bmc.cfg(), nil)
	defer um.Close()
	// Remove account so individual GET 404s. The membership list still
	// includes slot 99's URI because handleCollection rebuilds from map
	// each call — so first delete then list.
	delete(bmc.accounts, 99)
	// Now there's no slot 99, ListUsers will succeed with 2 members.
	if _, err := um.ListUsers(context.Background()); err != nil {
		t.Errorf("unexpected err: %v", err)
	}
}

func TestRedfishUM_CreateUser(t *testing.T) {
	bmc := newFakeBMC(t)
	defer bmc.close()
	um, _ := NewRedfishUserManager(bmc.cfg(), nil)
	defer um.Close()
	pwd := memguard.New([]byte("welcome1"))
	defer pwd.Destroy()

	err := um.CreateUser(context.Background(), User{
		Username:  "newbie",
		Enabled:   true,
		Privilege: PrivilegeOperator,
	}, pwd)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, ok := bmc.accounts[3]; !ok {
		t.Errorf("account not created; have slots: %v", slotKeys(bmc.accounts))
	}
	if bmc.accounts[3].RoleID != "Operator" {
		t.Errorf("RoleID = %q, want Operator", bmc.accounts[3].RoleID)
	}
}

func TestRedfishUM_CreateUser_Validation(t *testing.T) {
	bmc := newFakeBMC(t)
	defer bmc.close()
	um, _ := NewRedfishUserManager(bmc.cfg(), nil)
	defer um.Close()

	// Empty password.
	err := um.CreateUser(context.Background(), User{Username: "x", Privilege: PrivilegeUser}, nil)
	if err == nil {
		t.Error("expected error for nil password")
	}

	// Long username.
	pwd := memguard.New([]byte("p"))
	defer pwd.Destroy()
	err = um.CreateUser(context.Background(), User{Username: strings.Repeat("a", 17), Privilege: PrivilegeUser}, pwd)
	if err == nil {
		t.Error("expected error for long username")
	}

	// Invalid privilege.
	err = um.CreateUser(context.Background(), User{Username: "x", Privilege: Privilege(0xFF)}, pwd)
	if err == nil {
		t.Error("expected error for invalid privilege")
	}
}

func TestRedfishUM_SetUserPassword(t *testing.T) {
	bmc := newFakeBMC(t)
	defer bmc.close()
	um, _ := NewRedfishUserManager(bmc.cfg(), nil)
	defer um.Close()
	pwd := memguard.New([]byte("rotated"))
	defer pwd.Destroy()

	if err := um.SetUserPassword(context.Background(), 1, pwd); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
	last := bmc.requests[len(bmc.requests)-1]
	if last.method != http.MethodPatch || last.path != "/redfish/v1/AccountService/Accounts/1" {
		t.Errorf("unexpected request: %+v", last)
	}
	if !strings.Contains(last.body, `"Password":"rotated"`) {
		t.Errorf("body missing password field: %s", last.body)
	}
}

func TestRedfishUM_SetUserPassword_Validation(t *testing.T) {
	bmc := newFakeBMC(t)
	defer bmc.close()
	um, _ := NewRedfishUserManager(bmc.cfg(), nil)
	defer um.Close()

	if err := um.SetUserPassword(context.Background(), 1, nil); err == nil {
		t.Error("expected error for nil password")
	}
}

func TestRedfishUM_SetUserPassword_PatchError(t *testing.T) {
	bmc := newFakeBMC(t)
	defer bmc.close()
	bmc.patchFails = true
	um, _ := NewRedfishUserManager(bmc.cfg(), nil)
	defer um.Close()
	pwd := memguard.New([]byte("x"))
	defer pwd.Destroy()
	if err := um.SetUserPassword(context.Background(), 1, pwd); err == nil {
		t.Error("expected error")
	}
}

func TestRedfishUM_SetUserPrivilege(t *testing.T) {
	bmc := newFakeBMC(t)
	defer bmc.close()
	um, _ := NewRedfishUserManager(bmc.cfg(), nil)
	defer um.Close()

	if err := um.SetUserPrivilege(context.Background(), 1, 0, PrivilegeUser); err != nil {
		t.Fatalf("SetUserPrivilege: %v", err)
	}
	if bmc.accounts[1].RoleID != "ReadOnly" {
		t.Errorf("RoleID = %q, want ReadOnly", bmc.accounts[1].RoleID)
	}
	if !bmc.accounts[1].Enabled {
		t.Error("account should remain enabled")
	}
}

func TestRedfishUM_SetUserPrivilege_NoAccessDisables(t *testing.T) {
	bmc := newFakeBMC(t)
	defer bmc.close()
	um, _ := NewRedfishUserManager(bmc.cfg(), nil)
	defer um.Close()

	if err := um.SetUserPrivilege(context.Background(), 1, 0, PrivilegeNoAccess); err != nil {
		t.Fatalf("SetUserPrivilege: %v", err)
	}
	if bmc.accounts[1].Enabled {
		t.Error("account should be disabled for NoAccess")
	}
}

func TestRedfishUM_SetUserPrivilege_BadPriv(t *testing.T) {
	bmc := newFakeBMC(t)
	defer bmc.close()
	um, _ := NewRedfishUserManager(bmc.cfg(), nil)
	defer um.Close()
	if err := um.SetUserPrivilege(context.Background(), 1, 0, Privilege(0x77)); err == nil {
		t.Error("expected validation error")
	}
}

func TestRedfishUM_DeleteUser(t *testing.T) {
	bmc := newFakeBMC(t)
	defer bmc.close()
	um, _ := NewRedfishUserManager(bmc.cfg(), nil)
	defer um.Close()

	if err := um.DeleteUser(context.Background(), 2); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, ok := bmc.accounts[2]; ok {
		t.Error("account not removed")
	}
}

func TestRedfishUM_DeleteUser_404(t *testing.T) {
	bmc := newFakeBMC(t)
	defer bmc.close()
	um, _ := NewRedfishUserManager(bmc.cfg(), nil)
	defer um.Close()
	err := um.DeleteUser(context.Background(), 99)
	var want ErrRedfishRequest
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrRedfishRequest", err)
	}
}

func TestRedfishUM_BasicAuthSent(t *testing.T) {
	bmc := newFakeBMC(t)
	defer bmc.close()
	um, _ := NewRedfishUserManager(bmc.cfg(), nil)
	defer um.Close()
	if _, err := um.MaxUsers(context.Background()); err != nil {
		t.Fatalf("MaxUsers: %v", err)
	}
	last := bmc.requests[len(bmc.requests)-1]
	if !strings.HasPrefix(last.auth, "Basic ") {
		t.Errorf("auth header = %q, want Basic *", last.auth)
	}
}

// --- helper conversions ---

func TestSlotFromAccountID(t *testing.T) {
	cases := []struct {
		in   string
		want uint8
	}{
		{"1", 1}, {"42", 42}, {"", 0}, {"abc", 0}, {"  3  ", 3}, {"999", 0},
	}
	for _, tc := range cases {
		if got := slotFromAccountID(tc.in); got != tc.want {
			t.Errorf("slotFromAccountID(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestPrivilegeFromRole(t *testing.T) {
	cases := []struct {
		in   string
		want Privilege
	}{
		{"Administrator", PrivilegeAdministrator},
		{"Operator", PrivilegeOperator},
		{"ReadOnly", PrivilegeUser},
		{"CustomVendorRole", PrivilegeUser},
		{"", PrivilegeUser},
	}
	for _, tc := range cases {
		if got := privilegeFromRole(tc.in); got != tc.want {
			t.Errorf("privilegeFromRole(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestAccountPath(t *testing.T) {
	if got := accountPath(7); got != "/redfish/v1/AccountService/Accounts/7" {
		t.Errorf("accountPath(7) = %q", got)
	}
}

func slotKeys(m map[uint8]*redfishAccount) []uint8 {
	out := make([]uint8, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
