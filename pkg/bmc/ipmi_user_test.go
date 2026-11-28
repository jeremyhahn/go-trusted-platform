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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// mockSender records IPMI commands and returns canned responses keyed by
// (netFn, cmd). Optionally returns a fixed error to simulate transport
// failure. Get User Name answers an empty 16-byte name unless a test sets
// another response.
type mockSender struct {
	calls     []mockCall
	responses map[uint16][]byte
	err       error
	// cmdErr fails only the listed commands (after recording the call).
	cmdErr map[byte]error
}

type mockCall struct {
	netFn byte
	cmd   byte
	data  []byte
}

func key(netFn, cmd byte) uint16 {
	return uint16(netFn)<<8 | uint16(cmd)
}

func (m *mockSender) Send(netFn, cmd byte, data []byte) ([]byte, error) {
	cp := append([]byte(nil), data...)
	m.calls = append(m.calls, mockCall{netFn: netFn, cmd: cmd, data: cp})
	if m.err != nil {
		return nil, m.err
	}
	if e, ok := m.cmdErr[cmd]; ok {
		return nil, e
	}
	if r, ok := m.responses[key(netFn, cmd)]; ok {
		return append([]byte(nil), r...), nil
	}
	return nil, nil
}

func newMock() *mockSender {
	return &mockSender{responses: map[uint16][]byte{key(netFnApp, cmdGetUserName): make([]byte, ipmiMaxUsernameLen)}}
}

func (m *mockSender) lastCall(t *testing.T) mockCall {
	t.Helper()
	if len(m.calls) == 0 {
		t.Fatal("no calls recorded")
	}
	return m.calls[len(m.calls)-1]
}

func newUM(s ipmiSender) *ipmiUserManager {
	return &ipmiUserManager{sender: s, channel: defaultIPMIChannel}
}

// --- constructors ---

func TestNewIPMIUserManager_DefaultChannel(t *testing.T) {
	um := NewIPMIUserManager(newMock(), 0, nil)
	got := um.(*ipmiUserManager).channel
	if got != defaultIPMIChannel {
		t.Errorf("channel = %d, want %d", got, defaultIPMIChannel)
	}
}

func TestNewIPMIUserManager_ExplicitChannel(t *testing.T) {
	um := NewIPMIUserManager(newMock(), 7, nil)
	got := um.(*ipmiUserManager).channel
	if got != 7 {
		t.Errorf("channel = %d, want 7", got)
	}
}

func TestNewUserManager_NilConfig(t *testing.T) {
	if _, err := NewUserManager(context.Background(), nil, nil); err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestNewUserManager_InvalidConfig(t *testing.T) {
	cfg := &Config{Address: "", Port: 623, Protocol: ProtocolIPMI}
	if _, err := NewUserManager(context.Background(), cfg, nil); err == nil {
		t.Fatal("expected error for empty address")
	}
}

func TestClose_NoCloser(t *testing.T) {
	um := newUM(newMock())
	if err := um.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}

type fakeCloser struct {
	called bool
	err    error
}

func (f *fakeCloser) Close() error {
	f.called = true
	return f.err
}

func TestClose_OwnedSession(t *testing.T) {
	c := &fakeCloser{}
	um := &ipmiUserManager{sender: newMock(), channel: 1, closer: c}
	if err := um.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if !c.called {
		t.Error("Close not propagated to owned closer")
	}
}

func TestClose_PropagatesError(t *testing.T) {
	sentinel := errors.New("close-fail")
	c := &fakeCloser{err: sentinel}
	um := &ipmiUserManager{sender: newMock(), channel: 1, closer: c}
	if err := um.Close(); !errors.Is(err, sentinel) {
		t.Errorf("Close() = %v, want %v", err, sentinel)
	}
}

// --- MaxUsers / GetUserAccess ---

func TestMaxUsers(t *testing.T) {
	m := newMock()
	// resp byte 0 low-6 = max users count
	m.responses[key(netFnApp, cmdGetUserAccess)] = []byte{0x10, 0x40, 0x00, 0x04}
	um := newUM(m)
	got, err := um.MaxUsers(context.Background())
	if err != nil {
		t.Fatalf("MaxUsers: %v", err)
	}
	if got != 0x10 {
		t.Errorf("MaxUsers = %d, want 16", got)
	}
}

func TestMaxUsers_ShortResponse(t *testing.T) {
	m := newMock()
	m.responses[key(netFnApp, cmdGetUserAccess)] = []byte{0x10}
	um := newUM(m)
	_, err := um.MaxUsers(context.Background())
	var want ErrIPMIShortResponse
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrIPMIShortResponse", err)
	}
}

func TestMaxUsers_TransportError(t *testing.T) {
	m := newMock()
	m.err = errors.New("net broken")
	um := newUM(m)
	_, err := um.MaxUsers(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- ListUsers ---

func TestListUsers_HappyPath(t *testing.T) {
	stages := []stage{
		// slot 1: max=2, enabled, admin
		{netFnApp, cmdGetUserAccess, 1, []byte{0x02, 0x40, 0x00, 0x04}},
		// slot 1: name "ADMIN"
		{netFnApp, cmdGetUserName, 1, append([]byte("ADMIN"), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)},
		// slot 2: enabled, operator
		{netFnApp, cmdGetUserAccess, 2, []byte{0x02, 0x40, 0x00, 0x03}},
		// slot 2: empty name -> skipped
		{netFnApp, cmdGetUserName, 2, make([]byte, 16)},
	}
	stageSender := &stagedSender{stages: stages, t: t}
	um := newUM(stageSender)
	users, err := um.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("got %d users, want 1: %+v", len(users), users)
	}
	if users[0].Username != "ADMIN" || users[0].Slot != 1 || users[0].Privilege != PrivilegeAdministrator {
		t.Errorf("unexpected user: %+v", users[0])
	}
	if !users[0].Enabled {
		t.Error("user expected enabled")
	}
}

func TestListUsers_FirstAccessError(t *testing.T) {
	m := newMock()
	m.err = errors.New("nope")
	um := newUM(m)
	if _, err := um.ListUsers(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestListUsers_GetNameError(t *testing.T) {
	stages := []stage{
		// slot 1 access OK (max=1)
		{netFnApp, cmdGetUserAccess, 1, []byte{0x01, 0x40, 0x00, 0x04}},
	}
	s := &stagedSender{stages: stages, t: t, errAfter: 1, errVal: errors.New("name-fail")}
	um := newUM(s)
	if _, err := um.ListUsers(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestListUsers_LaterSlotAccessError(t *testing.T) {
	stages := []stage{
		{netFnApp, cmdGetUserAccess, 1, []byte{0x02, 0x40, 0x00, 0x04}},
		{netFnApp, cmdGetUserName, 1, append([]byte("ADMIN"), make([]byte, 11)...)},
	}
	s := &stagedSender{stages: stages, t: t, errAfter: 2, errVal: errors.New("slot2-fail")}
	um := newUM(s)
	if _, err := um.ListUsers(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestListUsers_ShortNameResponse(t *testing.T) {
	stages := []stage{
		{netFnApp, cmdGetUserAccess, 1, []byte{0x01, 0x40, 0x00, 0x04}},
		{netFnApp, cmdGetUserName, 1, []byte{}},
	}
	s := &stagedSender{stages: stages, t: t}
	_, err := newUM(s).ListUsers(context.Background())
	var short ErrIPMIShortResponse
	if !errors.As(err, &short) {
		t.Fatalf("ListUsers = %v, want ErrIPMIShortResponse (an empty answer is not an empty slot)", err)
	}
}

// --- CreateUser ---

func TestCreateUser_HappyPath(t *testing.T) {
	m := newMock()
	um := newUM(m)
	pwd := memguard.NewMemoryEnclave([]byte("hunter2"))
	defer pwd.Destroy()

	err := um.CreateUser(context.Background(), User{
		Slot:      2,
		Username:  "alice",
		Enabled:   true,
		Privilege: PrivilegeAdministrator,
	}, pwd)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// probe, name, password set, access, then enable for an Enabled user.
	if len(m.calls) != 5 {
		t.Fatalf("want 5 calls, got %d", len(m.calls))
	}
	if m.calls[0].cmd != cmdGetUserName {
		t.Errorf("call[0] = 0x%02x, want GetUserName", m.calls[0].cmd)
	}
	if m.calls[1].cmd != cmdSetUserName {
		t.Errorf("call[1] = 0x%02x, want SetUserName", m.calls[1].cmd)
	}
	if m.calls[2].cmd != cmdSetUserPassword {
		t.Errorf("call[2] = 0x%02x, want SetUserPassword", m.calls[2].cmd)
	}
	if m.calls[3].cmd != cmdSetUserAccess {
		t.Errorf("call[3] = 0x%02x, want SetUserAccess", m.calls[3].cmd)
	}
	// User management commands live in the App network function.
	for i, c := range m.calls {
		if c.netFn != netFnApp {
			t.Errorf("call[%d] netFn = 0x%02x, want App (0x%02x)", i, c.netFn, netFnApp)
		}
	}
	// SetUserName payload: byte 0 = slot, bytes 1.. = name
	if m.calls[1].data[0] != 2 {
		t.Errorf("name slot = %d, want 2", m.calls[1].data[0])
	}
	if string(m.calls[1].data[1:6]) != "alice" {
		t.Errorf("name = %q, want alice", m.calls[1].data[1:6])
	}
	// SetUserAccess: flags should include change | ipmi-msg | link-auth, channel=1
	wantFlags := suaChangeBits | suaIPMIMsgEnable | suaLinkAuthEnable | 0x01
	if m.calls[3].data[0] != wantFlags {
		t.Errorf("SUA flags = 0x%02x, want 0x%02x", m.calls[3].data[0], wantFlags)
	}
	if m.calls[3].data[2] != byte(PrivilegeAdministrator) {
		t.Errorf("priv byte = 0x%02x, want 0x%02x", m.calls[3].data[2], byte(PrivilegeAdministrator))
	}
}

func TestCreateUser_DisabledFlags(t *testing.T) {
	m := newMock()
	um := newUM(m)
	err := um.CreateUser(context.Background(), User{
		Slot:      3,
		Username:  "svc",
		Enabled:   false,
		Privilege: PrivilegeUser,
	}, nil)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// probe, name, access, disable (no password)
	if len(m.calls) != 4 {
		t.Fatalf("want 4 calls, got %d", len(m.calls))
	}
	flags := m.calls[2].data[0]
	if flags&suaIPMIMsgEnable != 0 || flags&suaLinkAuthEnable != 0 {
		t.Errorf("disabled user should have IPMI/link-auth bits clear, got 0x%02x", flags)
	}
	if flags&suaChangeBits == 0 {
		t.Error("change-bits flag must be set")
	}
	if c := m.calls[3]; c.cmd != cmdSetUserPassword || len(c.data) != 2 || c.data[0] != 3 || c.data[1] != pwdOpDisable {
		t.Errorf("call 3 = cmd 0x%02x data %x, want Set User Password disable {03 00}", c.cmd, c.data)
	}
}

func TestCreateUser_HonorsExplicitChannel(t *testing.T) {
	m := newMock()
	um := newUM(m)
	pwd := memguard.NewMemoryEnclave([]byte("hunter2"))
	defer pwd.Destroy()
	if err := um.CreateUser(context.Background(), User{
		Slot: 4, Username: "x", Enabled: true, Privilege: PrivilegeUser, Channel: 0x0E,
	}, pwd); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// Calls: probe, name, password, access, enable.
	flags := m.calls[3].data[0]
	if flags&0x0F != 0x0E {
		t.Errorf("channel nibble = 0x%x, want 0x0E", flags&0x0F)
	}
}

func TestCreateUser_InvalidSlot(t *testing.T) {
	cases := []uint8{0, 0x40, 0xFF}
	for _, slot := range cases {
		um := newUM(newMock())
		err := um.CreateUser(context.Background(), User{Slot: slot, Privilege: PrivilegeUser}, nil)
		var want ErrInvalidConfig
		if !errors.As(err, &want) || want.Field != "slot" {
			t.Errorf("slot=%d: err = %v, want slot config error", slot, err)
		}
	}
}

func TestCreateUser_InvalidUsername(t *testing.T) {
	um := newUM(newMock())
	long := strings.Repeat("x", 17)
	err := um.CreateUser(context.Background(), User{
		Slot: 2, Username: long, Privilege: PrivilegeUser,
	}, nil)
	var want ErrInvalidConfig
	if !errors.As(err, &want) || want.Field != "username" {
		t.Errorf("err = %v, want username config error", err)
	}
}

// An empty or NUL-containing name decodes as an empty slot, so ListUsers
// hides the account and the occupied-slot guard lets a later create
// overwrite it. CreateUser refuses both before any BMC write.
func TestCreateUser_RefusesEmptyOrNULUsernameWritesNothing(t *testing.T) {
	cases := []struct {
		name     string
		username string
	}{
		{name: "empty", username: ""},
		{name: "leading_nul", username: "\x00admin"},
		{name: "embedded_nul", username: "ad\x00min"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMock()
			err := newUM(m).CreateUser(context.Background(), User{
				Slot: 5, Username: tc.username, Enabled: true, Privilege: PrivilegeOperator,
			}, memguard.NewMemoryEnclave([]byte("s3cret")))
			var cfgErr ErrInvalidConfig
			if !errors.As(err, &cfgErr) {
				t.Fatalf("err = %v, want ErrInvalidConfig", err)
			}
			if cfgErr.Field != "username" {
				t.Errorf("Field = %q, want username", cfgErr.Field)
			}
			if len(m.calls) != 0 {
				t.Fatalf("want no BMC write, got %d calls (first cmd 0x%02x)", len(m.calls), m.calls[0].cmd)
			}
		})
	}
}

func TestCreateUser_InvalidPrivilege(t *testing.T) {
	um := newUM(newMock())
	err := um.CreateUser(context.Background(), User{
		Slot: 2, Username: "x", Privilege: Privilege(0x99),
	}, nil)
	var want ErrInvalidConfig
	if !errors.As(err, &want) || want.Field != "privilege" {
		t.Errorf("err = %v, want privilege config error", err)
	}
}

func TestCreateUser_NameSendError(t *testing.T) {
	m := newMock()
	m.err = errors.New("name-fail")
	um := newUM(m)
	err := um.CreateUser(context.Background(), User{
		Slot: 2, Username: "x", Privilege: PrivilegeUser,
	}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCreateUser_PasswordSendError(t *testing.T) {
	stages := []stage{
		{netFnApp, cmdGetUserName, 2, make([]byte, ipmiMaxUsernameLen)},
		{netFnApp, cmdSetUserName, 0, nil},
	}
	s := &stagedSender{stages: stages, t: t, errAfter: 2, errVal: errors.New("pwd-fail")}
	um := newUM(s)
	pwd := memguard.NewMemoryEnclave([]byte("p"))
	defer pwd.Destroy()
	err := um.CreateUser(context.Background(), User{
		Slot: 2, Username: "x", Privilege: PrivilegeUser, Enabled: true,
	}, pwd)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCreateUser_EnablesUser(t *testing.T) {
	m := newMock()
	um := newUM(m)
	pwd := memguard.NewMemoryEnclave([]byte("hunter2"))
	defer pwd.Destroy()
	if err := um.CreateUser(context.Background(), User{
		Slot: 5, Username: "bob", Enabled: true, Privilege: PrivilegeOperator,
	}, pwd); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	setIdx, enableIdx := -1, -1
	for i, c := range m.calls {
		if c.cmd != cmdSetUserPassword || len(c.data) < 2 {
			continue
		}
		switch c.data[1] & 0x03 {
		case pwdOpSet:
			setIdx = i
		case pwdOpEnable:
			enableIdx = i
			if c.data[0]&ipmiMaxUserSlot != 5 {
				t.Errorf("enable slot = %d, want 5", c.data[0]&ipmiMaxUserSlot)
			}
		}
	}
	if setIdx < 0 {
		t.Fatal("no pwdOpSet call")
	}
	if enableIdx < 0 {
		t.Fatal("an Enabled user got no pwdOpEnable call")
	}
	if enableIdx < setIdx {
		t.Errorf("pwdOpEnable (call %d) precedes pwdOpSet (call %d)", enableIdx, setIdx)
	}
}

func TestCreateUser_DisabledUserNotEnabled(t *testing.T) {
	m := newMock()
	um := newUM(m)
	pwd := memguard.NewMemoryEnclave([]byte("hunter2"))
	defer pwd.Destroy()
	if err := um.CreateUser(context.Background(), User{
		Slot: 5, Username: "bob", Enabled: false, Privilege: PrivilegeUser,
	}, pwd); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	for i, c := range m.calls {
		if c.cmd == cmdSetUserPassword && len(c.data) >= 2 && c.data[1]&0x03 == pwdOpEnable {
			t.Errorf("call %d enables a disabled user", i)
		}
	}
}

// statefulUserSender models a BMC's per-slot user name and global enable
// flag. Set User Name and Set User Access do not touch the global enable
// flag, as on a real BMC: only Set User Password ops 01b/00b change it.
type statefulUserSender struct {
	names   map[uint8]string
	enabled map[uint8]bool
	calls   []mockCall
}

func newStatefulUserSender() *statefulUserSender {
	return &statefulUserSender{names: map[uint8]string{}, enabled: map[uint8]bool{}}
}

func (s *statefulUserSender) Send(netFn, cmd byte, data []byte) ([]byte, error) {
	cp := append([]byte(nil), data...)
	s.calls = append(s.calls, mockCall{netFn: netFn, cmd: cmd, data: cp})
	switch cmd {
	case cmdGetUserName:
		resp := make([]byte, ipmiMaxUsernameLen)
		copy(resp, s.names[data[0]&ipmiMaxUserSlot])
		return resp, nil
	case cmdSetUserName:
		s.names[data[0]&ipmiMaxUserSlot] = trimNullPadded(data[1:])
	case cmdSetUserPassword:
		if len(data) >= 2 {
			slot := data[0] & ipmiMaxUserSlot
			switch data[1] & 0x03 {
			case pwdOpEnable:
				s.enabled[slot] = true
			case pwdOpDisable:
				s.enabled[slot] = false
			}
		}
	}
	return nil, nil
}

func TestCreateUser_RecreatedDisabledSlotIsDisabled(t *testing.T) {
	s := newStatefulUserSender()
	um := newUM(s)
	ctx := context.Background()
	pwd := memguard.NewMemoryEnclave([]byte("hunter2"))
	defer pwd.Destroy()
	if err := um.CreateUser(ctx, User{
		Slot: 4, Username: "alice", Enabled: true, Privilege: PrivilegeAdministrator,
	}, pwd); err != nil {
		t.Fatalf("CreateUser enabled: %v", err)
	}
	if !s.enabled[4] {
		t.Fatal("an enabled create left the slot disabled")
	}
	if err := um.DeleteUser(ctx, 4); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if s.names[4] != "" {
		t.Fatalf("DeleteUser left name %q", s.names[4])
	}
	// IPMI behaviour: DeleteUser clears the name and channel access but
	// leaves the slot's global enable flag set.
	if !s.enabled[4] {
		t.Fatal("model: DeleteUser should leave the global enable flag set")
	}
	if err := um.CreateUser(ctx, User{
		Slot: 4, Username: "bob", Enabled: false, Privilege: PrivilegeUser,
	}, nil); err != nil {
		t.Fatalf("CreateUser disabled: %v", err)
	}
	if s.names[4] != "bob" {
		t.Fatalf("name = %q, want bob", s.names[4])
	}
	if s.enabled[4] {
		t.Error("a disabled create left the reused slot globally enabled")
	}
}

func TestCreateUser_LongPasswordWritesNothing(t *testing.T) {
	m := newMock()
	um := newUM(m)
	pwd := memguard.NewMemoryEnclave([]byte("abcdefghijklmnopqrstu")) // 21 bytes
	defer pwd.Destroy()
	err := um.CreateUser(context.Background(), User{
		Slot: 2, Username: "x", Privilege: PrivilegeUser, Enabled: true,
	}, pwd)
	var cfgErr ErrInvalidConfig
	if !errors.As(err, &cfgErr) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
	if len(m.calls) != 0 {
		t.Fatalf("want no BMC write, got %d calls (first cmd 0x%02x)", len(m.calls), m.calls[0].cmd)
	}
}

// TestCreateUser_EnabledWithoutPasswordWritesNothing pins that an Enabled
// user with no password is refused before any IPMI write: the slot keeps its
// old password state, so enabling it could activate an old or blank one.
func TestCreateUser_EnabledWithoutPasswordWritesNothing(t *testing.T) {
	cases := []struct {
		name string
		pwd  *memguard.MemoryEnclave
	}{
		{name: "nil", pwd: nil},
		{name: "empty", pwd: memguard.NewMemoryEnclave([]byte{})},
		{name: "all_nul", pwd: memguard.NewMemoryEnclave([]byte{0})},
		{name: "embedded_nul", pwd: memguard.NewMemoryEnclave([]byte("ab\x00cd"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMock()
			err := newUM(m).CreateUser(context.Background(), User{
				Slot: 5, Username: "bob", Enabled: true, Privilege: PrivilegeOperator,
			}, tc.pwd)
			var cfgErr ErrInvalidConfig
			if !errors.As(err, &cfgErr) {
				t.Fatalf("err = %v, want ErrInvalidConfig", err)
			}
			if cfgErr.Field != "password" {
				t.Errorf("Field = %q, want password", cfgErr.Field)
			}
			if len(m.calls) != 0 {
				t.Fatalf("want no BMC write, got %d calls (first cmd 0x%02x)", len(m.calls), m.calls[0].cmd)
			}
		})
	}
	t.Run("disabled_name_only_succeeds", func(t *testing.T) {
		m := newMock()
		if err := newUM(m).CreateUser(context.Background(), User{
			Slot: 5, Username: "bob", Enabled: false, Privilege: PrivilegeOperator,
		}, nil); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		disables := 0
		for _, c := range m.calls {
			if c.cmd != cmdSetUserPassword {
				continue
			}
			if len(c.data) == 2 && c.data[0] == 5 && c.data[1] == pwdOpDisable {
				disables++
				continue
			}
			t.Fatalf("disabled name-only user sent a password write (data %x)", c.data)
		}
		if disables != 1 {
			t.Fatalf("disabled name-only user sent %d disables, want 1", disables)
		}
	})
}

func TestCreateUser_PartialFailureLeavesTheSlot(t *testing.T) {
	m := newMock()
	pwdErr := errors.New("pwd-fail")
	m.cmdErr = map[byte]error{cmdSetUserPassword: pwdErr}
	um := newUM(m)
	pwd := memguard.NewMemoryEnclave([]byte("p"))
	defer pwd.Destroy()
	u := User{Slot: 2, Username: "x", Privilege: PrivilegeUser, Enabled: true}
	err := um.CreateUser(context.Background(), u, pwd)
	if !errors.Is(err, pwdErr) {
		t.Fatalf("err = %v, want the password error", err)
	}
	failIdx := -1
	for i, c := range m.calls {
		if c.cmd == cmdSetUserPassword {
			failIdx = i
			break
		}
	}
	if failIdx < 0 {
		t.Fatal("no SetUserPassword call")
	}
	for i, c := range m.calls[failIdx+1:] {
		switch c.cmd {
		case cmdSetUserName, cmdSetUserAccess, cmdSetUserPassword:
			t.Errorf("call[%d] = 0x%02x: a failed create wrote the slot after the password failure", failIdx+1+i, c.cmd)
		}
	}
}

// lostEnableSender records every call and fails only the Set User Password
// enable operation, as when the BMC applies the enable but its UDP response
// is lost. Get User Name returns an empty name; reReadErr, when set, fails
// every Get User Name after the first (the probe).
type lostEnableSender struct {
	calls     []mockCall
	enableErr error
	reReadErr error
	gets      int
}

func (s *lostEnableSender) Send(netFn, cmd byte, data []byte) ([]byte, error) {
	cp := append([]byte(nil), data...)
	s.calls = append(s.calls, mockCall{netFn: netFn, cmd: cmd, data: cp})
	if cmd == cmdGetUserName {
		s.gets++
		if s.gets > 1 && s.reReadErr != nil {
			return nil, s.reReadErr
		}
		return make([]byte, ipmiMaxUsernameLen), nil
	}
	if cmd == cmdSetUserPassword && len(data) >= 2 && data[1]&0x03 == pwdOpEnable {
		return nil, s.enableErr
	}
	return nil, nil
}

// TestCreateUser_LostEnableResponseLeavesTheSlot: the enable may have been
// applied, but the slot's ownership cannot be proven, so it is left for the
// operator (Tenant ruling, Codex #2199 round 17).
func TestCreateUser_LostEnableResponseLeavesTheSlot(t *testing.T) {
	s := &lostEnableSender{enableErr: errors.New("enable response lost")}
	um := newUM(s)
	pwd := memguard.NewMemoryEnclave([]byte("hunter2"))
	defer pwd.Destroy()
	u := User{Slot: 4, Username: "eve", Privilege: PrivilegeAdministrator, Enabled: true}
	err := um.CreateUser(context.Background(), u, pwd)
	if !errors.Is(err, s.enableErr) {
		t.Fatalf("err = %v, want the enable error", err)
	}
	enableIdx := -1
	for i, c := range s.calls {
		if c.cmd == cmdSetUserPassword && len(c.data) >= 2 && c.data[1]&0x03 == pwdOpEnable {
			enableIdx = i
		}
	}
	if enableIdx < 0 {
		t.Fatal("no enable call")
	}
	for i, c := range s.calls[enableIdx+1:] {
		switch c.cmd {
		case cmdSetUserName, cmdSetUserAccess, cmdSetUserPassword:
			t.Errorf("call[%d] = 0x%02x: a failed create wrote the slot after the lost enable", enableIdx+1+i, c.cmd)
		}
	}
}

func TestCreateUser_FailedReReadIsJoined(t *testing.T) {
	s := &lostEnableSender{
		enableErr: errors.New("enable response lost"),
		reReadErr: errors.New("re-read failed"),
	}
	um := newUM(s)
	pwd := memguard.NewMemoryEnclave([]byte("hunter2"))
	defer pwd.Destroy()
	u := User{Slot: 6, Username: "mal", Privilege: PrivilegeOperator, Enabled: true}
	err := um.CreateUser(context.Background(), u, pwd)
	if !errors.Is(err, s.enableErr) {
		t.Errorf("err = %v, want the enable error", err)
	}
	if !errors.Is(err, s.reReadErr) {
		t.Errorf("err = %v, want the re-read error", err)
	}
}

// lostNameSender applies every write but loses the response to the first
// (non-zero) Set User Name, as a BMC whose UDP reply is dropped does: the
// name is stored in name and Get User Name returns it.
type lostNameSender struct {
	calls   []mockCall
	nameErr error
	name    string
}

func (s *lostNameSender) Send(netFn, cmd byte, data []byte) ([]byte, error) {
	cp := append([]byte(nil), data...)
	s.calls = append(s.calls, mockCall{netFn: netFn, cmd: cmd, data: cp})
	if cmd == cmdGetUserName {
		resp := make([]byte, ipmiMaxUsernameLen)
		copy(resp, s.name)
		return resp, nil
	}
	if cmd == cmdSetUserName && len(data) >= 2 {
		for _, b := range data[1:] {
			if b != 0 {
				s.name = trimNullPadded(data[1:])
				return nil, s.nameErr
			}
		}
	}
	return nil, nil
}

// TestCreateUser_LostNameResponseLeavesTheSlot: a name write whose response
// was lost is not rolled back; the slot shows the name, so ErrSlotOccupied
// is joined and nothing more is written (Codex #2199 round 17).
func TestCreateUser_LostNameResponseLeavesTheSlot(t *testing.T) {
	s := &lostNameSender{nameErr: errors.New("name response lost")}
	um := newUM(s)
	u := User{Slot: 4, Username: "eve", Privilege: PrivilegeAdministrator, Enabled: false}
	err := um.CreateUser(context.Background(), u, nil)
	if !errors.Is(err, s.nameErr) {
		t.Fatalf("err = %v, want the name error", err)
	}
	var occ ErrSlotOccupied
	if !errors.As(err, &occ) || occ.Slot != 4 {
		t.Errorf("err = %v, want ErrSlotOccupied{Slot: 4} joined", err)
	}
	want := []byte{cmdGetUserName, cmdSetUserName, cmdGetUserName}
	if len(s.calls) != len(want) {
		t.Fatalf("got %d calls, want %d (probe, failed name write, re-read)", len(s.calls), len(want))
	}
	for i, c := range s.calls {
		if c.cmd != want[i] {
			t.Errorf("call[%d] = 0x%02x, want 0x%02x", i, c.cmd, want[i])
		}
	}
	if s.name != "eve" {
		t.Errorf("slot name = %q, want eve (left as the BMC holds it)", s.name)
	}
}

// A create aimed at a slot that already holds an account must not touch it,
// even when the manager is called without Service.CreateUser (the CLI): a
// rejected name write would otherwise roll the existing account back.
func TestCreateUser_OccupiedSlotSurvivesRejectedName(t *testing.T) {
	m := newMock()
	m.responses[key(netFnApp, cmdGetUserName)] = append([]byte("admin"), make([]byte, 11)...)
	m.cmdErr = map[byte]error{cmdSetUserName: errors.New("duplicate name")}
	err := newUM(m).CreateUser(context.Background(), User{
		Slot: 2, Username: "admin", Privilege: PrivilegeAdministrator, Enabled: false,
	}, nil)
	var occ ErrSlotOccupied
	if !errors.As(err, &occ) || occ.Slot != 2 {
		t.Fatalf("err = %v, want ErrSlotOccupied{Slot: 2}", err)
	}
	for i, c := range m.calls {
		switch c.cmd {
		case cmdSetUserName, cmdSetUserAccess, cmdSetUserPassword:
			t.Errorf("call[%d] = 0x%02x: the occupied account was written", i, c.cmd)
		}
	}
	if len(m.calls) == 0 || m.calls[0].cmd != cmdGetUserName || len(m.calls[0].data) == 0 || m.calls[0].data[0] != 2 {
		t.Fatal("first call is not the Get User Name probe of slot 2")
	}
}

// TestCreateUser_RefusesTheAnonymousSlot: slot 1 is the built-in anonymous
// user, which Get User Name reports as empty. A create aimed at it is refused
// before any command, so a rejected fixed-name write can never roll the
// anonymous user back (Codex #2199 round 15).
func TestCreateUser_RefusesTheAnonymousSlot(t *testing.T) {
	m := newMock() // Get User Name answers an empty name, as the anonymous slot does
	m.cmdErr = map[byte]error{cmdSetUserName: errors.New("fixed name")}
	pwd := memguard.NewMemoryEnclave([]byte("hunter2"))
	defer pwd.Destroy()
	err := newUM(m).CreateUser(context.Background(), User{
		Slot: 1, Username: "alice", Privilege: PrivilegeAdministrator, Enabled: true,
	}, pwd)
	var cfgErr ErrInvalidConfig
	if !errors.As(err, &cfgErr) || cfgErr.Field != "slot" {
		t.Fatalf("CreateUser into slot 1 = %v, want ErrInvalidConfig on slot", err)
	}
	for i, c := range m.calls {
		switch c.cmd {
		case cmdSetUserName, cmdSetUserAccess, cmdSetUserPassword:
			t.Errorf("call[%d] = 0x%02x: the anonymous user was written", i, c.cmd)
		}
	}
	if len(m.calls) != 0 {
		t.Errorf("want no IPMI command, got %d", len(m.calls))
	}
}

// interleavedNameSender is a second manager's view of the shared simulated
// BMC bmc. On its first non-empty Set User Name it runs before (the other
// manager's whole create), then fails that write with nameErr without
// applying it, as a BMC whose reply is lost after a racing create does.
type interleavedNameSender struct {
	bmc     *statefulUserSender
	before  func()
	nameErr error
	calls   []mockCall
}

func (s *interleavedNameSender) Send(netFn, cmd byte, data []byte) ([]byte, error) {
	cp := append([]byte(nil), data...)
	s.calls = append(s.calls, mockCall{netFn: netFn, cmd: cmd, data: cp})
	if cmd == cmdSetUserName && len(data) >= 2 && s.before != nil {
		named := false
		for _, b := range data[1:] {
			if b != 0 {
				named = true
				break
			}
		}
		if named {
			f := s.before
			s.before = nil
			f()
			return nil, s.nameErr
		}
	}
	return s.bmc.Send(netFn, cmd, data)
}

// TestCreateUser_RollbackSparesAnotherManagersAccount: two managers share
// one simulated BMC; both probe slot 3 empty, the first completes its
// create, the second's name write then fails. Its rollback must not
// disable, revoke or clear the first manager's account (Codex #2199 round
// 16).
func TestCreateUser_RollbackSparesAnotherManagersAccount(t *testing.T) {
	shared := newStatefulUserSender()
	first := newUM(shared)
	pwdA := memguard.NewMemoryEnclave([]byte("alice-pw"))
	defer pwdA.Destroy()
	pwdB := memguard.NewMemoryEnclave([]byte("bob-pw"))
	defer pwdB.Destroy()
	var firstErr error
	second := &interleavedNameSender{
		bmc:     shared,
		nameErr: errors.New("name response lost"),
		before: func() {
			firstErr = first.CreateUser(context.Background(), User{
				Slot: 3, Username: "alice", Privilege: PrivilegeAdministrator, Enabled: true,
			}, pwdA)
		},
	}
	err := newUM(second).CreateUser(context.Background(), User{
		Slot: 3, Username: "bob", Privilege: PrivilegeOperator, Enabled: true,
	}, pwdB)
	if firstErr != nil {
		t.Fatalf("first CreateUser: %v", firstErr)
	}
	if !errors.Is(err, second.nameErr) {
		t.Fatalf("err = %v, want the name error", err)
	}
	var occ ErrSlotOccupied
	if !errors.As(err, &occ) || occ.Slot != 3 {
		t.Errorf("err = %v, want ErrSlotOccupied{Slot: 3} joined", err)
	}
	if shared.names[3] != "alice" {
		t.Errorf("slot 3 name = %q, want alice", shared.names[3])
	}
	if !shared.enabled[3] {
		t.Error("the first manager's account was disabled")
	}
	idx := -1
	for i, c := range second.calls {
		if c.cmd == cmdSetUserName {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("the second manager sent no Set User Name")
	}
	for i, c := range second.calls[idx+1:] {
		switch c.cmd {
		case cmdSetUserName, cmdSetUserAccess, cmdSetUserPassword:
			t.Errorf("call[%d] = 0x%02x: the second manager wrote the first manager's slot", idx+1+i, c.cmd)
		}
	}
}

// TestCreateUser_SameUsernameRaceLeavesTheOtherAccount: two managers share
// one simulated BMC and create the same username in slot 3. Both probe it
// empty, the first completes, and the second's name write then fails. A name
// re-read cannot tell the two writes apart, so the second must not disable,
// revoke or clear the first manager's account (Codex #2199 round 17).
func TestCreateUser_SameUsernameRaceLeavesTheOtherAccount(t *testing.T) {
	shared := newStatefulUserSender()
	first := newUM(shared)
	pwdA := memguard.NewMemoryEnclave([]byte("alice-pw"))
	defer pwdA.Destroy()
	pwdB := memguard.NewMemoryEnclave([]byte("bob-pw"))
	defer pwdB.Destroy()
	var firstErr error
	second := &interleavedNameSender{
		bmc:     shared,
		nameErr: errors.New("name response lost"),
		before: func() {
			firstErr = first.CreateUser(context.Background(), User{
				Slot: 3, Username: "alice", Privilege: PrivilegeAdministrator, Enabled: true,
			}, pwdA)
		},
	}
	err := newUM(second).CreateUser(context.Background(), User{
		Slot: 3, Username: "alice", Privilege: PrivilegeOperator, Enabled: true,
	}, pwdB)
	if firstErr != nil {
		t.Fatalf("first CreateUser: %v", firstErr)
	}
	if !errors.Is(err, second.nameErr) {
		t.Fatalf("err = %v, want the name error", err)
	}
	var occ ErrSlotOccupied
	if !errors.As(err, &occ) || occ.Slot != 3 {
		t.Errorf("err = %v, want ErrSlotOccupied{Slot: 3} joined", err)
	}
	if shared.names[3] != "alice" {
		t.Errorf("slot 3 name = %q, want alice", shared.names[3])
	}
	if !shared.enabled[3] {
		t.Error("the first manager's account was disabled")
	}
	idx := -1
	for i, c := range second.calls {
		if c.cmd == cmdSetUserName {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("the second manager sent no Set User Name")
	}
	for i, c := range second.calls[idx+1:] {
		switch c.cmd {
		case cmdSetUserName, cmdSetUserAccess, cmdSetUserPassword:
			t.Errorf("call[%d] = 0x%02x: the second manager wrote the first manager's slot", idx+1+i, c.cmd)
		}
	}
}

// A failed probe returns its error and writes nothing.
func TestCreateUser_NameProbeErrorWritesNothing(t *testing.T) {
	m := newMock()
	probeErr := errors.New("probe lost")
	m.cmdErr = map[byte]error{cmdGetUserName: probeErr}
	err := newUM(m).CreateUser(context.Background(), User{
		Slot: 3, Username: "admin", Privilege: PrivilegeAdministrator, Enabled: false,
	}, nil)
	if !errors.Is(err, probeErr) {
		t.Fatalf("err = %v, want the probe error", err)
	}
	if len(m.calls) != 1 {
		t.Fatalf("want only the probe, got %d calls", len(m.calls))
	}
}

// A Get User Name answer shorter than the 16-byte name field is refused, so a
// truncated or empty answer is never read as an empty slot and nothing is
// written or rolled back.
func TestCreateUser_ShortNameProbeWritesNothing(t *testing.T) {
	cases := []struct {
		name string
		resp []byte
	}{
		{"no_data", nil},
		{"empty", []byte{}},
		{"fifteen_zero_bytes", make([]byte, 15)},
		{"truncated_name", []byte("adm")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMock()
			m.responses[key(netFnApp, cmdGetUserName)] = tc.resp
			err := newUM(m).CreateUser(context.Background(), User{
				Slot: 2, Username: "bob", Privilege: PrivilegeUser, Enabled: false,
			}, nil)
			var short ErrIPMIShortResponse
			if !errors.As(err, &short) {
				t.Fatalf("err = %v, want ErrIPMIShortResponse", err)
			}
			if short.Command != "Get User Name" || short.Got != len(tc.resp) || short.Want != ipmiMaxUsernameLen {
				t.Errorf("short = %+v, want Get User Name got %d want %d", short, len(tc.resp), ipmiMaxUsernameLen)
			}
			if len(m.calls) != 1 {
				t.Fatalf("want only the probe, got %d calls", len(m.calls))
			}
		})
	}
}

// cancelOnNameSender cancels the create's context once the name is written,
// as a caller that disconnects mid-create would.
type cancelOnNameSender struct {
	*mockSender
	cancel context.CancelFunc
}

func (s cancelOnNameSender) Send(netFn, cmd byte, data []byte) ([]byte, error) {
	resp, err := s.mockSender.Send(netFn, cmd, data)
	if cmd == cmdSetUserName {
		s.cancel()
	}
	return resp, err
}

// TestCreateUser_CancelledContextStopsWrites: a create whose context ends
// writes nothing more, so a caller that timed out or disconnected cannot
// leave an account created and enabled behind it (Codex #2199 round 18).
func TestCreateUser_CancelledContextStopsWrites(t *testing.T) {
	user := User{Slot: 3, Username: "carol", Privilege: PrivilegeOperator, Enabled: true}

	t.Run("cancelled_before_create", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		mock := newMock()
		m := newUM(mock)
		pwd := memguard.NewMemoryEnclave([]byte("hunter2"))
		err := m.CreateUser(ctx, user, pwd)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("CreateUser err = %v, want context.Canceled", err)
		}
		for _, c := range mock.calls {
			switch c.cmd {
			case cmdSetUserName, cmdSetUserPassword, cmdSetUserAccess:
				t.Errorf("cancelled create wrote command %#x", c.cmd)
			}
		}
	})

	t.Run("cancelled_after_name_write", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		mock := newMock()
		m := newUM(cancelOnNameSender{mockSender: mock, cancel: cancel})
		pwd := memguard.NewMemoryEnclave([]byte("hunter2"))
		err := m.CreateUser(ctx, user, pwd)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("CreateUser err = %v, want context.Canceled", err)
		}
		named := false
		for _, c := range mock.calls {
			switch c.cmd {
			case cmdSetUserName:
				named = true
			case cmdSetUserPassword, cmdSetUserAccess:
				if named {
					t.Errorf("create wrote command %#x after its context was cancelled", c.cmd)
				}
			}
		}
		if !named {
			t.Fatal("the name was never written; the test did not reach the cancel")
		}
	})
}

// --- SetUserPassword ---

func TestSetUserPassword(t *testing.T) {
	m := newMock()
	um := newUM(m)
	pwd := memguard.NewMemoryEnclave([]byte("p@ssw0rd"))
	defer pwd.Destroy()

	if err := um.SetUserPassword(context.Background(), 5, pwd); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
	c := m.lastCall(t)
	if c.cmd != cmdSetUserPassword {
		t.Errorf("cmd = 0x%02x, want SetUserPassword", c.cmd)
	}
	// 16-byte password form: byte 0 low-6 = slot, bit 7 = 0
	if c.data[0]&0x80 != 0 {
		t.Error("expected 16-byte password form (bit 7 = 0)")
	}
	if c.data[0]&ipmiMaxUserSlot != 5 {
		t.Errorf("slot = %d, want 5", c.data[0]&ipmiMaxUserSlot)
	}
	if c.data[1] != pwdOpSet {
		t.Errorf("op = 0x%02x, want pwdOpSet", c.data[1])
	}
	if string(c.data[2:10]) != "p@ssw0rd" {
		t.Errorf("password bytes = %q, want p@ssw0rd", c.data[2:10])
	}
	if len(c.data) != 2+ipmiPwdLenShort {
		t.Errorf("payload len = %d, want %d", len(c.data), 2+ipmiPwdLenShort)
	}
}

func TestSetUserPassword_LongPasswordSets20ByteFlag(t *testing.T) {
	m := newMock()
	um := newUM(m)
	pwd := memguard.NewMemoryEnclave([]byte(strings.Repeat("a", 18)))
	defer pwd.Destroy()

	if err := um.SetUserPassword(context.Background(), 5, pwd); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
	c := m.lastCall(t)
	if c.data[0]&0x80 == 0 {
		t.Error("expected 20-byte password form (bit 7 = 1)")
	}
	if len(c.data) != 2+ipmiPwdLenLong {
		t.Errorf("payload len = %d, want %d", len(c.data), 2+ipmiPwdLenLong)
	}
}

func TestSetUserPassword_RejectsOversized(t *testing.T) {
	um := newUM(newMock())
	pwd := memguard.NewMemoryEnclave([]byte(strings.Repeat("x", 21)))
	defer pwd.Destroy()
	err := um.SetUserPassword(context.Background(), 5, pwd)
	var want ErrInvalidConfig
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrInvalidConfig", err)
	}
}

func TestSetUserPassword_NilOrEmpty(t *testing.T) {
	um := newUM(newMock())
	if err := um.SetUserPassword(context.Background(), 5, nil); err == nil {
		t.Error("expected error for nil password")
	}
	empty := memguard.NewMemoryEnclave(nil)
	defer empty.Destroy()
	if err := um.SetUserPassword(context.Background(), 5, empty); err == nil {
		t.Error("expected error for empty password")
	}
}

func TestSetUserPassword_DestroyedSecret(t *testing.T) {
	um := newUM(newMock())
	pwd := memguard.NewMemoryEnclave([]byte("x"))
	pwd.Destroy()
	if err := um.SetUserPassword(context.Background(), 5, pwd); err == nil {
		t.Error("expected error for destroyed secret")
	}
}

func TestSetUserPassword_InvalidSlot(t *testing.T) {
	um := newUM(newMock())
	pwd := memguard.NewMemoryEnclave([]byte("x"))
	defer pwd.Destroy()
	err := um.SetUserPassword(context.Background(), 0, pwd)
	if err == nil {
		t.Error("expected slot validation error")
	}
}

func TestSetUserPassword_TransportError(t *testing.T) {
	m := newMock()
	m.err = errors.New("transport")
	um := newUM(m)
	pwd := memguard.NewMemoryEnclave([]byte("x"))
	defer pwd.Destroy()
	if err := um.SetUserPassword(context.Background(), 5, pwd); err == nil {
		t.Error("expected transport error")
	}
}

// TestSetUserPassword_ActivatesDisabledReusedSlot covers the activation
// path of a slot created disabled: a reused slot whose global enable flag a
// disabled create cleared is enabled again once its password is set, so a
// later role grant leaves an account that can authenticate.
func TestSetUserPassword_ActivatesDisabledReusedSlot(t *testing.T) {
	s := newStatefulUserSender()
	um := newUM(s)
	ctx := context.Background()
	pwd := memguard.NewMemoryEnclave([]byte("hunter2"))
	defer pwd.Destroy()
	if err := um.CreateUser(ctx, User{
		Slot: 4, Username: "alice", Enabled: true, Privilege: PrivilegeAdministrator,
	}, pwd); err != nil {
		t.Fatalf("CreateUser enabled: %v", err)
	}
	if err := um.DeleteUser(ctx, 4); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if err := um.CreateUser(ctx, User{
		Slot: 4, Username: "bob", Enabled: false, Privilege: PrivilegeUser,
	}, nil); err != nil {
		t.Fatalf("CreateUser disabled: %v", err)
	}
	if s.enabled[4] {
		t.Fatal("a disabled create left the reused slot globally enabled")
	}
	next := memguard.NewMemoryEnclave([]byte("s3cret"))
	defer next.Destroy()
	if err := um.SetUserPassword(ctx, 4, next); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
	if err := um.SetUserPrivilege(ctx, 4, 0, PrivilegeUser); err != nil {
		t.Fatalf("SetUserPrivilege: %v", err)
	}
	if !s.enabled[4] {
		t.Error("password and role set, but the slot's global enable flag is still clear")
	}
}

// TestSetUserPassword_FailedSetSendsNoEnable: when the password write fails,
// the slot is never enabled, so a stale or blank password is not activated.
func TestSetUserPassword_FailedSetSendsNoEnable(t *testing.T) {
	m := newMock()
	m.err = errors.New("transport")
	um := newUM(m)
	pwd := memguard.NewMemoryEnclave([]byte("x"))
	defer pwd.Destroy()
	if err := um.SetUserPassword(context.Background(), 5, pwd); err == nil {
		t.Fatal("expected transport error")
	}
	for _, c := range m.calls {
		if c.cmd == cmdSetUserPassword && len(c.data) >= 2 && c.data[1]&0x03 == pwdOpEnable {
			t.Errorf("a failed password set was followed by an enable: % x", c.data)
		}
	}
}

// --- SetUserPrivilege ---

func TestSetUserPrivilege_DefaultsChannel(t *testing.T) {
	m := newMock()
	um := newUM(m)
	if err := um.SetUserPrivilege(context.Background(), 2, 0, PrivilegeOperator); err != nil {
		t.Fatalf("SetUserPrivilege: %v", err)
	}
	c := m.lastCall(t)
	if c.data[0]&0x0F != defaultIPMIChannel {
		t.Errorf("channel nibble = %d, want %d", c.data[0]&0x0F, defaultIPMIChannel)
	}
}

func TestSetUserPrivilege_NoAccessDisablesFlags(t *testing.T) {
	m := newMock()
	um := newUM(m)
	if err := um.SetUserPrivilege(context.Background(), 2, 1, PrivilegeNoAccess); err != nil {
		t.Fatalf("SetUserPrivilege: %v", err)
	}
	flags := m.lastCall(t).data[0]
	if flags&suaIPMIMsgEnable != 0 || flags&suaLinkAuthEnable != 0 {
		t.Errorf("NoAccess should clear ipmi/link bits, got 0x%02x", flags)
	}
}

func TestSetUserPrivilege_InvalidSlot(t *testing.T) {
	um := newUM(newMock())
	if err := um.SetUserPrivilege(context.Background(), 0, 1, PrivilegeUser); err == nil {
		t.Error("expected slot validation error")
	}
}

func TestSetUserPrivilege_InvalidPrivilege(t *testing.T) {
	um := newUM(newMock())
	if err := um.SetUserPrivilege(context.Background(), 2, 1, Privilege(0x77)); err == nil {
		t.Error("expected privilege validation error")
	}
}

// --- DeleteUser ---

func TestDeleteUser(t *testing.T) {
	m := newMock()
	um := newUM(m)
	if err := um.DeleteUser(context.Background(), 3); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if len(m.calls) != 2 {
		t.Fatalf("want 2 calls, got %d", len(m.calls))
	}
	if m.calls[0].cmd != cmdSetUserName {
		t.Errorf("call[0] = 0x%02x, want SetUserName", m.calls[0].cmd)
	}
	// Name payload: slot + 16 zero bytes
	for i, b := range m.calls[0].data[1:] {
		if b != 0 {
			t.Errorf("name byte %d = 0x%02x, want 0", i, b)
		}
	}
	if m.calls[1].cmd != cmdSetUserAccess {
		t.Errorf("call[1] = 0x%02x, want SetUserAccess", m.calls[1].cmd)
	}
	if m.calls[1].data[2]&guaPrivilegeMask != byte(PrivilegeNoAccess) {
		t.Errorf("priv = 0x%02x, want NoAccess", m.calls[1].data[2])
	}
}

func TestDeleteUser_InvalidSlot(t *testing.T) {
	um := newUM(newMock())
	if err := um.DeleteUser(context.Background(), 0); err == nil {
		t.Error("expected slot error")
	}
}

func TestDeleteUser_NameError(t *testing.T) {
	m := newMock()
	m.err = errors.New("nm")
	um := newUM(m)
	if err := um.DeleteUser(context.Background(), 3); err == nil {
		t.Error("expected error")
	}
}

// --- helpers ---

func TestTrimNullPadded(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte("ADMIN\x00\x00\x00"), "ADMIN"},
		{[]byte("\x00ignored"), ""},
		{[]byte("nopad"), "nopad"},
		{[]byte{}, ""},
	}
	for _, tc := range cases {
		if got := trimNullPadded(tc.in); got != tc.want {
			t.Errorf("trimNullPadded(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestZero(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	zero(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("byte %d = %d, want 0", i, v)
		}
	}
}

func TestErrIPMIShortResponse_Message(t *testing.T) {
	e := ErrIPMIShortResponse{Command: "X", Got: 1, Want: 4}
	if !strings.Contains(e.Error(), "X") || !strings.Contains(e.Error(), "1") {
		t.Errorf("error message missing fields: %s", e.Error())
	}
}

// --- stagedSender ---

// stage is one programmed response: matching netFn/cmd/(optional slot)
// returns resp.
type stage struct {
	netFn, cmd byte
	matchSlot  byte
	resp       []byte
}

// stagedSender returns canned responses in declared order. After errAfter
// successful calls (1-based count), it returns errVal.
type stagedSender struct {
	stages   []stage
	idx      int
	t        *testing.T
	errAfter int
	errVal   error
	calls    int
}

func (s *stagedSender) Send(netFn, cmd byte, data []byte) ([]byte, error) {
	s.calls++
	if s.errAfter > 0 && s.calls > s.errAfter {
		return nil, s.errVal
	}
	if s.idx >= len(s.stages) {
		s.t.Fatalf("stagedSender: unexpected call %d (netFn=0x%02x cmd=0x%02x)", s.calls, netFn, cmd)
	}
	st := s.stages[s.idx]
	s.idx++
	if st.netFn != netFn || st.cmd != cmd {
		s.t.Fatalf("stagedSender call %d: got (0x%02x,0x%02x), want (0x%02x,0x%02x)",
			s.calls, netFn, cmd, st.netFn, st.cmd)
	}
	if st.matchSlot != 0 {
		// For Get User Access: data = [channel, slot]. For Get User Name: data = [slot].
		var slot byte
		if cmd == cmdGetUserAccess && len(data) >= 2 {
			slot = data[1] & ipmiMaxUserSlot
		} else if len(data) >= 1 {
			slot = data[0] & ipmiMaxUserSlot
		}
		if slot != st.matchSlot {
			s.t.Fatalf("stagedSender call %d: slot=%d, want %d", s.calls, slot, st.matchSlot)
		}
	}
	return append([]byte(nil), st.resp...), nil
}
