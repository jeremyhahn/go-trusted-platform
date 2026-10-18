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
// failure.
type mockSender struct {
	calls     []mockCall
	responses map[uint16][]byte
	err       error
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
	if r, ok := m.responses[key(netFn, cmd)]; ok {
		return append([]byte(nil), r...), nil
	}
	return nil, nil
}

func newMock() *mockSender {
	return &mockSender{responses: map[uint16][]byte{}}
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
	if len(m.calls) != 3 {
		t.Fatalf("want 3 calls, got %d", len(m.calls))
	}
	if m.calls[0].cmd != cmdSetUserName {
		t.Errorf("call[0] = 0x%02x, want SetUserName", m.calls[0].cmd)
	}
	if m.calls[1].cmd != cmdSetUserPassword {
		t.Errorf("call[1] = 0x%02x, want SetUserPassword", m.calls[1].cmd)
	}
	if m.calls[2].cmd != cmdSetUserAccess {
		t.Errorf("call[2] = 0x%02x, want SetUserAccess", m.calls[2].cmd)
	}
	// User management commands live in the App network function.
	for i, c := range m.calls {
		if c.netFn != netFnApp {
			t.Errorf("call[%d] netFn = 0x%02x, want App (0x%02x)", i, c.netFn, netFnApp)
		}
	}
	// SetUserName payload: byte 0 = slot, bytes 1.. = name
	if m.calls[0].data[0] != 2 {
		t.Errorf("name slot = %d, want 2", m.calls[0].data[0])
	}
	if string(m.calls[0].data[1:6]) != "alice" {
		t.Errorf("name = %q, want alice", m.calls[0].data[1:6])
	}
	// SetUserAccess: flags should include change | ipmi-msg | link-auth, channel=1
	wantFlags := suaChangeBits | suaIPMIMsgEnable | suaLinkAuthEnable | 0x01
	if m.calls[2].data[0] != wantFlags {
		t.Errorf("SUA flags = 0x%02x, want 0x%02x", m.calls[2].data[0], wantFlags)
	}
	if m.calls[2].data[2] != byte(PrivilegeAdministrator) {
		t.Errorf("priv byte = 0x%02x, want 0x%02x", m.calls[2].data[2], byte(PrivilegeAdministrator))
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
	// 2 calls (no password)
	if len(m.calls) != 2 {
		t.Fatalf("want 2 calls, got %d", len(m.calls))
	}
	flags := m.calls[1].data[0]
	if flags&suaIPMIMsgEnable != 0 || flags&suaLinkAuthEnable != 0 {
		t.Errorf("disabled user should have IPMI/link-auth bits clear, got 0x%02x", flags)
	}
	if flags&suaChangeBits == 0 {
		t.Error("change-bits flag must be set")
	}
}

func TestCreateUser_HonorsExplicitChannel(t *testing.T) {
	m := newMock()
	um := newUM(m)
	if err := um.CreateUser(context.Background(), User{
		Slot: 4, Username: "x", Enabled: true, Privilege: PrivilegeUser, Channel: 0x0E,
	}, nil); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	flags := m.calls[1].data[0]
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
		{netFnApp, cmdSetUserName, 0, nil},
	}
	s := &stagedSender{stages: stages, t: t, errAfter: 1, errVal: errors.New("pwd-fail")}
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
