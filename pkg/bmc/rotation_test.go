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
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// fakeUM is a stand-in ManagedUserManager used by rotation tests.
// SetUserPassword records the password bytes and optionally returns
// an error. MaxUsers returns a preset value or error.
type fakeUM struct {
	mu             sync.Mutex
	creds          *Credentials // what this session was opened with
	setErr         error
	maxUsersErr    error
	capturedPasswd []byte
	capturedSlot   uint8
	setCallCount   int
	maxUsersCalls  int
	closeCalled    bool
}

func (f *fakeUM) ListUsers(context.Context) ([]User, error) { return nil, nil }
func (f *fakeUM) CreateUser(context.Context, User, *memguard.Secret) error {
	return nil
}
func (f *fakeUM) DeleteUser(context.Context, uint8) error { return nil }
func (f *fakeUM) SetUserPrivilege(context.Context, uint8, uint8, Privilege) error {
	return nil
}

func (f *fakeUM) SetUserPassword(_ context.Context, slot uint8, pw *memguard.Secret) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setCallCount++
	if f.setErr != nil {
		return f.setErr
	}
	f.capturedSlot = slot
	f.capturedPasswd = append([]byte(nil), pw.Bytes()...)
	return nil
}

func (f *fakeUM) MaxUsers(context.Context) (uint8, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.maxUsersCalls++
	if f.maxUsersErr != nil {
		return 0, f.maxUsersErr
	}
	return 10, nil
}

func (f *fakeUM) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCalled = true
	return nil
}

// stageFactory returns UserManagerFactory functions whose behaviour
// can be orchestrated by the test. Each call records the passed
// credentials and returns the next staged manager (or error).
type stageFactory struct {
	mu     sync.Mutex
	stages []stageFactoryEntry
	idx    int
	opened []*Credentials
}

type stageFactoryEntry struct {
	mgr *fakeUM
	err error
}

func (s *stageFactory) add(um *fakeUM, err error) {
	s.stages = append(s.stages, stageFactoryEntry{mgr: um, err: err})
}

func (s *stageFactory) factory() UserManagerFactory {
	return func(_ context.Context, _ *Config, creds *Credentials) (ManagedUserManager, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		// Record a snapshot of the password so later assertions can
		// inspect it even after the password may have been rotated
		// in the store.
		snap := &Credentials{
			Username: creds.Username,
			Password: memguard.New(append([]byte(nil), creds.Password.Bytes()...)),
		}
		s.opened = append(s.opened, snap)
		if s.idx >= len(s.stages) {
			return nil, errors.New("stageFactory: unexpected additional call")
		}
		e := s.stages[s.idx]
		s.idx++
		if e.err != nil {
			return nil, e.err
		}
		e.mgr.creds = snap
		return e.mgr, nil
	}
}

// --- construction ---

func TestNewRotationEngine_MissingDeps(t *testing.T) {
	_, err := NewRotationEngine(RotationOptions{})
	var want ErrInvalidRotationConfig
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want ErrInvalidRotationConfig", err)
	}
	_, err = NewRotationEngine(RotationOptions{Store: NewMemoryStore()})
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want ErrInvalidRotationConfig for missing factory", err)
	}
}

func TestNewRotationEngine_DefaultGenerator(t *testing.T) {
	e, err := NewRotationEngine(RotationOptions{
		Store:   NewMemoryStore(),
		Factory: func(context.Context, *Config, *Credentials) (ManagedUserManager, error) { return nil, nil },
	})
	if err != nil {
		t.Fatalf("NewRotationEngine: %v", err)
	}
	pwd, err := e.generate()
	if err != nil {
		t.Fatalf("default generate: %v", err)
	}
	defer pwd.Destroy()
	if pwd.Size() != DefaultPasswordLength {
		t.Errorf("size = %d, want %d", pwd.Size(), DefaultPasswordLength)
	}
}

// --- happy path ---

func TestRotateOnce_HappyPath(t *testing.T) {
	store := NewMemoryStore()
	defer store.DestroyAll()
	_ = store.Put(context.Background(), "bmc01", NewCredentials("ADMIN", []byte("old")))

	applyUM := &fakeUM{}
	verifyUM := &fakeUM{}
	sf := &stageFactory{}
	sf.add(applyUM, nil)  // apply session uses old creds
	sf.add(verifyUM, nil) // verify session uses new creds

	gen := func() (*memguard.Secret, error) {
		return memguard.New([]byte("NEW_PW")), nil
	}
	e, err := NewRotationEngine(RotationOptions{
		Store: store, Factory: sf.factory(), Generate: gen,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = e.RotateOnce(context.Background(), "bmc01", &Config{
		Address: "x", Port: 623, Protocol: ProtocolIPMI,
	}, 2)
	if err != nil {
		t.Fatalf("RotateOnce: %v", err)
	}

	// Store now has the new password.
	got, err := store.Get(context.Background(), "bmc01")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Password.Bytes()) != "NEW_PW" {
		t.Errorf("store password = %q, want NEW_PW", got.Password.Bytes())
	}

	// Apply session must have been opened with old creds.
	if string(sf.opened[0].Password.Bytes()) != "old" {
		t.Errorf("apply session password = %q, want old", sf.opened[0].Password.Bytes())
	}
	// Verify session must have been opened with new creds.
	if string(sf.opened[1].Password.Bytes()) != "NEW_PW" {
		t.Errorf("verify session password = %q, want NEW_PW", sf.opened[1].Password.Bytes())
	}
	// Apply session must have called SetUserPassword once with new pw.
	if applyUM.setCallCount != 1 {
		t.Errorf("apply SetUserPassword calls = %d", applyUM.setCallCount)
	}
	if string(applyUM.capturedPasswd) != "NEW_PW" {
		t.Errorf("captured new pw = %q", applyUM.capturedPasswd)
	}
	if applyUM.capturedSlot != 2 {
		t.Errorf("slot = %d, want 2", applyUM.capturedSlot)
	}
	// Verify session must have called MaxUsers once.
	if verifyUM.maxUsersCalls != 1 {
		t.Errorf("verify MaxUsers calls = %d", verifyUM.maxUsersCalls)
	}
	// Both sessions closed.
	if !applyUM.closeCalled || !verifyUM.closeCalled {
		t.Error("sessions not closed")
	}
}

// --- validation ---

func TestRotateOnce_EmptyName(t *testing.T) {
	e := mustEngine(t, NewMemoryStore(), okFactory(), nil)
	err := e.RotateOnce(context.Background(), "", &Config{Address: "x", Port: 1, Protocol: ProtocolIPMI}, 1)
	var want ErrInvalidCredentials
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestRotateOnce_NilConfig(t *testing.T) {
	e := mustEngine(t, NewMemoryStore(), okFactory(), nil)
	err := e.RotateOnce(context.Background(), "bmc", nil, 1)
	var want ErrNilConfig
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrNilConfig", err)
	}
}

// --- error paths ---

func TestRotateOnce_StoreMissingCreds(t *testing.T) {
	store := NewMemoryStore()
	e := mustEngine(t, store, okFactory(), nil)
	err := e.RotateOnce(context.Background(), "nope", &Config{Address: "x", Port: 1, Protocol: ProtocolIPMI}, 1)
	var want ErrCredentialsNotFound
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrCredentialsNotFound", err)
	}
}

func TestRotateOnce_GenerateFails(t *testing.T) {
	store := NewMemoryStore()
	_ = store.Put(context.Background(), "bmc", NewCredentials("u", []byte("p")))
	sentinel := errors.New("entropy down")
	e, _ := NewRotationEngine(RotationOptions{
		Store:    store,
		Factory:  okFactory(),
		Generate: func() (*memguard.Secret, error) { return nil, sentinel },
	})
	err := e.RotateOnce(context.Background(), "bmc", &Config{Address: "x", Port: 1, Protocol: ProtocolIPMI}, 1)
	var want ErrRotationGenerate
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrRotationGenerate", err)
	}
}

func TestRotateOnce_StoreAheadFails(t *testing.T) {
	store := NewMemoryStore()
	_ = store.Put(context.Background(), "bmc", NewCredentials("u", []byte("p")))
	// Wrap store so Put fails.
	failing := &failPutStore{CredentialStore: store, putErr: errors.New("disk full")}
	e := mustEngine(t, failing, okFactory(), nil)
	err := e.RotateOnce(context.Background(), "bmc", &Config{Address: "x", Port: 1, Protocol: ProtocolIPMI}, 1)
	var want ErrRotationStoreAhead
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrRotationStoreAhead", err)
	}
}

func TestRotateOnce_ApplyConnectFails(t *testing.T) {
	store := NewMemoryStore()
	defer store.DestroyAll()
	_ = store.Put(context.Background(), "bmc", NewCredentials("u", []byte("p")))
	sf := &stageFactory{}
	sf.add(nil, errors.New("dial fail")) // apply session fails to open
	sf.add(&fakeUM{}, nil)               // rollback session (opened with new creds — succeeds)
	e := mustEngine(t, store, sf.factory(), nil)
	err := e.RotateOnce(context.Background(), "bmc", &Config{Address: "x", Port: 1, Protocol: ProtocolIPMI}, 1)
	// Rollback path triggers because apply errored.
	var want ErrRotationReverted
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrRotationReverted", err)
	}
}

func TestRotateOnce_ApplySetFails(t *testing.T) {
	store := NewMemoryStore()
	defer store.DestroyAll()
	_ = store.Put(context.Background(), "bmc", NewCredentials("u", []byte("p")))
	applyUM := &fakeUM{setErr: errors.New("bmc rejected")}
	rollbackUM := &fakeUM{}
	sf := &stageFactory{}
	sf.add(applyUM, nil)
	sf.add(rollbackUM, nil)
	e := mustEngine(t, store, sf.factory(), nil)
	err := e.RotateOnce(context.Background(), "bmc", &Config{Address: "x", Port: 1, Protocol: ProtocolIPMI}, 1)
	var want ErrRotationReverted
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrRotationReverted", err)
	}
}

func TestRotateOnce_VerifyFails_RollbackSucceeds(t *testing.T) {
	store := NewMemoryStore()
	defer store.DestroyAll()
	_ = store.Put(context.Background(), "bmc", NewCredentials("u", []byte("oldpw")))
	applyUM := &fakeUM{}
	verifyUM := &fakeUM{maxUsersErr: errors.New("auth denied with new pw")}
	rollbackUM := &fakeUM{}
	sf := &stageFactory{}
	sf.add(applyUM, nil)
	sf.add(verifyUM, nil)
	sf.add(rollbackUM, nil)
	e := mustEngine(t, store, sf.factory(), nil)
	err := e.RotateOnce(context.Background(), "bmc", &Config{Address: "x", Port: 1, Protocol: ProtocolIPMI}, 1)
	var want ErrRotationReverted
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrRotationReverted", err)
	}
	// Rollback session must have issued SetUserPassword with oldpw.
	if string(rollbackUM.capturedPasswd) != "oldpw" {
		t.Errorf("rollback set-pw = %q, want oldpw", rollbackUM.capturedPasswd)
	}
	// Store must reflect old password again.
	got, _ := store.Get(context.Background(), "bmc")
	if string(got.Password.Bytes()) != "oldpw" {
		t.Errorf("store after rollback = %q, want oldpw", got.Password.Bytes())
	}
}

func TestRotateOnce_VerifyFails_RollbackConnectFails(t *testing.T) {
	store := NewMemoryStore()
	defer store.DestroyAll()
	_ = store.Put(context.Background(), "bmc", NewCredentials("u", []byte("oldpw")))
	sf := &stageFactory{}
	sf.add(&fakeUM{}, nil)                                 // apply ok
	sf.add(&fakeUM{maxUsersErr: errors.New("authz")}, nil) // verify fails
	sf.add(nil, errors.New("dial fail"))                   // rollback connect fails
	e := mustEngine(t, store, sf.factory(), nil)
	err := e.RotateOnce(context.Background(), "bmc", &Config{Address: "x", Port: 1, Protocol: ProtocolIPMI}, 1)
	var want ErrRotationCatastrophic
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrRotationCatastrophic", err)
	}
	// Store should still hold new password (not rolled back).
	got, _ := store.Get(context.Background(), "bmc")
	if string(got.Password.Bytes()) == "oldpw" {
		t.Error("store wrongly rolled back to oldpw in catastrophic path")
	}
}

func TestRotateOnce_VerifyFails_RollbackSetFails(t *testing.T) {
	store := NewMemoryStore()
	defer store.DestroyAll()
	_ = store.Put(context.Background(), "bmc", NewCredentials("u", []byte("oldpw")))
	rollbackUM := &fakeUM{setErr: errors.New("bmc locked")}
	sf := &stageFactory{}
	sf.add(&fakeUM{}, nil)
	sf.add(&fakeUM{maxUsersErr: errors.New("x")}, nil)
	sf.add(rollbackUM, nil)
	e := mustEngine(t, store, sf.factory(), nil)
	err := e.RotateOnce(context.Background(), "bmc", &Config{Address: "x", Port: 1, Protocol: ProtocolIPMI}, 1)
	var want ErrRotationCatastrophic
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrRotationCatastrophic", err)
	}
}

func TestRotateOnce_RollbackStoreWriteFails(t *testing.T) {
	store := NewMemoryStore()
	_ = store.Put(context.Background(), "bmc", NewCredentials("u", []byte("oldpw")))
	// Wrap with a store that fails Put on the SECOND call (the
	// store-rollback write), but succeeds on the first (store-ahead).
	failing := &eventualFailStore{CredentialStore: store, failAfter: 1, putErr: errors.New("disk")}
	sf := &stageFactory{}
	sf.add(&fakeUM{}, nil)
	sf.add(&fakeUM{maxUsersErr: errors.New("x")}, nil)
	sf.add(&fakeUM{}, nil) // rollback OK
	e := mustEngine(t, failing, sf.factory(), nil)
	err := e.RotateOnce(context.Background(), "bmc", &Config{Address: "x", Port: 1, Protocol: ProtocolIPMI}, 1)
	var want ErrRotationStoreRollback
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrRotationStoreRollback", err)
	}
}

// --- GenerateRandomPassword ---

func TestGenerateRandomPassword(t *testing.T) {
	p, err := GenerateRandomPassword(16)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	defer p.Destroy()
	if p.Size() != 16 {
		t.Errorf("size = %d, want 16", p.Size())
	}
	// All chars in alphabet.
	for _, b := range p.Bytes() {
		if !inAlphabet(b) {
			t.Errorf("char %c not in alphabet", b)
		}
	}
}

func TestGenerateRandomPassword_ClampsAbove20(t *testing.T) {
	p, err := GenerateRandomPassword(30)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	defer p.Destroy()
	if p.Size() != 20 {
		t.Errorf("size = %d, want 20 (clamped)", p.Size())
	}
}

func TestGenerateRandomPassword_Invalid(t *testing.T) {
	cases := []int{0, -1, -100}
	for _, n := range cases {
		if _, err := GenerateRandomPassword(n); err == nil {
			t.Errorf("GenerateRandomPassword(%d) = nil error", n)
		}
	}
}

func TestGenerateRandomPassword_DifferentEachTime(t *testing.T) {
	a, _ := GenerateRandomPassword(20)
	defer a.Destroy()
	b, _ := GenerateRandomPassword(20)
	defer b.Destroy()
	if a.EqualBytes(b.Bytes()) {
		t.Error("two generations returned identical bytes (extremely unlikely)")
	}
}

// --- helpers ---

func inAlphabet(b byte) bool {
	for _, c := range passwordAlphabet {
		if byte(c) == b {
			return true
		}
	}
	return false
}

func okFactory() UserManagerFactory {
	return func(context.Context, *Config, *Credentials) (ManagedUserManager, error) {
		return &fakeUM{}, nil
	}
}

func mustEngine(t *testing.T, s CredentialStore, f UserManagerFactory, gen PasswordGenerator) *RotationEngine {
	t.Helper()
	if gen == nil {
		gen = func() (*memguard.Secret, error) { return memguard.New([]byte("new")), nil }
	}
	e, err := NewRotationEngine(RotationOptions{Store: s, Factory: f, Generate: gen})
	if err != nil {
		t.Fatalf("NewRotationEngine: %v", err)
	}
	return e
}

// failPutStore fails all Put calls with putErr.
type failPutStore struct {
	CredentialStore
	putErr error
}

func (s *failPutStore) Put(ctx context.Context, name string, c *Credentials) error {
	if s.putErr != nil {
		return s.putErr
	}
	return s.CredentialStore.Put(ctx, name, c)
}

// eventualFailStore fails Put calls after failAfter successful ones.
type eventualFailStore struct {
	CredentialStore
	failAfter int
	putErr    error
	count     int
	mu        sync.Mutex
}

func (s *eventualFailStore) Put(ctx context.Context, name string, c *Credentials) error {
	s.mu.Lock()
	s.count++
	n := s.count
	s.mu.Unlock()
	if n > s.failAfter {
		return s.putErr
	}
	return s.CredentialStore.Put(ctx, name, c)
}

// TestErrRotationMessages covers error stringification + Unwrap.
func TestErrRotationMessages(t *testing.T) {
	cases := []error{
		ErrInvalidRotationConfig{Field: "f", Reason: "r"},
		ErrRotationGenerate{Cause: errors.New("g")},
		ErrRotationStoreAhead{Cause: errors.New("s")},
		ErrRotationConnect{Phase: "apply", Cause: errors.New("c")},
		ErrRotationApply{Cause: errors.New("a")},
		ErrRotationVerify{Cause: errors.New("v")},
		ErrRotationReverted{Cause: errors.New("r")},
		ErrRotationStoreRollback{Cause: errors.New("sr")},
		ErrRotationCatastrophic{Name: "n", ApplyErr: errors.New("a"), RollbackE: errors.New("r")},
	}
	for _, e := range cases {
		if e.Error() == "" {
			t.Errorf("empty error from %T", e)
		}
	}
	// Unwrap chains.
	inner := errors.New("inner")
	for _, e := range []error{
		ErrRotationGenerate{Cause: inner},
		ErrRotationStoreAhead{Cause: inner},
		ErrRotationConnect{Cause: inner},
		ErrRotationApply{Cause: inner},
		ErrRotationVerify{Cause: inner},
		ErrRotationReverted{Cause: inner},
		ErrRotationStoreRollback{Cause: inner},
	} {
		if !errors.Is(e, inner) {
			t.Errorf("%T does not unwrap to inner", e)
		}
	}
}
