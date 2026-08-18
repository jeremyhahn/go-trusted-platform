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
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// CredentialPrefix is the canonical path prefix for BMC credentials
// in the platform secret store. Callers that need to list or scope
// operations across all BMC creds can glob on this prefix.
const CredentialPrefix = "bmc/"

// Credentials holds a BMC username + password pair.
//
// Password is held in locked memory via memguard.MemoryEnclave. The zero value
// is not usable; construct via NewCredentials or load via a CredentialStore.
// Callers must call Destroy when finished to release the password.
type Credentials struct {
	Username string
	Password *memguard.MemoryEnclave
}

// CredentialVersion represents a point-in-time snapshot of credentials.
// Credential data is NOT included in history listings for security.
// Use Get to retrieve the current version.
type CredentialVersion struct {
	Version   uint64
	CreatedAt time.Time
}

// NewCredentials wraps the given username and password into a Credentials
// value. The password bytes are copied into locked memory and zeroed
// from the caller's slice. If password is nil, an empty locked buffer
// is used (callers who want "no password" can pass nil).
func NewCredentials(username string, password []byte) *Credentials {
	return &Credentials{
		Username: username,
		Password: memguard.NewMemoryEnclave(password),
	}
}

// NewCredentialsFromStrings is a convenience for callers that already
// have the password as a string (config files, CLI flags). The string
// is copied into locked memory but the original cannot be wiped.
func NewCredentialsFromStrings(username, password string) *Credentials {
	return &Credentials{
		Username: username,
		Password: memguard.NewMemoryEnclaveFromString(password),
	}
}

// Destroy releases the Credentials' password material. Safe to call
// multiple times and on a nil receiver.
func (c *Credentials) Destroy() {
	if c == nil {
		return
	}
	c.Password.Destroy()
}

// IsAlive reports whether the credentials still hold unreleased
// password material.
func (c *Credentials) IsAlive() bool {
	if c == nil {
		return false
	}
	return c.Password.IsAlive()
}

// Clone returns an independent copy of c whose password lives in a
// fresh locked buffer. The returned value has its own lifecycle;
// destroying the clone has no effect on the source.
func (c *Credentials) Clone() *Credentials {
	if c == nil || !c.IsAlive() {
		return nil
	}
	pwBytes := append([]byte(nil), c.Password.Bytes()...)
	return &Credentials{
		Username: c.Username,
		Password: memguard.NewMemoryEnclave(pwBytes),
	}
}

// CredentialStore persists BMC credentials keyed by an opaque name
// (typically the BMC address or hostname). Implementations encrypt at
// rest and ensure credentials traverse process memory only inside
// memguard.MemoryEnclave buffers.
type CredentialStore interface {
	// Get fetches credentials for the given name. The returned
	// Credentials is a fresh copy owned by the caller; destroying
	// it has no effect on the store. Returns ErrCredentialsNotFound
	// if no entry exists.
	Get(ctx context.Context, name string) (*Credentials, error)

	// Put stores credentials for the given name. If the credential
	// already exists, a new version is created (rotation) rather than
	// overwriting the previous value. The store takes ownership of
	// creds.Password; after a successful Put, callers must not
	// reference creds again unless they have explicitly retained
	// another handle via Clone.
	Put(ctx context.Context, name string, creds *Credentials) error

	// Delete soft-deletes the current version of credentials for the
	// given name. Previous versions are preserved for audit history.
	// Returns nil if the entry does not exist (idempotent).
	Delete(ctx context.Context, name string) error

	// List returns the names of all BMC credential entries stored.
	List(ctx context.Context) ([]string, error)

	// History returns ordered credential versions (newest first) for
	// audit. Returns empty slice if the credential has no history.
	History(ctx context.Context, name string) ([]CredentialVersion, error)
}

// CredentialPath composes the canonical secret-store path for a given
// BMC name: "bmc/<name>". Callers building custom paths should use
// this helper so the scheme stays consistent across the codebase.
func CredentialPath(name string) string {
	return CredentialPrefix + name
}

// NameFromCredentialPath is the inverse of CredentialPath. Returns
// empty string if the path is not a BMC credential path.
func NameFromCredentialPath(path string) string {
	if !strings.HasPrefix(path, CredentialPrefix) {
		return ""
	}
	return path[len(CredentialPrefix):]
}

// credentialRecord is the on-the-wire representation of a Credentials
// value. Stored inside a secret store as a JSON blob. The password is
// a plaintext string here only for the marshaled byte slice's brief
// lifetime; the marshaled bytes are zeroed after the store write.
type credentialRecord struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// MarshalCredentials serializes creds into a byte slice suitable for
// storage. The returned slice must be zeroed by the caller after the
// store write completes — it contains plaintext password bytes.
func MarshalCredentials(creds *Credentials) ([]byte, error) {
	if creds == nil {
		return nil, ErrInvalidCredentials{Reason: "nil credentials"}
	}
	var out []byte
	err := creds.Password.Open(func(pw []byte) error {
		rec := credentialRecord{Username: creds.Username, Password: string(pw)}
		// #nosec G117 -- the secret in the marshaled struct is the point.
		// This is the serialization format written into the secret store,
		// not a log line or an API response; the store is what protects it.
		// The caller zeroes the returned bytes after the write, as the doc
		// comment above requires.
		b, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		out = b
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UnmarshalCredentials parses stored bytes back into a Credentials
// value with the password restored to locked memory. The input slice
// b is zeroed before return regardless of outcome.
func UnmarshalCredentials(b []byte) (*Credentials, error) {
	defer zero(b)
	var rec credentialRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, ErrInvalidCredentials{Reason: err.Error()}
	}
	pwBytes := []byte(rec.Password)
	creds := &Credentials{
		Username: rec.Username,
		Password: memguard.NewMemoryEnclave(pwBytes),
	}
	// Scrub the intermediate string backing via the []byte view.
	// Go strings are immutable so we can only zero the copy we owned
	// via []byte(rec.Password); that slice already became part of the
	// memguard.MemoryEnclave and was wiped as "source" by memguard.New.
	return creds, nil
}

// MemoryStore is an in-memory CredentialStore backed by a sync.RWMutex
// map. Suitable for unit tests and single-process, non-persistent
// deployments. The stored Credentials keep their passwords in locked
// memory for their lifetime in the store.
type MemoryStore struct {
	mu   sync.RWMutex
	data map[string]*Credentials
}

// Compile-time interface check.
var _ CredentialStore = (*MemoryStore)(nil)

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{data: map[string]*Credentials{}}
}

// Get returns a clone of the credentials stored under name. The
// returned value is caller-owned — destroying it does not affect the
// store.
func (s *MemoryStore) Get(_ context.Context, name string) (*Credentials, error) {
	if name == "" {
		return nil, ErrInvalidCredentials{Reason: "empty name"}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.data[name]
	if !ok || !c.IsAlive() {
		return nil, ErrCredentialsNotFound{Name: name}
	}
	return c.Clone(), nil
}

// Put stores or replaces the credentials for name. Any previously
// stored credentials are destroyed on replace.
func (s *MemoryStore) Put(_ context.Context, name string, creds *Credentials) error {
	if name == "" {
		return ErrInvalidCredentials{Reason: "empty name"}
	}
	if creds == nil || !creds.IsAlive() {
		return ErrInvalidCredentials{Reason: "credentials are nil or destroyed"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.data[name]; ok {
		existing.Destroy()
	}
	s.data[name] = creds
	return nil
}

// Delete removes the credentials for name. No-op if the entry does
// not exist. The removed credentials are destroyed.
func (s *MemoryStore) Delete(_ context.Context, name string) error {
	if name == "" {
		return ErrInvalidCredentials{Reason: "empty name"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.data[name]; ok {
		existing.Destroy()
		delete(s.data, name)
	}
	return nil
}

// List returns the names currently stored, in unspecified order.
func (s *MemoryStore) List(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.data))
	for k := range s.data {
		out = append(out, k)
	}
	return out, nil
}

// History returns an empty slice for the in-memory store. MemoryStore
// does not track version history.
func (s *MemoryStore) History(_ context.Context, name string) ([]CredentialVersion, error) {
	if name == "" {
		return nil, ErrInvalidCredentials{Reason: "empty name"}
	}
	return []CredentialVersion{}, nil
}

// DestroyAll releases all stored credentials. Primarily for test
// cleanup and process shutdown.
func (s *MemoryStore) DestroyAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.data {
		c.Destroy()
	}
	s.data = map[string]*Credentials{}
}

// validateName enforces a minimal naming scheme for BMC credential
// keys: non-empty, no whitespace, no slashes (paths are composed via
// CredentialPath so slashes would confuse the store).
func validateName(name string) error {
	if name == "" {
		return ErrInvalidCredentials{Reason: "empty name"}
	}
	if strings.ContainsAny(name, " \t\n\r") {
		return ErrInvalidCredentials{Reason: fmt.Sprintf("whitespace in name %q", name)}
	}
	if strings.Contains(name, "/") {
		return ErrInvalidCredentials{Reason: fmt.Sprintf("slash in name %q (paths are composed via CredentialPath)", name)}
	}
	return nil
}
