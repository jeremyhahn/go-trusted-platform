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

// Package store persists attestation manifests and per-enrollment
// events so the WebUI's /attestation/manifests, /attestation/verify,
// and /attestation/eventlogs pages have real data to render.
//
// Phase 3 first-ship uses a single-node file-backed store under
// <PlatformDir>/attestation/{manifests,events}/<id>.json. A
// QuicBaaS-replicated implementation can land later by satisfying
// the Store interface; the AttestationService consumes the
// interface directly.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
)

// EventKind classifies an enrollment-time attestation observation.
// The WebUI's /attestation/eventlogs page filters by kind to separate
// successful captures from failures + tampering signals.
type EventKind string

const (
	EventKindEnrollSuccess    EventKind = "enroll_success"
	EventKindEnrollFailure    EventKind = "enroll_failure"
	EventKindManifestCaptured EventKind = "manifest_captured"
	EventKindManifestVerified EventKind = "manifest_verified"
	EventKindManifestRejected EventKind = "manifest_rejected"
	EventKindManifestDeleted  EventKind = "manifest_deleted"
	// EventKindDeviceQuoteVerified records a device quote that passed every
	// check: attestation certificate, signature, nonce and PCR baseline.
	EventKindDeviceQuoteVerified EventKind = "device_quote_verified"
	// EventKindDeviceQuoteRejected records a device quote that failed. The
	// event's Metadata["cryptographic"] says whether the failure was a
	// cryptographic one (bad signature, wrong nonce, PCR mismatch, untrusted
	// certificate) or an absence of evidence (no certificate, no profile),
	// which is denied service but never quarantined.
	EventKindDeviceQuoteRejected EventKind = "device_quote_rejected"
	// EventKindPCRBaselineCaptured records a trust-on-first-use PCR baseline
	// being written to a device profile. It is a security event: every
	// device that later attests against that profile is measured against
	// the values captured here.
	EventKindPCRBaselineCaptured EventKind = "pcr_baseline_captured"

	// EventKindDeviceAttestCertRecorded records an operator recording (or
	// re-recording) a device's attestation certificate on its platform
	// record without re-enrolling the device. It is a security event: the
	// recorded certificate is the trust anchor every later quote from that
	// device is verified against. Metadata carries the source the
	// certificate came from ("device", "ca", "reissued") and whether the
	// CA was asked to re-issue it.
	EventKindDeviceAttestCertRecorded EventKind = "device_attest_cert_recorded"

	// EventKindDeviceAttestCertRefused records a record attempt that the
	// fail-closed preflight refused — the candidate did not parse, did not
	// chain to the platform CA, lacked tcg-cap-verifiedTPMRestricted or
	// certified a key other than the device's enrolled attestation key.
	// Nothing on the device record changed. Reason carries the detail.
	EventKindDeviceAttestCertRefused EventKind = "device_attest_cert_refused"

	// EventKindCallerAdmitted records a machine peer admitted to a
	// quote-producing endpoint by the node's caller-admission policy
	// (#226). Metadata carries the strategy, the peer identity and the
	// transport address.
	EventKindCallerAdmitted EventKind = "caller_admitted"

	// EventKindCallerRefused records a machine peer refused by the policy.
	// Reason distinguishes "not on the list" (a configuration matter) from
	// "measured state unacceptable" (a security event); the two must never
	// be conflated in audit.
	EventKindCallerRefused EventKind = "caller_refused"
)

// Event records a single attestation observation. Events are
// append-only — they never get rewritten — so the timeline matches
// what actually happened during enrollment and verification.
type Event struct {
	ID         string            `json:"id"`
	Kind       EventKind         `json:"kind"`
	HostID     string            `json:"host_id,omitempty"`
	ManifestID string            `json:"manifest_id,omitempty"`
	CN         string            `json:"cn,omitempty"`
	ClientIP   string            `json:"client_ip,omitempty"`
	Timestamp  time.Time         `json:"timestamp"`
	Outcome    string            `json:"outcome,omitempty"`
	Reason     string            `json:"reason,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// Store is the persistence surface the AttestationService consumes.
// Implementations must be safe for concurrent use.
type Store interface {
	// PutManifest persists or updates a manifest. The manifest's ID
	// field is used as the storage key; callers MUST populate it.
	PutManifest(m *manifest.HostManifest) error

	// GetManifest loads a manifest by ID. Returns ErrManifestNotFound
	// when the manifest is unknown.
	GetManifest(id string) (*manifest.HostManifest, error)

	// ListManifests returns all manifests, optionally filtered by
	// host ID + time range. Limit<=0 returns all matches.
	ListManifests(filter ListFilter) ([]*manifest.HostManifest, error)

	// DeleteManifest removes a manifest by ID.
	DeleteManifest(id string) error

	// PutEvent appends an event to the event log.
	PutEvent(e *Event) error

	// ListEvents returns events newest-first, optionally filtered by
	// host + kind + time range. Limit<=0 returns all matches.
	ListEvents(filter EventFilter) ([]*Event, error)
}

// ListFilter narrows a ListManifests query.
type ListFilter struct {
	HostID string
	Since  time.Time
	Until  time.Time
	Limit  int
}

// EventFilter narrows a ListEvents query.
type EventFilter struct {
	HostID     string
	ManifestID string
	Kind       EventKind
	Since      time.Time
	Until      time.Time
	Limit      int
}

// FileStore is the default file-backed Store implementation.
type FileStore struct {
	root      string
	manifests string
	events    string
	mu        sync.Mutex
}

// NewFileStore prepares the manifest + event directories under root
// and returns a ready store.
func NewFileStore(root string) (*FileStore, error) {
	if root == "" {
		return nil, errInvalidStoreConfig{Field: "root", Reason: "cannot be empty"}
	}
	manifests := filepath.Join(root, "manifests")
	events := filepath.Join(root, "events")
	for _, d := range []string{manifests, events} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, &WrappedError{Msg: fmt.Sprintf("attestation/store: mkdir %s", d), Err: err}
		}
	}
	return &FileStore{root: root, manifests: manifests, events: events}, nil
}

func (s *FileStore) manifestPath(id string) string {
	return filepath.Join(s.manifests, id+".json")
}

func (s *FileStore) eventPath(id string) string {
	return filepath.Join(s.events, id+".json")
}

// PutManifest writes the manifest atomically (temp file + rename).
func (s *FileStore) PutManifest(m *manifest.HostManifest) error {
	if m == nil {
		return errInvalidStoreConfig{Field: "manifest", Reason: "nil"}
	}
	if m.ID == "" {
		return errInvalidStoreConfig{Field: "manifest.id", Reason: "empty"}
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	path := s.manifestPath(m.ID)
	tmp := path + ".tmp"
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// GetManifest loads a manifest by ID.
func (s *FileStore) GetManifest(id string) (*manifest.HostManifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.manifestPath(id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrManifestNotFound{ID: id}
		}
		return nil, err
	}
	var m manifest.HostManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, &WrappedError{Msg: fmt.Sprintf("attestation/store: decode manifest %s", id), Err: err}
	}
	return &m, nil
}

// ListManifests walks the manifest directory and decodes every entry.
// At the volumes Phase 3 ships at this is fine; if the store grows to
// millions of manifests, a B-tree index lands alongside.
func (s *FileStore) ListManifests(filter ListFilter) ([]*manifest.HostManifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.manifests)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]*manifest.HostManifest, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.manifests, e.Name()))
		if err != nil {
			continue
		}
		var m manifest.HostManifest
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		if !matchesManifest(filter, &m) {
			continue
		}
		out = append(out, &m)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Timestamp.After(out[j].Timestamp)
	})
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
}

// DeleteManifest removes a manifest.
func (s *FileStore) DeleteManifest(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.manifestPath(id)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrManifestNotFound{ID: id}
		}
		return err
	}
	return nil
}

// PutEvent persists an event. If e.ID is empty a new ID is assigned.
func (s *FileStore) PutEvent(e *Event) error {
	if e == nil {
		return errInvalidStoreConfig{Field: "event", Reason: "nil"}
	}
	if e.ID == "" {
		id, err := newEventID()
		if err != nil {
			return err
		}
		e.ID = id
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	body, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	path := s.eventPath(e.ID)
	tmp := path + ".tmp"
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ListEvents walks the event directory and returns matching events
// newest-first.
func (s *FileStore) ListEvents(filter EventFilter) ([]*Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.events)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]*Event, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.events, e.Name()))
		if err != nil {
			continue
		}
		var ev Event
		if err := json.Unmarshal(data, &ev); err != nil {
			continue
		}
		if !matchesEvent(filter, &ev) {
			continue
		}
		out = append(out, &ev)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Timestamp.After(out[j].Timestamp)
	})
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
}

func matchesManifest(f ListFilter, m *manifest.HostManifest) bool {
	if f.HostID != "" && f.HostID != m.HostID {
		return false
	}
	if !f.Since.IsZero() && m.Timestamp.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && m.Timestamp.After(f.Until) {
		return false
	}
	return true
}

func matchesEvent(f EventFilter, e *Event) bool {
	if f.HostID != "" && f.HostID != e.HostID {
		return false
	}
	if f.ManifestID != "" && f.ManifestID != e.ManifestID {
		return false
	}
	if f.Kind != "" && f.Kind != e.Kind {
		return false
	}
	if !f.Since.IsZero() && e.Timestamp.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && e.Timestamp.After(f.Until) {
		return false
	}
	return true
}

func newEventID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(b), nil
}

// ErrManifestNotFound is returned by GetManifest / DeleteManifest
// when the supplied ID has no corresponding row.
type ErrManifestNotFound struct {
	ID string
}

func (e ErrManifestNotFound) Error() string {
	return "attestation/store: manifest not found: " + e.ID
}

// errInvalidStoreConfig is the validation error type for construction
// and put-time argument checks.
type errInvalidStoreConfig struct {
	Field  string
	Reason string
}

func (e errInvalidStoreConfig) Error() string {
	return fmt.Sprintf("attestation/store: invalid %s: %s", e.Field, e.Reason)
}
