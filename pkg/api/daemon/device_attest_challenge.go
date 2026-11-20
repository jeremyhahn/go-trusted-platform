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

package daemon

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// attestChallengeTTL is how long an issued attestation challenge stays
// usable (#2136).
const attestChallengeTTL = 5 * time.Minute

const (
	attestChallengeNonceBytes = 32
	attestChallengeIDBytes    = 16
)

// attestChallenge is one issued, not yet used challenge.
type attestChallenge struct {
	deviceID    string
	tenant      string
	tenantBound bool
	nonce       []byte
	expiresAt   time.Time
}

// attestChallengeKeyPrefix is the object-storage key prefix of issued,
// not yet used attestation challenges.
const attestChallengeKeyPrefix = "attest-challenges/"

// attestChallengeKey is the object-storage key of challenge id.
func attestChallengeKey(id string) string {
	return attestChallengeKeyPrefix + id + ".json"
}

// attestChallengeRecord is the JSON form of an attestChallenge in object
// storage.
type attestChallengeRecord struct {
	DeviceID    string    `json:"device_id"`
	Tenant      string    `json:"tenant"`
	TenantBound bool      `json:"tenant_bound"`
	Nonce       []byte    `json:"nonce"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// attestChallengeStore holds the server-issued single-use nonces AttestDevice
// binds a quote to (#2136). With a backend (the daemon's shared object
// store) every challenge is an object under attest-challenges/, so it
// survives a restart and is honoured by any daemon sharing the store;
// single use across daemons rests on DeleteObject refusing a key that is
// already gone. Without a backend it is in-memory and per process: a
// challenge issued by one daemon is unknown to another, and a restart
// forgets every outstanding challenge (the device asks for a new one).
type attestChallengeStore struct {
	mu      sync.Mutex
	entries map[string]attestChallenge
	ttl     time.Duration
	now     func() time.Time
	backend objectstorage.Client
}

func newAttestChallengeStore() *attestChallengeStore {
	return &attestChallengeStore{
		entries: make(map[string]attestChallenge),
		ttl:     attestChallengeTTL,
		now:     time.Now,
	}
}

// issue records a fresh challenge for deviceID under the caller's tenant and
// returns its ID and entry. Expired entries are dropped first.
func (c *attestChallengeStore) issue(ctx context.Context, deviceID, tenant string, tenantBound bool) (string, attestChallenge, error) {
	nonce := make([]byte, attestChallengeNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return "", attestChallenge{}, fmt.Errorf("draw challenge nonce: %w", err)
	}
	rawID := make([]byte, attestChallengeIDBytes)
	if _, err := rand.Read(rawID); err != nil {
		return "", attestChallenge{}, fmt.Errorf("draw challenge id: %w", err)
	}
	id := hex.EncodeToString(rawID)

	if c.backend != nil {
		entry := attestChallenge{
			deviceID:    deviceID,
			tenant:      tenant,
			tenantBound: tenantBound,
			nonce:       nonce,
			expiresAt:   c.now().Add(c.ttl),
		}
		raw, err := json.Marshal(attestChallengeRecord{
			DeviceID:    entry.deviceID,
			Tenant:      entry.tenant,
			TenantBound: entry.tenantBound,
			Nonce:       entry.nonce,
			ExpiresAt:   entry.expiresAt,
		})
		if err != nil {
			return "", attestChallenge{}, fmt.Errorf("encode challenge: %w", err)
		}
		if _, err := c.backend.PutObject(ctx, &objectstorage.PutObjectRequest{
			Key:         attestChallengeKey(id),
			Value:       raw,
			ContentType: "application/json",
		}); err != nil {
			return "", attestChallenge{}, fmt.Errorf("store challenge: %w", err)
		}
		return id, entry, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
	entry := attestChallenge{
		deviceID:    deviceID,
		tenant:      tenant,
		tenantBound: tenantBound,
		nonce:       nonce,
		expiresAt:   now.Add(c.ttl),
	}
	c.entries[id] = entry
	return id, entry, nil
}

// take removes the challenge and returns it: a challenge is consumed by the
// first attempt that names it, whatever that attempt's result.
func (c *attestChallengeStore) take(ctx context.Context, id string) (attestChallenge, bool) {
	if c.backend != nil {
		key := attestChallengeKey(id)
		got, err := c.backend.GetObject(ctx, &objectstorage.GetObjectRequest{Key: key})
		if err != nil || got == nil {
			return attestChallenge{}, false
		}
		// The delete is the claim: a daemon that loses the race finds the
		// key gone and must not honour the challenge.
		del, err := c.backend.DeleteObject(ctx, &objectstorage.DeleteObjectRequest{Key: key})
		if err != nil || del == nil || !del.Success {
			return attestChallenge{}, false
		}
		var rec attestChallengeRecord
		if err := json.Unmarshal(got.Value, &rec); err != nil {
			return attestChallenge{}, false
		}
		return attestChallenge{
			deviceID:    rec.DeviceID,
			tenant:      rec.Tenant,
			tenantBound: rec.TenantBound,
			nonce:       rec.Nonce,
			expiresAt:   rec.ExpiresAt,
		}, true
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	if ok {
		delete(c.entries, id)
	}
	return e, ok
}

// WithDeviceAttestChallengeRequired makes AttestDevice refuse a request that
// names no challenge_id (#2136). Without it a request without a challenge is
// verified as before, against the nonce the caller chose.
func WithDeviceAttestChallengeRequired() DeviceGRPCOption {
	return func(s *DeviceGRPCService) { s.challengeRequired = true }
}

// WithDeviceAttestChallengeStorage keeps issued attestation challenges in
// the shared object store, so they survive a restart and any daemon over
// the same store honours them once (#2136). A nil client keeps the
// per-process in-memory store.
func WithDeviceAttestChallengeStorage(storage objectstorage.Client) DeviceGRPCOption {
	return func(s *DeviceGRPCService) {
		if storage != nil {
			s.challenges.backend = storage
		}
	}
}

// IssueAttestationChallenge issues a single-use nonce for device_id, bound to
// the caller's tenant, that AttestDevice checks the quote against (#2136).
func (s *DeviceGRPCService) IssueAttestationChallenge(
	ctx context.Context,
	req *platformv1.IssueAttestationChallengeRequest,
) (*platformv1.IssueAttestationChallengeResponse, error) {
	if req.GetDeviceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "device_id is required")
	}
	tenant, bound := callerTenant(ctx)
	id, entry, err := s.challenges.issue(ctx, req.GetDeviceId(), tenant, bound)
	if err != nil {
		s.logger.Error("attestation challenge could not be issued", "device_id", req.GetDeviceId(), "error", err)
		return nil, status.Error(codes.Internal, "attestation challenge could not be issued")
	}
	return &platformv1.IssueAttestationChallengeResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "attestation challenge issued",
		},
		ChallengeId: id,
		Nonce:       entry.nonce,
		ExpiresAt:   timestamppb.New(entry.expiresAt),
	}, nil
}

// checkAttestChallenge enforces the challenge named by req before the quote
// is verified. With no challenge_id it refuses only when the service requires
// a challenge. A named challenge is consumed here, then must be live, for
// this device, for the caller's tenant, and carry the nonce the evidence
// presents; the verifier then proves the quote was made over that nonce.
func (s *DeviceGRPCService) checkAttestChallenge(ctx context.Context, req *platformv1.AttestDeviceRequest) error {
	id := req.GetChallengeId()
	if id == "" {
		if s.challengeRequired {
			return status.Error(codes.InvalidArgument, "challenge_id is required")
		}
		return nil
	}
	entry, ok := s.challenges.take(ctx, id)
	if !ok {
		return status.Error(codes.FailedPrecondition, "attestation challenge is unknown or already used")
	}
	if s.challenges.now().After(entry.expiresAt) {
		return status.Error(codes.FailedPrecondition, "attestation challenge has expired")
	}
	if entry.deviceID != req.GetDeviceId() {
		return status.Error(codes.FailedPrecondition, "attestation challenge was issued for another device")
	}
	tenant, bound := callerTenant(ctx)
	if tenant != entry.tenant || bound != entry.tenantBound {
		return status.Error(codes.PermissionDenied, "attestation challenge was issued to another tenant")
	}
	var evidence DeviceQuoteEvidence
	if err := json.Unmarshal(req.GetEvidence(), &evidence); err != nil {
		return status.Error(codes.InvalidArgument, "evidence is not valid quote evidence")
	}
	if subtle.ConstantTimeCompare(evidence.Nonce, entry.nonce) != 1 {
		return status.Error(codes.FailedPrecondition, "evidence nonce does not match the challenge")
	}
	return nil
}
