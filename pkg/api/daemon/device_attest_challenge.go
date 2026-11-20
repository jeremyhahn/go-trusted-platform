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
	"errors"
	"fmt"
	"log/slog"
	"strings"
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

// attestChallengeSweepInterval is how often the DeviceGRPCService sweeps
// expired, never-used challenges from the store (#2136).
const attestChallengeSweepInterval = time.Minute

// attestChallengeSweepPage is the ListObjects page size of one sweep.
const attestChallengeSweepPage = 100

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
// A challenge that is issued and never used is swept once its TTL has
// passed: sweep removes expired objects (or entries), and the
// DeviceGRPCService runs it on a ticker (StartChallengeSweeper).
type attestChallengeStore struct {
	mu      sync.Mutex
	entries map[string]attestChallenge
	ttl     time.Duration
	now     func() time.Time
	backend objectstorage.Client
	logger  *slog.Logger
	sweeper challengeSweeper
}

// challengeSweeper is the state of the ticker goroutine that sweeps the
// store; mu guards every field.
type challengeSweeper struct {
	mu      sync.Mutex
	cancel  context.CancelFunc
	ticker  *time.Ticker
	wg      sync.WaitGroup
	started int
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

func (c *attestChallengeStore) log() *slog.Logger {
	if c.logger != nil {
		return c.logger
	}
	return slog.Default()
}

// sweep removes every challenge whose TTL has passed and returns how many
// went. A challenge at exactly its expiry is kept, the rule take applies.
// With a backend it lists every page of attest-challenges/, then deletes
// the expired keys it found: an unreadable or
// undecodable record is skipped (logged), a delete another daemon won is
// not counted, and a failed delete is reported after the rest are tried.
func (c *attestChallengeStore) sweep(ctx context.Context) (int, error) {
	if c.backend == nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		now := c.now()
		removed := 0
		for k, e := range c.entries {
			if now.After(e.expiresAt) {
				delete(c.entries, k)
				removed++
			}
		}
		return removed, nil
	}

	// List every page first and delete after: a delete during the listing
	// would shift an offset cursor and skip keys.
	var expired []string
	cursor := ""
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		page, err := c.backend.ListObjects(ctx, &objectstorage.ListObjectsRequest{
			Prefix: attestChallengeKeyPrefix,
			Limit:  attestChallengeSweepPage,
			Cursor: cursor,
		})
		if err != nil {
			return 0, fmt.Errorf("list challenges: %w", err)
		}
		if page == nil {
			break
		}
		for _, obj := range page.Objects {
			if obj == nil || !strings.HasPrefix(obj.Key, attestChallengeKeyPrefix) {
				continue
			}
			got, err := c.backend.GetObject(ctx, &objectstorage.GetObjectRequest{Key: obj.Key})
			if err != nil || got == nil {
				// Gone already (used, or swept by another daemon).
				continue
			}
			var rec attestChallengeRecord
			if err := json.Unmarshal(got.Value, &rec); err != nil {
				c.log().Warn("attestation challenge record is not readable; kept", "key", obj.Key, "error", err)
				continue
			}
			if c.now().After(rec.ExpiresAt) {
				expired = append(expired, obj.Key)
			}
		}
		if !page.HasMore {
			break
		}
		cursor = page.NextCursor
	}

	removed := 0
	var errs error
	for _, key := range expired {
		if err := ctx.Err(); err != nil {
			return removed, errors.Join(errs, err)
		}
		del, err := c.backend.DeleteObject(ctx, &objectstorage.DeleteObjectRequest{Key: key})
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("delete %s: %w", key, err))
			continue
		}
		// Not Success: another daemon took or swept it first.
		if del != nil && del.Success {
			removed++
		}
	}
	return removed, errs
}

// runSweeper sweeps the store on every tick until ctx is done, handing each
// result to done when it is non-nil.
func (c *attestChallengeStore) runSweeper(ctx context.Context, ticks <-chan time.Time, done func(removed int, err error)) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			removed, err := c.sweep(ctx)
			if done != nil {
				done(removed, err)
			}
		}
	}
}

// StartChallengeSweeper sweeps expired, never-used attestation challenges
// from the store every interval (attestChallengeSweepInterval when interval
// is not positive) until StopChallengeSweeper (#2136). It is a no-op while
// a sweeper runs.
func (s *DeviceGRPCService) StartChallengeSweeper(interval time.Duration) {
	c := s.challenges
	sw := &c.sweeper
	sw.mu.Lock()
	defer sw.mu.Unlock()
	if sw.cancel != nil {
		return
	}
	if interval <= 0 {
		interval = attestChallengeSweepInterval
	}
	if c.logger == nil {
		c.logger = s.logger
	}
	logger := c.log()
	ctx, cancel := context.WithCancel(context.Background())
	ticker := time.NewTicker(interval)
	sw.cancel = cancel
	sw.ticker = ticker
	sw.started++
	sw.wg.Add(1)
	go func() {
		defer sw.wg.Done()
		c.runSweeper(ctx, ticker.C, func(removed int, err error) {
			if err != nil {
				logger.Warn("attestation challenge sweep failed", "removed", removed, "error", err)
				return
			}
			if removed > 0 {
				logger.Debug("expired attestation challenges swept", "removed", removed)
			}
		})
	}()
}

// StopChallengeSweeper stops the sweeper StartChallengeSweeper started and
// waits for it to exit. It is a no-op when none runs.
func (s *DeviceGRPCService) StopChallengeSweeper() {
	sw := &s.challenges.sweeper
	sw.mu.Lock()
	defer sw.mu.Unlock()
	if sw.cancel == nil {
		return
	}
	sw.cancel()
	sw.ticker.Stop()
	sw.wg.Wait()
	sw.cancel = nil
	sw.ticker = nil
}
