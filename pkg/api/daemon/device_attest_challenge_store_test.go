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
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// challengeObjectStore is an in-memory object store shared by several
// DeviceGRPCService instances, standing in for config.App.Storage.
type challengeObjectStore struct {
	objectstorage.Client
	mu      sync.Mutex
	objects map[string][]byte
	putErr  error
	delErr  error
}

func newChallengeObjectStore() *challengeObjectStore {
	return &challengeObjectStore{objects: map[string][]byte{}}
}

func (s *challengeObjectStore) PutObject(_ context.Context, req *objectstorage.PutObjectRequest) (*objectstorage.PutObjectResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.putErr != nil {
		return nil, s.putErr
	}
	s.objects[req.Key] = append([]byte(nil), req.Value...)
	return &objectstorage.PutObjectResponse{}, nil
}

func (s *challengeObjectStore) GetObject(_ context.Context, req *objectstorage.GetObjectRequest) (*objectstorage.GetObjectResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.objects[req.Key]
	if !ok {
		return nil, errors.New("object not found")
	}
	return &objectstorage.GetObjectResponse{Key: req.Key, Value: append([]byte(nil), v...)}, nil
}

func (s *challengeObjectStore) DeleteObject(_ context.Context, req *objectstorage.DeleteObjectRequest) (*objectstorage.DeleteObjectResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.delErr != nil {
		return nil, s.delErr
	}
	if _, ok := s.objects[req.Key]; !ok {
		return nil, errors.New("object not found")
	}
	delete(s.objects, req.Key)
	return &objectstorage.DeleteObjectResponse{Key: req.Key, Success: true}, nil
}

func (s *challengeObjectStore) keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.objects))
	for k := range s.objects {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestDeviceAttestChallengeStore_SharedObjectStorage(t *testing.T) {
	attest := func(ctx context.Context, f *quoteFixture, svc *DeviceGRPCService, ch *platformv1.IssueAttestationChallengeResponse) (*platformv1.AttestDeviceResponse, error) {
		return svc.AttestDevice(ctx, &platformv1.AttestDeviceRequest{
			DeviceId:    itoa(f.device.ID),
			Evidence:    f.evidence(t, ch.GetNonce(), goldenPCRs()),
			ChallengeId: ch.GetChallengeId(),
		})
	}
	newSvc := func(f *quoteFixture, clock *time.Time, store objectstorage.Client) *DeviceGRPCService {
		return challengeService(t, f, clock, WithDeviceAttestChallengeRequired(), WithDeviceAttestChallengeStorage(store))
	}

	t.Run("issued on A, honoured on B", func(t *testing.T) {
		f := newQuoteFixture(t)
		clock := f.now
		store := newChallengeObjectStore()
		a, b := newSvc(f, &clock, store), newSvc(f, &clock, store)
		ctx := tokenCallerContext("tenant-a")

		ch := issueChallenge(t, ctx, a, itoa(f.device.ID))
		keys := store.keys()
		require.Len(t, keys, 1)
		assert.True(t, strings.HasPrefix(keys[0], "attest-challenges/"), keys[0])
		assert.True(t, strings.HasSuffix(keys[0], ".json"), keys[0])

		resp, err := attest(ctx, f, b, ch)
		require.NoError(t, err)
		assert.True(t, resp.GetVerified())
		assert.True(t, resp.GetNonceValid())
		assert.Empty(t, store.keys())
	})

	t.Run("survives a restart", func(t *testing.T) {
		f := newQuoteFixture(t)
		clock := f.now
		store := newChallengeObjectStore()
		ctx := tokenCallerContext("tenant-a")
		ch := issueChallenge(t, ctx, newSvc(f, &clock, store), itoa(f.device.ID))

		// A is gone; C is a fresh daemon over the same store.
		c := newSvc(f, &clock, store)
		resp, err := attest(ctx, f, c, ch)
		require.NoError(t, err)
		assert.True(t, resp.GetVerified())
	})

	t.Run("single use across daemons", func(t *testing.T) {
		f := newQuoteFixture(t)
		clock := f.now
		store := newChallengeObjectStore()
		a, b := newSvc(f, &clock, store), newSvc(f, &clock, store)
		ctx := tokenCallerContext("tenant-a")

		ch := issueChallenge(t, ctx, a, itoa(f.device.ID))
		_, err := attest(ctx, f, b, ch)
		require.NoError(t, err)
		_, err = attest(ctx, f, a, ch)
		requireChallengeCode(t, err, codes.FailedPrecondition)
	})

	t.Run("concurrent take", func(t *testing.T) {
		f := newQuoteFixture(t)
		clock := f.now
		store := newChallengeObjectStore()
		ctx := tokenCallerContext("tenant-a")
		const n = 8
		svcs := make([]*DeviceGRPCService, n)
		for i := range svcs {
			svcs[i] = newSvc(f, &clock, store)
		}
		ch := issueChallenge(t, ctx, svcs[0], itoa(f.device.ID))
		evidence := f.evidence(t, ch.GetNonce(), goldenPCRs())

		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range svcs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, errs[i] = svcs[i].AttestDevice(ctx, &platformv1.AttestDeviceRequest{
					DeviceId:    itoa(f.device.ID),
					Evidence:    evidence,
					ChallengeId: ch.GetChallengeId(),
				})
			}(i)
		}
		wg.Wait()

		ok, refused := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case status.Code(err) == codes.FailedPrecondition:
				refused++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}
		assert.Equal(t, 1, ok)
		assert.Equal(t, n-1, refused)
	})

	t.Run("expired across daemons", func(t *testing.T) {
		f := newQuoteFixture(t)
		clock := f.now
		store := newChallengeObjectStore()
		a, b := newSvc(f, &clock, store), newSvc(f, &clock, store)
		ctx := tokenCallerContext("tenant-a")

		ch := issueChallenge(t, ctx, a, itoa(f.device.ID))
		clock = f.now.Add(5*time.Minute + time.Second)
		_, err := attest(ctx, f, b, ch)
		requireChallengeCode(t, err, codes.FailedPrecondition)
		assert.Empty(t, store.keys())
	})

	t.Run("tenant across daemons", func(t *testing.T) {
		f := newQuoteFixture(t)
		clock := f.now
		store := newChallengeObjectStore()
		a, b := newSvc(f, &clock, store), newSvc(f, &clock, store)

		ch := issueChallenge(t, tokenCallerContext("tenant-a"), a, itoa(f.device.ID))
		_, err := attest(tokenCallerContext("tenant-b"), f, b, ch)
		requireChallengeCode(t, err, codes.PermissionDenied)
	})

	t.Run("fails closed", func(t *testing.T) {
		f := newQuoteFixture(t)
		clock := f.now
		ctx := tokenCallerContext("tenant-a")

		broken := newChallengeObjectStore()
		broken.putErr = errors.New("storage unavailable")
		a := newSvc(f, &clock, broken)
		_, err := a.IssueAttestationChallenge(ctx, &platformv1.IssueAttestationChallengeRequest{DeviceId: itoa(f.device.ID)})
		requireChallengeCode(t, err, codes.Internal)
		assert.Empty(t, a.challenges.entries, "a failed put must not fall back to memory")
		assert.Empty(t, broken.keys())

		store := newChallengeObjectStore()
		b := newSvc(f, &clock, store)
		ch := issueChallenge(t, ctx, b, itoa(f.device.ID))
		store.mu.Lock()
		store.delErr = errors.New("storage unavailable")
		store.mu.Unlock()
		_, err = attest(ctx, f, b, ch)
		requireChallengeCode(t, err, codes.FailedPrecondition)
	})

	t.Run("nil storage keeps the in-memory store", func(t *testing.T) {
		f := newQuoteFixture(t)
		clock := f.now
		svc := newSvc(f, &clock, nil)
		ctx := tokenCallerContext("tenant-a")

		ch := issueChallenge(t, ctx, svc, itoa(f.device.ID))
		resp, err := attest(ctx, f, svc, ch)
		require.NoError(t, err)
		assert.True(t, resp.GetVerified())
	})
}
