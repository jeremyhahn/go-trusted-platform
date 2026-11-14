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

package adminclaim

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdktransport "github.com/jeremyhahn/go-quicbaas/sdk/go/transport"
)

// TransactionExecutor is the narrow slice of the SDK compare-and-swap
// client the claim's store-wide completion lease runs on. Satisfied by
// quicbaas.SDK().Transaction().
type TransactionExecutor interface {
	Execute(ctx context.Context, req *quicbaassdk.TxnRequest) (*quicbaassdk.TxnResponse, error)
}

const (
	// completionEntityType is the store entity the completion lease is
	// written under.
	completionEntityType = "adminclaim"

	// completionLeaseTTL bounds how long a completion lease holds the
	// claim closed to every other instance. An instance that dies holding
	// it leaves the claim closed for at most this long.
	completionLeaseTTL = 2 * time.Minute

	// completionDeadline bounds the holder's own work under the lease. It
	// is well inside completionLeaseTTL, so a lease is never taken over
	// while its holder can still enrol.
	completionDeadline = completionLeaseTTL / 2
)

// completionLease is the value of the lease record: who holds it, and
// until when.
type completionLease struct {
	Holder    string    `json:"holder"`
	ExpiresAt time.Time `json:"expires_at"`
}

// completionLock makes the claim's check-then-enrol atomic across every
// platformd instance sharing one store (#172). The process-local mutex in
// FinishPasskey serialises one instance; this lease serialises them all:
// exactly one instance at a time may read the factor history and enrol,
// and every other one is refused with ErrClaimInProgress until the
// holder releases the lease, after which its factor history refuses the
// claim as ErrAlreadyClaimed.
//
// The lease is released after completion or failure, never kept: the
// factor history is what keeps a claimed identity closed, so revoking its
// last factor still makes it claimable again (the #169 ruling).
type completionLock struct {
	txn      TransactionExecutor
	tenantID string
	key      string
	ttl      time.Duration
	now      func() time.Time
}

func newCompletionLock(txn TransactionExecutor, tenantID, adminUsername string) *completionLock {
	return &completionLock{
		txn:      txn,
		tenantID: tenantID,
		key:      completionKey(tenantID, adminUsername),
		ttl:      completionLeaseTTL,
		now:      time.Now,
	}
}

func completionKey(tenantID, adminUsername string) string {
	return completionEntityType + "/" + tenantID + "/" + adminUsername + "/completion"
}

// acquire takes the lease, or takes over one whose holder let it expire.
// It returns the function that releases it. A lease another instance
// holds is ErrClaimInProgress; a store that cannot run the transaction is
// ErrCompletionLockUnavailable, so no claim completes without the lease.
func (l *completionLock) acquire(ctx context.Context) (func(context.Context) error, error) {
	ctx = sdktransport.ContextWithTenant(ctx, l.tenantID)
	value, err := l.leaseValue()
	if err != nil {
		return nil, ErrCompletionLockUnavailable{Err: err}
	}
	resp, err := l.txn.Execute(ctx, &quicbaassdk.TxnRequest{
		Compare: []quicbaassdk.Compare{
			// Version 0: the record does not exist.
			{Key: l.key, Target: quicbaassdk.CompareVersion, Result: quicbaassdk.CompareEqual, Revision: 0},
		},
		Success: []quicbaassdk.TxnOp{
			{Type: quicbaassdk.TxnOpPut, EntityType: completionEntityType, Key: l.key, Value: value},
		},
		Failure: []quicbaassdk.TxnOp{
			{Type: quicbaassdk.TxnOpGet, EntityType: completionEntityType, Key: l.key},
		},
	})
	if err != nil {
		return nil, ErrCompletionLockUnavailable{Err: err}
	}
	if resp == nil {
		return nil, ErrCompletionLockUnavailable{}
	}
	if resp.Succeeded {
		return l.releaser(value), nil
	}
	if len(resp.Responses) == 0 || len(resp.Responses[0].Value) == 0 {
		// Held, but the holder's lease was not returned: nothing to
		// compare a takeover against.
		return nil, ErrClaimInProgress{}
	}
	seen := resp.Responses[0].Value
	var held completionLease
	if json.Unmarshal(seen, &held) == nil && l.now().Before(held.ExpiresAt) {
		return nil, ErrClaimInProgress{}
	}
	// Expired (or unreadable, which only this code could have written):
	// take it over, but only if it is still exactly the lease just read,
	// so two instances racing for a stale lease cannot both win.
	resp, err = l.txn.Execute(ctx, &quicbaassdk.TxnRequest{
		Compare: []quicbaassdk.Compare{
			{Key: l.key, Target: quicbaassdk.CompareValue, Result: quicbaassdk.CompareEqual, Value: seen},
		},
		Success: []quicbaassdk.TxnOp{
			{Type: quicbaassdk.TxnOpPut, EntityType: completionEntityType, Key: l.key, Value: value},
		},
	})
	if err != nil {
		return nil, ErrCompletionLockUnavailable{Err: err}
	}
	if resp == nil || !resp.Succeeded {
		return nil, ErrClaimInProgress{}
	}
	return l.releaser(value), nil
}

func (l *completionLock) leaseValue() ([]byte, error) {
	holder := make([]byte, 16)
	if _, err := rand.Read(holder); err != nil {
		return nil, err
	}
	return json.Marshal(completionLease{
		Holder:    hex.EncodeToString(holder),
		ExpiresAt: l.now().Add(l.ttl).UTC(),
	})
}

// releaser deletes the lease only while it is still ours: a lease taken
// over after expiry belongs to its new holder.
func (l *completionLock) releaser(value []byte) func(context.Context) error {
	value = bytes.Clone(value)
	return func(ctx context.Context) error {
		ctx = sdktransport.ContextWithTenant(ctx, l.tenantID)
		_, err := l.txn.Execute(ctx, &quicbaassdk.TxnRequest{
			Compare: []quicbaassdk.Compare{
				{Key: l.key, Target: quicbaassdk.CompareValue, Result: quicbaassdk.CompareEqual, Value: value},
			},
			Success: []quicbaassdk.TxnOp{
				{Type: quicbaassdk.TxnOpDelete, EntityType: completionEntityType, Key: l.key},
			},
		})
		return err
	}
}

// ProbeTransactions reports whether txn can run the completion lease's
// compare-and-swap for tenantID. It runs a read-only transaction: a
// compare with no operations changes nothing. A deployment wires the
// lease, and with it the multi-instance claim, only when this succeeds;
// otherwise the ceremony stays refused there (ErrMultiInstanceUnsupported).
func ProbeTransactions(ctx context.Context, txn TransactionExecutor, tenantID string) error {
	if txn == nil {
		return ErrDependencyRequired{Name: "transaction client"}
	}
	_, err := txn.Execute(sdktransport.ContextWithTenant(ctx, tenantID), &quicbaassdk.TxnRequest{
		Compare: []quicbaassdk.Compare{
			{Key: completionEntityType + "/" + tenantID + "/probe", Target: quicbaassdk.CompareVersion,
				Result: quicbaassdk.CompareEqual, Revision: 0},
		},
	})
	return err
}
