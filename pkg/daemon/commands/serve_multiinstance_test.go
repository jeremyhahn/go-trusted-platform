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

package commands

import (
	"context"
	"errors"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	platformquicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
)

// probeTxn answers every transaction with err, counting the calls.
type probeTxn struct {
	err   error
	calls int
}

func (p *probeTxn) Execute(context.Context, *quicbaassdk.TxnRequest) (*quicbaassdk.TxnResponse, error) {
	p.calls++
	if p.err != nil {
		return nil, p.err
	}
	return &quicbaassdk.TxnResponse{Succeeded: true}, nil
}

// TestAdminClaimTransactions: the admin-claim completion lease (#172) is
// wired only on a multi-instance deployment whose store answers the
// compare-and-swap probe; anything else leaves the ceremony as it was —
// refused on a multi-instance deployment.
func TestAdminClaimTransactions(t *testing.T) {
	ctx := context.Background()

	answering := &probeTxn{}
	assert.Same(t, answering, adminClaimTransactions(ctx, true, answering, "tenant-a", nil),
		"a multi-instance store that answers carries the lease")
	assert.Equal(t, 1, answering.calls)

	single := &probeTxn{}
	assert.Nil(t, adminClaimTransactions(ctx, false, single, "tenant-a", nil),
		"a single instance needs no store-wide lease")
	assert.Zero(t, single.calls, "and is not probed")

	mistyped := &probeTxn{err: errors.New("embedded: invalid request type")}
	assert.Nil(t, adminClaimTransactions(ctx, true, mistyped, "tenant-a", nil),
		"a store that cannot run the transaction keeps the ceremony refused")

	assert.Nil(t, adminClaimTransactions(ctx, true, nil, "tenant-a", nil))
}

// TestIsMultiInstanceDeployment covers the two shapes the review named:
// the DEFAULT single-node configuration (which carries a loopback raft
// address and must still be claimable) and the bootstrap member of a
// real cluster (which advertises a routable address and has an EMPTY
// join-addresses list).
func TestIsMultiInstanceDeployment(t *testing.T) {
	tests := []struct {
		name string
		cfg  *platformquicbaas.Config
		want bool
	}{
		{"nil config", nil, false},
		{"DefaultConfig — single node, no raft address", platformquicbaas.DefaultConfig(), false},
		{"empty", &platformquicbaas.Config{}, false},
		{"loopback ipv4", &platformquicbaas.Config{RaftAddress: "127.0.0.1:63000"}, false},
		{"loopback ipv6", &platformquicbaas.Config{RaftAddress: "[::1]:63000"}, false},
		{"localhost name", &platformquicbaas.Config{RaftAddress: "localhost:63000"}, false},
		{"unspecified", &platformquicbaas.Config{RaftAddress: "0.0.0.0:63000"}, false},
		{"cluster bootstrap member — routable, no join addresses",
			&platformquicbaas.Config{RaftAddress: "10.0.1.1:63000"}, true},
		{"cluster joiner — join addresses set",
			&platformquicbaas.Config{JoinAddresses: []string{"10.0.1.1:63000"}}, true},
		{"joiner with loopback advertise still multi-instance",
			&platformquicbaas.Config{RaftAddress: "127.0.0.1:63000", JoinAddresses: []string{"10.0.1.1:63000"}}, true},
		{"unparseable advertise address fails closed",
			&platformquicbaas.Config{RaftAddress: "not a valid address"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isMultiInstanceDeployment(tc.cfg))
		})
	}
}
