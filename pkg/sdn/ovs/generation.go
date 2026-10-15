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

package ovs

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"
)

// A gateway datapath service stamps every flow it installs with a cookie of
// two halves. The high 32 bits are the service's owner id (the gateway's
// 0xF1BE family), which Stop deletes under OwnerCookieMask. The low 32 bits
// are a flow generation, fresh on every start, so the flows a previous
// process left behind are told apart by cookie alone: a service process can
// die and restart without a Stop (#557), and its next Start installs the
// current set first and only then sweeps every flow of an older generation.
const (
	// OwnerCookieMask selects the owner id of a gateway service cookie.
	OwnerCookieMask uint64 = 0xFFFFFFFF00000000
)

// FlowSweeper is the part of the OVS client a generation sweep needs.
type FlowSweeper interface {
	GetFlowStats(ctx context.Context, bridgeName string, match string) ([]*Flow, error)
	DeleteFlowsByCookie(ctx context.Context, bridgeName string, cookie, cookieMask uint64) error
}

// NewGenerationCookie returns owner's cookie with a fresh, nonzero flow
// generation in its low 32 bits. owner must be a nonzero owner id with its
// low 32 bits clear.
func NewGenerationCookie(owner uint64) (uint64, error) {
	if err := checkOwner(owner); err != nil {
		return 0, err
	}
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, &WrappedError{Msg: "failed to draw a flow generation", Err: err}
		}
		if g := binary.BigEndian.Uint32(b[:]); g != 0 {
			return owner | uint64(g), nil
		}
	}
}

// SweepStaleGenerations deletes every flow on the bridge under current's
// owner whose cookie is not current: the flows a previous process installed
// for a configuration that has since changed. Call it only after the
// current set is installed. Installing replaced every flow of identical
// (table, priority, match) along with its cookie, so what is left under an
// older generation is exactly what no longer belongs, and traffic the
// current configuration carries never sees a gap. Another owner's flows are
// never touched: each stale cookie is deleted exactly.
func SweepStaleGenerations(ctx context.Context, client FlowSweeper, bridge string, current uint64) error {
	owner := current & OwnerCookieMask
	if err := checkOwner(owner); err != nil {
		return err
	}
	flows, err := client.GetFlowStats(ctx, bridge,
		fmt.Sprintf("cookie=0x%x/0x%x", owner, OwnerCookieMask))
	if err != nil {
		return err
	}
	stale := make(map[uint64]struct{})
	for _, f := range flows {
		c, err := parseCookie(f.Cookie)
		if err != nil || c == current || c&OwnerCookieMask != owner {
			continue
		}
		stale[c] = struct{}{}
	}
	for c := range stale {
		if err := client.DeleteFlowsByCookie(ctx, bridge, c, ^uint64(0)); err != nil {
			return err
		}
	}
	return nil
}

// checkOwner refuses an owner id that is zero, which would select every
// flow installed without a cookie, or that has generation bits set.
func checkOwner(owner uint64) error {
	if owner == 0 || owner&^OwnerCookieMask != 0 {
		return &ErrInvalidOwnerCookie{Owner: owner}
	}
	return nil
}

// ErrInvalidOwnerCookie is returned for an owner id a generation cannot be
// stamped under: zero, or with bits set below OwnerCookieMask.
type ErrInvalidOwnerCookie struct {
	Owner uint64
}

// Error implements the error interface.
func (e *ErrInvalidOwnerCookie) Error() string {
	return "invalid owner cookie 0x" + strconv.FormatUint(e.Owner, 16) +
		": an owner id is nonzero and has its low 32 bits clear"
}
