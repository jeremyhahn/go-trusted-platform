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
	"crypto/rand"
	"encoding/binary"
	"strconv"
	"strings"
)

// Flows added through the SDN API (every transport) carry a cookie that is
// their identity: the owner prefix below in the high 16 bits and 48 random
// bits under it. The flow ID the API returns is that cookie, so a delete or
// a stats query names exactly one flow, and a listing reports the same ID
// for it.
const (
	// APIFlowCookieOwner marks a flow the SDN API added. It is distinct
	// from the gateway's 0xF1BE family.
	APIFlowCookieOwner uint64 = 0xA9F1 << 48

	// FlowIDPrefix prefixes every flow ID.
	FlowIDPrefix = "flow-"
)

// NewAPIFlowCookie returns a fresh, nonzero cookie under the API owner
// prefix.
func NewAPIFlowCookie() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[2:]); err != nil {
		return 0, err
	}
	return APIFlowCookieOwner | binary.BigEndian.Uint64(b[:]), nil
}

// FlowID renders a cookie as the flow ID the API hands out.
func FlowID(cookie uint64) string {
	return FlowIDPrefix + "0x" + strconv.FormatUint(cookie, 16)
}

// ParseFlowID recovers the cookie from a flow ID: "flow-" followed by
// the cookie in hex (0x-prefixed) or decimal. Cookie 0 is refused: it is
// the cookie of every flow installed without one, and deleting "the" flow
// with cookie 0 would delete all of them.
func ParseFlowID(id string) (uint64, error) {
	raw, ok := strings.CutPrefix(id, FlowIDPrefix)
	if !ok {
		return 0, &ErrInvalidFlowID{ID: id, Reason: "a flow ID is " + FlowIDPrefix + "<cookie>"}
	}
	var (
		cookie uint64
		err    error
	)
	if hex, isHex := strings.CutPrefix(strings.ToLower(raw), "0x"); isHex {
		cookie, err = strconv.ParseUint(hex, 16, 64)
	} else {
		cookie, err = strconv.ParseUint(raw, 10, 64)
	}
	if err != nil {
		return 0, &ErrInvalidFlowID{ID: id, Reason: "the cookie does not parse"}
	}
	if cookie == 0 {
		return 0, &ErrInvalidFlowID{ID: id, Reason: "cookie 0 names every flow installed without a cookie"}
	}
	return cookie, nil
}

// ErrInvalidFlowID is returned for a flow ID that names no single flow.
type ErrInvalidFlowID struct {
	ID     string
	Reason string
}

// Error implements the error interface.
func (e *ErrInvalidFlowID) Error() string {
	return "invalid flow id " + strconv.Quote(e.ID) + ": " + e.Reason
}
