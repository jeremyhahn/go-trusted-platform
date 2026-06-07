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

package iam

import (
	"context"
	"errors"
	"strings"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
)

// QuicBaaSUserMirror satisfies the platform service-layer
// IAMUserMirror interface by delegating to a QuicBaaS IAM client.
// Used by the WebAuthn registration flow to mirror a newly-created
// platform user into the QuicBaaS IAM tenant so /api/v1/iam/users
// surfaces them.
//
// The interface itself lives in the platform service package so the
// service layer doesn't import the IAM REST package — this struct
// closes the dependency loop from the REST layer's perspective.
type QuicBaaSUserMirror struct {
	client IAMClient
}

// NewQuicBaaSUserMirror returns a mirror bound to the supplied
// adapter. Pass the same IAMClient the REST IAM router uses so both
// surfaces speak to the same tenant store.
func NewQuicBaaSUserMirror(client IAMClient) *QuicBaaSUserMirror {
	return &QuicBaaSUserMirror{client: client}
}

// MirrorUser creates the user in the QuicBaaS IAM tenant. The
// operation is idempotent — if the email already exists the IAM
// client returns AlreadyExists and we treat that as success so a
// failed first attempt followed by a retry doesn't tombstone the
// registration flow.
func (m *QuicBaaSUserMirror) MirrorUser(ctx context.Context, tenantID, email, displayName string, roles []string) error {
	if m == nil || m.client == nil {
		return nil
	}
	username := displayName
	if username == "" {
		username = localPart(email)
	}
	req := &iamsdk.CreateUserRequest{
		Username:    username,
		Email:       email,
		DisplayName: displayName,
		Roles:       roles,
	}
	_, err := m.client.CreateUser(ctx, tenantID, req)
	if err == nil {
		return nil
	}
	// Treat "already exists" as success. The IAM SDK doesn't expose a
	// typed sentinel today, so we fall back to substring matching on
	// the error message — the canonical text the QuicBaaS client
	// returns is "already exists".
	if isAlreadyExists(err) {
		return nil
	}
	return err
}

func localPart(email string) string {
	if i := strings.IndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return email
}

// isAlreadyExists matches the QuicBaaS IAM "already exists" envelope
// without coupling on the concrete error type. When a typed
// AlreadyExists error lands upstream, swap this for errors.As.
func isAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errAlreadyExistsSentinel) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "duplicate") ||
		strings.Contains(msg, "conflict")
}

// errAlreadyExistsSentinel is the typed sentinel callers can wrap
// when they want to bypass the substring check. Reserved for when
// the upstream SDK exposes a real typed error.
var errAlreadyExistsSentinel = errors.New("iam: user already exists")
