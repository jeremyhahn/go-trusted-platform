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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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

// MirrorUser creates the user in the QuicBaaS IAM tenant. It delegates
// to MirrorInvitedUser and drops the undo, so a create conflict gets the
// same identity and role checks.
func (m *QuicBaaSUserMirror) MirrorUser(ctx context.Context, tenantID, email, displayName string, roles []string) error {
	_, err := m.MirrorInvitedUser(ctx, tenantID, email, displayName, roles)
	return err
}

// MirrorInvitedUser creates the user in the QuicBaaS IAM tenant and returns
// an undo that removes only what this call wrote, so a pre-existing identity
// is never deleted: a created user is deleted, otherwise only the roles this
// call newly assigned are revoked. A create conflict is resolved by tenant
// and email: a username held by another email is ErrMirrorUsernameTaken, and
// the same identity is given the requested roles it does not hold yet. The
// IAM username is MirrorUsername(email), never the display name, which is
// sent as DisplayName only.
func (m *QuicBaaSUserMirror) MirrorInvitedUser(
	ctx context.Context, tenantID, email, displayName string, roles []string,
) (func(context.Context) error, error) {
	noop := func(context.Context) error { return nil }
	if m == nil || m.client == nil {
		return noop, nil
	}
	username := MirrorUsername(email)
	req := &iamsdk.CreateUserRequest{
		Username:    username,
		Email:       email,
		DisplayName: displayName,
		Roles:       roles,
	}
	created, err := m.client.CreateUser(ctx, tenantID, req)
	if err == nil {
		return func(ctx context.Context) error {
			id := ""
			if created != nil {
				id = created.ID
			}
			if id == "" {
				u, getErr := m.client.GetUserByEmail(ctx, tenantID, email)
				if getErr != nil {
					return getErr
				}
				if u == nil {
					return nil
				}
				id = u.ID
			}
			return m.client.DeleteUser(ctx, tenantID, id)
		}, nil
	}
	if !isAlreadyExists(err) {
		return nil, err
	}
	existing, getErr := m.client.GetUserByEmail(ctx, tenantID, email)
	if getErr != nil {
		msg := strings.ToLower(getErr.Error())
		if strings.Contains(msg, "not_found") || strings.Contains(msg, "not found") {
			return nil, ErrMirrorUsernameTaken{TenantID: tenantID, Username: username, Email: email}
		}
		return nil, fmt.Errorf("resolve existing IAM user %s: %w", email, getErr)
	}
	if existing == nil || !strings.EqualFold(strings.TrimSpace(existing.Email), strings.TrimSpace(email)) {
		return nil, ErrMirrorUsernameTaken{TenantID: tenantID, Username: username, Email: email}
	}
	if len(roles) == 0 {
		return noop, nil
	}
	held, err := m.heldRoleRefs(ctx, tenantID, existing.Roles)
	if err != nil {
		return nil, err
	}
	var assigned []string
	revoke := func(ctx context.Context) error {
		var errs []error
		for _, role := range assigned {
			if rErr := m.client.RevokeRole(ctx, tenantID, existing.ID, role); rErr != nil {
				errs = append(errs, rErr)
			}
		}
		return errors.Join(errs...)
	}
	for _, role := range roles {
		if _, ok := held[role]; ok {
			continue
		}
		if aErr := m.client.AssignRole(ctx, tenantID, existing.ID, role); aErr != nil {
			if isAlreadyExists(aErr) {
				continue
			}
			_ = revoke(ctx)
			return nil, aErr
		}
		assigned = append(assigned, role)
	}
	return revoke, nil
}

// heldRoleRefs returns the IDs and names of the roles whose ID is in
// roleIDs, plus the raw roleIDs entries, paging ListRoles like
// MirroredEmails pages users.
func (m *QuicBaaSUserMirror) heldRoleRefs(ctx context.Context, tenantID string, roleIDs []string) (map[string]struct{}, error) {
	held := make(map[string]struct{}, 2*len(roleIDs))
	ids := make(map[string]struct{}, len(roleIDs))
	for _, id := range roleIDs {
		held[id] = struct{}{}
		ids[id] = struct{}{}
	}
	req := &iamsdk.ListRolesRequest{PageSize: mirroredEmailsPageSize}
	for {
		resp, err := m.client.ListRoles(ctx, tenantID, req)
		if err != nil {
			return nil, err
		}
		for _, role := range resp.Roles {
			if _, ok := ids[role.ID]; ok {
				held[role.ID] = struct{}{}
				held[role.Name] = struct{}{}
			}
		}
		next := resp.Pagination.NextPageToken
		if !resp.Pagination.HasMore || next == "" || next == req.PageToken {
			return held, nil
		}
		req.PageToken = next
	}
}

// mirroredEmailsPageSize is the IAM ListUsers page size MirroredEmails reads
// with.
const mirroredEmailsPageSize = 100

// MirroredEmails returns the lower-cased email of every user the IAM tenant
// holds. The startup reconcile compares it with the platform user store to
// find users the mirror never wrote.
func (m *QuicBaaSUserMirror) MirroredEmails(ctx context.Context, tenantID string) (map[string]struct{}, error) {
	if m == nil || m.client == nil {
		return nil, ErrMirrorClientMissing{}
	}
	emails := make(map[string]struct{})
	req := &iamsdk.ListUsersRequest{PageSize: mirroredEmailsPageSize}
	for {
		resp, err := m.client.ListUsers(ctx, tenantID, req)
		if err != nil {
			return nil, err
		}
		for _, user := range resp.Users {
			emails[strings.ToLower(user.Email)] = struct{}{}
		}
		next := resp.Pagination.NextPageToken
		if !resp.Pagination.HasMore || next == "" || next == req.PageToken {
			return emails, nil
		}
		req.PageToken = next
	}
}

// UsernameFromEmail is the username a user created with only an email gets:
// the email's local part, or the whole address when it has none. The IAM SDK
// refuses an empty username, so every create path that takes an email and no
// username (REST, gRPC, Unix, QUIC and MCP alike) derives it here.
func UsernameFromEmail(email string) string {
	if i := strings.IndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return email
}

const (
	// mirrorUsernamePrefixMax bounds the sanitized local part so the
	// prefix, the dash and the hash fit the 64-byte IAM username limit.
	mirrorUsernamePrefixMax = 47
	// mirrorUsernameHashHex is the number of hex characters of the email
	// hash appended to the prefix.
	mirrorUsernameHashHex = 16
)

// MirrorUsername derives the IAM username a mirrored user is created with.
// The IAM store refuses usernames outside ^[a-zA-Z0-9_-]{3,64}$, and a
// display name or raw local part (jane.doe, jane+tag, al) breaks it, so the
// username is the lower-cased local part with every byte outside [a-z0-9_-]
// replaced by '_', cut to 47 bytes, plus '-' and 16 hex characters of the
// SHA-256 of the lower-cased, trimmed email. The result is 17-64 bytes, always
// valid, and the hash suffix keeps two emails with one local part apart
// (#2362).
func MirrorUsername(email string) string {
	normalized := strings.ToLower(strings.TrimSpace(email))
	local := normalized
	if i := strings.IndexByte(local, '@'); i >= 0 {
		local = local[:i]
	}
	if len(local) > mirrorUsernamePrefixMax {
		local = local[:mirrorUsernamePrefixMax]
	}
	prefix := []byte(local)
	for i, c := range prefix {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			prefix[i] = '_'
		}
	}
	sum := sha256.Sum256([]byte(normalized))
	return string(prefix) + "-" + hex.EncodeToString(sum[:])[:mirrorUsernameHashHex]
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
