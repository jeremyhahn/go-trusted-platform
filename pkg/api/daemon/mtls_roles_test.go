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
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	qberrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
)

// rolesUserClient is an IAM user client that records which lookup the mTLS
// role resolver called. Methods it does not override panic through the nil
// embedded interface.
type rolesUserClient struct {
	iam.UserClient
	user  *iam.User
	err   error
	calls []string
}

func (c *rolesUserClient) Get(_ context.Context, _, _ string) (*iam.User, error) {
	c.calls = append(c.calls, "Get")
	return c.user, c.err
}

func (c *rolesUserClient) GetByEmail(_ context.Context, _, _ string) (*iam.User, error) {
	c.calls = append(c.calls, "GetByEmail")
	return c.user, c.err
}

func (c *rolesUserClient) FindByUsername(_ context.Context, _, _ string) (*iam.User, error) {
	c.calls = append(c.calls, "FindByUsername")
	return c.user, c.err
}

// rolesIAMClient is an IAM client whose User() is the recording user client.
type rolesIAMClient struct {
	quicbaassdk.IAMClient
	users *rolesUserClient
}

func (c *rolesIAMClient) User() iam.UserClient { return c.users }

// TestIAMUserRoles_LooksUpEmailAndUsername pins that the mTLS role resolver
// resolves the certificate identity (an email SAN or a CN) to the IAM user
// by email or by username, never as a stored user ID (#1989).
func TestIAMUserPrincipal_LooksUpEmailAndUsername(t *testing.T) {
	cases := []struct {
		name       string
		subject    string
		user       *iam.User
		err        error
		wantCall   string
		wantUserID string
		wantRoles  []string
		wantErr    bool
	}{
		{
			name:       "email subject",
			subject:    "operator@example.com",
			user:       &iam.User{ID: "1234567890123456789", Roles: []string{"admin"}},
			wantCall:   "GetByEmail",
			wantUserID: "1234567890123456789",
			wantRoles:  []string{"admin"},
		},
		{
			name:       "CN subject",
			subject:    "operator",
			user:       &iam.User{ID: "1234567890123456789", Roles: []string{"viewer"}},
			wantCall:   "FindByUsername",
			wantUserID: "1234567890123456789",
			wantRoles:  []string{"viewer"},
		},
		{
			name:     "username not found",
			subject:  "unknown",
			err:      qberrors.NewNotFound("FindByUsername", "user"),
			wantCall: "FindByUsername",
			wantErr:  true,
		},
		{
			name:     "email not found",
			subject:  "unknown@example.com",
			err:      qberrors.NewNotFound("GetByEmail", "user"),
			wantCall: "GetByEmail",
			wantErr:  true,
		},
		{
			name:     "stored user without an ID",
			subject:  "operator@example.com",
			user:     &iam.User{Roles: []string{"admin"}},
			wantCall: "GetByEmail",
			wantErr:  true,
		},
		{
			name:     "no user record",
			subject:  "operator",
			wantCall: "FindByUsername",
			wantErr:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			users := &rolesUserClient{user: tc.user, err: tc.err}
			resolve := iamUserPrincipal(&rolesIAMClient{users: users})
			if resolve == nil {
				t.Fatal("iamUserPrincipal returned a nil resolver for a non-nil client")
			}
			userID, roles, err := resolve(context.Background(), "tenant-1", tc.subject)
			if len(users.calls) != 1 || users.calls[0] != tc.wantCall {
				t.Fatalf("lookups = %v, want exactly [%s]", users.calls, tc.wantCall)
			}
			if tc.wantErr {
				if err == nil {
					t.Fatalf("user %q roles %v, want a refusal", userID, roles)
				}
				if userID != "" || roles != nil {
					t.Fatalf("user %q roles %v on a refused lookup, want none", userID, roles)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if userID != tc.wantUserID {
				t.Fatalf("user ID = %q, want %q", userID, tc.wantUserID)
			}
			if len(roles) != len(tc.wantRoles) || roles[0] != tc.wantRoles[0] {
				t.Fatalf("roles = %v, want %v", roles, tc.wantRoles)
			}
		})
	}
}

// TestIAMUserRoles_NilUserClientRefused pins the fail-closed answer when the
// IAM client has no user service.
func TestIAMUserPrincipal_NilUserClientRefused(t *testing.T) {
	resolve := iamUserPrincipal(nilUsersIAMClient{})
	if _, _, err := resolve(context.Background(), "tenant-1", "operator@example.com"); err == nil {
		t.Fatal("a nil user client must refuse")
	}
}

type nilUsersIAMClient struct {
	quicbaassdk.IAMClient
}

func (nilUsersIAMClient) User() iam.UserClient { return nil }
