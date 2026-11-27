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
	"regexp"
	"strings"
	"testing"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMirrorUser_CreatesUserWithRoles(t *testing.T) {
	t.Parallel()
	var got *iamsdk.CreateUserRequest
	var gotTenant string
	client := &mockIAMClient{
		createUserFn: func(_ context.Context, tenantID string, req *iamsdk.CreateUserRequest) (*iamsdk.User, error) {
			gotTenant, got = tenantID, req
			return &iamsdk.User{}, nil
		},
	}

	err := NewQuicBaaSUserMirror(client).MirrorUser(context.Background(), "t1", "ann@example.com", "", []string{"admin"})

	require.NoError(t, err)
	assert.Equal(t, "t1", gotTenant)
	assert.Equal(t, MirrorUsername("ann@example.com"), got.Username, "the IAM username comes from the email, not the display name")
	assert.Equal(t, []string{"admin"}, got.Roles)
}

func TestMirrorUser_AlreadyExistsIsSuccessOtherErrorsAreNot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	exists := NewQuicBaaSUserMirror(&mockIAMClient{
		createUserFn: func(context.Context, string, *iamsdk.CreateUserRequest) (*iamsdk.User, error) {
			return nil, errors.New("iam.user: already exists")
		},
		getByEmailFn: func(context.Context, string, string) (*iamsdk.User, error) {
			return &iamsdk.User{ID: "u-ann", Email: "ann@example.com"}, nil
		},
	})
	require.NoError(t, exists.MirrorUser(ctx, "t1", "ann@example.com", "Ann", nil))

	roleErr := errors.New("iam.role: not_found")
	missingRole := NewQuicBaaSUserMirror(&mockIAMClient{
		createUserFn: func(context.Context, string, *iamsdk.CreateUserRequest) (*iamsdk.User, error) {
			return nil, roleErr
		},
	})
	assert.ErrorIs(t, missingRole.MirrorUser(ctx, "t1", "ann@example.com", "Ann", []string{"admin"}), roleErr)
}

// TestMirrorUser_UsernameHeldByAnotherEmailIsAnError: ann@one.example and
// ann@two.example derive the same username, so the conflict is another
// user's and must fail before the invitation is consumed.
func TestMirrorUser_UsernameHeldByAnotherEmailIsAnError(t *testing.T) {
	t.Parallel()
	cases := map[string]func(context.Context, string, string) (*iamsdk.User, error){
		"email has no IAM user": func(context.Context, string, string) (*iamsdk.User, error) {
			return nil, errors.New("iam.user: not_found")
		},
		"username held by another email": func(context.Context, string, string) (*iamsdk.User, error) {
			return &iamsdk.User{ID: "u-ann", Email: "ann@one.example"}, nil
		},
	}
	for name, getByEmail := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var assigns int
			m := NewQuicBaaSUserMirror(&mockIAMClient{
				createUserFn: func(context.Context, string, *iamsdk.CreateUserRequest) (*iamsdk.User, error) {
					return nil, errors.New("iam.user: already exists")
				},
				getByEmailFn: getByEmail,
				assignRoleFn: func(context.Context, string, string, string) error {
					assigns++
					return nil
				},
			})
			err := m.MirrorUser(context.Background(), "t1", "ann@two.example", "", []string{"viewer"})
			require.Error(t, err)
			assert.Zero(t, assigns)
		})
	}
}

// TestMirrorUser_ExistingIdentityGetsTheRequestedRoles: a mirror conflict for
// the same tenant and email assigns the requested roles the user lacks.
func TestMirrorUser_ExistingIdentityGetsTheRequestedRoles(t *testing.T) {
	t.Parallel()
	var assigns [][3]string
	m := NewQuicBaaSUserMirror(&mockIAMClient{
		createUserFn: func(context.Context, string, *iamsdk.CreateUserRequest) (*iamsdk.User, error) {
			return nil, errors.New("iam.user: already exists")
		},
		getByEmailFn: func(context.Context, string, string) (*iamsdk.User, error) {
			return &iamsdk.User{ID: "u-ann", Email: "ann@example.com", Roles: []string{"role-viewer"}}, nil
		},
		listRolesFn: func(context.Context, string, *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
			return &iamsdk.ListRolesResponse{Roles: []iamsdk.Role{
				{ID: "role-viewer", Name: "viewer"},
				{ID: "role-admin", Name: "admin"},
			}}, nil
		},
		assignRoleFn: func(_ context.Context, tenantID, userID, roleID string) error {
			assigns = append(assigns, [3]string{tenantID, userID, roleID})
			return nil
		},
	})
	require.NoError(t, m.MirrorUser(context.Background(), "t1", "ann@example.com", "", []string{"viewer", "admin"}))
	assert.Equal(t, [][3]string{{"t1", "u-ann", "admin"}}, assigns)
}

func TestMirroredEmails_ReadsEveryPage(t *testing.T) {
	t.Parallel()
	pages := map[string]*iamsdk.ListUsersResponse{
		"": {
			Users:      []iamsdk.User{{Email: "Ann@Example.com"}},
			Pagination: iamsdk.PaginationInfo{HasMore: true, NextPageToken: "p2"},
		},
		"p2": {
			Users: []iamsdk.User{{Email: "bob@example.com"}},
		},
	}
	client := &mockIAMClient{
		listUsersFn: func(_ context.Context, tenantID string, req *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
			assert.Equal(t, "t1", tenantID)
			return pages[req.PageToken], nil
		},
	}

	emails, err := NewQuicBaaSUserMirror(client).MirroredEmails(context.Background(), "t1")

	require.NoError(t, err)
	assert.Equal(t, map[string]struct{}{"ann@example.com": {}, "bob@example.com": {}}, emails)
}

func TestMirroredEmails_StopsOnARepeatedPageToken(t *testing.T) {
	t.Parallel()
	calls := 0
	client := &mockIAMClient{
		listUsersFn: func(context.Context, string, *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
			calls++
			return &iamsdk.ListUsersResponse{Pagination: iamsdk.PaginationInfo{HasMore: true, NextPageToken: "same"}}, nil
		},
	}

	_, err := NewQuicBaaSUserMirror(client).MirroredEmails(context.Background(), "t1")

	require.NoError(t, err)
	assert.Equal(t, 2, calls, "a server that keeps returning one token must not loop forever")
}

func TestMirroredEmails_Errors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	_, err := NewQuicBaaSUserMirror(nil).MirroredEmails(ctx, "t1")
	assert.ErrorAs(t, err, &ErrMirrorClientMissing{})

	listErr := errors.New("iam unavailable")
	client := &mockIAMClient{
		listUsersFn: func(context.Context, string, *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
			return nil, listErr
		},
	}
	_, err = NewQuicBaaSUserMirror(client).MirroredEmails(ctx, "t1")
	assert.ErrorIs(t, err, listErr)
}

func TestUsernameFromEmail(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"alice@acme.test": "alice",
		"bob":             "bob",
		"@acme.test":      "@acme.test",
		"":                "",
	}
	for email, want := range cases {
		if got := UsernameFromEmail(email); got != want {
			t.Errorf("UsernameFromEmail(%q) = %q, want %q", email, got, want)
		}
	}
}

// iamUsernameRule is the pinned go-quicbaas pkg/iam username rule that
// IdentityStore.CreateUser enforces.
var iamUsernameRule = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,64}$`)

// TestMirrorUsername_MatchesTheIAMUsernameRule: every email form, dotted,
// plus-tagged, short, quoted, over-long or without an @, maps to a username
// the IAM store accepts, and two emails with one local part stay apart
// (#2362).
func TestMirrorUsername_MatchesTheIAMUsernameRule(t *testing.T) {
	t.Parallel()
	emails := []string{
		"jane.doe@example.com",
		"jane+tag@example.com",
		"al@example.com",
		"a@example.com",
		"o'brien@example.com",
		strings.Repeat("x", 70) + "@example.com",
		"no-at-sign",
	}
	for _, email := range emails {
		got := MirrorUsername(email)
		assert.True(t, iamUsernameRule.MatchString(got), "MirrorUsername(%q) = %q breaks the IAM username rule", email, got)
	}
	assert.NotEqual(t, MirrorUsername("ann@one.example"), MirrorUsername("ann@two.example"))
	assert.Equal(t, MirrorUsername("ann@example.com"), MirrorUsername(" Ann@Example.com "))
}

// TestMirrorInvitedUser_UsernameIgnoresTheDisplayName: the mirror sends
// MirrorUsername(email) as the IAM username whatever the display name, and
// keeps the display name as DisplayName (#2362).
func TestMirrorInvitedUser_UsernameIgnoresTheDisplayName(t *testing.T) {
	t.Parallel()
	cases := []struct{ email, displayName string }{
		{"jane.doe@example.com", ""},
		{"jane+tag@example.com", ""},
		{"al@example.com", ""},
		{"jane@example.com", "Jane Doe"},
	}
	for _, tc := range cases {
		var got *iamsdk.CreateUserRequest
		client := &mockIAMClient{
			createUserFn: func(_ context.Context, _ string, req *iamsdk.CreateUserRequest) (*iamsdk.User, error) {
				got = req
				return &iamsdk.User{}, nil
			},
		}
		_, err := NewQuicBaaSUserMirror(client).MirrorInvitedUser(
			context.Background(), "t1", tc.email, tc.displayName, []string{"viewer"})
		require.NoError(t, err, tc.email)
		require.NotNil(t, got, tc.email)
		assert.True(t, iamUsernameRule.MatchString(got.Username), "username %q for %q breaks the IAM username rule", got.Username, tc.email)
		assert.Equal(t, MirrorUsername(tc.email), got.Username, tc.email)
		assert.Equal(t, tc.displayName, got.DisplayName, tc.email)
	}
}
