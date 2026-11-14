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

package iamuser_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/pkg/iam"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/auth/iamuser"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth/iamuser/iamusertest"
)

// The pinned embedded transport has no User/GetByEmail or User/FindByUsername:
// this is the gap Find closes, so the test pins it.
func TestEmbeddedTransportHasNoEmailOrUsernameLookup(t *testing.T) {
	t.Parallel()
	e := iamusertest.NewEmbedded(t)
	e.AddUser(t, "tenant-a", "alice@example.com", "alice", iam.LifecycleActive)
	ctx := context.Background()

	_, err := e.Client.User().GetByEmail(ctx, "tenant-a", "alice@example.com")
	assert.True(t, iamuser.Unimplemented(err), "GetByEmail on the embedded transport: %v", err)
	_, err = e.Client.User().FindByUsername(ctx, "tenant-a", "alice")
	assert.True(t, iamuser.Unimplemented(err), "FindByUsername on the embedded transport: %v", err)
}

func TestFindResolvesThroughTheEmbeddedTransport(t *testing.T) {
	t.Parallel()
	e := iamusertest.NewEmbedded(t)
	e.AddRole(t, "tenant-a", "admin")
	aliceID := e.AddUser(t, "tenant-a", "alice@example.com", "alice", iam.LifecycleActive, "admin")
	e.AddUser(t, "tenant-a", "bob@example.com", "bob", iam.LifecycleActive)
	e.AddUser(t, "tenant-b", "carol@example.com", "carol", iam.LifecycleActive)
	users := e.Client.User()
	ctx := context.Background()
	list := func(tenant string) iamuser.Lister {
		return func(ctx context.Context, req *sdkiam.ListUsersRequest) (*sdkiam.ListUsersResponse, error) {
			return users.List(ctx, tenant, req)
		}
	}
	byEmail := func(tenant, email string) (*sdkiam.User, error) {
		return iamuser.Find(ctx, func(ctx context.Context) (*sdkiam.User, error) {
			return users.GetByEmail(ctx, tenant, email)
		}, list(tenant), iamuser.ByEmail(email))
	}
	byUsername := func(tenant, username string) (*sdkiam.User, error) {
		return iamuser.Find(ctx, func(ctx context.Context) (*sdkiam.User, error) {
			return users.FindByUsername(ctx, tenant, username)
		}, list(tenant), iamuser.ByUsername(username))
	}

	t.Run("by email, in any case", func(t *testing.T) {
		user, err := byEmail("tenant-a", "Alice@Example.com")
		require.NoError(t, err)
		assert.Equal(t, aliceID, user.ID)
		assert.Equal(t, []string{"admin"}, user.Roles)
	})
	t.Run("by username", func(t *testing.T) {
		user, err := byUsername("tenant-a", "alice")
		require.NoError(t, err)
		assert.Equal(t, aliceID, user.ID)
	})
	t.Run("an email is not a username", func(t *testing.T) {
		_, err := byUsername("tenant-a", "alice@example.com")
		assert.True(t, sdkerrors.IsNotFound(err), "%v", err)
	})
	t.Run("another tenant's user is not found", func(t *testing.T) {
		_, err := byEmail("tenant-a", "carol@example.com")
		assert.True(t, sdkerrors.IsNotFound(err), "%v", err)
	})
	t.Run("a user IAM does not hold is not found", func(t *testing.T) {
		_, err := byEmail("tenant-a", "nobody@example.com")
		assert.True(t, sdkerrors.IsNotFound(err), "%v", err)
	})
}

func TestActiveRefusesEveryStateButActive(t *testing.T) {
	t.Parallel()
	e := iamusertest.NewEmbedded(t)
	states := map[iam.Lifecycle]bool{
		iam.LifecycleActive:    true,
		iam.LifecycleSuspended: false,
		iam.LifecycleLocked:    false,
		iam.LifecycleDisabled:  false,
	}
	for state, want := range states {
		id := e.AddUser(t, "tenant-a", string(state)+"@example.com", string(state), state)
		user, err := e.Client.User().Get(context.Background(), "tenant-a", id)
		require.NoError(t, err)
		assert.Equal(t, string(state), user.Lifecycle, "the embedded transport carries the lifecycle")
		assert.Equal(t, want, iamuser.Active(user), "lifecycle %s", state)
	}

	assert.False(t, iamuser.Active(nil))
	assert.False(t, iamuser.Active(&sdkiam.User{Lifecycle: "pending"}))
	assert.False(t, iamuser.Active(&sdkiam.User{Status: sdkiam.UserStatusSuspended}))
	assert.True(t, iamuser.Active(&sdkiam.User{Status: sdkiam.UserStatusActive}))
}

func TestFindUsesTheTransportLookupWhenItHasOne(t *testing.T) {
	t.Parallel()
	want := &sdkiam.User{ID: "u1"}
	listed := false
	list := func(context.Context, *sdkiam.ListUsersRequest) (*sdkiam.ListUsersResponse, error) {
		listed = true
		return nil, nil
	}

	user, err := iamuser.Find(context.Background(), func(context.Context) (*sdkiam.User, error) { return want, nil }, list, iamuser.ByEmail("a@example.com"))
	require.NoError(t, err)
	assert.Same(t, want, user)

	refused := sdkerrors.NewUnavailable("iam", "down")
	_, err = iamuser.Find(context.Background(), func(context.Context) (*sdkiam.User, error) { return nil, refused }, list, iamuser.ByEmail("a@example.com"))
	assert.ErrorIs(t, err, refused, "a lookup IAM could not answer is not turned into a listing")
	assert.False(t, listed)
}

func TestFindListingFallback(t *testing.T) {
	t.Parallel()
	unimplemented := func(context.Context) (*sdkiam.User, error) {
		return nil, sdkerrors.NewUnimplemented("iam.user.GetByEmail", "no")
	}
	pages := func(pages map[string]*sdkiam.ListUsersResponse) iamuser.Lister {
		return func(_ context.Context, req *sdkiam.ListUsersRequest) (*sdkiam.ListUsersResponse, error) {
			return pages[req.PageToken], nil
		}
	}
	page := func(next string, emails ...string) *sdkiam.ListUsersResponse {
		resp := &sdkiam.ListUsersResponse{Pagination: sdkiam.PaginationInfo{NextPageToken: next}}
		for _, email := range emails {
			resp.Users = append(resp.Users, sdkiam.User{ID: email, Email: email})
		}
		return resp
	}

	t.Run("follows page tokens", func(t *testing.T) {
		user, err := iamuser.Find(context.Background(), unimplemented, pages(map[string]*sdkiam.ListUsersResponse{
			"":   page("p2", "a@example.com"),
			"p2": page("", "b@example.com"),
		}), iamuser.ByEmail("b@example.com"))
		require.NoError(t, err)
		assert.Equal(t, "b@example.com", user.ID)
	})
	t.Run("two matches fail closed", func(t *testing.T) {
		_, err := iamuser.Find(context.Background(), unimplemented, pages(map[string]*sdkiam.ListUsersResponse{
			"":   page("p2", "b@example.com"),
			"p2": page("", "B@example.com"),
		}), iamuser.ByEmail("b@example.com"))
		assert.ErrorIs(t, err, iamuser.ErrAmbiguous)
	})
	t.Run("a repeated page token ends the listing", func(t *testing.T) {
		_, err := iamuser.Find(context.Background(), unimplemented, pages(map[string]*sdkiam.ListUsersResponse{
			"":   page("p2", "a@example.com"),
			"p2": page("p2", "c@example.com"),
		}), iamuser.ByEmail("b@example.com"))
		assert.True(t, sdkerrors.IsNotFound(err), "%v", err)
	})
	t.Run("a listing error is returned", func(t *testing.T) {
		boom := errors.New("boom")
		_, err := iamuser.Find(context.Background(), unimplemented, func(context.Context, *sdkiam.ListUsersRequest) (*sdkiam.ListUsersResponse, error) {
			return nil, boom
		}, iamuser.ByEmail("b@example.com"))
		assert.ErrorIs(t, err, boom)
	})
	t.Run("an empty key matches no one", func(t *testing.T) {
		_, err := iamuser.Find(context.Background(), unimplemented, pages(map[string]*sdkiam.ListUsersResponse{
			"": {Users: []sdkiam.User{{ID: "x"}}},
		}), iamuser.ByUsername(""))
		assert.True(t, sdkerrors.IsNotFound(err), "%v", err)
	})
}
