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
	"testing"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/transport/embedded"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// emailLookupUserClient answers GetByEmail with getErr and serves List from
// pages, one page per call, keyed by the request's PageToken.
type emailLookupUserClient struct {
	iamsdk.UserClient
	getErr     error
	pages      map[string]iamsdk.ListUsersResponse
	listTokens []string
}

func (c *emailLookupUserClient) GetByEmail(context.Context, string, string) (*iamsdk.User, error) {
	return nil, c.getErr
}

func (c *emailLookupUserClient) List(_ context.Context, _ string, req *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
	tok := ""
	if req != nil {
		tok = req.PageToken
	}
	c.listTokens = append(c.listTokens, tok)
	page := c.pages[tok]
	return &page, nil
}

type emailLookupSDKClient struct {
	iamsdk.Client
	users *emailLookupUserClient
}

func (c *emailLookupSDKClient) User() iamsdk.UserClient { return c.users }

func unknownGetByEmail() error {
	return embedded.NewUnknownMethodError("quicbaas.IAM.User", "GetByEmail")
}

// twoUserPages holds the users on two pages: the first page links to "p2".
func twoUserPages(second ...iamsdk.User) map[string]iamsdk.ListUsersResponse {
	return map[string]iamsdk.ListUsersResponse{
		"": {
			Users:      []iamsdk.User{{ID: "u1", Email: "first@example.com"}},
			Pagination: iamsdk.PaginationInfo{NextPageToken: "p2", HasMore: true},
		},
		"p2": {Users: second},
	}
}

func TestGetUserByEmailFallsBackToListWhenUnimplemented(t *testing.T) {
	t.Parallel()
	users := &emailLookupUserClient{
		getErr: unknownGetByEmail(),
		pages:  twoUserPages(iamsdk.User{ID: "u2", Email: "owner@example.com"}),
	}
	adapter := NewQuicBaaSIAMAdapter(&emailLookupSDKClient{users: users})

	user, err := adapter.GetUserByEmail(context.Background(), "tenant-a", "owner@example.com")

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "u2", user.ID)
	assert.Equal(t, []string{"", "p2"}, users.listTokens)
}

func TestGetUserByEmailFallbackNoMatchIsNotFound(t *testing.T) {
	t.Parallel()
	users := &emailLookupUserClient{
		getErr: unknownGetByEmail(),
		pages:  twoUserPages(iamsdk.User{ID: "u2", Email: "other@example.com"}),
	}
	adapter := NewQuicBaaSIAMAdapter(&emailLookupSDKClient{users: users})

	user, err := adapter.GetUserByEmail(context.Background(), "tenant-a", "owner@example.com")

	require.Error(t, err)
	assert.Nil(t, user)
	assert.True(t, sdkerrors.IsNotFound(err), "got %v", err)
}

func TestGetUserByEmailOtherErrorsAreReturned(t *testing.T) {
	t.Parallel()
	denied := errors.New("permission denied")
	users := &emailLookupUserClient{
		getErr: denied,
		pages:  twoUserPages(iamsdk.User{ID: "u2", Email: "owner@example.com"}),
	}
	adapter := NewQuicBaaSIAMAdapter(&emailLookupSDKClient{users: users})

	user, err := adapter.GetUserByEmail(context.Background(), "tenant-a", "owner@example.com")

	assert.Nil(t, user)
	assert.Same(t, denied, err)
	assert.Empty(t, users.listTokens, "List must not be called")
}

func TestGetUserByEmailFallbackMatchesExactly(t *testing.T) {
	t.Parallel()
	users := &emailLookupUserClient{
		getErr: unknownGetByEmail(),
		pages: twoUserPages(
			iamsdk.User{ID: "u2", Email: "Owner@Example.com"},
			iamsdk.User{ID: "u3", Email: "owner@example.com.evil"},
		),
	}
	adapter := NewQuicBaaSIAMAdapter(&emailLookupSDKClient{users: users})

	user, err := adapter.GetUserByEmail(context.Background(), "tenant-a", "owner@example.com")

	assert.Nil(t, user)
	assert.True(t, sdkerrors.IsNotFound(err), "got %v", err)
}

// TestGetUserByEmail_FallbackFullPageWithoutTokenIsNotNotFound covers a
// listing that ignores PageToken: a full page with no NextPageToken may hide
// the user on a later page, so the miss must not be reported as not found.
func TestGetUserByEmail_FallbackFullPageWithoutTokenIsNotNotFound(t *testing.T) {
	t.Parallel()
	full := make([]iamsdk.User, emailLookupPageSize)
	for i := range full {
		full[i] = iamsdk.User{ID: "u", Email: "someone@example.com"}
	}
	users := &emailLookupUserClient{
		getErr: unknownGetByEmail(),
		pages:  map[string]iamsdk.ListUsersResponse{"": {Users: full}},
	}
	adapter := NewQuicBaaSIAMAdapter(&emailLookupSDKClient{users: users})

	user, err := adapter.GetUserByEmail(context.Background(), "tenant-a", "owner@example.com")

	require.Error(t, err)
	assert.Nil(t, user)
	assert.False(t, sdkerrors.IsNotFound(err), "a truncated listing is not proof of absence: %v", err)
	assert.True(t, sdkerrors.IsUnavailable(err), "got %v", err)
	assert.Equal(t, []string{""}, users.listTokens)
}
