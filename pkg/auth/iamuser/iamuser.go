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

// Package iamuser finds one IAM user by email or username on every
// go-quicbaas transport the platform runs on, and says whether IAM holds
// that user as active (#646).
//
// The pinned SDK's embedded transport registers only User/Get and User/List
// for users: User/GetByEmail and User/FindByUsername answer "unknown method"
// there. Find asks the transport's own lookup first and, only when the
// transport does not implement it, lists the tenant's users and picks the
// one that matches. Every other failure is returned as it is, so a lookup
// that IAM refused or could not answer is never mistaken for "no such user".
package iamuser

import (
	"context"
	"errors"
	"strings"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/transport/embedded"
)

// maxListPages bounds the listing fallback, so a transport that keeps
// handing out page tokens cannot hold a lookup forever.
const maxListPages = 1000

// Lookup is the transport's own one-user lookup, such as UserClient.GetByEmail
// or UserClient.FindByUsername bound to a tenant and a key.
type Lookup func(ctx context.Context) (*sdkiam.User, error)

// Lister lists one page of the tenant's users, such as UserClient.List bound
// to a tenant.
type Lister func(ctx context.Context, req *sdkiam.ListUsersRequest) (*sdkiam.ListUsersResponse, error)

// Matcher reports whether a listed user is the one being looked up.
type Matcher func(user *sdkiam.User) bool

// ErrAmbiguous is returned when the listing fallback finds more than one
// user for a key IAM keeps unique. The lookup fails closed rather than pick
// one of them.
var ErrAmbiguous = errors.New("iamuser: more than one IAM user matches")

// Find returns the user lookup names. When the transport does not implement
// lookup, Find pages through list and returns the single user match accepts,
// or a NotFound error when none does.
//
// On the embedded transport the listing is the store's first page (qrdb
// serves 100 users when no page size reaches it): a user beyond it is not
// found, so the caller refuses rather than admits.
func Find(ctx context.Context, lookup Lookup, list Lister, match Matcher) (*sdkiam.User, error) {
	user, err := lookup(ctx)
	if err == nil || !Unimplemented(err) {
		return user, err
	}

	var found *sdkiam.User
	seen := map[string]struct{}{}
	token := ""
	for page := 0; page < maxListPages; page++ {
		resp, listErr := list(ctx, &sdkiam.ListUsersRequest{PageToken: token})
		if listErr != nil {
			return nil, listErr
		}
		if resp == nil {
			break
		}
		for i := range resp.Users {
			if !match(&resp.Users[i]) {
				continue
			}
			if found != nil {
				return nil, ErrAmbiguous
			}
			hit := resp.Users[i]
			found = &hit
		}
		next := resp.Pagination.NextPageToken
		if next == "" {
			break
		}
		if _, again := seen[next]; again {
			break
		}
		seen[next] = struct{}{}
		token = next
	}
	if found == nil {
		return nil, sdkerrors.NewNotFound("iamuser.Find", "user not found")
	}
	return found, nil
}

// ByEmail matches the user whose email is email, ignoring case and
// surrounding space. An empty email matches no one.
func ByEmail(email string) Matcher {
	want := strings.TrimSpace(email)
	return func(user *sdkiam.User) bool {
		return want != "" && user != nil && strings.EqualFold(strings.TrimSpace(user.Email), want)
	}
}

// ByUsername matches the user whose tenant-scoped username is username. An
// empty username matches no one.
func ByUsername(username string) Matcher {
	return func(user *sdkiam.User) bool {
		return username != "" && user != nil && user.Username == username
	}
}

// Unimplemented reports whether err is a transport saying it has no handler
// for the method: the embedded transport's UnknownMethodError, or an SDK
// Unimplemented error from a remote one.
func Unimplemented(err error) bool {
	var unknown *embedded.UnknownMethodError
	return errors.As(err, &unknown) || sdkerrors.IsUnimplemented(err)
}

// Active reports whether IAM holds the user as active. Lifecycle is the
// state the store holds (pending, active, suspended, locked, disabled or
// deleting) and only "active" passes. Status is the SDK's coarser enum,
// read only when the transport leaves Lifecycle empty.
func Active(user *sdkiam.User) bool {
	if user == nil {
		return false
	}
	if user.Lifecycle != "" {
		return user.Lifecycle == "active"
	}
	return user.Status == sdkiam.UserStatusActive || user.Status == sdkiam.UserStatusUnspecified
}
