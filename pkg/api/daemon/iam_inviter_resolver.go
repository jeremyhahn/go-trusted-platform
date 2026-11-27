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
	"fmt"
	"strconv"

	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"

	platformservice "github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
)

// ErrInviterIDNotUsable reports an IAM user whose canonical id is not a
// positive decimal, so it cannot be recorded as an invitation's inviter.
type ErrInviterIDNotUsable struct {
	ID string
}

func (e ErrInviterIDNotUsable) Error() string {
	return fmt.Sprintf("the inviter's IAM user id %q is not a positive decimal and cannot be recorded as the inviter", e.ID)
}

// iamInviterResolver reads IAM, not the platform-local user store, so the unclaimed /init admin and IAM-only system administrators resolve (#2362).
type iamInviterResolver struct {
	client   restiam.IAMClient
	tenantID string
}

func newIAMInviterResolver(client restiam.IAMClient, tenantID string) *iamInviterResolver {
	return &iamInviterResolver{client: client, tenantID: tenantID}
}

// GetByEmail looks the login email up in the resolver's IAM tenant. An IAM
// not-found answers platformservice.ErrUserNotFound so the caller tries the
// next name; an id that is not a positive decimal answers
// ErrInviterIDNotUsable.
func (r *iamInviterResolver) GetByEmail(ctx context.Context, email string) (*entities.User, error) {
	user, err := r.client.GetUserByEmail(ctx, r.tenantID, email)
	if err != nil {
		if sdkerrors.IsNotFound(err) {
			return nil, platformservice.ErrUserNotFound{Email: email}
		}
		return nil, fmt.Errorf("resolve the inviter in IAM: %w", err)
	}
	if user == nil {
		return nil, platformservice.ErrUserNotFound{Email: email}
	}
	id, parseErr := strconv.ParseUint(user.ID, 10, 64)
	if parseErr != nil || id == 0 {
		return nil, ErrInviterIDNotUsable{ID: user.ID}
	}
	return &entities.User{ID: id, Email: user.Email}, nil
}
