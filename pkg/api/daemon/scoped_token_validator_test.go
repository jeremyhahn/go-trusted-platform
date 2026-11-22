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

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
)

// scopedTokenValidator accepts every token and grants it scopes.
type scopedTokenValidator struct {
	scopes []string
}

func (v scopedTokenValidator) ValidateToken(ctx context.Context, token string) (bool, error) {
	return true, nil
}

func (v scopedTokenValidator) AuthorizeToken(ctx context.Context, token, requiredPerm, dpopProof, htm, htu string) (*platformtoken.AuthorizedContext, error) {
	return &platformtoken.AuthorizedContext{Subject: "u", Scopes: v.scopes}, nil
}
