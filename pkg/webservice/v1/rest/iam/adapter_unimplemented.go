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
	"strings"

	qberrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// upstreamUnimplemented maps an error that says the IAM service does not
// implement op (the pinned go-quicbaas embedded transport answers an
// unknown-method error for verbs it does not dispatch) to
// codes.Unimplemented, which handleError answers as 501. Any other error is
// returned unchanged. An operation the pinned upstream lacks is refused,
// never emulated.
func upstreamUnimplemented(op string, err error) error {
	if err == nil {
		return nil
	}
	if qberrors.IsUnimplemented(err) || status.Code(err) == codes.Unimplemented {
		return status.Errorf(codes.Unimplemented, "%s is not implemented by the pinned IAM service: %v", op, err)
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "unknown method") ||
		strings.Contains(msg, "not implemented") ||
		strings.Contains(msg, "unimplemented") {
		return status.Errorf(codes.Unimplemented, "%s is not implemented by the pinned IAM service: %v", op, err)
	}
	return err
}
