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

// upstreamUnimplemented maps an upstream refusal of an operation the pinned
// IAM service does not implement (the embedded transport's unknown method,
// an SDK unimplemented error or a gRPC Unimplemented status) to
// codes.Unimplemented, which the REST layer answers with 501. Any other
// error is returned unchanged. Nothing is emulated locally.
func upstreamUnimplemented(op string, err error) error {
	if err == nil {
		return nil
	}
	if qberrors.IsUnimplemented(err) || status.Code(err) == codes.Unimplemented || isUnimplementedMessage(err.Error()) {
		return status.Errorf(codes.Unimplemented, "%s is not implemented by the pinned IAM service: %v", op, err)
	}
	return err
}

func isUnimplementedMessage(msg string) bool {
	msg = strings.ToLower(msg)
	return strings.Contains(msg, "unknown method") ||
		strings.Contains(msg, "not implemented") ||
		strings.Contains(msg, "unimplemented")
}
