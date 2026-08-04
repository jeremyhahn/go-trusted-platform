//go:build awscompute

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

package aws

import (
	"errors"
	"strings"

	"github.com/aws/smithy-go"
)

// isNotFound reports whether an EC2 API error is a "resource not found"
// condition. EC2 signals these with error codes ending in ".NotFound"
// (e.g. InvalidInstanceID.NotFound, InvalidSnapshot.NotFound).
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		return strings.Contains(code, "NotFound")
	}
	return strings.Contains(err.Error(), "NotFound")
}
