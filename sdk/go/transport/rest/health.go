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

package rest

import (
	"errors"
	"net/http"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// probeMethods are the health probes. Their routes answer 503 when the probe
// fails and still carry the verdict in the body (docs/health/api.md §4), so
// a failed probe is an answer, as it is over gRPC, not a transport error.
var probeMethods = map[string]bool{
	platformv1.PlatformDaemon_GetHealth_FullMethodName: true,
	platformv1.PlatformDaemon_Liveness_FullMethodName:  true,
	platformv1.PlatformDaemon_Readiness_FullMethodName: true,
}

// probeVerdict reports whether err is a health probe's 503 verdict, decoding
// it into reply when it is. A 503 whose body is not the rpc's message (a
// proxy's error page, say) is not a verdict and stays an error.
func probeVerdict(method string, err error, reply interface{}) bool {
	if !probeMethods[method] {
		return false
	}
	var httpErr ErrHTTPStatus
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusServiceUnavailable {
		return false
	}
	return decodeJSONResult([]byte(httpErr.Body), reply) == nil
}
