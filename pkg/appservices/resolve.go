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

package appservices

import (
	"errors"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/transport/embedded"
)

// Resolver returns the SDK client of one service group, or nil while the
// SDK does not serve it.
type Resolver[C any] func() C

// resolve returns the client the resolver yields, or ErrNotConfigured when
// there is no resolver or it yields nil.
func resolve[C any](service string, resolver Resolver[C]) (C, error) {
	var zero C
	if resolver == nil {
		return zero, ErrNotConfigured{Service: service}
	}
	client := resolver()
	if any(client) == nil {
		return zero, ErrNotConfigured{Service: service}
	}
	return client, nil
}

// callFailed wraps an SDK error, or returns nil when there is none. The
// embedded transport answers a method it has no handler for with
// UnknownMethodError, which means the SDK on this node does not serve the
// service: that is ErrNotConfigured, not a failed call.
func callFailed(service, op string, err error) error {
	if err == nil {
		return nil
	}
	var unknown *embedded.UnknownMethodError
	if errors.As(err, &unknown) {
		return ErrNotConfigured{Service: service}
	}
	return ErrCallFailed{Service: service, Op: op, Cause: err}
}

// requireName refuses an empty name.
func requireName(service, field, name string) error {
	if name == "" {
		return ErrInvalidArgument{Service: service, Field: field, Reason: "is required"}
	}
	return nil
}

// requireNotNegative refuses a negative count or duration.
func requireNotNegative[N ~int | ~int64](service, field string, value N) error {
	if value < 0 {
		return ErrInvalidArgument{Service: service, Field: field, Reason: "must not be negative"}
	}
	return nil
}
