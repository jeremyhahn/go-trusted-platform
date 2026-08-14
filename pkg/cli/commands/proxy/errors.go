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

package proxy

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}

// proxyClient is the subset of the SDK proxy client the CLI commands use.
// It is satisfied by *proxysvc.Client and by test fakes.
type proxyClient interface {
	CreateRoute(ctx context.Context, route *platformv1.ProxyRoute) (*platformv1.ProxyRoute, uint64, error)
	GetRoute(ctx context.Context, id string) (*platformv1.ProxyRoute, error)
	UpdateRoute(ctx context.Context, route *platformv1.ProxyRoute) (*platformv1.ProxyRoute, uint64, error)
	DeleteRoute(ctx context.Context, id string) (uint64, error)
	ListRoutes(ctx context.Context) ([]*platformv1.ProxyRoute, uint64, error)
	CreatePool(ctx context.Context, pool *platformv1.ProxyPool) (*platformv1.ProxyPool, uint64, error)
	GetPool(ctx context.Context, id string) (*platformv1.ProxyPool, error)
	UpdatePool(ctx context.Context, pool *platformv1.ProxyPool) (*platformv1.ProxyPool, uint64, error)
	DeletePool(ctx context.Context, id string) (uint64, error)
	ListPools(ctx context.Context) ([]*platformv1.ProxyPool, uint64, error)
	Config(ctx context.Context) (*platformv1.GetProxyConfigResponse, error)
	Status(ctx context.Context) (*platformv1.GetProxyStatusResponse, error)
	Reload(ctx context.Context) (uint64, error)
	ZoneMatrix(ctx context.Context) (*platformv1.GetProxyZoneMatrixResponse, error)
}
