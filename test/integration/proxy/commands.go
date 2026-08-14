// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build integration

package proxy

import (
	"context"
	"fmt"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// ProxyCommands is the transport-agnostic surface every adapter (CLI plus
// the five SDK transports) implements, so the multi-protocol test body runs
// unchanged against each protocol.
type ProxyCommands interface {
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

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

	Status(ctx context.Context) (*platformv1.GetProxyStatusResponse, error)
	Reload(ctx context.Context) (uint64, error)
	ZoneMatrix(ctx context.Context) (*platformv1.GetProxyZoneMatrixResponse, error)
}

// ErrConnectionFailed indicates the adapter could not connect to platformd.
type ErrConnectionFailed struct {
	Protocol string
	Endpoint string
	Err      error
}

func (e ErrConnectionFailed) Error() string {
	return fmt.Sprintf("%s connection to %s failed: %v", e.Protocol, e.Endpoint, e.Err)
}

func (e ErrConnectionFailed) Unwrap() error { return e.Err }

// ErrCLICommandFailed indicates a platformctl invocation failed.
type ErrCLICommandFailed struct {
	Args   []string
	Output string
	Err    error
}

func (e ErrCLICommandFailed) Error() string {
	return fmt.Sprintf("platformctl %v failed: %v: %s", e.Args, e.Err, e.Output)
}

func (e ErrCLICommandFailed) Unwrap() error { return e.Err }

// ErrCLIDecodeFailed indicates platformctl JSON output did not parse.
type ErrCLIDecodeFailed struct {
	Args   []string
	Output string
	Err    error
}

func (e ErrCLIDecodeFailed) Error() string {
	return fmt.Sprintf("decoding platformctl %v output failed: %v: %s", e.Args, e.Err, e.Output)
}

func (e ErrCLIDecodeFailed) Unwrap() error { return e.Err }
