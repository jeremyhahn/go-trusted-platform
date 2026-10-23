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
	"errors"
	"math"
	"time"

	sdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/appservices"
	"github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/cache"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/messaging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/objectstorage"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/scheduler"
)

// appServiceServers are the gRPC services of the application services the
// composed go-quicbaas SDK serves: Cache, Scheduler, Messaging and
// ObjectStorage. One
// instance of each backs gRPC, the Unix socket, REST, QUIC and MCP.
type appServiceServers struct {
	cache         *CacheGRPCService
	scheduler     *SchedulerGRPCService
	messaging     *MessagingGRPCService
	objectStorage *ObjectStorageGRPCService
}

// newAppServiceServers builds the application services over the SDK the
// daemon's quicbaas DAO factory holds. The SDK is resolved on every call: it
// starts after the transports, and a node whose factory has no SDK answers
// the typed not-configured status.
func newAppServiceServers(config *Config, logger *logging.Logger) appServiceServers {
	return appServiceServersOver(func() sdk.Client { return platformSDK(config) }, logger)
}

// appServiceServersOver builds the servers over the SDK client sdkClient
// yields at call time; a nil client is a service the node does not serve.
func appServiceServersOver(sdkClient func() sdk.Client, logger *logging.Logger) appServiceServers {
	return appServiceServers{
		cache: NewCacheGRPCService(logger, appservices.NewCacheService(func() cache.Client {
			if client := sdkClient(); client != nil {
				return client.Cache()
			}
			return nil
		})),
		scheduler: NewSchedulerGRPCService(logger, appservices.NewSchedulerService(func() scheduler.Client {
			if client := sdkClient(); client != nil {
				return client.Scheduler()
			}
			return nil
		})),
		messaging: NewMessagingGRPCService(logger, appservices.NewMessagingService(func() messaging.Client {
			if client := sdkClient(); client != nil {
				return client.Messaging()
			}
			return nil
		})),
		objectStorage: NewObjectStorageGRPCService(logger, appservices.NewObjectStorageService(func() objectstorage.Client {
			if client := sdkClient(); client != nil {
				return client.ObjectStorage()
			}
			return nil
		})),
	}
}

// restServers returns the servers the REST handlers bind to. A missing
// server stays a nil interface, so its routes answer 503 instead of calling
// through a typed nil pointer.
func (s appServiceServers) restServers() restapi.AppServiceServers {
	var servers restapi.AppServiceServers
	if s.cache != nil {
		servers.Cache = s.cache
	}
	if s.scheduler != nil {
		servers.Scheduler = s.scheduler
	}
	if s.messaging != nil {
		servers.Messaging = s.messaging
	}
	if s.objectStorage != nil {
		servers.ObjectStorage = s.objectStorage
	}
	return servers
}

// AppServiceRESTServers returns the servers backing /api/v1/cache,
// /api/v1/scheduler, /api/v1/messaging and /api/v1/object-storage on the
// webservice listener: the
// instances every other transport shares.
func (d *Daemon) AppServiceRESTServers() restapi.AppServiceServers {
	return d.appServices.restServers()
}

// mcpServers returns the servers the MCP tools bind to, with the same
// nil-interface guarantee as restServers.
func (s appServiceServers) mcpServers() mcp.AppServiceServers {
	return mcp.AppServiceServers(s.restServers())
}

// SetAppServiceServers wires the servers the cache_*, scheduler_*,
// messaging_* and objectstorage_* MCP tools delegate to.
func (m *MCPServiceProvider) SetAppServiceServers(servers mcp.AppServiceServers) {
	m.appServices = servers
}

// AppServiceServers implements mcp.AppServiceProvider.
func (m *MCPServiceProvider) AppServiceServers() mcp.AppServiceServers {
	return m.appServices
}

// platformSDK returns the composed go-quicbaas SDK client of the daemon's
// quicbaas DAO factory, or nil when there is none yet.
func platformSDK(config *Config) sdk.Client {
	if config == nil || config.App == nil {
		return nil
	}
	factory, ok := config.App.DAOFactory().(*quicbaas.Factory)
	if !ok || factory == nil {
		return nil
	}
	return factory.SDK()
}

// appServiceError renders a service-layer error as the gRPC status every
// transport carries, and logs the failures that are not the caller's.
func appServiceError(logger *logging.Logger, op string, err error) error {
	st := appServiceStatus(err)
	if st.Code() == codes.Internal {
		logger.Error(err, op+" failed")
	}
	return st.Err()
}

func appServiceStatus(err error) *status.Status {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err)
	}
	var (
		notConfigured appservices.ErrNotConfigured
		invalid       appservices.ErrInvalidArgument
	)
	switch {
	case errors.As(err, &notConfigured):
		return ErrServiceNotConfigured{Service: notConfigured.Service, Detail: notConfigured.Error()}.GRPCStatus()
	case errors.As(err, &invalid):
		return status.New(codes.InvalidArgument, err.Error())
	}
	// An SDK error keeps its code: a typed SDK error (QBError) by its error
	// code, one from the gRPC transport by its status. The message names the
	// operation that failed.
	if code, ok := barrier.SDKCode(err); ok {
		return status.New(code, err.Error())
	}
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		return status.New(st.Code(), err.Error())
	}
	return status.New(codes.Internal, err.Error())
}

// appUnixMillis renders a time as Unix milliseconds, the zero time as 0.
func appUnixMillis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// appTime parses Unix milliseconds, 0 as the zero time.
func appTime(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

// appDuration converts milliseconds to a duration.
func appDuration(ms int64) time.Duration {
	return time.Duration(ms) * time.Millisecond
}

// appInt32 narrows a count for the wire, saturating rather than wrapping.
func appInt32(v int) int32 {
	switch {
	case v > math.MaxInt32:
		return math.MaxInt32
	case v < math.MinInt32:
		return math.MinInt32
	default:
		return int32(v)
	}
}
