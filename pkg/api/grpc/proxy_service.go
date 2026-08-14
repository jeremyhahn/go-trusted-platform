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

package grpc

import (
	"context"
	"errors"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Proxy gRPC service error types
// =============================================================================

// ErrNilProxyService is returned when the proxy service backend is nil.
type ErrNilProxyService struct{}

func (e ErrNilProxyService) Error() string {
	return "proxy service is nil"
}

// ErrMissingRouteID is returned when a route ID is required but not provided.
type ErrMissingRouteID struct{}

func (e ErrMissingRouteID) Error() string {
	return "route id is required"
}

// ErrMissingPoolID is returned when a pool ID is required but not provided.
type ErrMissingPoolID struct{}

func (e ErrMissingPoolID) Error() string {
	return "pool id is required"
}

// ErrMissingRoute is returned when a route body is required but not provided.
type ErrMissingRoute struct{}

func (e ErrMissingRoute) Error() string {
	return "route is required"
}

// ErrMissingPool is returned when a pool body is required but not provided.
type ErrMissingPool struct{}

func (e ErrMissingPool) Error() string {
	return "pool is required"
}

// ErrRouteIDMismatch is returned when the request ID and the route body ID
// are both set but differ.
type ErrRouteIDMismatch struct {
	RequestID string
	BodyID    string
}

func (e ErrRouteIDMismatch) Error() string {
	return "route id mismatch: request id " + e.RequestID + " != route id " + e.BodyID
}

// ErrPoolIDMismatch is returned when the request ID and the pool body ID
// are both set but differ.
type ErrPoolIDMismatch struct {
	RequestID string
	BodyID    string
}

func (e ErrPoolIDMismatch) Error() string {
	return "pool id mismatch: request id " + e.RequestID + " != pool id " + e.BodyID
}

// ErrProxyRouteNotFound indicates the requested route does not exist. Proxy
// service backends return this type so the transport layers map it to
// NotFound consistently.
type ErrProxyRouteNotFound struct {
	ID string
}

func (e ErrProxyRouteNotFound) Error() string {
	return "proxy route not found: " + e.ID
}

// ErrProxyRouteExists indicates a route with the same ID already exists.
type ErrProxyRouteExists struct {
	ID string
}

func (e ErrProxyRouteExists) Error() string {
	return "proxy route already exists: " + e.ID
}

// ErrProxyPoolNotFound indicates the requested pool does not exist.
type ErrProxyPoolNotFound struct {
	ID string
}

func (e ErrProxyPoolNotFound) Error() string {
	return "proxy pool not found: " + e.ID
}

// ErrProxyPoolExists indicates a pool with the same ID already exists.
type ErrProxyPoolExists struct {
	ID string
}

func (e ErrProxyPoolExists) Error() string {
	return "proxy pool already exists: " + e.ID
}

// ErrProxyPoolInUse indicates a pool cannot be deleted because one or more
// routes reference it.
type ErrProxyPoolInUse struct {
	ID     string
	Routes []string
}

func (e ErrProxyPoolInUse) Error() string {
	msg := "proxy pool in use: " + e.ID
	for i, r := range e.Routes {
		if i == 0 {
			msg += " (referenced by routes: " + r
			continue
		}
		msg += ", " + r
	}
	if len(e.Routes) > 0 {
		msg += ")"
	}
	return msg
}

// ErrProxyZoneMatrixUnavailable indicates no zone source is wired into the
// proxy service so the zone matrix cannot be computed.
type ErrProxyZoneMatrixUnavailable struct{}

func (e ErrProxyZoneMatrixUnavailable) Error() string {
	return "proxy zone matrix unavailable: no zone service configured"
}

// ErrProxyOperationFailed wraps an unclassified proxy backend failure.
type ErrProxyOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrProxyOperationFailed) Error() string {
	if e.Cause != nil {
		return "proxy operation " + e.Operation + " failed: " + e.Cause.Error()
	}
	return "proxy operation " + e.Operation + " failed"
}

// Unwrap exposes the underlying cause for errors.Is/As.
func (e ErrProxyOperationFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// ProxyService backend interface
// =============================================================================

// ProxyStatusInfo is the source-of-truth status snapshot for the proxy
// configuration store.
type ProxyStatusInfo struct {
	Version    uint64
	RouteCount int
	PoolCount  int
	UpdatedAt  time.Time
}

// ProxyZonePairInfo is one allowed (from, to) cell of the compiled SDN zone
// matrix.
type ProxyZonePairInfo struct {
	From     string
	To       string
	Services []string
}

// ProxyZoneMatrixInfo carries the SDN zone names and the compiled allowed
// traffic pairs.
type ProxyZoneMatrixInfo struct {
	Zones []string
	Pairs []ProxyZonePairInfo
}

// ProxyService is the platform-side proxy configuration surface the gRPC
// service delegates to. It is satisfied by the daemon's proxy store adapter.
//
// Error contract: implementations return the typed errors declared in this
// package (ErrProxyRouteNotFound, ErrProxyRouteExists, ErrProxyPoolNotFound,
// ErrProxyPoolExists, ErrProxyPoolInUse, ErrProxyZoneMatrixUnavailable) and
// pkg/proxy validation errors (*proxy.ConfigError and its sentinels) so the
// transport layers map them to consistent status codes.
type ProxyService interface {
	// CreateRoute stores a new route and returns the stored (normalized)
	// route plus the new config version.
	CreateRoute(ctx context.Context, route proxy.RouteConfig) (proxy.RouteConfig, uint64, error)

	// Route returns the route with the given ID.
	Route(ctx context.Context, id string) (proxy.RouteConfig, error)

	// UpdateRoute replaces an existing route and returns the stored route
	// plus the new config version.
	UpdateRoute(ctx context.Context, route proxy.RouteConfig) (proxy.RouteConfig, uint64, error)

	// DeleteRoute removes a route and returns the new config version.
	DeleteRoute(ctx context.Context, id string) (uint64, error)

	// Routes returns all routes plus the current config version.
	Routes(ctx context.Context) ([]proxy.RouteConfig, uint64, error)

	// CreatePool stores a new backend pool and returns the stored pool plus
	// the new config version.
	CreatePool(ctx context.Context, pool proxy.BackendPoolConfig) (proxy.BackendPoolConfig, uint64, error)

	// Pool returns the pool with the given ID.
	Pool(ctx context.Context, id string) (proxy.BackendPoolConfig, error)

	// UpdatePool replaces an existing pool and returns the stored pool plus
	// the new config version.
	UpdatePool(ctx context.Context, pool proxy.BackendPoolConfig) (proxy.BackendPoolConfig, uint64, error)

	// DeletePool removes a pool and returns the new config version. Pools
	// referenced by routes cannot be deleted (ErrProxyPoolInUse).
	DeletePool(ctx context.Context, id string) (uint64, error)

	// Pools returns all pools plus the current config version.
	Pools(ctx context.Context) ([]proxy.BackendPoolConfig, uint64, error)

	// Snapshot returns the full merged configuration and version.
	Snapshot(ctx context.Context) ([]proxy.RouteConfig, []proxy.BackendPoolConfig, uint64, error)

	// Status reports the store status.
	Status(ctx context.Context) (*ProxyStatusInfo, error)

	// Reload bumps the config version and returns it.
	Reload(ctx context.Context) (uint64, error)

	// ZoneMatrix returns the SDN zone names and compiled allowed pairs.
	ZoneMatrix(ctx context.Context) (*ProxyZoneMatrixInfo, error)
}

// =============================================================================
// ProxyGRPCService
// =============================================================================

// ProxyGRPCService implements the gRPC ProxyService server interface. It
// wraps the ProxyService backend to provide gRPC access to the reverse-proxy
// route/pool configuration store. The same instance backs the REST, QUIC and
// MCP transports so every protocol shares one code path and error mapping.
type ProxyGRPCService struct {
	platformv1.UnimplementedProxyServiceServer
	logger  *logging.Logger
	service ProxyService
}

// NewProxyGRPCService creates a new ProxyGRPCService instance.
func NewProxyGRPCService(logger *logging.Logger, service ProxyService) *ProxyGRPCService {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &ProxyGRPCService{
		logger:  logger,
		service: service,
	}
}

// requireService returns a typed FailedPrecondition error when the backing
// proxy service is not configured. Every RPC guards with this instead of
// panicking on a nil backend.
func (s *ProxyGRPCService) requireService() error {
	if s.service == nil {
		return status.Error(codes.FailedPrecondition, ErrNilProxyService{}.Error())
	}
	return nil
}

// mapError translates backend errors into gRPC status errors with
// consistent codes across all transports.
func (s *ProxyGRPCService) mapError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var (
		routeNotFound ErrProxyRouteNotFound
		routeExists   ErrProxyRouteExists
		poolNotFound  ErrProxyPoolNotFound
		poolExists    ErrProxyPoolExists
		poolInUse     ErrProxyPoolInUse
		zoneUnavail   ErrProxyZoneMatrixUnavailable
		configErr     *proxy.ConfigError
	)
	switch {
	case errors.As(err, &routeNotFound), errors.As(err, &poolNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.As(err, &routeExists), errors.As(err, &poolExists):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.As(err, &poolInUse):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.As(err, &zoneUnavail):
		return status.Error(codes.Unavailable, err.Error())
	case errors.As(err, &configErr),
		errors.Is(err, proxy.ErrNoListeners):
		return status.Error(codes.InvalidArgument, err.Error())
	}
	s.logger.Error(err, "proxy operation failed", "operation", operation)
	return status.Error(codes.Internal, ErrProxyOperationFailed{Operation: operation, Cause: err}.Error())
}

// =============================================================================
// Route RPCs
// =============================================================================

// CreateRoute creates a new proxy route.
func (s *ProxyGRPCService) CreateRoute(
	ctx context.Context,
	req *platformv1.CreateProxyRouteRequest,
) (*platformv1.CreateProxyRouteResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if req.GetRoute() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingRoute{}.Error())
	}
	route := ProxyRouteFromProto(req.GetRoute())
	if route.ID == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingRouteID{}.Error())
	}
	stored, version, err := s.service.CreateRoute(ctx, route)
	if err != nil {
		return nil, s.mapError("CreateRoute", err)
	}
	return &platformv1.CreateProxyRouteResponse{
		Route:   ProxyRouteToProto(stored),
		Version: version,
	}, nil
}

// GetRoute retrieves a proxy route by ID.
func (s *ProxyGRPCService) GetRoute(
	ctx context.Context,
	req *platformv1.GetProxyRouteRequest,
) (*platformv1.GetProxyRouteResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingRouteID{}.Error())
	}
	route, err := s.service.Route(ctx, req.GetId())
	if err != nil {
		return nil, s.mapError("GetRoute", err)
	}
	return &platformv1.GetProxyRouteResponse{Route: ProxyRouteToProto(route)}, nil
}

// UpdateRoute replaces an existing proxy route.
func (s *ProxyGRPCService) UpdateRoute(
	ctx context.Context,
	req *platformv1.UpdateProxyRouteRequest,
) (*platformv1.UpdateProxyRouteResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if req.GetRoute() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingRoute{}.Error())
	}
	route := ProxyRouteFromProto(req.GetRoute())
	switch {
	case route.ID == "" && req.GetId() == "":
		return nil, status.Error(codes.InvalidArgument, ErrMissingRouteID{}.Error())
	case route.ID == "":
		route.ID = req.GetId()
	case req.GetId() != "" && req.GetId() != route.ID:
		return nil, status.Error(codes.InvalidArgument,
			ErrRouteIDMismatch{RequestID: req.GetId(), BodyID: route.ID}.Error())
	}
	stored, version, err := s.service.UpdateRoute(ctx, route)
	if err != nil {
		return nil, s.mapError("UpdateRoute", err)
	}
	return &platformv1.UpdateProxyRouteResponse{
		Route:   ProxyRouteToProto(stored),
		Version: version,
	}, nil
}

// DeleteRoute removes a proxy route by ID.
func (s *ProxyGRPCService) DeleteRoute(
	ctx context.Context,
	req *platformv1.DeleteProxyRouteRequest,
) (*platformv1.DeleteProxyRouteResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingRouteID{}.Error())
	}
	version, err := s.service.DeleteRoute(ctx, req.GetId())
	if err != nil {
		return nil, s.mapError("DeleteRoute", err)
	}
	return &platformv1.DeleteProxyRouteResponse{Version: version}, nil
}

// ListRoutes returns all proxy routes.
func (s *ProxyGRPCService) ListRoutes(
	ctx context.Context,
	req *platformv1.ListProxyRoutesRequest,
) (*platformv1.ListProxyRoutesResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	routes, version, err := s.service.Routes(ctx)
	if err != nil {
		return nil, s.mapError("ListRoutes", err)
	}
	out := make([]*platformv1.ProxyRoute, 0, len(routes))
	for _, r := range routes {
		out = append(out, ProxyRouteToProto(r))
	}
	return &platformv1.ListProxyRoutesResponse{Routes: out, Version: version}, nil
}

// =============================================================================
// Pool RPCs
// =============================================================================

// CreatePool creates a new proxy backend pool.
func (s *ProxyGRPCService) CreatePool(
	ctx context.Context,
	req *platformv1.CreateProxyPoolRequest,
) (*platformv1.CreateProxyPoolResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if req.GetPool() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPool{}.Error())
	}
	pool := ProxyPoolFromProto(req.GetPool())
	if pool.ID == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPoolID{}.Error())
	}
	stored, version, err := s.service.CreatePool(ctx, pool)
	if err != nil {
		return nil, s.mapError("CreatePool", err)
	}
	return &platformv1.CreateProxyPoolResponse{
		Pool:    ProxyPoolToProto(stored),
		Version: version,
	}, nil
}

// GetPool retrieves a proxy backend pool by ID.
func (s *ProxyGRPCService) GetPool(
	ctx context.Context,
	req *platformv1.GetProxyPoolRequest,
) (*platformv1.GetProxyPoolResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPoolID{}.Error())
	}
	pool, err := s.service.Pool(ctx, req.GetId())
	if err != nil {
		return nil, s.mapError("GetPool", err)
	}
	return &platformv1.GetProxyPoolResponse{Pool: ProxyPoolToProto(pool)}, nil
}

// UpdatePool replaces an existing proxy backend pool.
func (s *ProxyGRPCService) UpdatePool(
	ctx context.Context,
	req *platformv1.UpdateProxyPoolRequest,
) (*platformv1.UpdateProxyPoolResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if req.GetPool() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPool{}.Error())
	}
	pool := ProxyPoolFromProto(req.GetPool())
	switch {
	case pool.ID == "" && req.GetId() == "":
		return nil, status.Error(codes.InvalidArgument, ErrMissingPoolID{}.Error())
	case pool.ID == "":
		pool.ID = req.GetId()
	case req.GetId() != "" && req.GetId() != pool.ID:
		return nil, status.Error(codes.InvalidArgument,
			ErrPoolIDMismatch{RequestID: req.GetId(), BodyID: pool.ID}.Error())
	}
	stored, version, err := s.service.UpdatePool(ctx, pool)
	if err != nil {
		return nil, s.mapError("UpdatePool", err)
	}
	return &platformv1.UpdateProxyPoolResponse{
		Pool:    ProxyPoolToProto(stored),
		Version: version,
	}, nil
}

// DeletePool removes a proxy backend pool by ID.
func (s *ProxyGRPCService) DeletePool(
	ctx context.Context,
	req *platformv1.DeleteProxyPoolRequest,
) (*platformv1.DeleteProxyPoolResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPoolID{}.Error())
	}
	version, err := s.service.DeletePool(ctx, req.GetId())
	if err != nil {
		return nil, s.mapError("DeletePool", err)
	}
	return &platformv1.DeleteProxyPoolResponse{Version: version}, nil
}

// ListPools returns all proxy backend pools.
func (s *ProxyGRPCService) ListPools(
	ctx context.Context,
	req *platformv1.ListProxyPoolsRequest,
) (*platformv1.ListProxyPoolsResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	pools, version, err := s.service.Pools(ctx)
	if err != nil {
		return nil, s.mapError("ListPools", err)
	}
	out := make([]*platformv1.ProxyPool, 0, len(pools))
	for _, p := range pools {
		out = append(out, ProxyPoolToProto(p))
	}
	return &platformv1.ListProxyPoolsResponse{Pools: out, Version: version}, nil
}

// =============================================================================
// Config / status / reload / zone matrix RPCs
// =============================================================================

// GetProxyConfig returns the full merged route/pool configuration plus the
// version counter.
func (s *ProxyGRPCService) GetProxyConfig(
	ctx context.Context,
	req *platformv1.GetProxyConfigRequest,
) (*platformv1.GetProxyConfigResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	routes, pools, version, err := s.service.Snapshot(ctx)
	if err != nil {
		return nil, s.mapError("GetProxyConfig", err)
	}
	outRoutes := make([]*platformv1.ProxyRoute, 0, len(routes))
	for _, r := range routes {
		outRoutes = append(outRoutes, ProxyRouteToProto(r))
	}
	outPools := make([]*platformv1.ProxyPool, 0, len(pools))
	for _, p := range pools {
		outPools = append(outPools, ProxyPoolToProto(p))
	}
	return &platformv1.GetProxyConfigResponse{
		Routes:  outRoutes,
		Pools:   outPools,
		Version: version,
	}, nil
}

// GetProxyStatus reports the configuration store status.
func (s *ProxyGRPCService) GetProxyStatus(
	ctx context.Context,
	req *platformv1.GetProxyStatusRequest,
) (*platformv1.GetProxyStatusResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	st, err := s.service.Status(ctx)
	if err != nil {
		return nil, s.mapError("GetProxyStatus", err)
	}
	resp := &platformv1.GetProxyStatusResponse{
		Version:    st.Version,
		RouteCount: uint32(st.RouteCount),
		PoolCount:  uint32(st.PoolCount),
	}
	if !st.UpdatedAt.IsZero() {
		resp.UpdatedAt = st.UpdatedAt.Unix()
	}
	return resp, nil
}

// ReloadProxyConfig bumps the config version.
func (s *ProxyGRPCService) ReloadProxyConfig(
	ctx context.Context,
	req *platformv1.ReloadProxyConfigRequest,
) (*platformv1.ReloadProxyConfigResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	version, err := s.service.Reload(ctx)
	if err != nil {
		return nil, s.mapError("ReloadProxyConfig", err)
	}
	return &platformv1.ReloadProxyConfigResponse{Version: version}, nil
}

// GetZoneMatrix returns the SDN zone names and compiled allowed pairs.
func (s *ProxyGRPCService) GetZoneMatrix(
	ctx context.Context,
	req *platformv1.GetProxyZoneMatrixRequest,
) (*platformv1.GetProxyZoneMatrixResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}
	matrix, err := s.service.ZoneMatrix(ctx)
	if err != nil {
		return nil, s.mapError("GetZoneMatrix", err)
	}
	pairs := make([]*platformv1.ProxyZonePair, 0, len(matrix.Pairs))
	for _, p := range matrix.Pairs {
		pairs = append(pairs, &platformv1.ProxyZonePair{
			From:     p.From,
			To:       p.To,
			Services: p.Services,
		})
	}
	return &platformv1.GetProxyZoneMatrixResponse{
		Zones: matrix.Zones,
		Pairs: pairs,
	}, nil
}

// =============================================================================
// Conversion helpers (pb <-> pkg/proxy domain types)
// =============================================================================

// ProxyRouteFromProto converts a protobuf ProxyRoute to a proxy.RouteConfig.
func ProxyRouteFromProto(pb *platformv1.ProxyRoute) proxy.RouteConfig {
	if pb == nil {
		return proxy.RouteConfig{}
	}
	return proxy.RouteConfig{
		ID:             pb.GetId(),
		Hosts:          pb.GetHosts(),
		PathPrefix:     pb.GetPathPrefix(),
		PoolID:         pb.GetPoolId(),
		Auth:           proxyAuthFromProto(pb.GetAuth()),
		StripPrefix:    pb.GetStripPrefix(),
		PreserveHost:   pb.GetPreserveHost(),
		PassthroughTCP: pb.GetPassthroughTcp(),
	}
}

// ProxyRouteToProto converts a proxy.RouteConfig to a protobuf ProxyRoute.
func ProxyRouteToProto(r proxy.RouteConfig) *platformv1.ProxyRoute {
	return &platformv1.ProxyRoute{
		Id:             r.ID,
		Hosts:          r.Hosts,
		PathPrefix:     r.PathPrefix,
		PoolId:         r.PoolID,
		Auth:           proxyAuthToProto(r.Auth),
		StripPrefix:    r.StripPrefix,
		PreserveHost:   r.PreserveHost,
		PassthroughTcp: r.PassthroughTCP,
	}
}

// proxyAuthFromProto converts protobuf auth requirements to the domain type.
func proxyAuthFromProto(pb *platformv1.ProxyAuthRequirements) proxy.AuthRequirements {
	if pb == nil {
		return proxy.AuthRequirements{}
	}
	return proxy.AuthRequirements{
		Mode:               pb.GetMode(),
		RequireIDevID:      pb.GetRequireIdevid(),
		AllowedZones:       pb.GetAllowedZones(),
		BackendZone:        pb.GetBackendZone(),
		RequireAttestation: pb.GetRequireAttestation(),
		AttestationMaxAge:  time.Duration(pb.GetAttestationMaxAgeNanos()),
		RequiredRoles:      pb.GetRequiredRoles(),
		RequiredScopes:     pb.GetRequiredScopes(),
		OPAPolicy:          pb.GetOpaPolicy(),
		TokenZone:          pb.GetTokenZone(),
	}
}

// proxyAuthToProto converts domain auth requirements to the protobuf type.
func proxyAuthToProto(a proxy.AuthRequirements) *platformv1.ProxyAuthRequirements {
	return &platformv1.ProxyAuthRequirements{
		Mode:                   a.Mode,
		RequireIdevid:          a.RequireIDevID,
		AllowedZones:           a.AllowedZones,
		BackendZone:            a.BackendZone,
		RequireAttestation:     a.RequireAttestation,
		AttestationMaxAgeNanos: int64(a.AttestationMaxAge),
		RequiredRoles:          a.RequiredRoles,
		RequiredScopes:         a.RequiredScopes,
		OpaPolicy:              a.OPAPolicy,
		TokenZone:              a.TokenZone,
	}
}

// ProxyPoolFromProto converts a protobuf ProxyPool to a
// proxy.BackendPoolConfig.
func ProxyPoolFromProto(pb *platformv1.ProxyPool) proxy.BackendPoolConfig {
	if pb == nil {
		return proxy.BackendPoolConfig{}
	}
	backends := make([]proxy.BackendConfig, 0, len(pb.GetBackends()))
	for _, b := range pb.GetBackends() {
		backends = append(backends, proxy.BackendConfig{
			URL:    b.GetUrl(),
			Weight: int(b.GetWeight()),
		})
	}
	var tls proxy.BackendTLSConfig
	if pbTLS := pb.GetTls(); pbTLS != nil {
		tls = proxy.BackendTLSConfig{
			TrustClass:     pbTLS.GetTrustClass(),
			MTLSClientCert: pbTLS.GetMtlsClientCert(),
		}
	}
	return proxy.BackendPoolConfig{
		ID:                  pb.GetId(),
		Backends:            backends,
		Balancer:            pb.GetBalancer(),
		TLS:                 tls,
		MaxIdleConnsPerHost: int(pb.GetMaxIdleConnsPerHost()),
		IdleConnTimeout:     time.Duration(pb.GetIdleConnTimeoutNanos()),
	}
}

// ProxyPoolToProto converts a proxy.BackendPoolConfig to a protobuf
// ProxyPool.
func ProxyPoolToProto(p proxy.BackendPoolConfig) *platformv1.ProxyPool {
	backends := make([]*platformv1.ProxyBackend, 0, len(p.Backends))
	for _, b := range p.Backends {
		backends = append(backends, &platformv1.ProxyBackend{
			Url:    b.URL,
			Weight: int32(b.Weight),
		})
	}
	return &platformv1.ProxyPool{
		Id:       p.ID,
		Backends: backends,
		Balancer: p.Balancer,
		Tls: &platformv1.ProxyBackendTLS{
			TrustClass:     p.TLS.TrustClass,
			MtlsClientCert: p.TLS.MTLSClientCert,
		},
		MaxIdleConnsPerHost:  int32(p.MaxIdleConnsPerHost),
		IdleConnTimeoutNanos: int64(p.IdleConnTimeout),
	}
}
