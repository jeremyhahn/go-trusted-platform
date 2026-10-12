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
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Conversion helpers between the platform.v1 wire messages and the engine
// configuration types. platformd's ProxyService serves routes and pools
// through them, and gatewayd uses them to turn a synced
// GetProxyConfigResponse into the routes and pools of its Config (adding its
// locally owned listeners).

// RouteFromProto converts a platform.v1 ProxyRoute to a RouteConfig.
func RouteFromProto(pb *platformv1.ProxyRoute) RouteConfig {
	if pb == nil {
		return RouteConfig{}
	}
	return RouteConfig{
		ID:             pb.GetId(),
		Hosts:          pb.GetHosts(),
		PathPrefix:     pb.GetPathPrefix(),
		PoolID:         pb.GetPoolId(),
		Auth:           authFromProto(pb.GetAuth()),
		StripPrefix:    pb.GetStripPrefix(),
		PreserveHost:   pb.GetPreserveHost(),
		PassthroughTCP: pb.GetPassthroughTcp(),
	}
}

// RouteToProto converts a RouteConfig to a platform.v1 ProxyRoute.
func RouteToProto(r RouteConfig) *platformv1.ProxyRoute {
	return &platformv1.ProxyRoute{
		Id:             r.ID,
		Hosts:          r.Hosts,
		PathPrefix:     r.PathPrefix,
		PoolId:         r.PoolID,
		Auth:           authToProto(r.Auth),
		StripPrefix:    r.StripPrefix,
		PreserveHost:   r.PreserveHost,
		PassthroughTcp: r.PassthroughTCP,
	}
}

// authFromProto converts platform.v1 auth requirements to AuthRequirements.
func authFromProto(pb *platformv1.ProxyAuthRequirements) AuthRequirements {
	if pb == nil {
		return AuthRequirements{}
	}
	return AuthRequirements{
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

// authToProto converts AuthRequirements to the platform.v1 message.
func authToProto(a AuthRequirements) *platformv1.ProxyAuthRequirements {
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

// PoolFromProto converts a platform.v1 ProxyPool to a BackendPoolConfig.
func PoolFromProto(pb *platformv1.ProxyPool) BackendPoolConfig {
	if pb == nil {
		return BackendPoolConfig{}
	}
	backends := make([]BackendConfig, 0, len(pb.GetBackends()))
	for _, b := range pb.GetBackends() {
		backends = append(backends, BackendConfig{
			URL:    b.GetUrl(),
			Weight: int(b.GetWeight()),
		})
	}
	var tls BackendTLSConfig
	if pbTLS := pb.GetTls(); pbTLS != nil {
		tls = BackendTLSConfig{
			TrustClass:     pbTLS.GetTrustClass(),
			MTLSClientCert: pbTLS.GetMtlsClientCert(),
		}
	}
	return BackendPoolConfig{
		ID:                  pb.GetId(),
		Backends:            backends,
		Balancer:            pb.GetBalancer(),
		TLS:                 tls,
		MaxIdleConnsPerHost: int(pb.GetMaxIdleConnsPerHost()),
		IdleConnTimeout:     time.Duration(pb.GetIdleConnTimeoutNanos()),
	}
}

// PoolToProto converts a BackendPoolConfig to a platform.v1 ProxyPool.
func PoolToProto(p BackendPoolConfig) *platformv1.ProxyPool {
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

// ConfigFromProto converts a synced GetProxyConfigResponse into the
// route/pool portion of a Config and its version. The caller supplies
// listeners (a gatewayd-local concern) before validating and running the
// engine.
func ConfigFromProto(resp *platformv1.GetProxyConfigResponse) ([]RouteConfig, []BackendPoolConfig, uint64) {
	if resp == nil {
		return nil, nil, 0
	}
	routes := make([]RouteConfig, 0, len(resp.GetRoutes()))
	for _, r := range resp.GetRoutes() {
		routes = append(routes, RouteFromProto(r))
	}
	pools := make([]BackendPoolConfig, 0, len(resp.GetPools()))
	for _, p := range resp.GetPools() {
		pools = append(pools, PoolFromProto(p))
	}
	return routes, pools, resp.GetVersion()
}
