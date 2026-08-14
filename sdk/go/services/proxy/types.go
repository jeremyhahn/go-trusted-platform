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

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Conversion helpers between the platform.v1 wire messages and the
// pkg/proxy engine configuration types. gatewayd uses these to turn a
// synced GetProxyConfigResponse into the proxy.Config consumed by the
// engine (adding its locally owned listeners), and to publish local
// definitions back to platformd.

// RouteToProto converts a proxy.RouteConfig to a platform.v1 ProxyRoute.
func RouteToProto(r proxy.RouteConfig) *platformv1.ProxyRoute {
	return &platformv1.ProxyRoute{
		Id:         r.ID,
		Hosts:      r.Hosts,
		PathPrefix: r.PathPrefix,
		PoolId:     r.PoolID,
		Auth: &platformv1.ProxyAuthRequirements{
			Mode:                   r.Auth.Mode,
			RequireIdevid:          r.Auth.RequireIDevID,
			AllowedZones:           r.Auth.AllowedZones,
			BackendZone:            r.Auth.BackendZone,
			RequireAttestation:     r.Auth.RequireAttestation,
			AttestationMaxAgeNanos: int64(r.Auth.AttestationMaxAge),
			RequiredRoles:          r.Auth.RequiredRoles,
			RequiredScopes:         r.Auth.RequiredScopes,
			OpaPolicy:              r.Auth.OPAPolicy,
			TokenZone:              r.Auth.TokenZone,
		},
		StripPrefix:    r.StripPrefix,
		PreserveHost:   r.PreserveHost,
		PassthroughTcp: r.PassthroughTCP,
	}
}

// RouteFromProto converts a platform.v1 ProxyRoute to a proxy.RouteConfig.
func RouteFromProto(pb *platformv1.ProxyRoute) proxy.RouteConfig {
	if pb == nil {
		return proxy.RouteConfig{}
	}
	var auth proxy.AuthRequirements
	if a := pb.GetAuth(); a != nil {
		auth = proxy.AuthRequirements{
			Mode:               a.GetMode(),
			RequireIDevID:      a.GetRequireIdevid(),
			AllowedZones:       a.GetAllowedZones(),
			BackendZone:        a.GetBackendZone(),
			RequireAttestation: a.GetRequireAttestation(),
			AttestationMaxAge:  time.Duration(a.GetAttestationMaxAgeNanos()),
			RequiredRoles:      a.GetRequiredRoles(),
			RequiredScopes:     a.GetRequiredScopes(),
			OPAPolicy:          a.GetOpaPolicy(),
			TokenZone:          a.GetTokenZone(),
		}
	}
	return proxy.RouteConfig{
		ID:             pb.GetId(),
		Hosts:          pb.GetHosts(),
		PathPrefix:     pb.GetPathPrefix(),
		PoolID:         pb.GetPoolId(),
		Auth:           auth,
		StripPrefix:    pb.GetStripPrefix(),
		PreserveHost:   pb.GetPreserveHost(),
		PassthroughTCP: pb.GetPassthroughTcp(),
	}
}

// PoolToProto converts a proxy.BackendPoolConfig to a platform.v1
// ProxyPool.
func PoolToProto(p proxy.BackendPoolConfig) *platformv1.ProxyPool {
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

// PoolFromProto converts a platform.v1 ProxyPool to a
// proxy.BackendPoolConfig.
func PoolFromProto(pb *platformv1.ProxyPool) proxy.BackendPoolConfig {
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
	if t := pb.GetTls(); t != nil {
		tls = proxy.BackendTLSConfig{
			TrustClass:     t.GetTrustClass(),
			MTLSClientCert: t.GetMtlsClientCert(),
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

// ConfigFromProto converts a synced GetProxyConfigResponse into the
// route/pool portion of a proxy.Config. The caller supplies listeners
// (a gatewayd-local concern) before validating and running the engine.
func ConfigFromProto(resp *platformv1.GetProxyConfigResponse) ([]proxy.RouteConfig, []proxy.BackendPoolConfig, uint64) {
	if resp == nil {
		return nil, nil, 0
	}
	routes := make([]proxy.RouteConfig, 0, len(resp.GetRoutes()))
	for _, r := range resp.GetRoutes() {
		routes = append(routes, RouteFromProto(r))
	}
	pools := make([]proxy.BackendPoolConfig, 0, len(resp.GetPools()))
	for _, p := range resp.GetPools() {
		pools = append(pools, PoolFromProto(p))
	}
	return routes, pools, resp.GetVersion()
}
