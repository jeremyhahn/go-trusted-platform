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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// CLIAdapter drives ProxyCommands by shelling out to "platformctl proxy
// ...", the operator-facing surface. It reuses the temp-config mechanism of
// the other CLI adapters so a single daemon instance is targeted.
type CLIAdapter struct {
	binaryPath string
	configDir  string
	configPath string
}

// NewCLIAdapter returns an unconfigured CLI adapter.
func NewCLIAdapter() *CLIAdapter { return &CLIAdapter{} }

// Name returns "CLI".
func (c *CLIAdapter) Name() string { return "CLI" }

// Setup locates platformctl and writes a temp config targeting the test
// daemon over the Unix socket.
func (c *CLIAdapter) Setup(ctx context.Context) error {
	endpoints := GetServiceEndpoints()
	binaryPath := endpoints.PlatformCTL
	if _, err := exec.LookPath(binaryPath); err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}
	c.binaryPath = binaryPath

	tmpDir, err := os.MkdirTemp("", "platformctl-proxy-test-*")
	if err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}
	c.configDir = tmpDir
	c.configPath = filepath.Join(tmpDir, "config.yaml")
	configContent := fmt.Sprintf(`current_context: integration-test
contexts:
  - name: integration-test
    type: local
    local:
      socket_path: %s
      grpc_addr: %s
`, endpoints.PlatformUnix, endpoints.PlatformGRPC)
	if err := os.WriteFile(c.configPath, []byte(configContent), 0o600); err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}
	return nil
}

// Teardown removes the temp config directory.
func (c *CLIAdapter) Teardown() error {
	if c.configDir != "" {
		os.RemoveAll(c.configDir)
		c.configDir = ""
		c.configPath = ""
	}
	return nil
}

// run invokes platformctl with the shared config/context flags plus JSON
// output.
func (c *CLIAdapter) run(ctx context.Context, args ...string) ([]byte, error) {
	full := []string{"--config", c.configPath, "--context", "integration-test"}
	full = append(full, args...)
	full = append(full, "--output", "json")
	cmd := exec.CommandContext(ctx, c.binaryPath, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		out := stdout.String()
		if stderr.Len() > 0 {
			out += "\nstderr: " + stderr.String()
		}
		return nil, ErrCLICommandFailed{Args: full, Output: out, Err: err}
	}
	return stdout.Bytes(), nil
}

// decode unmarshals CLI JSON output.
func (c *CLIAdapter) decode(args []string, out []byte, target any) error {
	if err := json.Unmarshal(out, target); err != nil {
		return ErrCLIDecodeFailed{Args: args, Output: string(out), Err: err}
	}
	return nil
}

// routeArgs converts a ProxyRoute into route add/update flags.
func routeArgs(verb string, route *platformv1.ProxyRoute) []string {
	args := []string{"proxy", "route", verb,
		"--id", route.GetId(),
		"--path-prefix", route.GetPathPrefix(),
		"--pool", route.GetPoolId(),
		"--auth-mode", route.GetAuth().GetMode(),
	}
	for _, h := range route.GetHosts() {
		args = append(args, "--host", h)
	}
	if auth := route.GetAuth(); auth != nil {
		if auth.GetRequireIdevid() {
			args = append(args, "--require-idevid")
		}
		for _, z := range auth.GetAllowedZones() {
			args = append(args, "--allowed-zone", z)
		}
		if auth.GetBackendZone() != "" {
			args = append(args, "--backend-zone", auth.GetBackendZone())
		}
		if auth.GetRequireAttestation() {
			args = append(args, "--require-attestation")
		}
		if auth.GetAttestationMaxAgeNanos() > 0 {
			args = append(args, "--attestation-max-age", time.Duration(auth.GetAttestationMaxAgeNanos()).String())
		}
		for _, r := range auth.GetRequiredRoles() {
			args = append(args, "--required-role", r)
		}
		for _, s := range auth.GetRequiredScopes() {
			args = append(args, "--required-scope", s)
		}
		if auth.GetOpaPolicy() != "" {
			args = append(args, "--opa-policy", auth.GetOpaPolicy())
		}
	}
	if route.GetStripPrefix() {
		args = append(args, "--strip-prefix")
	}
	if route.GetPreserveHost() {
		args = append(args, "--preserve-host")
	}
	return args
}

// poolArgs converts a ProxyPool into pool add/update flags.
func poolArgs(verb string, pool *platformv1.ProxyPool) []string {
	args := []string{"proxy", "pool", verb, "--id", pool.GetId()}
	for _, b := range pool.GetBackends() {
		entry := b.GetUrl()
		if b.GetWeight() > 0 {
			entry += "=" + strconv.Itoa(int(b.GetWeight()))
		}
		args = append(args, "--backend", entry)
	}
	if pool.GetBalancer() != "" {
		args = append(args, "--balancer", pool.GetBalancer())
	}
	if tlsCfg := pool.GetTls(); tlsCfg != nil {
		if tlsCfg.GetTrustClass() != "" {
			args = append(args, "--trust-class", tlsCfg.GetTrustClass())
		}
		if tlsCfg.GetMtlsClientCert() {
			args = append(args, "--mtls-client-cert")
		}
	}
	if pool.GetMaxIdleConnsPerHost() > 0 {
		args = append(args, "--max-idle-conns-per-host", strconv.Itoa(int(pool.GetMaxIdleConnsPerHost())))
	}
	if pool.GetIdleConnTimeoutNanos() > 0 {
		args = append(args, "--idle-conn-timeout", time.Duration(pool.GetIdleConnTimeoutNanos()).String())
	}
	return args
}

// routeEnvelope decodes the {"route": ..., "version": ...} CLI output.
type routeEnvelope struct {
	Route   *platformv1.ProxyRoute `json:"route"`
	Version uint64                 `json:"version"`
}

// poolEnvelope decodes the {"pool": ..., "version": ...} CLI output.
type poolEnvelope struct {
	Pool    *platformv1.ProxyPool `json:"pool"`
	Version uint64                `json:"version"`
}

// CreateRoute implements ProxyCommands via "proxy route add".
func (c *CLIAdapter) CreateRoute(ctx context.Context, route *platformv1.ProxyRoute) (*platformv1.ProxyRoute, uint64, error) {
	args := routeArgs("add", route)
	out, err := c.run(ctx, args...)
	if err != nil {
		return nil, 0, err
	}
	var envelope routeEnvelope
	if err := c.decode(args, out, &envelope); err != nil {
		return nil, 0, err
	}
	return envelope.Route, envelope.Version, nil
}

// GetRoute implements ProxyCommands via "proxy route get".
func (c *CLIAdapter) GetRoute(ctx context.Context, id string) (*platformv1.ProxyRoute, error) {
	args := []string{"proxy", "route", "get", id}
	out, err := c.run(ctx, args...)
	if err != nil {
		return nil, err
	}
	route := &platformv1.ProxyRoute{}
	if err := c.decode(args, out, route); err != nil {
		return nil, err
	}
	return route, nil
}

// UpdateRoute implements ProxyCommands via "proxy route update".
func (c *CLIAdapter) UpdateRoute(ctx context.Context, route *platformv1.ProxyRoute) (*platformv1.ProxyRoute, uint64, error) {
	args := routeArgs("update", route)
	out, err := c.run(ctx, args...)
	if err != nil {
		return nil, 0, err
	}
	var envelope routeEnvelope
	if err := c.decode(args, out, &envelope); err != nil {
		return nil, 0, err
	}
	return envelope.Route, envelope.Version, nil
}

// DeleteRoute implements ProxyCommands via "proxy route delete".
func (c *CLIAdapter) DeleteRoute(ctx context.Context, id string) (uint64, error) {
	args := []string{"proxy", "route", "delete", id}
	out, err := c.run(ctx, args...)
	if err != nil {
		return 0, err
	}
	var envelope struct {
		Version uint64 `json:"version"`
	}
	if err := c.decode(args, out, &envelope); err != nil {
		return 0, err
	}
	return envelope.Version, nil
}

// ListRoutes implements ProxyCommands via "proxy route list".
func (c *CLIAdapter) ListRoutes(ctx context.Context) ([]*platformv1.ProxyRoute, uint64, error) {
	args := []string{"proxy", "route", "list"}
	out, err := c.run(ctx, args...)
	if err != nil {
		return nil, 0, err
	}
	var envelope struct {
		Routes  []*platformv1.ProxyRoute `json:"routes"`
		Version uint64                   `json:"version"`
	}
	if err := c.decode(args, out, &envelope); err != nil {
		return nil, 0, err
	}
	return envelope.Routes, envelope.Version, nil
}

// CreatePool implements ProxyCommands via "proxy pool add".
func (c *CLIAdapter) CreatePool(ctx context.Context, pool *platformv1.ProxyPool) (*platformv1.ProxyPool, uint64, error) {
	args := poolArgs("add", pool)
	out, err := c.run(ctx, args...)
	if err != nil {
		return nil, 0, err
	}
	var envelope poolEnvelope
	if err := c.decode(args, out, &envelope); err != nil {
		return nil, 0, err
	}
	return envelope.Pool, envelope.Version, nil
}

// GetPool implements ProxyCommands via "proxy pool get".
func (c *CLIAdapter) GetPool(ctx context.Context, id string) (*platformv1.ProxyPool, error) {
	args := []string{"proxy", "pool", "get", id}
	out, err := c.run(ctx, args...)
	if err != nil {
		return nil, err
	}
	pool := &platformv1.ProxyPool{}
	if err := c.decode(args, out, pool); err != nil {
		return nil, err
	}
	return pool, nil
}

// UpdatePool implements ProxyCommands via "proxy pool update".
func (c *CLIAdapter) UpdatePool(ctx context.Context, pool *platformv1.ProxyPool) (*platformv1.ProxyPool, uint64, error) {
	args := poolArgs("update", pool)
	out, err := c.run(ctx, args...)
	if err != nil {
		return nil, 0, err
	}
	var envelope poolEnvelope
	if err := c.decode(args, out, &envelope); err != nil {
		return nil, 0, err
	}
	return envelope.Pool, envelope.Version, nil
}

// DeletePool implements ProxyCommands via "proxy pool delete".
func (c *CLIAdapter) DeletePool(ctx context.Context, id string) (uint64, error) {
	args := []string{"proxy", "pool", "delete", id}
	out, err := c.run(ctx, args...)
	if err != nil {
		return 0, err
	}
	var envelope struct {
		Version uint64 `json:"version"`
	}
	if err := c.decode(args, out, &envelope); err != nil {
		return 0, err
	}
	return envelope.Version, nil
}

// ListPools implements ProxyCommands via "proxy pool list".
func (c *CLIAdapter) ListPools(ctx context.Context) ([]*platformv1.ProxyPool, uint64, error) {
	args := []string{"proxy", "pool", "list"}
	out, err := c.run(ctx, args...)
	if err != nil {
		return nil, 0, err
	}
	var envelope struct {
		Pools   []*platformv1.ProxyPool `json:"pools"`
		Version uint64                  `json:"version"`
	}
	if err := c.decode(args, out, &envelope); err != nil {
		return nil, 0, err
	}
	return envelope.Pools, envelope.Version, nil
}

// Status implements ProxyCommands via "proxy status".
func (c *CLIAdapter) Status(ctx context.Context) (*platformv1.GetProxyStatusResponse, error) {
	args := []string{"proxy", "status"}
	out, err := c.run(ctx, args...)
	if err != nil {
		return nil, err
	}
	status := &platformv1.GetProxyStatusResponse{}
	if err := c.decode(args, out, status); err != nil {
		return nil, err
	}
	return status, nil
}

// Reload implements ProxyCommands via "proxy reload".
func (c *CLIAdapter) Reload(ctx context.Context) (uint64, error) {
	args := []string{"proxy", "reload"}
	out, err := c.run(ctx, args...)
	if err != nil {
		return 0, err
	}
	var envelope struct {
		Version uint64 `json:"version"`
	}
	if err := c.decode(args, out, &envelope); err != nil {
		return 0, err
	}
	return envelope.Version, nil
}

// ZoneMatrix implements ProxyCommands via "proxy zone-matrix".
func (c *CLIAdapter) ZoneMatrix(ctx context.Context) (*platformv1.GetProxyZoneMatrixResponse, error) {
	args := []string{"proxy", "zone-matrix"}
	out, err := c.run(ctx, args...)
	if err != nil {
		return nil, err
	}
	matrix := &platformv1.GetProxyZoneMatrixResponse{}
	if err := c.decode(args, out, matrix); err != nil {
		return nil, err
	}
	return matrix, nil
}

var _ ProxyCommands = (*CLIAdapter)(nil)
