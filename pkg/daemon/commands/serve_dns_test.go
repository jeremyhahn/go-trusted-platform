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

package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestWireDaemonDNSService_HandsTheAppServiceToTheDaemon(t *testing.T) {
	// The daemon's gRPC, QUIC, MCP and Unix DNS handlers serve exactly the
	// service App.ServiceRegistry() created; without it each answers
	// "DNS service not available".
	svc := &dns.Service{}
	cfg := daemon.DefaultConfig()

	wireDaemonDNSService(logging.NewLogger(0, nil), &app.App{DNSService: svc}, cfg)

	assert.Same(t, svc, cfg.DNSService)
}

func TestWireDaemonDNSService_NoDNSServerLeavesTheDaemonWithout(t *testing.T) {
	// A node with no dns: server section has no service: the field stays a
	// nil interface, so the daemon answers SERVICE_NOT_CONFIGURED rather
	// than calling through a typed nil.
	cfg := daemon.DefaultConfig()

	wireDaemonDNSService(logging.NewLogger(0, nil), &app.App{}, cfg)

	assert.Nil(t, cfg.DNSService)
}

func TestWireDaemonDNSService_NilAppOrConfigIsANoOp(t *testing.T) {
	cfg := daemon.DefaultConfig()
	logger := logging.NewLogger(0, nil)

	assert.NotPanics(t, func() { wireDaemonDNSService(logger, nil, cfg) })
	assert.NotPanics(t, func() { wireDaemonDNSService(logger, &app.App{DNSService: &dns.Service{}}, nil) })
	assert.Nil(t, cfg.DNSService)
}
