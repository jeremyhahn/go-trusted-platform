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

// Command deploy-agent is the QUIC deploy agent (#1700): it runs on a
// deploy target in place of an SSH server and serves the bootstrap
// deployer's Run, CopyFileStream and StatRemote over mutually
// authenticated TLS 1.3. configs/os/deploy-agent.service runs it under
// systemd; docs/bootstrap/remote-deploy.md describes it.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/deployer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/deployer/quicagent"
)

// config is the agent's command line.
type config struct {
	listen   string
	certPath string
	keyPath  string
	clientCA string
}

// errUsage is a command line the agent cannot run with.
var errUsage = errors.New("usage")

func parseArgs(args []string, stderr io.Writer) (config, error) {
	var c config
	fs := flag.NewFlagSet("deploy-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&c.listen, "listen", fmt.Sprintf(":%d", deployer.DefaultAgentPort), "UDP address the agent listens on")
	fs.StringVar(&c.certPath, "cert", "", "PEM certificate the agent presents (required)")
	fs.StringVar(&c.keyPath, "key", "", "PEM private key of the agent certificate (required)")
	fs.StringVar(&c.clientCA, "client-ca", "", "PEM CA bundle a deployer's client certificate must chain to (required)")
	if err := fs.Parse(args); err != nil {
		return c, fmt.Errorf("%w: %v", errUsage, err)
	}
	if fs.NArg() != 0 {
		return c, fmt.Errorf("%w: unexpected arguments %q", errUsage, fs.Args())
	}
	for _, f := range []struct{ name, value string }{
		{"cert", c.certPath}, {"key", c.keyPath}, {"client-ca", c.clientCA},
	} {
		if f.value == "" {
			return c, fmt.Errorf("%w: -%s is required", errUsage, f.name)
		}
	}
	return c, nil
}

// run serves the agent until ctx is done. ready, when not nil, receives
// the bound address.
func run(ctx context.Context, args []string, stderr io.Writer, ready func(net.Addr)) error {
	c, err := parseArgs(args, stderr)
	if err != nil {
		return err
	}
	tlsConf, err := quicagent.ServerTLSConfig(c.certPath, c.keyPath, c.clientCA)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	return quicagent.ListenAndServe(ctx, c.listen, tlsConf, logger, ready)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stderr, nil); err != nil {
		fmt.Fprintf(os.Stderr, "deploy-agent: %v\n", err)
		if errors.Is(err, errUsage) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}
