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

package quicagent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"os"
	"strconv"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/deployer"
)

// The QUIC deploy agent is the deployer's TransportQUIC: a program that
// imports this package can deploy to a target that runs only the agent.
func init() {
	deployer.RegisterTransport(deployer.TransportQUIC, NewRemoteHost)
}

// NewRemoteHost is the deployer.TransportQUIC factory: a Client for the
// agent at config.Host:config.AgentPort, presenting the certificate at
// config.AgentCertPath and verifying the agent against config.AgentCAPath
// under config.AgentServerName (empty means config.Host).
func NewRemoteHost(config *deployer.DeployConfig) (deployer.RemoteHost, error) {
	if config.Host == "" {
		return nil, deployer.ErrInvalidDeployConfig{Field: "host", Reason: "must not be empty"}
	}
	port := config.AgentPort
	if port == 0 {
		port = deployer.DefaultAgentPort
	}
	serverName := config.AgentServerName
	if serverName == "" {
		serverName = config.Host
	}
	tlsConf, err := ClientTLSConfig(config.AgentCertPath, config.AgentKeyPath, config.AgentCAPath, serverName)
	if err != nil {
		return nil, err
	}
	return NewClient(net.JoinHostPort(config.Host, strconv.Itoa(port)), tlsConf)
}

// ClientTLSConfig loads the deployer's side of the mutual TLS: the PEM
// client certificate and key, and the PEM CA bundle the agent's
// certificate must chain to.
func ClientTLSConfig(certPath, keyPath, caPath, serverName string) (*tls.Config, error) {
	cert, err := loadKeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	pool, err := loadCAPool(caPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ServerTLSConfig loads the agent's side of the mutual TLS: the PEM agent
// certificate and key, and the PEM CA bundle a deployer's client
// certificate must chain to.
func ServerTLSConfig(certPath, keyPath, clientCAPath string) (*tls.Config, error) {
	cert, err := loadKeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	pool, err := loadCAPool(clientCAPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ListenAndServe runs the agent on the UDP address addr until ctx is
// done; it is the agent's whole lifecycle (cmd/deploy-agent). ready, when
// not nil, receives the bound address once the agent listens.
func ListenAndServe(ctx context.Context, addr string, tlsConf *tls.Config, logger *slog.Logger, ready func(net.Addr)) error {
	srv, err := NewServer(tlsConf, logger)
	if err != nil {
		return err
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer pc.Close()
	if ready != nil {
		ready(pc.LocalAddr())
	}
	if logger != nil {
		logger.Info("deploy agent listening", slog.String("addr", pc.LocalAddr().String()))
	}
	return srv.Serve(ctx, pc)
}

func loadKeyPair(certPath, keyPath string) (tls.Certificate, error) {
	if certPath == "" {
		return tls.Certificate{}, ErrLoadTLS{What: "certificate", Path: certPath, Cause: errors.New("no path")}
	}
	if keyPath == "" {
		return tls.Certificate{}, ErrLoadTLS{What: "key", Path: keyPath, Cause: errors.New("no path")}
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, ErrLoadTLS{What: "certificate and key", Path: certPath, Cause: err}
	}
	return cert, nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, ErrLoadTLS{What: "CA bundle", Path: path, Cause: errors.New("no path")}
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrLoadTLS{What: "CA bundle", Path: path, Cause: err}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, ErrLoadTLS{What: "CA bundle", Path: path, Cause: errors.New("no PEM certificate in the file")}
	}
	return pool, nil
}
