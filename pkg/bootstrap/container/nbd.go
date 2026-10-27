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

package container

import (
	"crypto/tls"
	"log/slog"
	"net"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/nbd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// nbdIdentities returns the hostnames of the manifest's diskless-nbd nodes:
// the only identities the export server serves. A node listed under
// several MACs appears once.
func (m *Manifest) nbdIdentities() []string {
	seen := make(map[string]bool)
	var identities []string
	for _, entry := range m.Nodes {
		if entry.BootModel != nbd.BootModel || seen[entry.Hostname] {
			continue
		}
		seen[entry.Hostname] = true
		identities = append(identities, entry.Hostname)
	}
	return identities
}

// newNBDServer builds the export server for the manifest's diskless-nbd
// nodes. It returns nil when the manifest has none, so a container that
// serves no such node needs no NBD configuration and opens no NBD port.
func newNBDServer(config *ServerConfig, manifest *Manifest, logger *slog.Logger) (*nbd.Server, error) {
	identities := manifest.nbdIdentities()
	if len(identities) == 0 {
		return nil, nil
	}
	if err := config.NBD.validate(); err != nil {
		return nil, err
	}

	certificate, err := tls.LoadX509KeyPair(config.NBD.CertFile, config.NBD.KeyFile)
	if err != nil {
		return nil, ErrNBDCredentials{CertFile: config.NBD.CertFile, KeyFile: config.NBD.KeyFile, Err: err}
	}
	// The anchor reads the CA file on every handshake, so a bundle that
	// is rotated, or delivered after start-up, applies to the next attach.
	anchor, err := trust.NewAnchor(trust.NewFileAnchorSource(config.NBD.CAFile))
	if err != nil {
		return nil, ErrServerStartFailed{Cause: err}
	}

	volumes, err := nbdVolumes(config)
	if err != nil {
		return nil, err
	}

	return nbd.NewServer(nbd.Config{
		Certificate: certificate,
		Anchor:      anchor,
		Identities:  identities,
		Volumes:     volumes,
		VolumeSize:  config.NBD.VolumeSize,
		Logger:      logger,
	})
}

// nbdVolumes is the store behind the diskless-nbd exports, and the one place
// it is chosen: local files under NBDConfig.VolumeDir on this boot node. The
// export server and the installed-UKI route both reach volumes through it.
func nbdVolumes(config *ServerConfig) (nbd.VolumeProvider, error) {
	volumes, err := nbd.NewLocalVolumes(config.NBD.VolumeDir)
	if err != nil {
		return nil, err
	}
	return volumes, nil
}

// nbdServerAddr is the address a diskless-nbd node attaches its root from:
// the export server's listener. A listener bound to every address names the
// provisioning address, DHCPConfig.ServerIP, in its place.
func nbdServerAddr(config *ServerConfig) (nbd.ServerAddr, error) {
	listenAddr := config.NBD.ListenAddr
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return nbd.ServerAddr{}, ErrNBDServerAddress{ListenAddr: listenAddr, Err: err}
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = config.DHCPConfig.ServerIP
	}
	addr, err := nbd.ParseServerAddr(net.JoinHostPort(host, port))
	if err != nil {
		return nbd.ServerAddr{}, ErrNBDServerAddress{ListenAddr: listenAddr, Err: err}
	}
	return addr, nil
}
