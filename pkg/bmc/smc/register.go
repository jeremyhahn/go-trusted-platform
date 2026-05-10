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

package smc

import (
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// init registers the Supermicro CGI cert-upload backend with pkg/bmc
// so that bmc.AutoCertManager can resolve CertBackendSMCCGI to a
// real CertificateManager. Users opt in by adding a side-effect
// import of this package:
//
//	import _ "github.com/jeremyhahn/go-trusted-platform/pkg/bmc/smc"
func init() {
	bmc.RegisterCertFactory(bmc.CertBackendSMCCGI, func(cfg *bmc.Config, logger *slog.Logger) (bmc.ManagedCertificateManager, error) {
		return NewCertManager(cfg, logger)
	})
}
