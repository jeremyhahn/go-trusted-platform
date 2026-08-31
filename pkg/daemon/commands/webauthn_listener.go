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
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/webauthn"
)

// listenerWebAuthnConfig returns the WebAuthn handler config for one
// webservice listener, or nil to disable the listener's WebAuthn routes.
// The embedded SDK's WebAuthn factory serves a SINGLE relying party (the
// one mirrored into the QuicBaaS config); a listener declaring a different
// RP ID could register routes whose every ceremony fails in the browser,
// so its routes are explicitly DISABLED with an ERROR instead — a
// deterministic, visible degradation rather than a user-discovered one —
// until upstream multi-RP support (go-quicbaas#264) lands.
func listenerWebAuthnConfig(wsConfig *v1.Config, sdkRPID string, logger *logging.Logger) *webauthn.Config {
	if wsConfig == nil || wsConfig.WebAuthn == nil {
		return nil
	}
	if sdkRPID != "" && wsConfig.WebAuthn.RPID != sdkRPID {
		logger.Errorf(
			"webservice declares WebAuthn relying party %q but the embedded SDK factory serves only %q — WebAuthn routes on this listener are DISABLED (upstream multi-RP support required: go-quicbaas#264)",
			wsConfig.WebAuthn.RPID, sdkRPID)
		return nil
	}
	return &webauthn.Config{
		RPDisplayName: wsConfig.WebAuthn.RPDisplayName,
		RPID:          wsConfig.WebAuthn.RPID,
		RPOrigins:     wsConfig.WebAuthn.RPOrigins,
	}
}
