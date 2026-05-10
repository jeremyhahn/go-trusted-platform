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

package tpm

import (
	"bytes"
	"encoding/pem"
)

// safeCertificateText returns a terminal-safe textual representation of
// certData. If certData is already PEM (starts with the standard BEGIN
// banner) it's returned as-is. Otherwise it's assumed to be DER and is
// wrapped in a CERTIFICATE PEM block. This prevents raw DER bytes from
// being printed to a user's terminal, where non-printable bytes (0x1B
// ESC, 0x07 BEL, etc) corrupt the terminal state and force the operator
// to `reset` their session.
//
// Callers that explicitly want the raw bytes (piping to openssl, writing
// to a file with `-o json`, etc.) should handle that format selection
// before reaching this helper.
func safeCertificateText(certData []byte) string {
	if len(certData) == 0 {
		return ""
	}

	// Already PEM? Return verbatim.
	if bytes.Contains(certData, []byte("-----BEGIN")) {
		return string(certData)
	}

	// Assume DER and wrap.
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certData,
	}
	return string(pem.EncodeToMemory(block))
}
