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

// Package smc implements Supermicro-specific BMC management paths that
// are not covered by standard Redfish. The primary path is the ATEN
// BMC CGI SSL upload flow used by X10/X11 generation firmware where
// Redfish CertificateService is missing or unreliable.
//
// # Wire protocol provenance
//
// The CGI SSL upload sequence implemented here matches the flow
// documented by Supermicro in the SMCIPMITool manual and observed in
// multiple open-source implementations (SuperDoctor, ipmiview, several
// community Python/Go scripts). The sequence is:
//
//	POST /cgi/login.cgi           (form: name=USER&pwd=PWD)
//	-> Set-Cookie: SID=<token>
//	POST /cgi/upload_ssl.cgi      (multipart: cert_file, key_file; Cookie: SID)
//	-> HTML success page
//	POST /cgi/op.cgi              (form: op=SSL_VALIDATE&r=<ts>; Cookie: SID)
//	-> JSON/text status
//	POST /cgi/BMC_reset.cgi       (Cookie: SID)
//	-> HTML/empty success
//	POST /cgi/logout.cgi          (Cookie: SID)
//
// # Hardware validation status
//
// This package has been tested only against httptest fakes that model
// the wire protocol above. Before it is enabled by the auto-fallback
// orchestrator (slice 8) on real hardware, a HAR capture of a manual
// SSL upload via the iKVM HTML5 UI on the target X10 firmware should
// be diffed against the implemented flow — see the project task
// "Validate SMC CGI cert upload on real X10 hardware".
package smc
