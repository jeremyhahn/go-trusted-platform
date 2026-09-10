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

package dns

import (
	"strconv"
	"strings"
)

// corefileBlock renders one CoreDNS server block. It is the single place the
// Corefile is spelled, so a directive added for one listener cannot go
// missing on the other.
//
// dns64 is rendered before forward deliberately: the plugin intercepts an
// AAAA question, lets the rest of the chain answer it, and synthesises from
// an A lookup only when that answer carried no AAAA. Ordering it after the
// resolver would leave it nothing to intercept.
func corefileBlock(port int, forwarders []string, dns64Stanza string) string {
	var b strings.Builder
	b.WriteString("\n.:" + strconv.Itoa(port) + " {\n")
	b.WriteString("\ttrustedPlatform\n")
	b.WriteString("\tlog\n")
	b.WriteString("\tchaos\n")
	b.WriteString(dns64Stanza)
	if len(forwarders) > 0 {
		b.WriteString("\tforward . " + strings.Join(forwarders, " ") + "\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// NewCorefile renders a server block with no forwarders and no DNS64.
func NewCorefile(port int) string {
	return corefileBlock(port, nil, "")
}

// NewCorefileWithForwarders renders a server block that forwards names it is
// not authoritative for.
func NewCorefileWithForwarders(port int, forwarders []string) string {
	return corefileBlock(port, forwarders, "")
}

// NewCorefileForServer renders the block for a named listener, including the
// DNS64 stanza when that listener synthesises.
func NewCorefileForServer(server string, port int, forwarders []string, dns64 *DNS64Config) string {
	return corefileBlock(port, forwarders, dns64.CorefileStanza(server))
}
