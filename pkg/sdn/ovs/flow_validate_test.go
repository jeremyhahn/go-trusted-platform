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

package ovs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateFlowMod(t *testing.T) {
	tests := []struct {
		name    string
		flow    *FlowMod
		wantErr bool
	}{
		{name: "normal", flow: &FlowMod{Priority: 100, Match: "nw_src=192.0.2.10", Actions: "normal"}},
		{name: "drop", flow: &FlowMod{Priority: 100, Match: "nw_src=192.0.2.10", Actions: "drop"}},
		{name: "controller", flow: &FlowMod{Priority: 100, Actions: "controller"}},
		{name: "output port", flow: &FlowMod{Priority: 100, Match: "nw_dst=198.51.100.0/24", Actions: "output:3"}},
		{name: "nil flow", flow: nil, wantErr: true},
		{name: "output not a port", flow: &FlowMod{Priority: 100, Actions: "output:not-a-port"}, wantErr: true},
		{name: "match not an ip", flow: &FlowMod{Priority: 100, Match: "nw_src=not-an-ip", Actions: "normal"}, wantErr: true},
		{name: "cookie not hex", flow: &FlowMod{Priority: 100, Cookie: "zz", Actions: "normal"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFlowMod(tt.flow)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}
