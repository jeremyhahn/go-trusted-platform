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
)

// Every command's flags can host platformd: without it an embedded context
// is refused at connect (#691).
func TestGetCommonFlags_CanHostAnEmbeddedDaemon(t *testing.T) {
	if getCommonFlags().StartEmbedded == nil {
		t.Fatal("StartEmbedded is nil: embedded contexts cannot connect")
	}
}
