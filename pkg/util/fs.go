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

package util

import (
	"io"
	"os"
	"strings"
)

func IsEmpty(dir string) bool {
	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	if _, err = f.Readdirnames(1); err == io.EOF {
		return true
	}
	return false
}

func EscapeFilePath(path string) string {
	// List of characters to escape in Linux file paths
	specialChars := ` !"#$%&'()*,:;<=>?@[\]^` + "`" + `{|}~`

	// Replace each special character with an escaped version
	var escapedPath strings.Builder
	for _, ch := range path {
		if strings.ContainsRune(specialChars, ch) || ch == '\\' {
			escapedPath.WriteRune('\\')
		}
		escapedPath.WriteRune(ch)
	}
	return escapedPath.String()
}
