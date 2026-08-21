// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package fips

import (
	"os"
	"path/filepath"
	"testing"
)

// withFIPSActivation points the kernel indicator at a fixture for one test and
// restores it afterwards. Test-only: the variable is unexported and this file
// is _test.go, so production has no way to reach it.
func withFIPSActivation(t *testing.T, enabled bool) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fips_enabled")
	value := "0\n"
	if enabled {
		value = "1\n"
	}
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	original := fipsIndicatorPath
	fipsIndicatorPath = path
	t.Cleanup(func() { fipsIndicatorPath = original })

	if IsEnabled() != enabled {
		t.Fatalf("fixture did not take effect: IsEnabled()=%v want %v", IsEnabled(), enabled)
	}
}
