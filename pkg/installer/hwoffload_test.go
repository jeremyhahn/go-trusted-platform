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

package installer

import (
	"bytes"
	"compress/gzip"
	"errors"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
)

// fullOffloadConfig enables every symbol CheckHWOffloadSupport requires,
// mixing =y and =m the way a real Alpine linux-lts config does.
const fullOffloadConfig = `#
# Automatically generated file; DO NOT EDIT.
#
CONFIG_NET_CLS_FLOWER=m
CONFIG_NET_SWITCHDEV=y
CONFIG_NET_TC_SKB_EXT=y
CONFIG_NF_FLOW_TABLE=m
CONFIG_NET_ACT_CT=m
CONFIG_MLX5_ESWITCH=y
CONFIG_MLX5_CLS_ACT=y
CONFIG_MLX5_TC_CT=y
CONFIG_BNXT_FLOWER_OFFLOAD=y
CONFIG_UNRELATED=y
`

func TestCheckHWOffloadSupportAllPresent(t *testing.T) {
	got, err := CheckHWOffloadSupport(strings.NewReader(fullOffloadConfig))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.CoreSupported() {
		t.Errorf("CoreSupported() = false, want true (missing core: %v)", got.MissingCore)
	}
	if missing := got.Missing(); len(missing) != 0 {
		t.Errorf("Missing() = %v, want empty", missing)
	}
}

func TestCheckHWOffloadSupportMissingSymbols(t *testing.T) {
	// "is not set" comments and absent symbols both count as missing;
	// =n (never emitted by kconfig, but defensive) also counts as missing.
	config := `CONFIG_NET_CLS_FLOWER=m
CONFIG_NET_SWITCHDEV=y
# CONFIG_NET_TC_SKB_EXT is not set
CONFIG_NF_FLOW_TABLE=m
CONFIG_NET_ACT_CT=n
CONFIG_MLX5_ESWITCH=y
CONFIG_MLX5_CLS_ACT=y
CONFIG_BNXT_FLOWER_OFFLOAD=y
`
	got, err := CheckHWOffloadSupport(strings.NewReader(config))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.CoreSupported() {
		t.Error("CoreSupported() = true, want false")
	}
	wantCore := []string{"CONFIG_NET_TC_SKB_EXT", "CONFIG_NET_ACT_CT"}
	if !reflect.DeepEqual(got.MissingCore, wantCore) {
		t.Errorf("MissingCore = %v, want %v", got.MissingCore, wantCore)
	}
	wantMLX5 := []string{"CONFIG_MLX5_TC_CT"}
	if !reflect.DeepEqual(got.MissingMLX5, wantMLX5) {
		t.Errorf("MissingMLX5 = %v, want %v", got.MissingMLX5, wantMLX5)
	}
	if len(got.MissingBNXT) != 0 {
		t.Errorf("MissingBNXT = %v, want empty", got.MissingBNXT)
	}
	wantAll := []string{"CONFIG_NET_TC_SKB_EXT", "CONFIG_NET_ACT_CT", "CONFIG_MLX5_TC_CT"}
	if !reflect.DeepEqual(got.Missing(), wantAll) {
		t.Errorf("Missing() = %v, want %v", got.Missing(), wantAll)
	}
}

func TestCheckHWOffloadSupportGzipInput(t *testing.T) {
	// /proc/config.gz is gzip-compressed; the checker must detect the
	// magic and decompress transparently.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(fullOffloadConfig)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	got, err := CheckHWOffloadSupport(&buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if missing := got.Missing(); len(missing) != 0 {
		t.Errorf("Missing() = %v, want empty", missing)
	}
}

func TestCheckHWOffloadSupportEmptyInput(t *testing.T) {
	got, err := CheckHWOffloadSupport(strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.CoreSupported() {
		t.Error("CoreSupported() = true for empty config, want false")
	}
	wantTotal := len(hwOffloadCoreConfigs) + len(hwOffloadMLX5Configs) + len(hwOffloadBNXTConfigs)
	if missing := got.Missing(); len(missing) != wantTotal {
		t.Errorf("Missing() returned %d symbols, want %d", len(missing), wantTotal)
	}
}

func TestCheckHWOffloadSupportReadError(t *testing.T) {
	readErr := errors.New("device gone")
	if _, err := CheckHWOffloadSupport(iotest.ErrReader(readErr)); err == nil {
		t.Fatal("expected error, got nil")
	} else if !errors.Is(err, readErr) {
		t.Errorf("error %v does not wrap %v", err, readErr)
	}
}

func TestCheckHWOffloadSupportCorruptGzip(t *testing.T) {
	// A stream that starts with the gzip magic but is not valid gzip
	// must surface a typed decompression error, not garbage results.
	corrupt := []byte{0x1f, 0x8b, 0xde, 0xad, 0xbe, 0xef}
	if _, err := CheckHWOffloadSupport(bytes.NewReader(corrupt)); err == nil {
		t.Fatal("expected error, got nil")
	}
}
