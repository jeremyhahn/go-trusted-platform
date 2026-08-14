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
	"bufio"
	"compress/gzip"
	"io"
	"strings"
)

// Kernel config symbols required for OVS tc-flower hardware offload on
// 100/200/400G NICs. The core set gates the tc classifier/action path and
// the conntrack fast path used by every offload-capable driver; the mlx5
// and bnxt sets gate the driver-side offload engines (ConnectX switchdev
// e-switch and NetXtreme TruFlow respectively). Alpine's linux-lts config
// varies per release, so these must be verified against the running
// kernel — see docs/sdn/performance/hw-offload.md.
var (
	hwOffloadCoreConfigs = []string{
		"CONFIG_NET_CLS_FLOWER",
		"CONFIG_NET_SWITCHDEV",
		"CONFIG_NET_TC_SKB_EXT",
		"CONFIG_NF_FLOW_TABLE",
		"CONFIG_NET_ACT_CT",
	}
	hwOffloadMLX5Configs = []string{
		"CONFIG_MLX5_ESWITCH",
		"CONFIG_MLX5_CLS_ACT",
		"CONFIG_MLX5_TC_CT",
	}
	hwOffloadBNXTConfigs = []string{
		"CONFIG_BNXT_FLOWER_OFFLOAD",
	}
)

// HWOffloadSupport reports which kernel config symbols required for OVS
// hardware offload are missing from a kernel configuration, grouped by
// scope so callers can warn only about the driver families actually
// present on the host.
type HWOffloadSupport struct {
	// MissingCore lists absent symbols every offload-capable driver
	// needs (tc-flower classifier, switchdev, conntrack fast path).
	MissingCore []string

	// MissingMLX5 lists absent Mellanox ConnectX / BlueField
	// (mlx5_core switchdev) offload symbols.
	MissingMLX5 []string

	// MissingBNXT lists absent Broadcom NetXtreme-E (bnxt_en TruFlow)
	// offload symbols.
	MissingBNXT []string
}

// CoreSupported reports whether every core (driver-independent) offload
// symbol is enabled.
func (s *HWOffloadSupport) CoreSupported() bool {
	return len(s.MissingCore) == 0
}

// Missing returns every absent symbol across all groups in declaration
// order, suitable for a single warning log line.
func (s *HWOffloadSupport) Missing() []string {
	var all []string
	all = append(all, s.MissingCore...)
	all = append(all, s.MissingMLX5...)
	all = append(all, s.MissingBNXT...)
	return all
}

// CheckHWOffloadSupport parses kernel configuration content in the
// /proc/config.gz format (gzip-compressed or plain "CONFIG_X=y" text —
// gzip is detected from the stream magic) and reports which symbols
// required for OVS tc-flower hardware offload are missing. A symbol
// counts as present when set to "y" or "m"; "# CONFIG_X is not set"
// lines and absent symbols count as missing.
//
// The parser accepts an io.Reader so callers can feed /proc/config.gz,
// a /boot/config-<kver> file, or in-memory test fixtures. It is not yet
// wired into a runtime path: the natural warning call-site is where
// `ovs.hw-offload: true` is applied to the Open_vSwitch table
// (pkg/app/sdn.go applyOVSGlobalConfig), which is owned by another
// workstream — wire it there once that surface is open for changes.
func CheckHWOffloadSupport(config io.Reader) (*HWOffloadSupport, error) {
	br := bufio.NewReader(config)
	magic, err := br.Peek(2)
	if err != nil && err != io.EOF {
		return nil, &WrappedError{Msg: "hw-offload check: failed to read kernel config", Err: err}
	}

	var r io.Reader = br
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, &WrappedError{Msg: "hw-offload check: failed to decompress kernel config", Err: err}
		}
		defer gz.Close()
		r = gz
	}

	enabled := make(map[string]bool)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		symbol, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if value == "y" || value == "m" {
			enabled[symbol] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, &WrappedError{Msg: "hw-offload check: failed to scan kernel config", Err: err}
	}

	missing := func(symbols []string) []string {
		var absent []string
		for _, symbol := range symbols {
			if !enabled[symbol] {
				absent = append(absent, symbol)
			}
		}
		return absent
	}

	return &HWOffloadSupport{
		MissingCore: missing(hwOffloadCoreConfigs),
		MissingMLX5: missing(hwOffloadMLX5Configs),
		MissingBNXT: missing(hwOffloadBNXTConfigs),
	}, nil
}
