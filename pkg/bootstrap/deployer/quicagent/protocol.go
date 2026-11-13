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

// Package quicagent is the QUIC deploy agent: a Server that runs on a
// deploy target and a Client that implements deployer.RemoteHost against
// it. Each operation (Run, CopyFileStream, StatRemote) is one bidirectional
// QUIC stream carrying a length-prefixed JSON request, an optional raw
// body, and a length-prefixed JSON response. The session is TLS 1.3 with
// mutual certificate authentication; there is no SSH fallback. See
// docs/bootstrap/remote-deploy.md.
package quicagent

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
)

// ALPN is the application protocol the agent and client negotiate.
const ALPN = "gtp-deploy-agent/1"

// maxFrameSize bounds a request or response frame (command output included).
const maxFrameSize = 16 << 20

// maxOutputSize is the budget for a Run's stdout and stderr together. JSON
// encodes a byte as at most six (an invalid UTF-8 byte becomes "�"),
// so a full budget still fits one response frame.
const maxOutputSize = maxFrameSize / 8

// Operation names on the wire.
const (
	opRun  = "run"
	opCopy = "copy"
	opStat = "stat"
)

// copyFileMode is the mode of a file the agent writes for CopyFileStream.
const copyFileMode = 0o644

// fipsCurves are the key-exchange groups both ends offer: the NIST curves
// approved for FIPS 140-3. TLS 1.3 cipher suites are fixed by crypto/tls;
// in FIPS 140-3 mode (GODEBUG=fips140=on) it keeps to AES-GCM.
var fipsCurves = []tls.CurveID{tls.CurveP256, tls.CurveP384}

// request opens every operation stream.
type request struct {
	Op      string `json:"op"`
	Command string `json:"command,omitempty"`
	Path    string `json:"path,omitempty"`
	Size    int64  `json:"size,omitempty"`
}

// response closes every operation stream.
type response struct {
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`
	Size     int64  `json:"size,omitempty"`
	MTime    int64  `json:"mtime,omitempty"`
	NotFound bool   `json:"not_found,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Error    string `json:"error,omitempty"`
}

// writeFrame writes v as one length-prefixed JSON frame in a single Write,
// so the header and payload are not split into separate STREAM frames.
func writeFrame(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(payload) > maxFrameSize {
		return ErrFrameTooLarge{Size: uint32(len(payload))}
	}
	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf, uint32(len(payload)))
	copy(buf[4:], payload)
	_, err = w.Write(buf)
	return err
}

// readFrame reads one length-prefixed JSON frame into v.
func readFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrameSize {
		return ErrFrameTooLarge{Size: n}
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}
	return json.Unmarshal(payload, v)
}
