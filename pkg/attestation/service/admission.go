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

package service

import (
	"context"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/store"
)

var _ calleradmission.Auditor = (*Service)(nil)

// RecordAdmission writes a caller-admission decision to the attestation
// event log. It is the node's audit trail for "who asked this TPM to quote,
// and were they allowed" — every decision lands here, admitted or not.
func (s *Service) RecordAdmission(_ context.Context, d calleradmission.Decision) error {
	if s == nil || s.store == nil {
		return ErrTPMSessionNotConfigured{Op: "RecordAdmission"}
	}
	meta := map[string]string{
		"strategy":          string(d.Strategy),
		"reason":            string(d.Reason),
		"security_relevant": strconv.FormatBool(!d.Admitted && d.Reason.SecurityRelevant()),
	}
	if len(d.Names) > 0 {
		meta["names"] = strings.Join(d.Names, ",")
	}
	ev := &store.Event{
		Kind:      store.EventKindCallerAdmitted,
		CN:        d.Identity,
		ClientIP:  clientIP(d.RemoteAddr),
		Timestamp: d.At,
		Outcome:   "admitted",
		Reason:    d.Detail,
		Metadata:  meta,
	}
	if !d.Admitted {
		ev.Kind = store.EventKindCallerRefused
		ev.Outcome = "refused"
	}
	return s.store.PutEvent(ev)
}

// clientIP strips the port from a transport address for the event's
// ClientIP field, which the existing enrollment events populate the same
// way.
func clientIP(remoteAddr string) string {
	if i := strings.LastIndexByte(remoteAddr, ':'); i > 0 && !strings.Contains(remoteAddr[i:], "]") {
		host := remoteAddr[:i]
		return strings.Trim(host, "[]")
	}
	return remoteAddr
}
