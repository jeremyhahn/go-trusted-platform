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

package zone

// Verdict is the result of a single inter-zone traffic decision.
type Verdict struct {
	// Allowed is true when traffic from the source zone to the destination
	// zone is permitted.
	Allowed bool

	// Services is the allowlist of service names that may traverse this path.
	// A nil or empty slice means all services are permitted (when Allowed is
	// true).
	Services []string
}

// matrixKey is the composite map key used for O(1) matrix lookups.
type matrixKey struct {
	from Zone
	to   Zone
}

// Matrix is the compiled inter-zone allow/deny lookup table derived from a
// resolved set of ZoneConfig declarations.  The default policy is deny; only
// paths explicitly opened by AllowTo (and not blocked by IsolateFrom or
// Isolate) appear in the allow table.
//
// Use Allowed to query the matrix.
type Matrix struct {
	// table maps (from, to) → Verdict.  Absent entries are deny.
	table map[matrixKey]Verdict
}

// Allowed returns the Verdict for traffic travelling from zone from to zone
// to.  If neither zone appears in the compiled set the verdict is deny.
func (m Matrix) Allowed(from, to Zone) Verdict {
	v, ok := m.table[matrixKey{from: from, to: to}]
	if !ok {
		return Verdict{Allowed: false}
	}
	return v
}

// CompileMatrix derives the inter-zone allow/deny matrix from the zone
// declarations and returns an O(1)-queryable Matrix.
//
// Compilation rules (in precedence order):
//
//  1. Default policy is deny for all (from, to) pairs.
//  2. For each zone Z with AllowTo entries, each declared path opens a
//     directed allow from Z → target with an optional service scope.
//  3. Intra-zone traffic (from == to) is allowed for zones that do not carry
//     Isolate=true.  Isolated zones must declare an explicit self-entry in
//     AllowTo to permit intra-zone traffic.
//  4. IsolateFrom: a zone Z with IsolateFrom=[A, B] cannot send traffic TO A
//     or B — those outbound paths are forcibly denied even if Z.AllowTo
//     declares them.  This matches the YAML configuration convention
//     documented in docs/architecture/reference-network.md (e.g.
//     "public.isolate_from: [trusted]" means public→trusted is denied).
//  5. Isolate: if zone Z has Isolate=true, only paths explicitly listed in
//     Z.AllowTo are open; no other outbound path from Z is allowed (rule 2
//     already satisfies this since the loop adds only declared paths).
//
// The Internet → public ingress relationship is not represented as a matrix
// cell; it is captured by ZoneConfig.InternetIngress and enforced at the
// flow-rule generation layer.
func CompileMatrix(zones []ZoneConfig) Matrix {
	m := Matrix{
		table: make(map[matrixKey]Verdict, len(zones)*len(zones)),
	}

	// Build a set of hard-deny pairs from IsolateFrom declarations.
	// IsolateFrom on zone Z listing T means: deny traffic FROM Z TO T
	// (outbound deny: "I am isolated from T, so I cannot send to T").
	type pair = matrixKey
	hardDeny := make(map[pair]struct{})
	for _, z := range zones {
		for _, dst := range z.IsolateFrom {
			hardDeny[pair{from: z.Name, to: dst}] = struct{}{}
		}
	}

	// Open intra-zone allow for non-isolated zones.
	for _, z := range zones {
		if !z.Isolate {
			key := matrixKey{from: z.Name, to: z.Name}
			if _, denied := hardDeny[key]; !denied {
				m.table[key] = Verdict{Allowed: true}
			}
		}
	}

	// Open directed paths from AllowTo declarations.
	for _, z := range zones {
		for _, path := range z.AllowTo {
			key := matrixKey{from: z.Name, to: path.Zone}
			// IsolateFrom takes precedence; skip if hard-denied.
			if _, denied := hardDeny[key]; denied {
				continue
			}
			var svc []string
			if len(path.Services) > 0 {
				svc = make([]string, len(path.Services))
				copy(svc, path.Services)
			}
			m.table[key] = Verdict{Allowed: true, Services: svc}
		}
	}

	return m
}
