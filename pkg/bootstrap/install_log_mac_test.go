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

package bootstrap

import "testing"

// TestSanitizeMACForPath covers the happy path: standard colon-separated
// MAC is normalized to lowercase dash-separated form used in the upload
// path. A mismatch between MACs on the orchestrator vs autoinstall sides
// causes the poller to silently miss install.log uploads, so this
// normalization must be stable.
func TestSanitizeMACForPath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"aa:bb:cc:dd:ee:ff", "aa-bb-cc-dd-ee-ff"},
		{"AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff"},
		{"aa-bb-cc-dd-ee-ff", "aa-bb-cc-dd-ee-ff"},
		{"AABBCCDDEEFF", "aa-bb-cc-dd-ee-ff"},
		{"00:25:90:00:02:aa", "00-25-90-00-02-aa"},
	}
	for _, tc := range cases {
		if got := sanitizeMACForPath(tc.in); got != tc.want {
			t.Errorf("sanitizeMACForPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestSanitizeMACForPath_Invalid verifies that inputs that don't
// contain exactly 12 hex digits return empty string rather than a
// malformed path. The caller treats empty as "skip this MAC".
func TestSanitizeMACForPath_Invalid(t *testing.T) {
	cases := []string{
		"",
		"not a mac",
		"aa:bb:cc:dd:ee",       // 10 hex (5 octets)
		"aa:bb:cc:dd:ee:ff:11", // 14 hex (7 octets)
		"zzzzzz",
	}
	for _, in := range cases {
		if got := sanitizeMACForPath(in); got != "" {
			t.Errorf("sanitizeMACForPath(%q) = %q, want empty", in, got)
		}
	}
}

// TestCandidateURLs verifies the poll-URL precedence: MAC-keyed paths
// first (one per known MAC, in listed order), hostname path last. This
// ordering lets a robust MAC-based match win before we fall through to
// the fragile hostname path.
func TestCandidateURLs(t *testing.T) {
	p := &InstallLogPoller{
		Hostname: "node-02",
		MACs:     []string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"},
	}
	got := p.candidateURLs("http://sink:8080")
	want := []string{
		"http://sink:8080/installs/mac/aa-bb-cc-dd-ee-ff/install.log",
		"http://sink:8080/installs/mac/11-22-33-44-55-66/install.log",
		"http://sink:8080/installs/node-02/install.log",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d URLs %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("candidate[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestCandidateURLs_HostnameOnly covers the fallback-only case: no
// MACs known (older orchestrator configs, dry runs). The hostname path
// is still produced so older deployments continue to work.
func TestCandidateURLs_HostnameOnly(t *testing.T) {
	p := &InstallLogPoller{Hostname: "node-02"}
	got := p.candidateURLs("http://sink:8080")
	want := []string{"http://sink:8080/installs/node-02/install.log"}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("got %v, want %v", got, want)
	}
}
