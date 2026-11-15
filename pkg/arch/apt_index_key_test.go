package arch

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// aptRefreshKeyScript prints APT_REFRESH, the cache key of the devcontainer's
// apt layer (Tenant Agent ruling 676, item 2).
const aptRefreshKeyScript = "scripts/apt-refresh-key.sh"

// inRelease is a Debian InRelease file trimmed to the fields the key reads:
// a Date: line, then SHA256: entries for the Packages and Sources indexes.
type inRelease struct {
	date     string
	amd64Sum string
	arm64Sum string
	srcSum   string
}

func (r inRelease) String() string {
	var b strings.Builder
	b.WriteString("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n")
	b.WriteString("Origin: Debian\nLabel: Debian\nSuite: stable\nCodename: bookworm\n")
	fmt.Fprintf(&b, "Date: %s\n", r.date)
	b.WriteString("Architectures: all amd64 arm64\nComponents: main contrib non-free-firmware\n")
	b.WriteString("MD5Sum:\n d41d8cd98f00b204e9800998ecf8427e 0 main/binary-amd64/Packages.xz\n")
	b.WriteString("SHA256:\n")
	fmt.Fprintf(&b, " %s 1234 main/binary-amd64/Packages\n", strings.Repeat("1", 64))
	fmt.Fprintf(&b, " %s 567 main/binary-amd64/Packages.xz\n", r.amd64Sum)
	fmt.Fprintf(&b, " %s 1234 main/binary-arm64/Packages\n", strings.Repeat("2", 64))
	fmt.Fprintf(&b, " %s 568 main/binary-arm64/Packages.xz\n", r.arm64Sum)
	fmt.Fprintf(&b, " %s 99 main/binary-i386/Packages.xz\n", strings.Repeat("3", 64))
	fmt.Fprintf(&b, " %s 890 main/source/Sources.xz\n", r.srcSum)
	fmt.Fprintf(&b, " %s 12 contrib/binary-amd64/Release\n", strings.Repeat("4", 64))
	b.WriteString("-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n")
	return b.String()
}

func baseRelease(seed string) inRelease {
	return inRelease{
		date:     "Sat, 14 Nov 2026 09:12:33 UTC",
		amd64Sum: strings.Repeat(seed+"a", 32),
		arm64Sum: strings.Repeat(seed+"b", 32),
		srcSum:   strings.Repeat(seed+"c", 32),
	}
}

// runAptRefreshKey serves the two suites' InRelease files from httptest and
// runs the script against them through APT_SUITES.
func runAptRefreshKey(t *testing.T, suites map[string]inRelease) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not installed")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/InRelease")
		rel, ok := suites[name]
		if !ok || !strings.HasSuffix(r.URL.Path, "/InRelease") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(rel.String()))
	}))
	t.Cleanup(srv.Close)

	var urls []string
	for _, name := range []string{"bookworm", "bookworm-security"} {
		urls = append(urls, srv.URL+"/"+name)
	}
	cmd := exec.Command("/bin/sh", filepath.Join(repoRoot(t), aptRefreshKeyScript))
	cmd.Env = append(cmd.Environ(), "APT_SUITES="+strings.Join(urls, "\n"))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: %v\nstderr: %s", aptRefreshKeyScript, err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), stderr.String()
}

var hexSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestAptRefreshKeyFollowsPackageIndexes(t *testing.T) {
	base := map[string]inRelease{
		"bookworm":          baseRelease("0"),
		"bookworm-security": baseRelease("5"),
	}
	key, stderr := runAptRefreshKey(t, base)
	if !hexSHA256.MatchString(key) {
		t.Fatalf("key %q is not a hex sha256 (stderr: %s)", key, stderr)
	}
	if strings.Contains(stderr, "warning") {
		t.Fatalf("unexpected fallback warning: %s", stderr)
	}

	with := func(suite string, edit func(*inRelease)) map[string]inRelease {
		out := map[string]inRelease{}
		for k, v := range base {
			out[k] = v
		}
		rel := out[suite]
		edit(&rel)
		out[suite] = rel
		return out
	}

	same := []struct {
		name   string
		suites map[string]inRelease
	}{
		{"date only", with("bookworm", func(r *inRelease) { r.date = "Sun, 15 Nov 2026 03:00:01 UTC" })},
		{"sources only", with("bookworm-security", func(r *inRelease) { r.srcSum = strings.Repeat("d", 64) })},
	}
	for _, tt := range same {
		t.Run("unchanged/"+tt.name, func(t *testing.T) {
			if got, _ := runAptRefreshKey(t, tt.suites); got != key {
				t.Fatalf("key changed on %s: %s -> %s", tt.name, key, got)
			}
		})
	}

	changed := []struct {
		name   string
		suites map[string]inRelease
	}{
		{"amd64 Packages.xz", with("bookworm", func(r *inRelease) { r.amd64Sum = strings.Repeat("e", 64) })},
		{"arm64 Packages.xz", with("bookworm-security", func(r *inRelease) { r.arm64Sum = strings.Repeat("f", 64) })},
	}
	for _, tt := range changed {
		t.Run("changed/"+tt.name, func(t *testing.T) {
			got, _ := runAptRefreshKey(t, tt.suites)
			if got == key {
				t.Fatalf("key unchanged after the %s SHA256 line changed: %s", tt.name, key)
			}
			if !hexSHA256.MatchString(got) {
				t.Fatalf("key %q is not a hex sha256", got)
			}
		})
	}
}

func TestAptRefreshKeyFallsBackWhenASuiteIsUnreachable(t *testing.T) {
	key, stderr := runAptRefreshKey(t, map[string]inRelease{"bookworm": baseRelease("0")})
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}Z$`).MatchString(key) {
		t.Fatalf("fallback key %q is not the UTC date and hour", key)
	}
	if !strings.Contains(stderr, "warning: apt-refresh-key:") {
		t.Fatalf("no fallback warning on stderr: %q", stderr)
	}
}
