package arch

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeGo answers `go env NAME` from the FAKE_NAME environment variable, the
// way the go command reports its environment.
const fakeGo = `#!/bin/sh
[ "$1" = env ] || { echo "fake go: unexpected $*" >&2; exit 2; }
eval "printf '%s\n' \"\${FAKE_$2-}\""
`

// TestCIGoIntegrityScript: ruling 869. The script passes only the pool's
// expected module environment and names each departure from it.
func TestCIGoIntegrityScript(t *testing.T) {
	script, err := filepath.Abs("../../scripts/ci-go-integrity.sh")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(fakeGo), 0o755); err != nil { // #nosec G306 -- the stub must be executable
		t.Fatal(err)
	}
	good := map[string]string{
		"GOSUMDB": "sum.golang.org", "GONOSUMDB": "", "GOPRIVATE": "", "GONOPROXY": "", "GOINSECURE": "",
		"GOFLAGS": "-mod=readonly", "GOPROXY": "http://lan.example:3300|https://proxy.golang.org",
	}
	for _, c := range []struct {
		name   string
		change map[string]string
		extra  []string
		want   string
	}{
		{name: "the pool's environment passes", want: ""},
		{name: "another checksum database", change: map[string]string{"GOSUMDB": "off"}, want: "GOSUMDB is 'off'"},
		{name: "a GONOSUMDB exemption", change: map[string]string{"GONOSUMDB": "github.com/x"}, want: "GONOSUMDB is 'github.com/x'"},
		{name: "a GOPRIVATE exemption", change: map[string]string{"GOPRIVATE": "github.com/x"}, want: "GOPRIVATE is"},
		{name: "a GOINSECURE exemption", change: map[string]string{"GOINSECURE": "github.com/x"}, want: "GOINSECURE is"},
		{name: "a GONOPROXY direct fetch", change: map[string]string{"GONOPROXY": "github.com/x"}, want: "GONOPROXY is"},
		{name: "a later -mod overrides readonly", change: map[string]string{"GOFLAGS": "-mod=readonly -mod=mod"}, want: "sets -mod=mod"},
		{name: "an earlier -mod beside readonly", change: map[string]string{"GOFLAGS": "-mod=vendor -mod=readonly"}, want: "sets -mod=vendor"},
		{name: "a pool runner is checked", extra: []string{"RUNNER_ENVIRONMENT=self-hosted"}, change: map[string]string{"GOSUMDB": "off"}, want: "GOSUMDB is 'off'"},
		{name: "a GitHub-hosted runner is not a pool", extra: []string{"RUNNER_ENVIRONMENT=github-hosted"}, change: map[string]string{"GOSUMDB": "off", "GOPROXY": "https://proxy.golang.org,direct"}, want: ""},
		{name: "another runner label is still checked", extra: []string{"RUNNER_ENVIRONMENT=github-hosted-ish"}, change: map[string]string{"GOSUMDB": "off"}, want: "GOSUMDB is 'off'"},
		{name: "GONOSUMCHECK set", extra: []string{"GONOSUMCHECK=1"}, want: "GONOSUMCHECK is set"},
		{name: "an -insecure flag", change: map[string]string{"GOFLAGS": "-mod=readonly -insecure"}, want: "carries -insecure"},
		{name: "no read-only module mode", change: map[string]string{"GOFLAGS": "-buildvcs=false"}, want: "lacks -mod=readonly"},
		{name: "a direct fallback", change: map[string]string{"GOPROXY": "https://proxy.golang.org,direct"}, want: "falls back to direct"},
		{name: "a direct fallback behind a space", change: map[string]string{"GOPROXY": "http://lan.example:3300|https://proxy.golang.org, direct"}, want: "falls back to direct"},
		{name: "a direct fallback with trailing space", change: map[string]string{"GOPROXY": "direct ,https://proxy.golang.org"}, want: "falls back to direct"},
		{name: "a quoted -mod override", change: map[string]string{"GOFLAGS": "-mod=readonly '-mod=mod'"}, want: "holds quoting"},
		{name: "a double-quoted -mod override", change: map[string]string{"GOFLAGS": `-mod=readonly "-mod=mod"`}, want: "holds quoting"},
		{name: "a --mod override", change: map[string]string{"GOFLAGS": "-mod=readonly --mod=mod"}, want: "sets -mod=mod"},
		{name: "--mod=readonly counts as readonly", change: map[string]string{"GOFLAGS": "--mod=readonly"}, want: ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			// RUNNER_ENVIRONMENT is unset unless a case sets it: unset is checked.
			env := []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")}
			for k, v := range good {
				if nv, ok := c.change[k]; ok {
					v = nv
				}
				env = append(env, "FAKE_"+k+"="+v)
			}
			cmd := exec.Command("bash", script) // #nosec G204 -- the repository's own script
			cmd.Env = append(env, c.extra...)
			out, err := cmd.CombinedOutput()
			if c.want == "" {
				if err != nil {
					t.Fatalf("the script refused: %v\n%s", err, out)
				}
				return
			}
			if err == nil {
				t.Fatalf("the script passed; want a refusal containing %q:\n%s", c.want, out)
			}
			if !strings.Contains(string(out), c.want) {
				t.Fatalf("the refusal lacks %q:\n%s", c.want, out)
			}
		})
	}
}
