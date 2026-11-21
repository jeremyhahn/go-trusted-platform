package diskimage

import (
	"bytes"
	"strings"
	"testing"

	pkgdiskimage "github.com/jeremyhahn/go-trusted-platform/pkg/diskimage"
)

// The create command claims registration only when the build registered the
// manifest (Result.Registered); an unregistered manifest is reported as such
// (Codex P1, #1907).
func TestPrintManifestLineReportsRegistration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result pkgdiskimage.Result
		want   string
		absent string
	}{
		{"registered", pkgdiskimage.Result{Manifest: "/out/a.manifest", Registered: true}, "/out/a.manifest (registered in the reference-values store)", ""},
		{"unregistered", pkgdiskimage.Result{Manifest: "/out/a.manifest"}, "/out/a.manifest (NOT registered in the reference-values store)", "(registered in"},
		{"unmeasured", pkgdiskimage.Result{Unmeasured: "no Secure Boot"}, "Measurement manifest: none (no Secure Boot)", "registered"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			printManifestLine(&out, &tc.result)
			if !strings.Contains(out.String(), tc.want) {
				t.Fatalf("printed %q, want %q", out.String(), tc.want)
			}
			if tc.absent != "" && strings.Contains(out.String(), tc.absent) {
				t.Fatalf("printed %q, must not contain %q", out.String(), tc.absent)
			}
		})
	}
}
