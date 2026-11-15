// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package arch

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	codeReviewWorkflowFile = ".github/workflows/code-review.yml"

	// codeReviewVerdictRead marks the approval gate's run script: the
	// reviewer's standing verdict on the head.
	codeReviewVerdictRead = `verdict=$(get_all "/pulls/$PR_NUM/reviews?"`
	codeReviewVerdictCase = `case "$verdict"`
	codeReviewTwinWait    = `"$waited" -lt 4500`
	codeReviewLabelsRead  = `/issues/$PR_NUM/labels`
	codeReviewOwnerHold   = `needs-owner`
)

// loadCodeReviewGateStep returns the approval gate's step of code-review.yml.
func loadCodeReviewGateStep(t *testing.T) ciStep {
	t.Helper()
	wf := loadCIWorkflow(t, repoRoot(t), codeReviewWorkflowFile)
	var found []ciStep
	for _, j := range wf.Jobs {
		for _, s := range j.Steps {
			if strings.Contains(s.Run, codeReviewVerdictRead) {
				found = append(found, s)
			}
		}
	}
	require.Len(t, found, 1, "code-review.yml has no single approval gate step")
	return found[0]
}

// The gate owns the required Code Review (codex) context, so an approval
// that is already on the head must not pass it while the PR is on owner
// hold: the gate reads the live labels after the twin-review wait and
// before it accepts the verdict (Codex P1, #1921).
func TestCodeReviewGateReadsTheLiveLabelsBeforeTheVerdict(t *testing.T) {
	run := loadCodeReviewGateStep(t).Run
	wait := strings.Index(run, codeReviewTwinWait)
	verdict := strings.Index(run, codeReviewVerdictCase)
	require.GreaterOrEqual(t, wait, 0, "the gate has no twin-review wait")
	require.GreaterOrEqual(t, verdict, 0, "the gate has no verdict case")
	labels := strings.Index(run, codeReviewLabelsRead)
	require.GreaterOrEqual(t, labels, 0, "the gate never reads the PR's live labels")
	require.Greater(t, labels, wait, "the gate reads the labels before the twin-review wait ends")
	require.Less(t, labels, verdict, "the gate reads the labels after it accepts the verdict")
	hold := strings.Index(run[labels:], codeReviewOwnerHold)
	require.GreaterOrEqual(t, hold, 0, "the gate does not check the labels for %s", codeReviewOwnerHold)
	require.Less(t, labels+hold, verdict, "the gate checks %s after it accepts the verdict", codeReviewOwnerHold)
}

// fakeForgeCurl answers the gate's API reads from canned bodies: one code
// file, the head as the live head, an APPROVED review by the reviewer on the
// head, and the labels in $FAKE_LABELS. Any later page is empty.
const fakeForgeCurl = `#!/usr/bin/env bash
out= url=
while [ $# -gt 0 ]; do
  case "$1" in
    -o|-w|-H|--proto|--max-time|--retry) [ "$1" = -o ] && out=$2; shift 2 ;;
    *) url=$1; shift ;;
  esac
done
path=${url#"$REPO_API"}
case "$path" in
  "/pulls/$PR_NUM") body="{\"head\":{\"sha\":\"$EVENT_SHA\"}}" ;;
  *page=1)
    case "$path" in
      "/pulls/$PR_NUM/files?"*) body='[{"filename":"pkg/x/x.go"}]' ;;
      "/pulls/$PR_NUM/reviews?"*)
        body="[{\"id\":1,\"state\":\"APPROVED\",\"user\":{\"login\":\"$REVIEWER\"},\"commit_id\":\"$EVENT_SHA\",\"submitted_at\":\"2026-11-15T00:00:00Z\"}]" ;;
      "/issues/$PR_NUM/labels?"*) body=$FAKE_LABELS ;;
      *) echo "fake curl: unexpected $path" >&2; exit 22 ;;
    esac ;;
  *) body='[]' ;;
esac
printf '%s' "$body" >"$out"
printf 200
`

func TestCodeReviewGateRefusesAnApprovalOnOwnerHold(t *testing.T) {
	step := loadCodeReviewGateStep(t)
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("the gate script needs jq")
	}
	bin := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bin, "curl"), []byte(fakeForgeCurl), 0o755))

	cases := []struct {
		name     string
		labels   string
		wantPass bool
	}{
		{"an approval without the hold", `[{"name":"code-review"},{"name":"task:ready"}]`, true},
		{"an approval on owner hold", `[{"name":"code-review"},{"name":"needs-owner"}]`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), bash, "-eo", "pipefail", "-c", step.Run)
			cmd.Dir = t.TempDir()
			// Gitea mode: no twin-review wait, so no Actions reads.
			cmd.Env = []string{
				"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
				"FORGE=gitea",
				"REVIEWER=codex",
				"REPO_API=http://forge.example.invalid/api/v1/repos/o/r",
				"PR_NUM=7",
				"EVENT_SHA=" + strings.Repeat("a", 40),
				"BASE_SHA=" + strings.Repeat("b", 40),
				"BASE_REF=main",
				"GH_API_TOKEN=x",
				`NO_REVIEW_PATHS=^docs/.+$`,
				"FAKE_LABELS=" + tc.labels,
			}
			out, runErr := cmd.CombinedOutput()
			if tc.wantPass {
				require.NoError(t, runErr, string(out))
				require.Contains(t, string(out), "codex approved")
				return
			}
			var exitErr *exec.ExitError
			require.ErrorAs(t, runErr, &exitErr, "the gate passed:\n%s", out)
			require.Contains(t, string(out), "owner hold", string(out))
		})
	}
}
