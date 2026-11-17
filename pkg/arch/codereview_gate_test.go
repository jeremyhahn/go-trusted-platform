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
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	codeReviewWorkflowFile = ".github/workflows/code-review.yml"

	// codeReviewVerdictRead marks the approval gate's run script: the
	// reviewer's standing verdict on the head.
	codeReviewVerdictRead = `verdict=$(get_all "/pulls/$PR_NUM/reviews?"`
	codeReviewVerdictCase = `case "$verdict"`
	codeReviewTwinWait    = `"$waited" -lt 4500`
	codeReviewLabelsRead  = `.labels[].name`
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
# FAKE_FAIL, a glob on the path, makes the forge answer HTTP 500.
if [ -n "${FAKE_FAIL:-}" ] && [[ $path == $FAKE_FAIL ]]; then
  printf '{"message":"boom"}' >"$out"
  printf 500
  exit 0
fi
case "$path" in
  # The live PR: its head, its base (FAKE_BASE_REF, the run's BASE_REF by
  # default) and its labels.
  "/pulls/$PR_NUM")
    body="{\"head\":{\"sha\":\"$EVENT_SHA\"},\"base\":{\"ref\":\"${FAKE_BASE_REF:-$BASE_REF}\"},\"labels\":$FAKE_LABELS}" ;;
  # Gitea's issue labels are not paginated: every page is the full list.
  "/issues/$PR_NUM/labels?"*) body=$FAKE_LABELS ;;
  *page=1)
    case "$path" in
      "/pulls/$PR_NUM/files?"*) body=${FAKE_FILES:-'[{"filename":"pkg/x/x.go"}]'} ;;
      "/pulls/$PR_NUM/reviews?"*)
        body="[{\"id\":1,\"state\":\"APPROVED\",\"user\":{\"login\":\"$REVIEWER\"},\"commit_id\":\"$EVENT_SHA\",\"submitted_at\":\"2026-11-15T00:00:00Z\"}]" ;;
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

	const docsOnly = `[{"filename":"docs/x.md"}]`
	cases := []struct {
		name     string
		labels   string
		files    string // FAKE_FILES: the PR's files; code by default
		base     string // FAKE_BASE_REF: the live base; the run's BASE_REF by default
		fail     string // FAKE_FAIL: the path glob the forge answers HTTP 500
		wantPass bool
		wantOut  string
	}{
		// The labels come from the live PR, so a forge whose labels
		// endpoint is not paginated (Gitea) never loops (Codex P1, #1921).
		{"an approval without the hold", `[{"name":"code-review"},{"name":"task:ready"}]`, "", "", "", true, "codex approved"},
		{"an approval on owner hold", `[{"name":"code-review"},{"name":"needs-owner"}]`, "", "", "", false, "owner hold"},
		// The review job swaps needs-owner for needs-coordinator (v5.11.3);
		// the hold carries over, so the swap never releases an approval
		// (Codex P1 round 2, #1986).
		{"an approval on coordinator hold", `[{"name":"code-review"},{"name":"needs-coordinator"}]`, "", "", "", false, "coordinator hold"},
		{"a docs-only change", `[]`, docsOnly, "", "", true, "no review is required"},
		// A PR retargeted while the run waited never passes on the old
		// base's exempt diff or approval (Codex P1, #1921).
		{"a retargeted docs-only change", `[]`, docsOnly, "release", "", false, "retargeted from main to release"},
		{"a retargeted approved change", `[{"name":"code-review"}]`, "", "release", "", false, "retargeted from main to release"},
		// A failed page request fails the gate: it never ends the listing
		// as if the list were complete (Codex P1, #1921).
		{"a failed live PR read", `[{"name":"code-review"}]`, "", "", "/pulls/7", false, "answered HTTP 500"},
		{"a failed later reviews page", `[{"name":"code-review"}]`, "", "", "/pulls/7/reviews?*page=2", false, "answered HTTP 500"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A gate that loops on a page fails here, not at the job timeout.
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bash, "-eo", "pipefail", "-c", step.Run)
			cmd.WaitDelay = time.Second
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
				"FAKE_FILES=" + tc.files,
				"FAKE_BASE_REF=" + tc.base,
				"FAKE_FAIL=" + tc.fail,
			}
			out, runErr := cmd.CombinedOutput()
			require.NoError(t, ctx.Err(), "the gate did not finish:\n%s", out)
			if tc.wantPass {
				require.NoError(t, runErr, string(out))
				require.Contains(t, string(out), tc.wantOut)
				return
			}
			var exitErr *exec.ExitError
			require.ErrorAs(t, runErr, &exitErr, "the gate passed:\n%s", out)
			require.Contains(t, string(out), tc.wantOut, string(out))
		})
	}
}
