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
	"maps"
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
	codeReviewLabelsRead  = `.labels | if type == "array" then .[].name`
	codeReviewOwnerHold   = `needs-owner`
)

// loadCodeReviewGateStep returns the approval gate's step of code-review.yml,
// its Env the environment the runner gives it: the job's env, overridden by
// the step's own.
func loadCodeReviewGateStep(t *testing.T) ciStep {
	t.Helper()
	wf := loadCIWorkflow(t, repoRoot(t), codeReviewWorkflowFile)
	var found []ciStep
	for _, j := range wf.Jobs {
		for _, s := range j.Steps {
			if strings.Contains(s.Run, codeReviewVerdictRead) {
				env := maps.Clone(j.Env)
				if env == nil {
					env = map[string]string{}
				}
				maps.Copy(env, s.Env)
				s.Env = env
				found = append(found, s)
			}
		}
	}
	require.Len(t, found, 1, "code-review.yml has no single approval gate step")
	return found[0]
}

// The gate owns the required Code Review (codex) context, so an approval
// that is already on the head must not pass it while the PR is on owner
// hold: the gate reads the live labels and checks the holds in holds()
// (v5.12.11), which it calls before it accepts the verdict (Codex P1, #1921).
func TestCodeReviewGateReadsTheLiveLabelsBeforeTheVerdict(t *testing.T) {
	run := loadCodeReviewGateStep(t).Run
	// v5.12.8 dropped the gate's twin-review wait: the gate reads the twins
	// without waiting, so only the order labels -> hold -> verdict is pinned.
	verdict := strings.Index(run, codeReviewVerdictCase)
	require.GreaterOrEqual(t, verdict, 0, "the gate has no verdict case")
	labels := strings.Index(run, codeReviewLabelsRead)
	require.GreaterOrEqual(t, labels, 0, "the gate never reads the PR's live labels")
	require.Less(t, labels, verdict, "the gate reads the labels after it accepts the verdict")
	hold := strings.Index(run[labels:], codeReviewOwnerHold)
	require.GreaterOrEqual(t, hold, 0, "the gate does not check the labels for %s", codeReviewOwnerHold)
	require.Less(t, labels+hold, verdict, "the gate checks %s after it accepts the verdict", codeReviewOwnerHold)
}

// fakeForgeCurl answers the gate's API reads from canned bodies: one code
// file, the head as the live head, an APPROVED review by the reviewer on the
// head (or the reviews in $FAKE_REVIEWS), and the labels in $FAKE_LABELS.
// Any later page is empty.
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
        [ -z "${FAKE_REVIEWS:-}" ] || { printf '%s' "$FAKE_REVIEWS" >"$out"; printf 200; exit 0; }
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

	// The exemption lists are the workflow's own, so a CI-config path
	// reaches the guarded exemption exactly as it does in a run.
	noReview, docs := step.Env["NO_REVIEW_PATHS"], step.Env["DOCS_PATHS"]
	require.NotEmpty(t, noReview, "the gate step sets no NO_REVIEW_PATHS")
	require.NotEmpty(t, docs, "the gate step sets no DOCS_PATHS")

	const docsOnly = `[{"filename":"docs/x.md"}]`
	const ciOnly = `[{"filename":".github/workflows/ci.yml"}]`
	// jobs is this run's scope and review jobs: the guard's verdict
	// (SCOPE_SKIP) and both jobs' results. The zero value is a run whose
	// guard ran no skip and whose jobs succeeded.
	type jobs struct{ scopeSkip, scopeResult, reviewResult string }
	cases := []struct {
		name     string
		labels   string
		files    string // FAKE_FILES: the PR's files; code by default
		base     string // FAKE_BASE_REF: the live base; the run's BASE_REF by default
		fail     string // FAKE_FAIL: the path glob the forge answers HTTP 500
		jobs     jobs
		reviews  string // FAKE_REVIEWS: the reviews; an approval of the head by default
		wantPass bool
		wantOut  string
	}{
		// The labels come from the live PR, so a forge whose labels
		// endpoint is not paginated (Gitea) never loops (Codex P1, #1921).
		{"an approval without the hold", `[{"name":"code-review"},{"name":"task:ready"}]`, "", "", "", jobs{}, "", true, "codex approved"},
		{"an approval on owner hold", `[{"name":"code-review"},{"name":"needs-owner"}]`, "", "", "", jobs{}, "", false, "on hold (needs-owner)"},
		// The review job swaps needs-owner for needs-coordinator (v5.11.3);
		// the hold carries over, so the swap never releases an approval
		// (Codex P1 round 2, #1986).
		{"an approval on coordinator hold", `[{"name":"code-review"},{"name":"needs-coordinator"}]`, "", "", "", jobs{}, "", false, "on hold (needs-coordinator)"},
		{"a docs-only change", `[]`, docsOnly, "", "", jobs{}, "", true, "no review is required"},
		// A PR retargeted while the run waited never passes on the old
		// base's exempt diff or approval (Codex P1, #1921).
		{"a retargeted docs-only change", `[]`, docsOnly, "release", "", jobs{}, "", false, "retargeted from main to release"},
		{"a retargeted approved change", `[{"name":"code-review"}]`, "", "release", "", jobs{}, "", false, "retargeted from main to release"},
		// A failed page request fails the gate: it never ends the listing
		// as if the list were complete (Codex P1, #1921).
		{"a failed live PR read", `[{"name":"code-review"}]`, "", "", "/pulls/7", jobs{}, "", false, "answered HTTP 500"},
		{"a failed later reviews page", `[{"name":"code-review"}]`, "", "", "/pulls/7/reviews?*page=2", jobs{}, "", false, "answered HTTP 500"},
		// v5.12.1: this run's review job failed (a requested round that
		// ended red), so the approval already on the head is not reused.
		{"an approval after this run's review failed", `[{"name":"code-review"}]`, "", "", "", jobs{reviewResult: "failure"}, "", false, "review job failed"},
		// v5.12.2: a scope job that failed or was cancelled ran no review,
		// so the approval already on the head is not reused.
		{"an approval after the scope job failed", `[{"name":"code-review"}]`, "", "", "", jobs{scopeResult: "failure"}, "", false, "scope job ended failure"},
		{"an approval after the scope job was cancelled", `[{"name":"code-review"}]`, "", "", "", jobs{scopeResult: "cancelled"}, "", false, "scope job ended cancelled"},
		// v5.12.1 (ruling 443): CI config is exempt only when InfoSec's
		// guard cleared it on this event.
		{"a CI-only change the guard cleared", `[]`, ciOnly, "", "", jobs{scopeSkip: "true"}, `[]`, true, "no review is required"},
		{"a CI-only change the guard refused", `[]`, ciOnly, "", "", jobs{scopeSkip: "false"}, `[]`, false, "did not clear it"},
		{"a CI-only change the guard never judged", `[]`, ciOnly, "", "", jobs{}, `[]`, false, "did not clear it"},
		{"a code change with no approval", `[{"name":"code-review"}]`, "", "", "", jobs{}, `[]`, false, "codex must approve"},
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
				"NO_REVIEW_PATHS=" + noReview,
				// code-review v5.12.1 and v5.12.2: the docs list, the scope job
				// (InfoSec's guard) and this run's review job.
				"DOCS_PATHS=" + docs,
				"SCOPE_SKIP=" + tc.jobs.scopeSkip,
				"SCOPE_RESULT=" + or(tc.jobs.scopeResult, "success"),
				"REVIEW_RESULT=" + or(tc.jobs.reviewResult, "success"),
				"FAKE_REVIEWS=" + tc.reviews,
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

// or returns v, or def when v is empty.
// codeReviewJob returns the one job of code-review.yml with the given ID.
func codeReviewJob(t *testing.T, wf ciWorkflow, id string) ciJob {
	t.Helper()
	var found []ciJob
	for _, j := range wf.Jobs {
		if j.ID == id {
			found = append(found, j)
		}
	}
	require.Len(t, found, 1, "code-review.yml has no single %s job", id)
	return found[0]
}

// An unrelated label must still run the guard: the gate reads the scope
// job's SCOPE_SKIP, so a label filter on scope's if: would drop a
// guard-cleared CI-only PR's exemption on, say, a dept:software label event.
// Only the review job keeps the label filter (Codex P1, #2227).
func TestCodeReviewScopeJobIfCarriesNoLabelFilter(t *testing.T) {
	wf := loadCIWorkflow(t, repoRoot(t), codeReviewWorkflowFile)
	scope := codeReviewJob(t, wf, "scope")
	review := codeReviewJob(t, wf, "review")
	require.NotContains(t, scope.If, "github.event.label.name", "the scope job filters on the event's label")
	require.Contains(t, scope.If, "github.event.pull_request.draft != true")
	require.Contains(t, scope.If, "github.event.pull_request.state == 'open'")
	require.Contains(t, review.If, "github.event.label.name == 'code-review'", "the review job lost its label filter")
}

// The handoff re-runs a newer twin's red gate only once that run has
// completed, so it polls: the status is read again inside the loop, not only
// from the initial runs listing, within a bounded wait that fails the step
// (exit 5) past the bound (Codex P1, #2227).
func TestCodeReviewHandoffPollsANewerRunUntilItCompletes(t *testing.T) {
	wf := loadCIWorkflow(t, repoRoot(t), codeReviewWorkflowFile)
	gate := codeReviewJob(t, wf, "gate")
	var found []string
	for _, s := range gate.Steps {
		if strings.Contains(s.Run, `api POST "/actions/jobs/$gate/rerun"`) {
			found = append(found, s.Run)
		}
	}
	require.Len(t, found, 1, "the gate job has no single handoff step")
	run := found[0]
	require.Contains(t, run, `HANDOFF_POLL_S=${HANDOFF_POLL_S:-15}`)
	require.Contains(t, run, `HANDOFF_WAIT_S=${HANDOFF_WAIT_S:-300}`)
	require.Contains(t, run, `deadline=$((SECONDS + HANDOFF_WAIT_S))`)
	require.Contains(t, run, "exit 5", "the handoff never fails a stuck wait")

	start := strings.Index(run, `while read -r id status; do`)
	end := strings.Index(run, `done <<<"$newer"`)
	require.GreaterOrEqual(t, start, 0, "the handoff has no loop over the newer runs")
	require.GreaterOrEqual(t, end, 0, "the handoff loop does not read the newer runs")
	require.Less(t, start, end)
	body := run[start:end]
	require.Contains(t, body, `[ "$status" != completed ] || break`)
	require.Contains(t, body, `"$SECONDS" -ge "$deadline"`)
	sleep := strings.Index(body, `sleep "$HANDOFF_POLL_S"`)
	reread := strings.Index(body, `status=$(api GET "/actions/runs/$id"`)
	require.GreaterOrEqual(t, sleep, 0, "the handoff loop never waits between polls")
	require.GreaterOrEqual(t, reread, 0, "the handoff loop never reads the run's status again")
	require.Less(t, sleep, reread, "the handoff re-reads the status before it waits")
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
