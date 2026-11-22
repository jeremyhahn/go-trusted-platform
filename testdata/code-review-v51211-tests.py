#!/usr/bin/env python3
"""code-review-v51211-tests.py -- the regression tests for code-review.yml
v5.12.11 (Tenant Agent ruling 1079; Codex's two P1s on go-trusted-platform
#2227, and three gate hardenings from that repository's copy).

Each job's `if:` is evaluated with code-review-v51210-tests.py's expression
evaluator (loaded from that file, never copied); both gate steps are read
out of the workflow file and run under bash and jq against a fake forge: a
`curl` on PATH that answers from canned bodies, in order where a route has
a sequence (the last answer repeats), and logs every request with its
method. Nothing reaches the network.

  S. THE TEXT: the header entry; scope's `if:` is the draft clause and the
     open state; review keeps the shared condition and its skip clause; the
     handoff's only write is the gate job re-run, and its warning for a run
     still in progress is gone.
  A. P1-a, THE GUARD RUNS WHEREVER THE GATE RUNS: on every non-draft event
     of an open PR scope runs exactly when the gate runs; on an unrelated
     label (dept:software, ci:full, task:in-progress, a hold) scope runs,
     its skip=true reaches the gate's SCOPE_SKIP, review and
     review-opencode stay skipped, and the gate passes a CI-config-only
     change the guard cleared with no approval. A draft runs nothing. A
     scope job that failed or was cancelled still fails the gate closed.
  P. P1-b, THE HANDOFF WAITS FOR A NEWER RUN TO END: a newer run read in
     progress (gate red, or gate still running) is read again until it is
     completed, then its red gate is re-run exactly once, after the
     completed read; past the bound the step fails (exit 5, ::error::) with
     no re-run; a newer run that reviews the head itself is left to its own
     gate at once; an API error in the poll is a warning, exit 0.
  H. THE HOLD: the live PR's needs-owner or needs-coordinator fails an
     approved head; a live PR that answers no label list fails closed; the
     gate never reads the event payload's labels.
  G. get_all: a failed page (HTTP 500) or a page that is not a list fails
     the gate, on the reviews (GitHub) and the files (Gitea), never passes
     on the pages read before it.
  B. same_base: a PR whose live base is not this event's base fails, read
     before the no-review list (a docs-only change included), on Gitea's
     files path, and when it is retargeted only by the hold read. Each
     read is the only one wrong in B6 and B7, as the hold is in H7, so
     deleting any one same_base or holds call turns a check red.
  N. Negative controls: the same harness passes the head on an empty
     SCOPE_SKIP only when the change is exempt anyway, and a v5.12.10 file
     given as the argument fails A, P, G and B.

Run: python3 -I software/templates/github-actions/testdata/code-review-v51211-tests.py [workflow]
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
WORKFLOW = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parent / "code-review.yml"
FAILS = []
HEAD = "a" * 40
BASE = "b" * 40
REVIEWER = "codex-reviewer[bot]"
API = "https://api.github.test/repos/o/r"
FAKE_API_CRED = "fake-" + "api-cred"  # the fake forge ignores it
TITLE = f"Code Review: PR #7 into main at {HEAD}"
GATE = "Code Review (codex)"
STEP1 = "Require a Codex approval of the head, or a no-review change"
STEP2 = "Re-run a newer twin's failed gate on this head"
UNRELATED = ("dept:software", "ci:full", "task:in-progress", "needs-owner", "needs-coordinator")


def fatal(msg):
    print(f"FATAL: {msg}")
    sys.exit(9)


def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        FAILS.append(what)


# The v5.12.10 evaluator and parser, loaded from its file without its main().
EV = {"__name__": "v51210", "__file__": str(HERE / "code-review-v51210-tests.py")}
_ev_src = (HERE / "code-review-v51210-tests.py").read_text()
if not _ev_src.rstrip().endswith("\nmain()"):
    fatal("code-review-v51210-tests.py no longer ends in main(); load its evaluator another way")
exec(compile(_ev_src.rstrip()[:-len("main()")], EV["__file__"], "exec"), EV)
EV["WORKFLOW"] = WORKFLOW
once, job, key, block, evaluate, truthy = (EV[n] for n in ("once", "job", "key", "block", "evaluate", "truthy"))


def step(text, name):
    return once(r"\n      - name: " + re.escape(name) + r"\n(.*?)(?=\n      - (?:name|uses): |\Z)",
                text, f"the step '{name}'")


def run_script(text):
    body = once(r"\n        run: \|\n(.*)", "\n" + text, "a run block")
    lines = []
    for line in body.split("\n"):
        if line.strip() and not line.startswith("          "):
            break
        lines.append(line[10:])
    return "\n".join(lines) + "\n"


FAKE_CURL = r'''#!/usr/bin/env python3
import fnmatch, json, os, sys
args = sys.argv[1:]
out = fmt = None
url = None
method = "GET"
i = 0
while i < len(args):
    a = args[i]
    if a in ("-o", "-w", "-X", "-H", "--proto", "--max-time", "--retry", "--data-binary"):
        if a == "-o": out = args[i + 1]
        elif a == "-w": fmt = args[i + 1]
        elif a == "-X": method = args[i + 1]
        i += 2
        continue
    if not a.startswith("-"):
        url = a
    i += 1
base = os.environ["FAKE_BASE"]
path = url[len(base):] if url.startswith(base) else url
req = method + " " + path
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(req + "\n")
code, body = 404, '{"message":"no route"}'
for n, route in enumerate(json.loads(os.environ["FAKE_ROUTES"])):
    glob, answers = route[0], route[1:]
    if not fnmatch.fnmatchcase(req, glob):
        continue
    if isinstance(answers[0], list):  # a sequence: one answer per request, the last repeats
        state = os.path.join(os.environ["FAKE_STATE"], str(n))
        hits = int(open(state).read()) if os.path.exists(state) else 0
        open(state, "w").write(str(hits + 1))
        code, body = answers[0][min(hits, len(answers[0]) - 1)]
    else:
        code, body = answers
    break
if out:
    open(out, "w").write(body)
else:
    sys.stdout.write(body)
if fmt:
    sys.stdout.write(str(code))
'''


def run(script, routes, run_id="77", forge="github", **env_over):
    """Returns (exit code, output, requests)."""
    with tempfile.TemporaryDirectory() as d:
        tmp = pathlib.Path(d)
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        (tmp / "state").mkdir()
        (bin_dir / "curl").write_text(FAKE_CURL)
        (bin_dir / "curl").chmod(0o755)
        log = tmp / "requests.log"
        log.write_text("")
        env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp), "FAKE_LOG": str(log),
               "FAKE_STATE": str(tmp / "state"), "FAKE_ROUTES": json.dumps(routes),
               "FAKE_BASE": API, "FORGE": forge, "REVIEWER": REVIEWER, "REPO_API": API, "PR_NUM": "7",
               "EVENT_SHA": HEAD, "BASE_SHA": BASE, "BASE_REF": "main", "GITHUB_RUN_ID": run_id,
               "GH_API_TOKEN": FAKE_API_CRED, "NO_REVIEW_PATHS": NO_REVIEW, "DOCS_PATHS": DOCS,
               "SCOPE_SKIP": "false", "SCOPE_RESULT": "success", "REVIEW_RESULT": "skipped",
               "HANDOFF_POLL_S": "0", "HANDOFF_WAIT_S": "30"}
        env.update(env_over)
        out = subprocess.run(["bash", "-c", script], cwd=tmp, env=env,
                             capture_output=True, text=True, check=False, timeout=120)
        return out.returncode, out.stdout + out.stderr, log.read_text().splitlines()


def posts(reqs):
    return [r for r in reqs if r.startswith("POST ")]


# --- The gate's first step ------------------------------------------------

def pr_body(base="main", labels=("code-review", "task:ready"), no_labels=False):
    pr = {"state": "open", "head": {"sha": HEAD}, "base": {"ref": base}}
    if not no_labels:
        pr["labels"] = [{"name": n} for n in labels]
    return json.dumps(pr)


def review_page(verdict):
    return json.dumps([] if verdict is None else [
        {"id": 1, "state": verdict, "commit_id": HEAD, "user": {"login": REVIEWER},
         "submitted_at": "2026-11-21T00:00:00Z"}])


def gate_routes(files, verdict="APPROVED", pr=None, reviews=None, gitea=False):
    """files: changed paths. pr: one body, or a list of bodies (in order).
    reviews: a list of (code, body) answers by page, after which [] ends."""
    pr = pr if pr is not None else pr_body()
    pr_route = ["GET /pulls/7", [[200, b] for b in pr]] if isinstance(pr, list) else ["GET /pulls/7", 200, pr]
    flist = [{"filename": f} for f in files]
    routes = [pr_route,
              [f"GET /compare/{BASE}...{HEAD}", 200, json.dumps({"files": flist})],
              ["GET /actions/runs/77", 200, json.dumps({"workflow_id": 5})],
              ["GET /actions/workflows/5/runs?*", 200, json.dumps({"workflow_runs": []})]]
    if gitea:
        routes += [["GET /pulls/7/files?*page=1", 200, json.dumps(flist)],
                   ["GET /pulls/7/files?*", 200, "[]"]]
    pages = reviews if reviews is not None else [(200, review_page(verdict))]
    for n, (code, body) in enumerate(pages, 1):
        routes.append([f"GET /pulls/7/reviews?*page={n}", code, body])
    routes.append(["GET /pulls/7/reviews?*", 200, "[]"])
    return routes


# --- The handoff ----------------------------------------------------------

def jobs_body(gate_status, gate_conclusion, review="completed"):
    return json.dumps({"jobs": [
        {"id": 1, "name": "Review scope (InfoSec guard)", "status": "completed", "conclusion": "success"},
        {"id": 2, "name": "Codex review", "status": review, "conclusion": "skipped" if review == "completed" else None},
        {"id": 9000, "name": GATE, "status": gate_status, "conclusion": gate_conclusion}]})


def handoff_routes(listed_status, run_states, jobs):
    """Run 77 (suite 500) hands off to run 92 (suite 502). listed_status: 92's
    status in the runs list; run_states: GET /actions/runs/92's answers in
    order; jobs: GET /actions/runs/92/jobs's answers in order."""
    return [
        ["GET /actions/runs/77", 200, json.dumps({"workflow_id": 5, "check_suite_id": 500})],
        ["GET /actions/workflows/5/runs?*", 200, json.dumps({"workflow_runs": [
            {"id": 92, "check_suite_id": 502, "status": listed_status, "display_title": TITLE}]})],
        ["GET /actions/runs/92/jobs?*", [[200, b] for b in jobs]],
        ["GET /actions/runs/92", [[c, json.dumps({"id": 92, "status": s})] for c, s in run_states]],
        ["POST /actions/jobs/*/rerun", 201, ""],
    ]


def main():
    global NO_REVIEW, DOCS
    for tool in ("jq", "bash", "grep"):
        if shutil.which(tool) is None:
            fatal(f"{tool} is not on PATH")
    if not WORKFLOW.is_file():
        fatal(f"no workflow at {WORKFLOW}")
    src = WORKFLOW.read_text()
    version = once(r"^# code-review-template: (v5\.\d+\.\d+)\b", src, "the version line")
    print(f"     (workflow {WORKFLOW.name} at {version})")
    body = src.split("\njobs:\n", 1)[1]
    ids = re.findall(r"\n  ([a-z][a-z0-9-]*):\n", "\n" + body)
    texts = {j: job(src, j) for j in ids}
    jobs = []
    for j in ids:
        needs = key(texts[j], "needs") or ""
        needs = [n.strip() for n in needs.strip("[]").split(",") if n.strip()]
        jobs.append((j, key(texts[j], "if"), needs))
    gate = texts["gate"]
    s1 = run_script(step(gate, STEP1))
    s2 = run_script(step(gate, STEP2))
    NO_REVIEW = once(r"\n      NO_REVIEW_PATHS: '([^']*)'\n", gate, "NO_REVIEW_PATHS")
    DOCS = once(r"\n      DOCS_PATHS: '([^']*)'\n", gate, "DOCS_PATHS")
    scope_skip_expr = once(r"\n      SCOPE_SKIP: ([^\n]*)\n", gate, "the gate's SCOPE_SKIP")
    scope_result_expr = once(r"\n      SCOPE_RESULT: ([^\n]*)\n", gate, "the gate's SCOPE_RESULT")

    # S. The text.
    check(re.fullmatch(r"v5\.12\.(1[1-9]|[2-9]\d)|v5\.(1[3-9]|[2-9]\d)\.\d+|v([6-9]|\d\d)\.\d+\.\d+", version) is not None, f"S1 the version line ({version}), v5.12.11 or later")
    check("\n# v5.12.11 (2026-11-21, Tenant Agent ruling 1079" in src, "S2 the header has the v5.12.11 entry")
    check(block(texts["scope"], "if") == "github.event.pull_request.draft != true\n&& github.event.pull_request.state == 'open'",
          "S3 scope's if is the draft clause and the open state, no label filter")
    rv = block(texts["review"], "if")
    check(rv.startswith(EV["SHARED"] + "\n&& ") and "needs.scope.outputs.skip != 'true'" in rv,
          "S4 review keeps the shared condition and skips on scope skip=true")
    check(block(texts["review-opencode"], "if").startswith(EV["SHARED"] + "\n&& "), "S5 review-opencode keeps the shared condition")
    writes = re.findall(r"api (POST|PUT|PATCH|DELETE) \"([^\"]*)\"", s2)
    check(writes == [("POST", "/actions/jobs/$gate/rerun")], f"S6 the handoff's only write is the gate job re-run ({writes})")
    check("cannot be re-run yet" not in s2, "S7 the handoff no longer only warns about a run in progress")
    check("github.event.pull_request.labels" not in gate, "S8 the gate never reads the event payload's labels")

    # A. P1-a.
    def ctx_for(action, draft, labels, lab=None, state="open", skip="true"):
        c = EV["context"](action, draft, labels, lab, EV["GH"], state)
        c["needs"]["scope"]["outputs"]["skip"] = skip
        return c

    a_bad, n = [], 0
    for server, action, draft, labels, lab in EV["cases"]():
        c = EV["context"](action, draft, labels, lab, server)
        ran = EV["simulate"](jobs, c)
        n += 1
        if ran["gate"] != ran["scope"] or (draft and any(ran.values())):
            a_bad.append(f"{server} {action} draft={draft} label={lab}: scope={ran['scope']} gate={ran['gate']}")
    check(not a_bad, f"A1 scope runs exactly when the gate runs, and a draft runs nothing ({n} cases; {len(a_bad)} bad: {a_bad[:2]})")

    ci_only = [".github/workflows/lint.yml"]
    for lab in UNRELATED:
        labels = ("code-review", "task:ready", lab)
        c = ctx_for("labeled", False, labels, lab, skip="true")
        ran = EV["simulate"](jobs, c)
        ok_jobs = ran["scope"] and ran["gate"] and not ran["review"] and not ran["review-opencode"]
        needs = {"scope": {"result": "success" if ran["scope"] else "skipped",
                           "outputs": {"skip": "true"} if ran["scope"] else {}},
                 "review": {"result": "skipped", "outputs": {}}}
        skip = evaluate(scope_skip_expr, {"needs": needs})[0]
        result = evaluate(scope_result_expr, {"needs": needs})[0]
        rc, out, _ = run(s1, gate_routes(ci_only, verdict=None, pr=pr_body(labels=labels)),
                         SCOPE_SKIP="" if skip is None else str(skip), SCOPE_RESULT=str(result))
        hold = lab.startswith("needs-")
        if hold:
            check(ok_jobs and skip == "true" and rc == 3 and f"on hold ({lab})" in out and "no review is required" not in out,
                  f"A2 labeled {lab}: scope runs, review does not, the gate reads skip={skip}, and the live hold, read before the exemption, refuses the guard-cleared CI-only PR (rc {rc})")
        else:
            check(ok_jobs and skip == "true" and rc == 0 and "no review is required" in out,
                  f"A2 labeled {lab}: scope runs, review does not, the gate reads skip={skip} and passes the guard-cleared CI-only PR (rc {rc})")
    for lab in UNRELATED + ("code-review",):
        c = ctx_for("labeled", True, ("code-review", "task:ready", lab), lab)
        check(not any(EV["simulate"](jobs, c).values()), f"A3 a draft labeled {lab} runs no job")
    c = ctx_for("labeled", False, ("code-review", "task:ready"), "code-review", skip="true")
    check(not EV["simulate"](jobs, c)["review"], "A4 a requested review still skips when scope says skip=true")
    c = ctx_for("labeled", False, ("code-review", "task:ready"), "code-review", skip="false")
    check(EV["simulate"](jobs, c)["review"], "A5 a requested review runs when scope says skip=false")
    for res in ("failure", "cancelled"):
        rc, out, _ = run(s1, gate_routes(["pkg/x.go"]), SCOPE_SKIP="", SCOPE_RESULT=res)
        check(rc == 3 and f"scope job ended {res}" in out, f"A6 scope {res}, code approved: the gate fails closed (rc {rc})")
        rc, out, _ = run(s1, gate_routes(ci_only, verdict=None), SCOPE_SKIP="", SCOPE_RESULT=res)
        check(rc == 3, f"A7 scope {res}, CI-only, no approval: no exemption, the gate fails (rc {rc})")
    rc, out, _ = run(s1, gate_routes(ci_only, verdict=None), SCOPE_SKIP="", SCOPE_RESULT="skipped")
    check(rc == 3 and "did not clear it" in out, f"N1 control: an empty SCOPE_SKIP (v5.12.10's unrelated label) fails the CI-only PR (rc {rc})")
    rc, out, _ = run(s1, gate_routes(["docs/x.md"], verdict=None), SCOPE_SKIP="", SCOPE_RESULT="skipped")
    check(rc == 0, f"N2 control: a docs-only change is exempt without the guard (rc {rc})")

    # P. P1-b.
    red = jobs_body("completed", "failure")
    running = jobs_body("in_progress", None)
    rc, out, reqs = run(s2, handoff_routes("in_progress", [(200, "in_progress"), (200, "completed")], [red]))
    runs92 = [i for i, r in enumerate(reqs) if r == "GET /actions/runs/92"]
    post_at = [i for i, r in enumerate(reqs) if r.startswith("POST ")]
    check(rc == 0 and posts(reqs) == ["POST /actions/jobs/9000/rerun"] and len(runs92) == 2
          and post_at and post_at[0] > runs92[-1],
          f"P1 a newer run in progress with a red gate: read again until completed, then exactly one re-run (rc {rc}, {posts(reqs)}, {len(runs92)} run reads)")
    rc, out, reqs = run(s2, handoff_routes("in_progress", [(200, "in_progress"), (200, "in_progress"), (200, "completed")],
                                           [running, running, red]))
    check(rc == 0 and posts(reqs) == ["POST /actions/jobs/9000/rerun"],
          f"P2 a newer gate still running that ends red while polled: re-run once (rc {rc}, {posts(reqs)})")
    rc, out, reqs = run(s2, handoff_routes("in_progress", [(200, "in_progress"), (200, "completed")],
                                           [running, jobs_body("completed", "success")]))
    check(rc == 0 and not posts(reqs), f"P3 a newer gate that ends green while polled: no re-run (rc {rc})")
    rc, out, reqs = run(s2, handoff_routes("in_progress", [(200, "in_progress")], [red]),
                        HANDOFF_POLL_S="1", HANDOFF_WAIT_S="2")
    check(rc == 5 and "::error::" in out and "run 92" in out and "bound" in out and not posts(reqs),
          f"P4 the bound expires with the run still in progress: the step fails loudly, no re-run (rc {rc})")
    rc, out, reqs = run(s2, handoff_routes("in_progress", [(200, "in_progress")], [jobs_body("queued", None, review="in_progress")]),
                        HANDOFF_POLL_S="1", HANDOFF_WAIT_S="2")
    check(rc == 0 and not posts(reqs) and "reviews" in out and "GET /actions/runs/92" not in reqs,
          f"P5 a newer run reviewing the head itself is left to its own gate at once (rc {rc})")
    rc, out, reqs = run(s2, handoff_routes("in_progress", [(500, "in_progress")], [red]))
    check(rc == 0 and "::warning::" in out and "HTTP 500" in out and not posts(reqs),
          f"P6 an API error in the poll is a warning, exit 0 (rc {rc})")
    rc, out, reqs = run(s2, handoff_routes("completed", [(200, "completed")], [red]))
    check(rc == 0 and posts(reqs) == ["POST /actions/jobs/9000/rerun"] and "GET /actions/runs/92" not in reqs,
          f"P7 a newer run listed completed: its red gate is re-run with no poll (rc {rc})")

    # P8-P10 (the Tenant Agent's review of PR 94): a newer gate that has not
    # started is left to read the approval itself, at once; only a red gate
    # waits for its run to complete, and only it fails at the bound.
    rc, out, reqs = run(s2, handoff_routes("in_progress", [(200, "in_progress")], [jobs_body("queued", None)]),
                        HANDOFF_POLL_S="1", HANDOFF_WAIT_S="2")
    check(rc == 0 and not posts(reqs) and "::error::" not in out and "GET /actions/runs/92" not in reqs and "reads this approval itself" in out,
          f"P8 a newer run in progress with its gate queued: left to its own gate at once, no poll, no red (rc {rc})")
    rc, out, reqs = run(s2, handoff_routes("queued", [(200, "queued")], [json.dumps({"jobs": []})]),
                        HANDOFF_POLL_S="1", HANDOFF_WAIT_S="2")
    check(rc == 0 and not posts(reqs) and "::error::" not in out and "GET /actions/runs/92" not in reqs and "reads this approval itself" in out,
          f"P9 a newer run queued with no jobs: left to its own gate at once, no poll, no red (rc {rc})")
    rc, out, reqs = run(s2, handoff_routes("in_progress", [(200, "in_progress")], [running]),
                        HANDOFF_POLL_S="1", HANDOFF_WAIT_S="2")
    check(rc == 0 and not posts(reqs) and "::error::" not in out and "::warning::" in out and "still running" in out,
          f"P10 a newer gate still running past the bound: a warning, never a red step (rc {rc})")

    # H. The hold, from the live PR.
    for hold in ("needs-owner", "needs-coordinator"):
        rc, out, _ = run(s1, gate_routes(["pkg/x.go"], pr=pr_body(labels=("code-review", "task:ready", hold))))
        check(rc == 3 and f"on hold ({hold})" in out, f"H1 code approved at the head, live {hold}: the gate refuses (rc {rc})")
    rc, out, _ = run(s1, gate_routes(["pkg/x.go"], pr=pr_body(no_labels=True)))
    check(rc == 3 and "cannot read the labels" in out, f"H2 a live PR with no label list fails closed (rc {rc})")
    rc, out, _ = run(s1, gate_routes(["pkg/x.go"]))
    check(rc == 0, f"H3 code approved at the head, no hold: passes (rc {rc})")
    for hold in ("needs-owner", "needs-coordinator"):
        rc, out, _ = run(s1, gate_routes(["docs/x.md"], verdict=None, pr=pr_body(labels=("code-review", "task:ready", hold))))
        check(rc == 3 and f"on hold ({hold})" in out, f"H4 a docs-only change, live {hold}: the hold precedes the exemption and refuses (rc {rc})")
    # v5.12.12 (Codex's P1 on go-trusted-platform #2227): each hold with a
    # CI-only change InfoSec's guard cleared (SCOPE_SKIP=true), the other
    # exemption. Deleting the holds call before the exemption exit turns H4
    # and H5 red; H6 is the same change with no hold, which passes exempt.
    for hold in ("needs-owner", "needs-coordinator"):
        rc, out, _ = run(s1, gate_routes([".github/workflows/lint.yml"], verdict=None,
                                         pr=pr_body(labels=("code-review", "task:ready", hold))), SCOPE_SKIP="true")
        check(rc == 3 and f"on hold ({hold})" in out and "no review is required" not in out,
              f"H5 a guard-cleared CI-only change, live {hold}: the hold precedes the exemption and refuses (rc {rc})")
    rc, out, _ = run(s1, gate_routes([".github/workflows/lint.yml"], verdict=None), SCOPE_SKIP="true")
    check(rc == 0 and "no review is required" in out, f"H6 a guard-cleared CI-only change, no hold: exempt, passes (rc {rc})")

    # G. get_all.
    two_pages = [(200, review_page("APPROVED")), (500, '{"message":"boom"}')]
    rc, out, _ = run(s1, gate_routes(["pkg/x.go"], reviews=two_pages))
    check(rc == 3 and "HTTP 500" in out, f"G1 GitHub reviews, page 2 HTTP 500 after an approval on page 1: fails (rc {rc})")
    rc, out, _ = run(s1, gate_routes(["pkg/x.go"], reviews=[(200, review_page("APPROVED")), (200, '{"x":1}')]))
    check(rc == 3, f"G2 GitHub reviews, page 2 not a list: fails (rc {rc})")
    rc, out, _ = run(s1, gate_routes(["pkg/x.go"], reviews=two_pages, gitea=True), forge="gitea")
    check(rc == 3 and "HTTP 500" in out, f"G3 Gitea reviews, page 2 HTTP 500: fails (rc {rc})")
    routes = gate_routes(["docs/x.md"], verdict=None, gitea=True)
    routes.insert(0, ["GET /pulls/7/files?*page=2", 502, '{"message":"bad gateway"}'])
    routes.insert(0, ["GET /pulls/7/files?*page=1", 200, json.dumps([{"filename": "docs/x.md"}] * 50)])
    rc, out, _ = run(s1, routes, forge="gitea")
    check(rc == 3 and "HTTP 502" in out, f"G4 Gitea files, page 2 HTTP 502 after a docs-only page 1: fails, not exempt (rc {rc})")
    rc, out, _ = run(s1, gate_routes(["pkg/x.go"], gitea=True), forge="gitea")
    check(rc == 0, f"G5 Gitea, every page read: an approved head passes (rc {rc})")

    # B. same_base.
    rc, out, _ = run(s1, gate_routes(["pkg/x.go"], pr=pr_body(base="release")))
    check(rc == 3 and "retargeted from main to release" in out, f"B1 a retargeted PR, approved: fails (rc {rc})")
    rc, out, _ = run(s1, gate_routes(["docs/x.md"], verdict=None, pr=pr_body(base="release")))
    check(rc == 3 and "retargeted" in out, f"B2 a retargeted docs-only PR: never exempt (rc {rc})")
    rc, out, _ = run(s1, gate_routes(["docs/x.md"], verdict=None, pr=[pr_body(), pr_body(base="release")], gitea=True),
                     forge="gitea")
    check(rc == 3 and "retargeted" in out, f"B3 Gitea: retargeted between the two reads of the files path: fails (rc {rc})")
    rc, out, _ = run(s1, gate_routes(["pkg/x.go"], pr=[pr_body(), pr_body(base="release")]))
    check(rc == 3 and "retargeted" in out, f"B4 retargeted after the no-review list, read with the holds: fails (rc {rc})")
    rc, out, _ = run(s1, gate_routes(["pkg/x.go"], pr=json.dumps({"head": {"sha": HEAD}, "labels": []})))
    check(rc == 3 and "no base" in out, f"B5 a live PR with no base fails closed (rc {rc})")
    # v5.12.12 (the mutation pass on handbook PR 96): each same_base and
    # holds call is the only one that sees its read. The base is wrong, or
    # the hold is on, at one read only, and every later read is clean.
    rc, out, _ = run(s1, gate_routes(["pkg/x.go"], pr=[pr_body(base="release"), pr_body()]))
    check(rc == 3 and "retargeted from main to release" in out,
          f"B6 retargeted at the first read only, back on main for the holds: fails (rc {rc})")
    rc, out, _ = run(s1, gate_routes(["docs/x.md"], verdict=None, pr=[pr_body(), pr_body(base="release"), pr_body()],
                                     gitea=True), forge="gitea")
    check(rc == 3 and "retargeted" in out and "no review is required" not in out,
          f"B7 Gitea: retargeted at the files path read only: fails, not exempt (rc {rc})")
    for hold in ("needs-owner", "needs-coordinator"):
        held = pr_body(labels=("code-review", "task:ready", hold))
        rc, out, _ = run(s1, gate_routes(["pkg/x.go"], pr=[pr_body(), pr_body(), held]))
        check(rc == 3 and f"on hold ({hold})" in out,
              f"H7 {hold} put on after the exemption read, approved head: the second holds call refuses (rc {rc})")

    print(f"{'ALL PASS' if not FAILS else f'{len(FAILS)} FAILED'}")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
