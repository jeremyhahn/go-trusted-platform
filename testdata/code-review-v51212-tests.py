#!/usr/bin/env python3
"""code-review-v51212-tests.py -- the regression tests for code-review.yml
v5.12.12 (Tenant Agent rulings 1083 (5) and 1084 (1); Codex on
go-trusted-platform #2227: an approved head passed the gate while a
requested re-review was in flight; on go-quicbaas #2662: the cancel of
superseded runs read only the first page of each run list; on go-xkms
#2323: the cancellation guards had no tests of their own here).

The `supersede` job's step is read out of the workflow file and run under
bash and jq against a fake forge, as in code-review-v5128-tests.py, whose
harness this copies. Nothing reaches the network.

  P. THE PAGES: an older-head run of this PR on page 2, behind 100 runs of
     other PRs, is cancelled; a page of fewer than 100 runs ends the list
     (no page 2 is read); a list of full pages stops at page 10; an error
     on page 2 is a warning and exit 0, and nothing is cancelled.

  G. THE CANCELLATION GUARDS, each on page 2 behind 100 other-PR runs:
     only older-head runs of this PR are cancelled; a same-head twin, a
     newer run, another PR's run and a run whose review is in progress
     survive; when the head moved after the live-head read (a newer head's
     run, newer than this one, is listed) that run survives too.
  W. THE GATE FAILS CLOSED WHILE A TWIN REVIEWS, APPROVAL OR NOT: an
     approved head whose effort-label run's `Codex review` is queued or in
     progress fails the unrelated-label run's gate (exit 3, naming the
     twin); once that re-review approves, the gate passes; once it
     requests changes, the gate fails.
  C. A CANCELLED REVIEW IS NO REVIEW (Codex's P1 on go-trusted-platform
     #2227 at c6c70f34): scope success, this run's re-review cancelled, an
     earlier approval of the head standing, and no twin left (the shape of
     the handoff's re-run of that run's red gate): the gate fails closed
     (exit 3). A failed review still fails; a skipped or successful review
     with the approval still passes.
  H. THE HANDOFF, EXECUTED (Codex's P1 on go-trusted-platform #2227 at
     923d0d81: the handoff had only a text check): the gate's second step
     runs against a fake forge whose answers come in order. A newer run's
     red or cancelled gate is re-run exactly once; a run in progress is
     polled through to completed and re-run after the last read; a gate
     that ends green is left; past the bound the step fails (exit 5); a run
     reviewing the head itself, or whose gate is still queued, is left to
     its own gate; an older suite's run and another PR's run are never
     touched; an API error is a warning, exit 0.

Run: python3 -I software/templates/github-actions/testdata/code-review-v51212-tests.py [workflow]
"""
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
WORKFLOW = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parent / "code-review.yml"
FAILS = []
HEAD = "a" * 40
OLD = "c" * 40
OLDER = "d" * 40
API = "https://api.github.test/repos/o/r"
STEP = "Cancel this PR's runs on an older head"
REVIEWER = "codex-reviewer[bot]"
BASE = "b" * 40
NEW = "e" * 40
STATUSES = ("queued", "in_progress", "waiting", "pending", "requested")


def fatal(msg):
    print(f"FATAL: {msg}")
    sys.exit(9)


def once(pattern, text, what):
    found = re.findall(pattern, text, re.S)
    if len(found) != 1:
        fatal(f"{what}: found {len(found)} times in {WORKFLOW.name}, want 1")
    return found[0]


def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        FAILS.append(what)


def job(src, name):
    return once(r"\n  " + re.escape(name) + r":\n(.*?)(?=\n  [a-z][a-z0-9-]*:\n|\Z)", src, f"the job '{name}'")


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


def title(pr, sha, base="main"):
    return f"Code Review: PR #{pr} into {base} at {sha}"


def routes(runs, jobs=None, live=HEAD, state="open", pr_code=200, me_code=200,
           list_code=200, jobs_code=200, cancel_code=202):
    """runs: {status: [(id, head_sha, display_title)]}; jobs: {id: review status}. This run is 9000."""
    jobs = jobs or {}
    r = [["GET /pulls/7", pr_code, json.dumps({"state": state, "head": {"sha": live}})],
         ["GET /actions/runs/9000", me_code, json.dumps({"workflow_id": 5})]]
    for st in STATUSES:
        body = json.dumps({"workflow_runs": [
            {"id": i, "head_sha": h, "display_title": t, "status": st} for i, h, t in runs.get(st, [])]})
        r.append([f"GET /actions/workflows/5/runs?event=pull_request_target&status={st}&*", list_code, body])
    for i, rs in jobs.items():
        r.append([f"GET /actions/runs/{i}/jobs?*", jobs_code, json.dumps({"jobs": [
            {"name": "Review scope (InfoSec guard)", "status": "completed"},
            {"name": "Codex review", "status": rs}]})])
    r.append(["GET /actions/runs/*/jobs?*", jobs_code, json.dumps({"jobs": [
        {"name": "Review scope (InfoSec guard)", "status": "queued"},
        {"name": "Codex review", "status": "queued"}]})])
    r.append(["POST /actions/runs/*/cancel", cancel_code, ""])
    return r


def run(script, rts):
    with tempfile.TemporaryDirectory() as d:
        tmp = pathlib.Path(d)
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "curl").write_text(FAKE_CURL)
        (bin_dir / "curl").chmod(0o755)
        log = tmp / "requests.log"
        log.write_text("")
        env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp), "FAKE_LOG": str(log),
               "FAKE_ROUTES": json.dumps(rts), "FAKE_BASE": API, "REPO_API": API,
               "PR_NUM": "7", "EVENT_SHA": HEAD, "GITHUB_RUN_ID": "9000", "GH_API_TOKEN": "<REDACTED>"}
        out = subprocess.run(["bash", "-c", script], cwd=tmp, env=env,
                             capture_output=True, text=True, check=False, timeout=60)
        return out.returncode, out.stdout + out.stderr, log.read_text().splitlines()


def cancels(reqs):
    return sorted(int(r.split("/")[3]) for r in reqs if r.startswith("POST /actions/runs/") and r.endswith("/cancel"))


def paged(pages, st="queued", tail_code=200):
    """Routes whose STATUS list answers PAGES ([[run, ...] per page]); the
    pages after them answer [] (or TAIL_CODE on page len(pages)+1)."""
    r = routes({})
    extra = []
    for n, runs in enumerate(pages, 1):
        extra.append([f"GET /actions/workflows/5/runs?event=pull_request_target&status={st}&per_page=100&page={n}",
                      200, json.dumps({"workflow_runs": [
                          {"id": i, "head_sha": h, "display_title": t, "status": st} for i, h, t in runs]})])
    if tail_code != 200:
        extra.append([f"GET /actions/workflows/5/runs?event=pull_request_target&status={st}&per_page=100&page={len(pages) + 1}",
                      tail_code, '{"message":"boom"}'])
    return r[:2] + extra + r[2:]


def lists(reqs, st="queued"):
    return [r for r in reqs if r.startswith(f"GET /actions/workflows/5/runs?event=pull_request_target&status={st}&")]


def gate_routes(reviews, twin_status=None, twin_where="in_progress"):
    """The gate's fake forge: this run is 77; run 91 is the twin (the
    effort-label run on this head) whose `Codex review` is TWIN_STATUS
    (None: no twin listed)."""
    t = title(7, HEAD)
    listed = {"queued": [77], "in_progress": []}
    if twin_status is not None:
        listed[twin_where].append(91)
    return [
        [f"GET /compare/{BASE}...{HEAD}", 200, json.dumps({"files": [{"filename": "pkg/x.go"}]})],
        ["GET /actions/runs/77", 200, json.dumps({"workflow_id": 5})],
        ["GET /actions/workflows/5/runs?*status=queued*", 200,
         json.dumps({"workflow_runs": [{"id": i, "display_title": t} for i in listed["queued"]]})],
        ["GET /actions/workflows/5/runs?*status=in_progress*", 200,
         json.dumps({"workflow_runs": [{"id": i, "display_title": t} for i in listed["in_progress"]]})],
        ["GET /actions/runs/*/jobs?*", 200, json.dumps({"jobs": [
            {"name": "scope", "status": "completed"},
            {"name": "Codex review", "status": twin_status or "completed"}]})],
        ["GET /pulls/7", 200, json.dumps({"head": {"sha": HEAD}, "base": {"ref": "main"},
                                          "labels": [{"name": "code-review"}, {"name": "effort:high"}]})],
        ["GET /pulls/7/reviews?*page=1", 200, json.dumps([
            {"id": n, "state": st, "commit_id": HEAD, "user": {"login": REVIEWER},
             "submitted_at": f"2026-11-21T0{n}:00:00Z"} for n, st in enumerate(reviews, 1)])],
        ["GET /pulls/7/reviews?*", 200, "[]"],
    ]


def run_gate(script, rts, no_review, docs, review_result="skipped"):
    with tempfile.TemporaryDirectory() as d:
        tmp = pathlib.Path(d)
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "curl").write_text(FAKE_CURL)
        (bin_dir / "curl").chmod(0o755)
        (bin_dir / "sleep").write_text("#!/bin/sh\necho 'the gate slept' >&2\nexit 99\n")
        (bin_dir / "sleep").chmod(0o755)
        log = tmp / "requests.log"
        log.write_text("")
        env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp), "FAKE_LOG": str(log),
               "FAKE_ROUTES": json.dumps(rts), "FAKE_BASE": API,
               "FORGE": "github", "REVIEWER": REVIEWER, "REPO_API": API, "PR_NUM": "7",
               "EVENT_SHA": HEAD, "BASE_SHA": BASE, "BASE_REF": "main", "GITHUB_RUN_ID": "77",
               "GH_API_TOKEN": "<REDACTED>",
               "NO_REVIEW_PATHS": no_review, "DOCS_PATHS": docs,
               "SCOPE_SKIP": "false", "SCOPE_RESULT": "success", "REVIEW_RESULT": review_result}
        out = subprocess.run(["bash", "-c", script], cwd=tmp, env=env,
                             capture_output=True, text=True, check=False, timeout=60)
        return out.returncode, out.stdout + out.stderr


GATE = "Code Review (codex)"
HANDOFF = "Re-run a newer twin's failed gate on this head"


def handoff_jobs(gate_status, gate_conclusion, review="completed"):
    """A newer run's jobs: scope, its `Codex review` (REVIEW's status) and
    its gate (job 9000)."""
    return json.dumps({"jobs": [
        {"id": 1, "name": "Review scope (InfoSec guard)", "status": "completed", "conclusion": "success"},
        {"id": 2, "name": "Codex review", "status": review, "conclusion": "skipped" if review == "completed" else None},
        {"id": 9000, "name": GATE, "status": gate_status, "conclusion": gate_conclusion}]})


def handoff_routes(listed_status, run_states, jobs, others=()):
    """This run is 77 (suite 500); run 92 (suite 502) is the newer twin on
    the head. listed_status: 92's status in the runs list; run_states:
    GET /actions/runs/92's answers in order (code, status); jobs: GET
    /actions/runs/92/jobs's bodies in order (the last repeats). OTHERS:
    extra listed runs (id, suite, display_title) whose jobs answer a red
    gate (job 8000), so a re-run of one is visible as POST .../8000/rerun."""
    listed = [{"id": 92, "check_suite_id": 502, "status": listed_status, "display_title": title(7, HEAD)}]
    listed += [{"id": i, "check_suite_id": s, "status": "completed", "display_title": t} for i, s, t in others]
    other_red = json.dumps({"jobs": [{"id": 8000, "name": GATE, "status": "completed", "conclusion": "failure"}]})
    return [
        ["GET /actions/runs/77", 200, json.dumps({"workflow_id": 5, "check_suite_id": 500})],
        [f"GET /actions/workflows/5/runs?head_sha={HEAD}&*", 200, json.dumps({"workflow_runs": listed})],
        ["GET /actions/runs/92/jobs?*", [[200, b] for b in jobs]],
        ["GET /actions/runs/92", [[c, json.dumps({"id": 92, "status": s})] for c, s in run_states]],
        ["GET /actions/runs/*/jobs?*", 200, other_red],
        ["POST /actions/jobs/*/rerun", 201, ""],
    ]


def run_handoff(script, rts, poll="0", wait="30"):
    """Runs the handoff step (this run is 77). Returns (exit code, output,
    requests in order)."""
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
               "FAKE_STATE": str(tmp / "state"), "FAKE_ROUTES": json.dumps(rts), "FAKE_BASE": API,
               "FORGE": "github", "REPO_API": API, "PR_NUM": "7", "EVENT_SHA": HEAD, "BASE_REF": "main",
               "GITHUB_RUN_ID": "77", "GH_API_TOKEN": "<REDACTED>",
               "HANDOFF_POLL_S": poll, "HANDOFF_WAIT_S": wait}
        out = subprocess.run(["bash", "-c", script], cwd=tmp, env=env,
                             capture_output=True, text=True, check=False, timeout=120)
        return out.returncode, out.stdout + out.stderr, log.read_text().splitlines()


def posts(reqs):
    return [r for r in reqs if r.startswith("POST ")]


def round_block(src):
    """The guard's round count and round limit, from THE TWO-ROUND STOP to the round line."""
    a = src.index("          [[ $COORDINATOR_TURNS =~ ^[0-9]+$ ]] ||")
    b = src.index('echo "Codex round $round of $limit on PR $PR_NUM."', a)
    b = src.index("\n", b)
    return "\n".join(l[10:] if l.startswith("          ") else l for l in src[a:b].split("\n"))


def run_rounds(block, hist, labels, sha, turns=3):
    with tempfile.TemporaryDirectory() as tmp:
        out_file = os.path.join(tmp, "out")
        open(out_file, "w").close()
        script = ("set -euo pipefail\n"
                  "die() { echo \"die: $*\"; exit 9; }\n"
                  "api_all() { echo \"api_all called\"; exit 8; }\n"
                  "api() { echo \"api called\"; exit 8; }\n" + block + "\n")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GITHUB_OUTPUT": out_file, "WORK": tmp,
               "COORDINATOR_TURNS": str(turns), "labels": json.dumps(labels), "hist": json.dumps(hist),
               "EVENT_ACTION": "synchronize", "EVENT_LABEL": "", "REVIEWER": "codex", "PR_NUM": "5",
               "EVENT_SHA": sha, "FORGE": "gitea"}
        r = subprocess.run(["bash", "-c", script], cwd=tmp, env=env, capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout + r.stderr, open(out_file).read()


def verdict(rid, head, rnd, state="REQUEST_CHANGES"):
    return {"id": rid, "commit_id": head, "body": "", "head": head, "at": f"2026-11-21T16:0{rid % 10}:00Z",
            "stands": True, "state": state, "patch": "", "ctx": "", "round": rnd, "resume": ""}


def main():
    if not WORKFLOW.is_file():
        fatal(f"no workflow at {WORKFLOW}")
    src = WORKFLOW.read_text()
    once(r"^# code-review-template: v5\.12\.(1[2-9]|[2-9]\d)\b", src, "a version at or above v5.12.12")
    check("\n# v5.12.12 (2026-11-21, Tenant Agent rulings 1083 (5) and 1084 (1)" in src, "S1 the header has the v5.12.12 entry")
    script = run_script(step(job(src, "supersede"), STEP))
    others = [(1000 + i, OLD, title(70, OLD)) for i in range(100)]

    rc, out, reqs = run(script, paged([others, [(777, OLD, title(7, OLD))]]))
    check(rc == 0 and cancels(reqs) == [777], f"P1 an older-head run on page 2, behind 100 other runs, is cancelled ({cancels(reqs)})")
    check(len(lists(reqs)) == 2, f"P2 a full page reads the next; the short page ends it ({len(lists(reqs))} queued lists)")
    rc, out, reqs = run(script, paged([[(101, OLD, title(7, OLD))]]))
    check(rc == 0 and cancels(reqs) == [101] and len(lists(reqs)) == 1,
          f"P3 a page under 100 runs ends the list ({len(lists(reqs))} queued lists)")
    check(all(len(lists(reqs, st)) == 1 for st in STATUSES), "P4 every status is listed")
    full = routes({"queued": others})  # every queued page answers the same 100 runs
    rc, out, reqs = run(script, full)
    check(rc == 0 and len(lists(reqs)) == 10, f"P5 full pages stop at page 10 ({len(lists(reqs))} queued lists)")
    rc, out, reqs = run(script, paged([others[:99] + [(888, OLD, title(7, OLD))]], tail_code=502))
    check(rc == 0 and cancels(reqs) == [] and "::warning::Cancel superseded runs:" in out and "page 2" in out,
          f"P6 an error on page 2: a warning, exit 0, nothing cancelled ({cancels(reqs)})")

    # G: each guard on page 2, behind 100 runs of another PR.
    def page2(*runs):
        return paged([others, list(runs)])
    rc, out, reqs = run(script, page2((101, OLD, title(7, OLD)), (102, OLDER, title(7, OLDER))))
    check(rc == 0 and cancels(reqs) == [101, 102], f"G1 only older-head runs of this PR are cancelled ({cancels(reqs)})")
    rc, out, reqs = run(script, page2((103, HEAD, title(7, HEAD)), (104, OLD, title(7, HEAD))))
    check(rc == 0 and cancels(reqs) == [], f"G2 same-head twins survive ({cancels(reqs)})")
    rc, out, reqs = run(script, page2((9100, OLD, title(7, OLD))))
    check(rc == 0 and cancels(reqs) == [], f"G3 a run newer than this one survives ({cancels(reqs)})")
    rc, out, reqs = run(script, page2((105, OLD, title(70, OLD)), (106, OLD, title(17, OLD))))
    check(rc == 0 and cancels(reqs) == [], f"G4 other PRs' runs survive ({cancels(reqs)})")
    rts = page2((107, OLD, title(7, OLD)), (108, OLD, title(7, OLD)))
    rts = rts[:2] + [["GET /actions/runs/107/jobs?*", 200, json.dumps({"jobs": [
        {"name": "Codex review", "status": "in_progress"}]})]] + rts[2:]
    rc, out, reqs = run(script, rts)
    check(rc == 0 and cancels(reqs) == [108], f"G5 a run whose review is in progress survives; the idle one is cancelled ({cancels(reqs)})")
    rc, out, reqs = run(script, page2((9200, NEW, title(7, NEW)), (109, OLD, title(7, OLD))))
    check(rc == 0 and cancels(reqs) == [109],
          f"G6 the head moved after the live-head read: the newer head's run survives, the older one goes ({cancels(reqs)})")
    rc, out, reqs = run(script, [["GET /pulls/7", 200, json.dumps({"state": "open", "head": {"sha": NEW}})]] + page2((110, OLD, title(7, OLD))))
    check(rc == 0 and cancels(reqs) == [] and not lists(reqs),
          f"G7 a live head other than the event's: nothing listed, nothing cancelled ({cancels(reqs)})")

    # W: the gate with a twin's re-review in flight.
    gate = job(src, "gate")
    gscript = run_script(step(gate, "Require a Codex approval of the head, or a no-review change"))
    no_review = once(r"\n      NO_REVIEW_PATHS: '([^']*)'\n", gate, "NO_REVIEW_PATHS")
    docs = once(r"\n      DOCS_PATHS: '([^']*)'\n", gate, "DOCS_PATHS")
    for where in ("queued", "in_progress"):
        rc, out = run_gate(gscript, gate_routes(["APPROVED"], twin_status=where, twin_where=where), no_review, docs)
        check(rc == 3 and "runs in run 91" in out and "ruling 1084" in out,
              f"W1 approved head, the effort-label run's review {where}: the gate fails closed (got {rc})")
    rc, out = run_gate(gscript, gate_routes(["APPROVED", "APPROVED"], twin_status="completed"), no_review, docs)
    check(rc == 0 and "approved" in out, f"W2 after the re-review approves: the gate passes (got {rc})")
    rc, out = run_gate(gscript, gate_routes(["APPROVED", "REQUEST_CHANGES"], twin_status="completed"), no_review, docs)
    check(rc == 3 and "requested changes" in out, f"W3 after the re-review requests changes: the gate fails (got {rc})")
    rc, out = run_gate(gscript, gate_routes(["APPROVED"]), no_review, docs)
    check(rc == 0, f"W4 no twin, approved head: passes as before (got {rc})")

    # C: a cancelled re-review never reuses an earlier approval.
    rc, out = run_gate(gscript, gate_routes(["APPROVED"]), no_review, docs, "cancelled")
    check(rc == 3 and "was cancelled" in out and "v5.12.12" in out,
          f"C1 scope success, re-review cancelled, approval standing, handoff re-run: fails closed (got {rc})")
    rc, out = run_gate(gscript, gate_routes(["APPROVED"]), no_review, docs, "failure")
    check(rc == 3 and "job failed" in out, f"C2 a failed review still fails over an approval (got {rc})")
    rc, out = run_gate(gscript, gate_routes(["APPROVED"]), no_review, docs, "success")
    check(rc == 0 and "approved" in out, f"C3 a successful review with the approval passes (got {rc})")
    rc, out = run_gate(gscript, gate_routes(["APPROVED"]), no_review, docs, "skipped")
    check(rc == 0, f"C4 no review asked (skipped) with the approval passes as before (got {rc})")
    hand = step(gate, "Re-run a newer twin's failed gate on this head")
    check('.conclusion == "failure" or .conclusion == "cancelled"' in hand,
          "C5 the handoff still re-runs a cancelled run's red gate, which now fails closed (C1)")

    # H: the handoff step itself, executed against the fake forge (Codex's
    # P1 on go-trusted-platform #2227 at 923d0d81: C5 only read its text).
    hscript = run_script(hand)
    red = handoff_jobs("completed", "failure")
    cancelled = handoff_jobs("completed", "cancelled")
    rc, out, reqs = run_handoff(hscript, handoff_routes("completed", [(200, "completed")], [red]))
    check(rc == 0 and posts(reqs) == ["POST /actions/jobs/9000/rerun"],
          f"H1 a newer run completed with its gate red: that gate is re-run, once (rc {rc}, {posts(reqs)})")
    rc, out, reqs = run_handoff(hscript, handoff_routes("completed", [(200, "completed")], [cancelled]))
    check(rc == 0 and posts(reqs) == ["POST /actions/jobs/9000/rerun"],
          f"H2 a newer run whose gate was cancelled (C1's shape): that gate is re-run, once (rc {rc}, {posts(reqs)})")
    rc, out, reqs = run_handoff(hscript, handoff_routes(
        "in_progress", [(200, "in_progress"), (200, "in_progress"), (200, "completed")], [red]))
    runs92 = [i for i, r in enumerate(reqs) if r == "GET /actions/runs/92"]
    post_at = [i for i, r in enumerate(reqs) if r.startswith("POST ")]
    check(rc == 0 and posts(reqs) == ["POST /actions/jobs/9000/rerun"] and len(runs92) == 3
          and post_at and post_at[0] > runs92[-1],
          f"H3 a newer run in progress with a red gate: polled through to completed, then re-run once after the last read (rc {rc}, {len(runs92)} run reads, {posts(reqs)})")
    running = handoff_jobs("in_progress", None)
    rc, out, reqs = run_handoff(hscript, handoff_routes(
        "in_progress", [(200, "in_progress"), (200, "completed")], [running, red]))
    check(rc == 0 and posts(reqs) == ["POST /actions/jobs/9000/rerun"],
          f"H4 a newer gate still running that ends red while polled: re-run once (rc {rc}, {posts(reqs)})")
    rc, out, reqs = run_handoff(hscript, handoff_routes(
        "in_progress", [(200, "in_progress"), (200, "completed")], [running, handoff_jobs("completed", "success")]))
    check(rc == 0 and not posts(reqs), f"H5 a newer gate that ends green while polled: nothing re-run (rc {rc}, {posts(reqs)})")
    rc, out, reqs = run_handoff(hscript, handoff_routes("in_progress", [(200, "in_progress")], [red]), poll="1", wait="2")
    check(rc == 5 and "::error::" in out and "run 92" in out and "bound" in out and not posts(reqs),
          f"H6 the run never completes inside the bound: the step fails (exit 5, ::error::), nothing re-run (rc {rc})")
    rc, out, reqs = run_handoff(hscript, handoff_routes(
        "in_progress", [(200, "in_progress")], [handoff_jobs("queued", None, review="in_progress")]), poll="1", wait="2")
    check(rc == 0 and not posts(reqs) and "reviews" in out and "GET /actions/runs/92" not in reqs,
          f"H7 a newer run reviewing the head itself is left to its own review's gate at once (rc {rc}, {posts(reqs)})")
    rc, out, reqs = run_handoff(hscript, handoff_routes(
        "in_progress", [(200, "in_progress")], [handoff_jobs("queued", None)]), poll="1", wait="2")
    check(rc == 0 and not posts(reqs) and "::error::" not in out and "GET /actions/runs/92" not in reqs
          and "reads this approval itself" in out,
          f"H8 a newer run whose gate is queued is left to that gate at once, no poll, no red (rc {rc}, {posts(reqs)})")
    rc, out, reqs = run_handoff(hscript, handoff_routes("completed", [(200, "completed")], [red], others=[
        (60, 400, title(7, HEAD)), (93, 503, title(70, HEAD))]))
    check(rc == 0 and posts(reqs) == ["POST /actions/jobs/9000/rerun"],
          f"H9 an older suite's run and another PR's run, both red, are never re-run (rc {rc}, {posts(reqs)})")
    rc, out, reqs = run_handoff(hscript, handoff_routes("in_progress", [(500, "in_progress")], [red]))
    check(rc == 0 and "::warning::" in out and "HTTP 500" in out and not posts(reqs),
          f"H10 an API error while polling: a warning, exit 0, nothing re-run (rc {rc})")

    # R: ruling 1087 (3), a pushed fix is a new round by right.
    block = round_block(src)
    A, B = "a" * 40, "b" * 40
    at_limit = [verdict(i, "%040x" % i, i) for i in range(1, 5)] + [verdict(5, A, 5)]
    rc, out, o = run_rounds(block, at_limit, ["code-review", "needs-coordinator"], B)
    check(rc == 0 and "round=6" in o and "new round by right" in out,
          f"R1 at the last coordinator round, the head moved: reviewed as round 6 (got {rc}: {o.split()})")
    rc, out, o = run_rounds(block, at_limit, ["code-review", "needs-coordinator"], A)
    check(rc == 1 and "skip=round-limit" in o, f"R2 at the limit, the same head: the round limit stops it (got {rc})")
    two = [verdict(1, "%040x" % 1, 1), verdict(2, A, 2)]
    rc, out, o = run_rounds(block, two, ["code-review"], B)
    check(rc == 0 and "round=3" in o, f"R3 round 2 rejected, no needs-coordinator, the head moved: round 3 (got {rc})")
    rc, out, o = run_rounds(block, two, ["code-review"], A)
    check(rc == 1 and "skip=round-limit" in o, f"R4 round 2 rejected, the same head: stopped (got {rc})")
    rc, out, o = run_rounds(block, [verdict(1, A, 1)], ["code-review"], B)
    check(rc == 0 and "round=2" in o and "new round by right" not in out, f"R5 under the limit: round 2 as before (got {rc})")
    rc, out, o = run_rounds(block, two[:1] + [verdict(2, A, 2, "APPROVED")], ["code-review"], B)
    check(rc == 0 and "round=3" in o, f"R6 an approval at the limit, the head moved: reviewed (got {rc})")

    print(f"{'ALL PASS' if not FAILS else f'{len(FAILS)} FAILED'}")
    sys.exit(1 if FAILS else 0)


main()
