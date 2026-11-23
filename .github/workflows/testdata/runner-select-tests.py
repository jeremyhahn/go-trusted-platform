#!/usr/bin/env python3
"""runner-select-tests.py -- runs ci.yml's preflight step `Balanced runner
pool (ruling 1137)` (ci-template v1.54, Tenant Agent ruling 1137, which
replaces the hosted first rule of rulings 999 and 1024) against a fake
Actions API and asserts the runs-on JSON it outputs.

The code under test is read out of ci.yml, not copied: the `run: |` block of
the step named `Balanced runner pool (ruling 1137)`, found exactly once or
the test stops with FATAL (exit 9). It runs under `bash --noprofile --norc
-eo pipefail`, as the runner runs a step, with a fake `curl` first on PATH
that answers from canned replies; nothing reaches the network. The fake
also fails a case whose curl command line carries the token.

  A. Balance: H hosted, S1 bigdisk and S2 bigdisk-docker jobs (in progress
     plus queued, this run's jobs not counted) against HS=CI_HOSTED_SHARE,
     C1=CI_SELF_HOSTED_BIGDISK and C2=CI_SELF_HOSTED_BIGDISK_DOCKER; hosted
     use H/HS against self-hosted use max(S1/C1, S2/C2), by
     cross-multiplication, and a tie goes hosted. Completed jobs, jobs with
     no runner label and other self-hosted labels do not count; a hosted job
     never counts as self-hosted.
  B. Full pools: one full sends the run to the other (the self-hosted pool
     is full when S1 >= C1 or S2 >= C2, each alone); both full takes the
     shorter queue (bigdisk and bigdisk-docker queued together), and equal
     queues go hosted.
  C. No silent pick: C1 or C2 unset, 0 or not a whole number gives hosted
     with a ::warning and no call; HS unset, 0 or not a number gives a ::warning and
     HS=12; a reply that is not 200, no total_count, more than 1000
     entries, or a job list that cannot be counted gives hosted with a
     ::warning. A list short of its total is a lower bound (v1.59): it is
     counted and the choice still made, with a ::notice naming the
     shortfall (C8, C9, C12, C13).
  D. Off github.com: no call, the default output, the forge labels kept.
  E. ci-template v1.52 (kept): a pull request whose head repository is not
     this repository (a fork, or one since deleted) gets the hosted default
     with a ::notice and no call, even when self-hosted would win; a
     same-repository pull request and a push still balance.

Run: python3 -I software/templates/github-actions/testdata/runner-select-tests.py
"""
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
WORKFLOW = HERE.parent / "ci.yml"
STEP = "      - name: Balanced runner pool (ruling 1137)\n"
TOKEN = "<fake-token-0123456789>"
FAILS = 0
HOSTED = '"ubuntu-latest"'


def fatal(msg):
    print(f"FATAL: {msg}")
    sys.exit(9)


def script():
    text = WORKFLOW.read_text()
    if text.count(STEP) != 1:
        fatal("the step `Balanced runner pool (ruling 1137)` is not in ci.yml exactly once")
    rest = text.split(STEP, 1)[1].split("\n")
    out, inside = [], False
    for line in rest:
        if not inside:
            if line == "        run: |":
                inside = True
            elif line.startswith("      - "):
                break
            continue
        if line.strip() and not line.startswith(" " * 10):
            break
        out.append(line[10:])
    if not out:
        fatal("the step's run block is not found")
    return "\n".join(out) + "\n"


SCRIPT = script()

FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
if any(os.environ["FAKE_TOKEN"] in a for a in args):
    print("token on the curl command line", file=sys.stderr)
    sys.exit(97)
out = args[args.index("-o") + 1]
url = args[-1]
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(url + "\n")
for key, code, body in json.load(open(os.environ["FAKE_RESP"])):
    if key in url:
        with open(out, "w") as f:
            f.write(body)
        sys.stdout.write(str(code))
        sys.exit(0)
with open(out, "w") as f:
    f.write('{"message":"Not Found"}')
sys.stdout.write("404")
'''


def iso(age):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - age))


def jobj(run, status, labels, age=5):
    return {"run_id": run, "status": status, "labels": labels, "created_at": iso(age), "started_at": iso(age)}


def runs(*ids, total=None):
    return json.dumps({"total_count": len(ids) if total is None else total, "workflow_runs": [{"id": i} for i in ids]})


def jobs(*js, total=None):
    return json.dumps({"total_count": len(js) if total is None else total, "jobs": list(js)})


def run(resp, server="https://github.com", hs="10", c1="10", c2="10", event="push", head=""):
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        (d / "bin").mkdir()
        curl = d / "bin" / "curl"
        curl.write_text(FAKE_CURL)
        curl.chmod(0o755)
        (d / "resp.json").write_text(json.dumps(resp))
        (d / "out").write_text("")
        (d / "log").write_text("")
        (d / "tmp").mkdir()
        (d / "step.sh").write_text(SCRIPT)
        env = {
            "PATH": f"{d / 'bin'}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "FAKE_RESP": str(d / "resp.json"), "FAKE_LOG": str(d / "log"), "FAKE_TOKEN": TOKEN,
            "GITHUB_OUTPUT": str(d / "out"), "RUNNER_TEMP": str(d / "tmp"),
            "SERVER": server, "API": "https://api.github.com/repos/o/r/actions", "RUN_ID": "100",
            "JOB_TOKEN": TOKEN, "HS": hs, "C1": c1, "C2": c2,
            "EVENT": event, "HEAD_REPO": head, "REPO": "o/r",
        }
        p = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", str(d / "step.sh")],
                           env=env, capture_output=True, text=True, timeout=60)
        outs = dict(l.split("=", 1) for l in (d / "out").read_text().splitlines() if "=" in l)
        return p.returncode, p.stdout + p.stderr, outs, (d / "log").read_text().splitlines()


def case(label, resp, runner, docker, want=(), not_want=(), calls=None, **kw):
    global FAILS
    rc, out, outs, log = run(resp, **kw)
    ok = (rc == 0 and outs.get("runner") == runner and outs.get("runner_docker") == docker
          and all(w in out for w in want) and not any(w in out for w in not_want)
          and (calls is None or len(log) == calls) and TOKEN not in out)
    print(f"{'PASS' if ok else 'FAIL'}: {label}")
    if not ok:
        FAILS += 1
        print(f"  exit {rc}; outputs {outs}; wanted runner={runner} runner_docker={docker}; calls {len(log)}")
        print("  " + out.replace("\n", "\n  "))


U = ["ubuntu-latest"]
SH = ["self-hosted", "linux", "x64", "bigdisk-docker"]


SELF = '["self-hosted","linux","x64","bigdisk"]'
SELF_D = '["self-hosted","linux","x64","bigdisk-docker"]'
B1 = ["self-hosted", "linux", "x64", "bigdisk"]


def pool(h=0, hq=0, s1=0, s1q=0, s2=0, s2q=0, extra=()):
    """Run 101 holds h hosted in progress and hq queued, s1/s1q bigdisk and
    s2/s2q bigdisk-docker; run 100 (this run) is listed but its jobs are
    never read (the fake answers 404 for them)."""
    js = ([jobj(101, "in_progress", U) for _ in range(h)] + [jobj(101, "queued", U) for _ in range(hq)]
          + [jobj(101, "in_progress", B1) for _ in range(s1)] + [jobj(101, "queued", B1) for _ in range(s1q)]
          + [jobj(101, "in_progress", SH) for _ in range(s2)] + [jobj(101, "queued", SH) for _ in range(s2q)]
          + list(extra))
    return [["runs?status=queued", 200, runs()], ["runs?status=in_progress", 200, runs(100, 101)],
            ["runs/101/jobs", 200, jobs(*js)]]


# A. balance (HS, C1, C2 default to 10)
case("A1 hosted use lower: hosted",
     pool(h=2, s1=5), HOSTED, HOSTED,
     ["hosted 2 of CI_HOSTED_SHARE=10", "bigdisk 5 of CI_SELF_HOSTED_BIGDISK=10", "bigdisk-docker 0 of CI_SELF_HOSTED_BIGDISK_DOCKER=10"], ["::warning::"])
case("A2 self-hosted use lower: self-hosted",
     pool(h=5, s1=2, s2=2), SELF, SELF_D, ["::notice::", "run on the Dells"], ["::warning::"])
case("A3 equal use: hosted",
     pool(h=3, s2=3), HOSTED, HOSTED, ["use hosted 3/10, bigdisk 0/10, bigdisk-docker 3/10"])
case("A4 equal use by cross-multiplication (2/10 against 4/20): hosted",
     pool(h=2, s1=4), HOSTED, HOSTED, c1="20")
case("A5 self-hosted use is the larger kind: S2/C2 3/6 against hosted 4/20 goes hosted",
     pool(h=4, s1=0, s2=3), HOSTED, HOSTED, hs="20", c2="6")
case("A6 both kinds below hosted use: 9/20 hosted against 1/6 and 1/6 goes self-hosted",
     pool(h=9, s1=1, s2=1), SELF, SELF_D, hs="20", c1="6", c2="6")
case("A7 one kind ties hosted use: hosted (1/10 hosted, bigdisk 1/10)",
     pool(h=1, s1=1, s2=0), HOSTED, HOSTED)
case("A8 nothing in flight: hosted (a tie at 0)",
     pool(), HOSTED, HOSTED, ["hosted 0 of", "bigdisk 0 of", "bigdisk-docker 0 of"])
case("A9 queued jobs count with in-progress ones",
     pool(h=1, hq=3, s1=1, s1q=1, s2q=1), SELF, SELF_D, ["hosted 4 of", "(3 queued)", "bigdisk 2 of", "bigdisk-docker 1 of", "(2 self-hosted queued)"])
case("A10 hosted jobs never count as self-hosted; completed, unlabelled and other self-hosted labels do not count",
     pool(h=1, extra=[jobj(101, "completed", SH) for _ in range(30)] + [jobj(101, "in_progress", []) for _ in range(5)]
          + [jobj(101, "in_progress", ["self-hosted", "linux", "x64", "release"])]
          + [jobj(101, "in_progress", ["self-hosted", "ubuntu-latest"])]),
     SELF, SELF_D, ["hosted 1 of", "bigdisk 0 of", "bigdisk-docker 0 of"])
case("A11 a job on bigdisk-docker counts as S2 only",
     pool(h=5, extra=[jobj(101, "in_progress", ["self-hosted", "bigdisk", "bigdisk-docker"])]),
     SELF, SELF_D, ["bigdisk 0 of", "bigdisk-docker 1 of"])
case("A12 this run's jobs are not read or counted",
     pool(h=1) + [["runs/100/jobs", 200, jobs(*[jobj(100, "in_progress", SH) for _ in range(50)])]],
     SELF, SELF_D, ["bigdisk-docker 0 of"])
case("A13 a run listed as queued and as in progress is read once",
     [["runs?status=queued", 200, runs(101)], ["runs?status=in_progress", 200, runs(100, 101)],
      ["runs/101/jobs", 200, jobs(*[jobj(101, "in_progress", U) for _ in range(3)])]],
     SELF, SELF_D, ["hosted 3 of"], calls=3)
case("A14 a second page is read",
     [["runs?status=queued", 200, runs()],
      ["runs?status=in_progress&per_page=100&page=1", 200, runs(100, total=2)],
      ["runs?status=in_progress&per_page=100&page=2", 200, runs(101, total=2)],
      ["runs/101/jobs", 200, jobs(*[jobj(101, "in_progress", U) for _ in range(4)])]],
     SELF, SELF_D, ["hosted 4 of"])

# B. full pools
case("B1 hosted full, self-hosted free: self-hosted",
     pool(h=10, s1=9, s2=9), SELF, SELF_D, ["the hosted pool is full (10 of 10)"])
case("B2 self-hosted full, hosted free: hosted",
     pool(h=9, s1=10, s2=10), HOSTED, HOSTED, ["the self-hosted pool is full"])
case("B3 only bigdisk full (C1): self-hosted full, hosted",
     pool(h=9, s1=2, s2=0), HOSTED, HOSTED, ["the self-hosted pool is full (bigdisk 2 of 2, bigdisk-docker 0 of 10)"], c1="2")
case("B4 only bigdisk-docker full (C2): self-hosted full, hosted",
     pool(h=9, s1=0, s2=3), HOSTED, HOSTED, ["the self-hosted pool is full (bigdisk 0 of 10, bigdisk-docker 3 of 3)"], c2="3")
case("B5 both full, self-hosted queue shorter: self-hosted",
     pool(h=6, hq=4, s1=9, s1q=1), SELF, SELF_D, ["both pools full: hosted 4 queued, self-hosted 1 queued"])
case("B6 both full, hosted queue shorter: hosted",
     pool(h=10, hq=1, s1=5, s2=8, s2q=2), HOSTED, HOSTED, ["both pools full: hosted 1 queued, self-hosted 2 queued"])
case("B7 both full, the self-hosted queue counts both kinds",
     pool(h=8, hq=2, s1=8, s1q=1, s2=9, s2q=1), HOSTED, HOSTED, ["self-hosted 2 queued"])
case("B8 both full, equal queues: hosted",
     pool(h=12, s1=12), HOSTED, HOSTED, ["both pools full: hosted 0 queued, self-hosted 0 queued"])

# C. no silent pick
for var, kw in (("CI_SELF_HOSTED_BIGDISK", "c1"), ("CI_SELF_HOSTED_BIGDISK_DOCKER", "c2")):
    for label, v in (("unset", ""), ("0", "0"), ("not a number", "ten"), ("negative", "-3"), ("00", "00"), ("a decimal", "1.5")):
        case(f"C1 {var} {label}: hosted, with a warning, no call",
             pool(h=10), HOSTED, HOSTED, ["::warning::", f"{var}='{v}'"], calls=0, **{kw: v})
case("C2 a value 08 reads as 8, not octal",
     pool(h=5, s1=1), SELF, SELF_D, ["CI_SELF_HOSTED_BIGDISK=8"], c1="08")
for label, hs in (("unset", ""), ("0", "0"), ("not a number", "x12")):
    case(f"C3 CI_HOSTED_SHARE {label}: a warning and HS=12",
         pool(h=11, s1=1), SELF, SELF_D, ["::warning::", "CI_HOSTED_SHARE", "HS=12", "hosted 11 of CI_HOSTED_SHARE=12"], hs=hs)
case("C4 CI_HOSTED_SHARE unset: 12 hosted jobs fill the hosted pool",
     pool(h=12, s1=9), SELF, SELF_D, ["the hosted pool is full (12 of 12)"], hs="")
case("C5 a 403 on the run list: hosted, with a warning naming why",
     [["runs?status=queued", 403, '{"message":"Resource not accessible by integration"}']],
     HOSTED, HOSTED, ["::warning::runner selection: the Actions API gave no complete run list", "403", "ubuntu-latest"])
case("C6 a 500 on a job list: hosted, with a warning",
     pool(h=1)[:2] + [["runs/101/jobs", 500, "{}"]], HOSTED, HOSTED, ["::warning::", "no complete job list", "500"])
case("C7 a 200 with no total_count: hosted, with a warning",
     [["runs?status=queued", 200, '{"workflow_runs":[]}']], HOSTED, HOSTED, ["::warning::", "no total_count"])
# C8, C9, C12, C13 (v1.59): a list short of its total_count is a lower
# bound, counted and still chosen from, with a notice; never hosted for it.
case("C8 a run list short of its total: a lower bound, still chosen (self-hosted), with a notice",
     [["runs?status=queued", 200, runs()],
      ["runs?status=in_progress&per_page=100&page=1", 200, runs(101, total=5)],
      ["runs?status=in_progress&per_page=100&page=2", 200, runs(total=5)],
      ["runs/101/jobs", 200, jobs(*[jobj(101, "in_progress", U) for _ in range(9)])]],
     SELF, SELF_D, ["::notice::", "1 of 5 entries", "lower bound", "hosted 9 of CI_HOSTED_SHARE=10"], ["::warning::"])
case("C9 a job list short of its total: a lower bound, still chosen (self-hosted), with a notice",
     pool(h=1)[:2] + [["runs/101/jobs?filter=latest&per_page=100&page=1", 200, jobs(jobj(101, "in_progress", U), total=4)],
                      ["runs/101/jobs?filter=latest&per_page=100&page=2", 200, jobs(total=4)]],
     SELF, SELF_D, ["::notice::", "runs/101/jobs?filter=latest: 1 of 4 entries", "lower bound"], ["::warning::"])
case("C12 go-qrdb #1680: runs?status=queued gives 1 of 2 entries, hosted full: self-hosted",
     [["runs?status=queued&per_page=100&page=1", 200, runs(101, total=2)],
      ["runs?status=queued&per_page=100&page=2", 200, runs(total=2)],
      ["runs?status=in_progress", 200, runs(100)],
      ["runs/101/jobs", 200, jobs(*[jobj(101, "queued", U) for _ in range(10)])]],
     SELF, SELF_D, ["::notice::", "runs?status=queued: 1 of 2 entries", "the hosted pool is full (10 of 10)"],
     ["::warning::", "no complete run list"])
case("C13 a short list where hosted use is the lower: hosted, with the notice and no warning",
     [["runs?status=queued&per_page=100&page=1", 200, runs(101, total=2)],
      ["runs?status=queued&per_page=100&page=2", 200, runs(total=2)],
      ["runs?status=in_progress", 200, runs(100)],
      ["runs/101/jobs", 200, jobs(jobj(101, "in_progress", U), *[jobj(101, "in_progress", B1) for _ in range(5)])]],
     HOSTED, HOSTED, ["::notice::", "1 of 2 entries", "hosted 1 of CI_HOSTED_SHARE=10"], ["::warning::"])
case("C10 a job list that is not a list of objects: hosted, with a warning",
     pool(h=1)[:2] + [["runs/101/jobs", 200, '{"total_count":1,"jobs":[7]}']],
     HOSTED, HOSTED, ["::warning::", "could not be counted"])
case("C11 a route the API does not answer (404): hosted, with a warning",
     [], HOSTED, HOSTED, ["::warning::", "404"])

# D. off github.com
case("D1 Gitea: no call, the default output",
     [], HOSTED, HOSTED, ["not github.com"], ["::warning::"], calls=0, server="https://forge.example")
case("D2 Gitea with the self-hosted variables unset: no call, no warning",
     [], HOSTED, HOSTED, ["not github.com"], ["::warning::"], calls=0, server="https://forge.example", c1="", c2="")

# E. a fork's pull request (v1.52, kept)
WIN = pool(h=9)
case("E1 a fork's pull request where self-hosted would win: hosted, no call",
     WIN, HOSTED, HOSTED, ["::notice::", "a fork", "ci-template v1.52"], ["::warning::"], calls=0,
     event="pull_request", head="fork/r")
case("E2 a pull request whose head repository is gone: hosted, no call",
     WIN, HOSTED, HOSTED, ["a fork"], calls=0, event="pull_request", head="")
case("E3 a fork under pull_request_target: hosted, no call",
     WIN, HOSTED, HOSTED, ["a fork"], calls=0, event="pull_request_target", head="fork/r")
case("E4 a same-repository pull request still balances",
     WIN, SELF, SELF_D, ["::notice::", "run on the Dells"], ["a fork"], event="pull_request", head="o/r")
case("E5 a push still balances",
     WIN, SELF, SELF_D, ["run on the Dells"], ["a fork"])
case("E6 off github.com a fork keeps the forge labels: no call, no fork notice",
     [], HOSTED, HOSTED, ["not github.com"], ["a fork"], calls=0, server="gitea", event="pull_request", head="fork/r")

print(f"{'ALL PASS' if not FAILS else f'{FAILS} FAILED'}")
sys.exit(1 if FAILS else 0)
