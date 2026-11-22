#!/usr/bin/env python3
"""code-review-v51210-tests.py -- the regression tests for code-review.yml
v5.12.10 (Codex's P1 on trusted-firmware #653: every non-draft suite carries
the required context `Code Review (codex)`).

The evaluator is v5.12.9's (code-review-v5129-tests.py): every job's `if:`
and the gate's `name:` are read out of the workflow file and evaluated
against synthetic event payloads. Nothing runs a workflow. These tests
supersede v5.12.9's gate checks (S3, S4, A, D1 there), which now apply to
scope, review and review-opencode only.

  S. THE TEXT: scope, review and review-opencode keep v5.12.9's shared
     condition; the gate's `if:` is `always() && <draft clause>` and its
     name the draft clause's expression; the gate's verdict step does not
     fail on a skipped scope or review; the handoff's selector is read out.
  G. On every non-draft event and label (dept:software, ci:full,
     task:in-progress, holds included), GitHub and Gitea, the gate runs as
     `Code Review (codex)`.
  K. A labeled dept:software, ci:full or task:in-progress event runs no
     scope and no review (no reviewer runner).
  B. A draft runs no job, for every event type and label.
  P. THE P1 SCENARIO: R1 (opened) reviews; R2 (labeled dept:software,
     newer suite) runs its gate while R1's review is in flight, so R2's
     gate fails at once; R1's review approves and R1's gate passes; R1's
     handoff selector (the file's own jq, run by jq) picks R2's gate and
     re-runs it, which reads the approval. The newest suite then carries a
     green `Code Review (codex)`: the merge is permitted.
  N. Negative control: the same scenario against v5.12.9 (pass its file as
     the argument) fails P, because R2's gate is skipped as `Code Review
     (not requested)` and the selector never picks it.

Run: python3 -I software/templates/github-actions/testdata/code-review-v51210-tests.py [workflow]
"""
import itertools
import json
import shutil
import subprocess
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
WORKFLOW = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parent / "code-review.yml"
FAILS = []
REQUIRED = "Code Review (codex)"
GH = "https://github.com"
GITEA = "https://gitea.example.test"
REPO = "o/r"
EVENTS = ("opened", "reopened", "synchronize", "labeled", "ready_for_review")
LABELS = ("code-review", "task:ready", "dept:software", "ci:full", "agent:opencode",
          "model:gpt", "effort:high", "task:in-progress", "needs-owner", "needs-coordinator")
REQUESTING = ("code-review", "task:ready", "agent:opencode", "model:gpt", "effort:high")
SHARED = """github.event.pull_request.draft != true
&& (github.event.action != 'labeled'
|| github.event.label.name == 'code-review'
|| github.event.label.name == 'task:ready'
|| startsWith(github.event.label.name, 'agent:')
|| startsWith(github.event.label.name, 'model:')
|| startsWith(github.event.label.name, 'effort:'))"""
LABEL_LIST = SHARED.split("\n", 1)[1][3:]
HOLDS = ("needs-owner", "needs-coordinator")
GATE = SHARED[:-1] + "".join(f"\n|| github.event.label.name == '{h}'" for h in HOLDS) + ")"


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


def key(text, k):
    """A job-level key: a one-line value, or a `>-` block folded to one line."""
    m = re.search(r"\n    " + k + r": >-\n((?:      [^\n]*\n?)+)", "\n" + text)
    if m:
        return " ".join(line.strip() for line in m.group(1).splitlines() if line.strip())
    m = re.search(r"\n    " + k + r": ([^\n]*)", "\n" + text)
    return m.group(1).split(" #")[0].strip() if m else None


def block(text, k):
    m = re.search(r"\n    " + k + r": >-\n((?:      [^\n]*\n?)+)", "\n" + text)
    return "\n".join(line[6:] for line in m.group(1).splitlines()) if m else ""


# --- A small GitHub Actions expression evaluator -------------------------

TOKEN = re.compile(r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<num>\d+(?:\.\d+)?)|(?P<op>==|!=|&&|\|\||[!(),])"
                   r"|(?P<id>[A-Za-z_][A-Za-z0-9_-]*(?:\.(?:\*|[A-Za-z_][A-Za-z0-9_-]*))*))")


def tokenize(s):
    out, i = [], 0
    s = s.strip()
    while i < len(s):
        m = TOKEN.match(s, i)
        if not m or m.end() == i:
            raise ValueError(f"cannot read the expression at {s[i:i + 30]!r}")
        i = m.end()
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
    return out


def truthy(v):
    return not (v is None or v is False or v == 0 or v == "")


def lookup(path, ctx):
    vals = [ctx]
    star = False
    for part in path.split("."):
        nxt = []
        for v in vals:
            if part == "*":
                star = True
                if isinstance(v, list):
                    nxt.extend(v)
                elif isinstance(v, dict):
                    nxt.extend(v.values())
            elif isinstance(v, dict):
                nxt.append(v.get(part))
            else:
                nxt.append(None)
        vals = nxt
    return vals if star else (vals[0] if vals else None)


def equal(a, b):
    if isinstance(a, str) and isinstance(b, str):
        return a.lower() == b.lower()
    return a == b


class Expr:
    def __init__(self, text, ctx, status):
        self.t = tokenize(text)
        self.i = 0
        self.ctx = ctx
        self.status = status
        self.used_status = False

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self, want=None):
        tok = self.peek()
        if want is not None and tok[1] != want:
            raise ValueError(f"want {want!r}, got {tok!r}")
        self.i += 1
        return tok

    def run(self):
        v = self.or_()
        if self.i != len(self.t):
            raise ValueError(f"trailing tokens {self.t[self.i:]}")
        return v

    def or_(self):
        v = self.and_()
        while self.peek()[1] == "||":
            self.take()
            r = self.and_()
            v = v if truthy(v) else r
        return v

    def and_(self):
        v = self.cmp()
        while self.peek()[1] == "&&":
            self.take()
            r = self.cmp()
            v = r if truthy(v) else v
        return v

    def cmp(self):
        v = self.unary()
        while self.peek()[1] in ("==", "!="):
            op = self.take()[1]
            r = self.unary()
            v = equal(v, r) if op == "==" else not equal(v, r)
        return v

    def unary(self):
        if self.peek()[1] == "!":
            self.take()
            return not truthy(self.unary())
        return self.atom()

    def atom(self):
        kind, val = self.take()
        if val == "(":
            v = self.or_()
            self.take(")")
            return v
        if kind == "str":
            return val[1:-1].replace("''", "'")
        if kind == "num":
            return float(val)
        if kind == "id":
            if val in ("true", "false", "null"):
                return {"true": True, "false": False, "null": None}[val]
            if self.peek()[1] == "(":
                self.take("(")
                args = []
                while self.peek()[1] != ")":
                    args.append(self.or_())
                    if self.peek()[1] == ",":
                        self.take()
                self.take(")")
                return self.call(val, args)
            return lookup(val, self.ctx)
        raise ValueError(f"unexpected token {val!r}")

    def call(self, name, args):
        n = name.lower()
        if n == "always":
            self.used_status = True
            return True
        if n == "success":
            self.used_status = True
            return self.status
        if n == "contains":
            hay, needle = args
            if isinstance(hay, list):
                return any(equal(h, needle) for h in hay)
            return str(needle).lower() in str(hay or "").lower()
        if n == "startswith":
            return str(args[0] or "").lower().startswith(str(args[1] or "").lower())
        raise ValueError(f"no function {name}")


def evaluate(text, ctx, status=True):
    text = text.strip()
    m = re.fullmatch(r"\$\{\{(.*)\}\}", text, re.S)
    e = Expr(m.group(1) if m else text, ctx, status)
    return e.run(), e.used_status


def job_name(text, ctx):
    """A job name: literal text, or one ${{ }} expression evaluated."""
    text = text.strip()
    return evaluate(text, ctx)[0] if re.fullmatch(r"\$\{\{(.*)\}\}", text, re.S) else text


# --- The cases ------------------------------------------------------------

def context(action, draft, labels, label=None, server=GH, state="open", agent=""):
    pr = {"number": 7, "state": state, "draft": draft, "labels": [{"name": n} for n in labels],
          "head": {"repo": {"full_name": REPO}, "sha": "a" * 40}, "base": {"ref": "main"}}
    event = {"action": action, "pull_request": pr}
    if label is not None:
        event["label"] = {"name": label}
    return {"github": {"server_url": server, "repository": REPO, "event": event},
            "needs": {"scope": {"outputs": {"skip": "false"}}, "review": {"outputs": {"agent": agent}}}}


def simulate(jobs, ctx):
    """jobs: [(id, if, needs)] in file order -> {id: ran}."""
    ran = {}
    for jid, cond, needs in jobs:
        ok_needs = all(ran.get(n, False) for n in needs)
        if cond is None:
            ran[jid] = ok_needs
            continue
        v, used = evaluate(cond, ctx, status=ok_needs)
        ran[jid] = truthy(v) and (used or ok_needs)
    return ran


def cases():
    for server, action, draft in itertools.product((GH, GITEA), EVENTS, (False, True)):
        for base in ((), ("code-review", "task:ready"), ("code-review", "task:ready", "dept:software")):
            if action == "labeled":
                for lab in LABELS:
                    yield server, action, draft, tuple(sorted(set(base) | {lab})), lab
            else:
                yield server, action, draft, base, None


DRAFT = "github.event.pull_request.draft != true"
UNRELATED = ("dept:software", "ci:full", "task:in-progress")


def handoff_select(src):
    """The handoff step's jq filter over a run's jobs, verbatim."""
    # v5.12.11: the jobs are read into $jobs first, then selected.
    m = once(r"gate=\$\((?:api GET \"/actions/runs/\$id/jobs\?per_page=100\" \|\s*)?jq -r '(\[\.jobs\[\]\?.*?)'(?: <<<\"\$jobs\")?\)", src,
             "the handoff's jobs selector")
    return m


def jq(filt, doc):
    out = subprocess.run(["jq", "-r", filt], input=json.dumps(doc), capture_output=True, text=True, check=True)
    return out.stdout.strip()


def suite_jobs(ids, ran, gate_name, gate_conclusion):
    jobs = []
    for i, j in enumerate(ids):
        name = gate_name if j == "gate" else j
        if j == "gate" and ran[j]:
            jobs.append({"id": 100 + i, "name": name, "status": "completed", "conclusion": gate_conclusion})
        elif ran[j]:
            jobs.append({"id": 100 + i, "name": name, "status": "completed", "conclusion": "success"})
        else:
            jobs.append({"id": 100 + i, "name": name, "status": "completed", "conclusion": "skipped"})
    return {"jobs": jobs}


def main():
    for tool in ("jq",):
        if shutil.which(tool) is None:
            fatal(f"{tool} is not on PATH")
    if not WORKFLOW.is_file():
        fatal(f"no workflow at {WORKFLOW}")
    src = WORKFLOW.read_text()
    version = once(r"^# code-review-template: (v5\.12\.\d+)\b", src, "a v5.12 version")
    body = src.split("\njobs:\n", 1)[1]
    ids = re.findall(r"\n  ([a-z][a-z0-9-]*):\n", "\n" + body)
    texts = {j: job(src, j) for j in ids}
    jobs = []
    for j in ids:
        needs = key(texts[j], "needs") or ""
        needs = [n.strip() for n in needs.strip("[]").split(",") if n.strip()]
        jobs.append((j, key(texts[j], "if"), needs))
    gate_name = key(texts["gate"], "name")
    print(f"     (workflow {WORKFLOW.name} at {version})")
    # v5.12.11 (ruling 1079): scope runs on every non-draft event the gate
    # runs on; the scope halves of S2, K and G1 are superseded by
    # code-review-v51211-tests.py and apply only below it.
    v51211 = version not in ("v5.12.9", "v5.12.10")
    reviewers = ("review", "review-opencode") if v51211 else ("scope", "review", "review-opencode")

    # S. The text.
    check(ids == ["supersede", "scope", "review", "review-opencode", "gate"], f"S1 the jobs are the five known ({ids})")
    for j in reviewers:
        check(block(texts[j], "if").startswith(SHARED + "\n&& "), f"S2 {j}'s if keeps v5.12.9's shared condition")
    if v51211:
        print("skip S2 scope's if keeps v5.12.9's shared condition (v5.12.11: code-review-v51211-tests.py)")
    check(block(texts["gate"], "if") == "always() && " + DRAFT, "S3 the gate's if is always() && the draft clause")
    check(block(texts["gate"], "name") == "${{ " + DRAFT + "\n&& 'Code Review (codex)' || 'Code Review (not requested)' }}",
          "S4 the gate's name is the draft clause's expression")
    check(re.search(r"\n    name: [^>\n]*Code Review \(codex\)", src) is None, "S5 no job has the literal required name")
    gate_steps = texts["gate"].split("\n    steps:\n", 1)[-1]
    # v5.12.12: the review check is a case that also fails a cancelled review.
    check(('[ "$REVIEW_RESULT" != failure ]' in gate_steps
           or ('case "$REVIEW_RESULT" in' in gate_steps and "            failure) fail" in gate_steps))
          and "failure|cancelled) fail" in gate_steps
          and '"$REVIEW_RESULT" = skipped' not in gate_steps and '"$SCOPE_RESULT" = skipped' not in gate_steps,
          "S6 the verdict step fails only on a failed review or a failed/cancelled scope, never on a skip")
    check("\n# v5.12.10 (2026-11-21" in src, "S7 the header has the v5.12.10 entry")
    sel = handoff_select(src)
    check('.name == "Code Review (codex)"' in sel, "S8 the handoff selects the gate by its required name")

    # G, K, B over every case.
    g_bad, k_bad, b_bad, n = [], [], [], 0
    for server, action, draft, labels, lab in cases():
        ctx = context(action, draft, labels, lab, server, agent="opencode" if lab == "agent:opencode" else "")
        ran = simulate(jobs, ctx)
        name = job_name(gate_name, ctx)
        n += 1
        tag = f"{server.split('//')[1]} {action} draft={draft} label={lab} labels={','.join(labels)}"
        if not draft and not (ran["gate"] and name == REQUIRED):
            g_bad.append(f"{tag}: ran={ran['gate']} name={name!r}")
        if draft and (ran["gate"] or name == REQUIRED):
            g_bad.append(f"{tag}: a draft's gate ran={ran['gate']} name={name!r}")
        if action == "labeled" and lab in UNRELATED and any(ran[j] for j in reviewers):
            k_bad.append(tag)
        if draft and any(ran.values()):
            b_bad.append(tag)
    for lab in UNRELATED:
        for server in (GH, GITEA):
            ctx = context("labeled", False, ("code-review", "task:ready", lab), lab, server)
            ran = simulate(jobs, ctx)
            check(ran["gate"] and job_name(gate_name, ctx) == REQUIRED and not ran["review"]
                  and (v51211 or not ran["scope"]),
                  f"G1 labeled {lab} on {server.split('//')[1]}: the gate alone runs, as {REQUIRED}")
    check(not g_bad, f"G every non-draft event runs the gate as {REQUIRED}, a draft never ({len(g_bad)} bad: {g_bad[:2]})")
    check(not k_bad, f"K an unrelated label runs no {'/'.join(reviewers)} ({len(k_bad)} bad: {k_bad[:2]})")
    check(not b_bad, f"B a draft runs no job on any event ({len(b_bad)} bad: {b_bad[:2]})")
    ctx = context("labeled", False, ("code-review", "task:ready", "needs-owner"), "needs-owner")
    check(simulate(jobs, ctx)["gate"] and job_name(gate_name, ctx) == REQUIRED, "H1 a hold re-runs `Code Review (codex)`")
    print(f"     ({n} cases)")

    # P. The P1 scenario.
    r1 = context("opened", False, ("code-review", "task:ready"))
    r2 = context("labeled", False, ("code-review", "task:ready", "dept:software"), "dept:software")
    ran1, ran2 = simulate(jobs, r1), simulate(jobs, r2)
    check(ran1["review"] and ran1["gate"], "P1 R1 (opened) reviews and gates")
    # R2's gate, if it runs, fails at once: R1's review of the head is in flight (v5.12.6).
    suites = {1: suite_jobs(ids, ran1, job_name(gate_name, r1), "success"),
              2: suite_jobs(ids, ran2, job_name(gate_name, r2), "failure")}
    # R1's gate passes after the approval; its handoff runs the file's selector on every newer suite.
    rerun = {s: jq(sel, suites[s]) for s in suites if s > 1}
    for s, gid in rerun.items():
        if gid:
            for jb in suites[s]["jobs"]:
                if str(jb["id"]) == gid:
                    jb["conclusion"] = "success"  # the re-run reads the approval
    newest = suites[max(suites)]["jobs"]
    ctxs = [jb for jb in newest if jb["name"] == REQUIRED]
    check(bool(rerun.get(2)), f"P2 R1's handoff selector picks R2's gate (picked {rerun.get(2)!r})")
    check(len(ctxs) == 1 and ctxs[0]["conclusion"] == "success",
          f"P3 the newest suite carries a green {REQUIRED}: the approved head may merge ({ctxs})")

    # N. The evaluator is not vacuous.
    check(evaluate("a.b == 'X' && !contains(a.l.*.n, 'y')", {"a": {"b": "x", "l": [{"n": "Y"}]}})[0] is False,
          "N1 the evaluator: case-insensitive ==, contains over .*.")

    print(f"{'ALL PASS' if not FAILS else f'{len(FAILS)} FAILED'}")
    sys.exit(1 if FAILS else 0)


main()
