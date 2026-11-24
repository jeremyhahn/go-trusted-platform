#!/usr/bin/env python3
"""code-review-v51213-tests.py -- the regression tests for code-review.yml
v5.12.13: a pull request is reviewed once, when it is ready for merge, never
as a draft.

Each job's `if:` is read out of the workflow and evaluated by the v5.12.9
tests' expression evaluator against synthetic events; the live draft checks
are read out of the workflow and run under bash and jq against a fake PR.
Nothing reaches the network.

  J. Job conditions: a draft event starts no scope, review or opencode job,
     on every event type and on GitHub and Gitea; a ready PR labelled
     code-review and task:ready runs scope, review and the gate on
     ready_for_review, synchronize and a `labeled` code-review; the
     opencode job runs on Gitea when the route names it.
  L. Live checks: the Codex guard and the opencode guard end skip=draft after
     their closed-PR check, and the Codex and opencode posts post nothing,
     when the live PR is a draft (a queued or re-run job whose payload says
     ready); a ready PR, or one whose forge sends no draft field, goes on.
  N. Negative controls: the workflow with a check or a condition removed
     fails.

Run: python3 -I code-review-v51213-tests.py [workflow]
"""
import os
import pathlib
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
WORKFLOW = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parent / "code-review.yml"
FAILS = []
GH = "https://github.com"
GITEA = "https://gitea.example.test"
REPO = "o/r"
EVENTS = ("opened", "reopened", "synchronize", "labeled", "ready_for_review")
DRAFT_TEST = '''[ "$(jq -r '.draft // false' <<<"$pr")" != true ] || '''


def fatal(msg):
    print(f"FATAL: {msg}")
    sys.exit(9)


def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        FAILS.append(what)


def job(src, name):
    m = re.search(r"\n  " + re.escape(name) + r":\n(.*?)(?=\n  [a-z][a-z0-9-]*:\n|\Z)", src, re.S)
    return m.group(1) if m else None


def key(text, k):
    """A job-level key: a one-line value, or a `>-` block folded to one line."""
    m = re.search(r"\n    " + k + r": >-\n((?:      [^\n]*\n?)+)", "\n" + text)
    if m:
        return " ".join(line.strip() for line in m.group(1).splitlines() if line.strip())
    m = re.search(r"\n    " + k + r": ([^\n]*)", "\n" + text)
    return m.group(1).split(" #")[0].strip() if m else None


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


# --- J. Job conditions ----------------------------------------------------

def context(action, draft, labels, label=None, server=GH, agent=""):
    pr = {"number": 7, "state": "open", "draft": draft, "labels": [{"name": n} for n in labels],
          "head": {"repo": {"full_name": REPO}, "sha": "a" * 40}, "base": {"ref": "main"}}
    event = {"action": action, "pull_request": pr}
    if label is not None:
        event["label"] = {"name": label}
    return {"github": {"server_url": server, "repository": REPO, "event": event},
            "needs": {"scope": {"outputs": {"skip": "false", "code": "true", "row": "true"}}, "review": {"outputs": {"agent": agent}}}}


def jobs_of(src):
    body = src.split("\njobs:\n", 1)[1]
    out = []
    for j in re.findall(r"\n  ([a-z][a-z0-9-]*):\n", "\n" + body):
        text = job(src, j)
        needs = key(text, "needs") or ""
        out.append((j, key(text, "if"), [n.strip() for n in needs.strip("[]").split(",") if n.strip()]))
    return out


def simulate(jobs, ctx):
    ran = {}
    for jid, cond, needs in jobs:
        ok_needs = all(ran.get(n, False) for n in needs)
        if cond is None:
            ran[jid] = ok_needs
            continue
        v, used = evaluate(cond, ctx, status=ok_needs)
        ran[jid] = truthy(v) and (used or ok_needs)
    return ran


def top_conjuncts(cond):
    out, depth, quoted, start, i = [], 0, False, 0, 0
    while i < len(cond):
        c = cond[i]
        if c == "'":
            quoted = not quoted
        elif not quoted and c == "(":
            depth += 1
        elif not quoted and c == ")":
            depth -= 1
        elif not quoted and depth == 0 and cond.startswith("&&", i):
            out.append(cond[start:i].strip())
            start = i + 2
            i += 1
        i += 1
    return out + [cond[start:].strip()]


def job_problems(src):
    jobs = jobs_of(src)
    bad = []
    # Each review job skips a draft on its own, whatever the jobs it needs do.
    for j, cond, _ in jobs:
        if j in ("scope", "review", "review-opencode") and \
                "github.event.pull_request.draft != true" not in top_conjuncts(cond or ""):
            bad.append(f"{j}'s if has no top-level draft clause")
    for server in (GH, GITEA):
        for action in EVENTS:
            label = "code-review" if action == "labeled" else None
            ran = simulate(jobs, context(action, True, ("code-review", "task:ready"), label, server, "opencode"))
            for j in ("scope", "review", "review-opencode"):
                if ran.get(j):
                    bad.append(f"a draft's {action} on {server} runs {j}")
    for action, label in (("ready_for_review", None), ("synchronize", None), ("labeled", "code-review")):
        ran = simulate(jobs, context(action, False, ("code-review", "task:ready"), label))
        for j in ("scope", "review", "gate"):
            if not ran.get(j):
                bad.append(f"a ready PR's {action} does not run {j}")
    ran = simulate(jobs, context("labeled", False, ("code-review", "task:ready", "agent:opencode"),
                                 "agent:opencode", GITEA, "opencode"))
    if not ran.get("review-opencode"):
        bad.append("a ready PR's labeled agent:opencode on Gitea does not run review-opencode")
    return bad


# --- L. Live checks -------------------------------------------------------

# (job, the live check before it, the line after it, what a draft must print)
SITES = (
    ("review", '            echo "skip=closed" >> "$GITHUB_OUTPUT"\n            exit 0\n          fi\n',
     'if [ "$head" != "$EVENT_SHA" ]', "skip=draft"),
    ("review", 'during the review; not posting."\n            exit 0\n          fi\n',
     'if [ "$(jq -r \'.base.ref // empty\' <<<"$pr")" != "$BASE_REF" ]', None),
    ("review-opencode", 'echo "skip=closed" >> "$GITHUB_OUTPUT"; exit 0\n          fi\n',
     'if [ "$head" != "$EVENT_SHA" ]', "skip=draft"),
    ("review-opencode", 'posting nothing."; touch "$WORK/verdict"; exit 0\n          fi\n',
     'jq -n --rawfile b "$WORK/body.md"', None),
)


def draft_line(text, before, after):
    """The live draft check between `before` and `after` in text, or None."""
    i = text.find(before)
    if i < 0:
        return None
    rest = text[i + len(before):]
    j = rest.find(after)
    if j < 0:
        return None
    lines = [l.strip() for l in rest[:j].splitlines() if l.strip() and not l.strip().startswith("#")]
    return lines[0] if len(lines) == 1 and lines[0].startswith(DRAFT_TEST) else None


def run_line(line, pr):
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "out")
        open(out, "w").close()
        script = f"set -euo pipefail\nPR_NUM=7\nGITHUB_OUTPUT={out}\nWORK={d}\npr=$(cat {d}/pr)\n{line}\necho CONTINUED\n"
        with open(os.path.join(d, "pr"), "w") as f:
            f.write(pr)
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
        return r.returncode, r.stdout, open(out).read()


def live_problems(src):
    bad = []
    for n, (j, before, after, output) in enumerate(SITES, 1):
        text = job(src, j)
        line = draft_line(text or "", before, after)
        if line is None:
            bad.append(f"L{n} {j}: no live draft check right after its live closed-PR check")
            continue
        rc, out, gh_out = run_line(line, '{"state":"open","draft":true}')
        if rc != 0 or "CONTINUED" in out or (output and output not in gh_out):
            bad.append(f"L{n} {j}: a live draft goes on (rc={rc}, output={gh_out.strip()!r})")
        for pr in ('{"state":"open","draft":false}', '{"state":"open"}'):
            rc, out, _ = run_line(line, pr)
            if rc != 0 or "CONTINUED" not in out:
                bad.append(f"L{n} {j}: {pr} is stopped (rc={rc})")
    return bad


def main():
    if not WORKFLOW.is_file():
        fatal(f"no workflow at {WORKFLOW}")
    src = WORKFLOW.read_text()
    for j in ("scope", "review", "review-opencode", "gate"):
        if job(src, j) is None:
            fatal(f"no job {j} in {WORKFLOW}")

    bad = job_problems(src)
    check(not bad, f"J a draft starts no review job; a ready PR runs scope, review and the gate ({bad[:3]})")
    bad = live_problems(src)
    check(not bad, f"L the live draft checks stop a draft and pass a ready PR ({bad[:3]})")

    # N. Negative controls.
    clause = "github.event.pull_request.draft != true\n      && "
    for j in ("scope", "review", "review-opencode"):
        text = job(src, j)
        mutated = src.replace(text, text.replace(clause, "", 1), 1)
        check(mutated != src and job_problems(mutated), f"N1 {j} without its draft clause fails J")
    for n, (j, before, after, _) in enumerate(SITES, 1):
        text = job(src, j)
        line = draft_line(text, before, after)
        if line is None:
            continue
        mutated = src.replace(text, re.sub(r"\n[^\n]*" + re.escape(line), "", text, count=1), 1)
        check(mutated != src and live_problems(mutated), f"N2 L{n} removed fails L")

    print(f"{'ALL PASS' if not FAILS else f'{len(FAILS)} FAILED'}")
    sys.exit(1 if FAILS else 0)


main()
