"""code-review-v51214-tests.py -- the regression tests for code-review.yml
v5.12.14: only code changes are code reviewed, and only on a SPEC row PR.

The steps are read out of the workflow and run under bash and jq against a
fake forge (a `curl` on PATH that answers from canned bodies); the job
conditions are evaluated by the v5.12.9 suite's evaluator. Nothing reaches
the network.

  P. NON_CODE_PATHS: documentation and configuration are non-code; Go, C,
     Kotlin, TypeScript, Python, shell, Makefile, Dockerfile, proto, go.mod
     and go.sum are code, wherever they sit.
  S. The scope job's code step: every page is read; one code file makes
     code=true; no file, an API error or a non-list fails closed (code=true
     or a failed step); row=true on a row/<n>- branch or the main-fix label.
  J. Job conditions: a non-code PR runs the review job without labels; a
     code PR runs it only with code-review and task:ready on a row PR.
  T. TRUSTED_PR: a non-code PR skips review only when its head is in this
     repository and its author is trusted (owner, *-agent[bot]); a fork, an
     outside author or dependabot takes the normal review path.
  R. The guard: a trusted non-code PR ends requested=true nocode=true before
     the label checks; a code PR, an untrusted one or an unknown answer goes on.
  B. The post step: a non-code PR is approved with "No code changed; code
     review not required.", through the same live checks and post; Codex's
     steps do not run.
  G. The gate: a non-code change passes; a code change on a non-row PR fails
     and says why; a row PR needs the reviewer's approval as before.

Run: python3 -I code-review-v51214-tests.py [workflow]
"""
import json
import os
import pathlib
import re
import shlex
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
GH = "https://github.com"
REPO = "o/r"
NO_CODE_BODY = "No code changed; code review not required."


def fatal(msg):
    print(f"FATAL: {msg}")
    sys.exit(9)


def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        FAILS.append(what)


def once(pattern, text, what):
    found = re.findall(pattern, text, re.S)
    if len(found) != 1:
        fatal(f"{what}: found {len(found)} times, want 1")
    return found[0]


def job(src, name):
    return once(r"\n  " + re.escape(name) + r":\n(.*?)(?=\n  [a-z][a-z0-9-]*:\n|\Z)", src, f"the job '{name}'")


def step(text, name):
    return once(r"\n      - name: " + re.escape(name) + r"\n(.*?)(?=\n      - (?:name|uses): |\Z)", text, f"the step '{name}'")


def run_script(text):
    body = once(r"\n        run: \|\n(.*)", "\n" + text, "a run block")
    lines = []
    for line in body.split("\n"):
        if line.strip() and not line.startswith("          "):
            break
        lines.append(line[10:])
    return "\n".join(lines) + "\n"


def key(text, k):
    m = re.search(r"\n    " + k + r": >-\n((?:      [^\n]*\n?)+)", "\n" + text)
    if m:
        return " ".join(line.strip() for line in m.group(1).splitlines() if line.strip())
    m = re.search(r"\n    " + k + r": ([^\n]*)", "\n" + text)
    return m.group(1).split(" #")[0].strip() if m else None


def env_value(src, name):
    return once(r"\n  " + name + r": '([^']*)'\n", src, f"the workflow env {name}")


FAKE_CURL = r'''#!/usr/bin/env python3
import fnmatch, json, os, sys
args = sys.argv[1:]
out = fmt = url = None
i = 0
while i < len(args):
    a = args[i]
    if a in ("-o", "-w", "-X", "-H", "--proto", "--max-time", "--retry", "--data-binary"):
        if a == "-o": out = args[i + 1]
        elif a == "-w": fmt = args[i + 1]
        i += 2
        continue
    if not a.startswith("-"):
        url = a
    i += 1
base = os.environ["FAKE_BASE"]
path = url[len(base):] if url.startswith(base) else url
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(path + "\n")
code, body = 404, '{"message":"no route"}'
for glob, c, b in json.loads(os.environ["FAKE_ROUTES"]):
    if fnmatch.fnmatchcase(path, glob):
        code, body = c, b
        break
if out:
    open(out, "w").write(body)
else:
    sys.stdout.write(body)
if fmt:
    sys.stdout.write(str(code))
'''


def run_fake(script, routes, env_extra):
    with tempfile.TemporaryDirectory() as d:
        tmp = pathlib.Path(d)
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "curl").write_text(FAKE_CURL)
        (bin_dir / "curl").chmod(0o755)
        log = tmp / "requests.log"
        log.write_text("")
        outf = tmp / "out"
        outf.write_text("")
        env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp), "FAKE_LOG": str(log),
               "FAKE_ROUTES": json.dumps(routes), "FAKE_BASE": API, "FORGE": "github",
               "REPO_API": API, "PR_NUM": "7", "GITHUB_OUTPUT": str(outf), "GH_API_TOKEN": "fake"}
        env.update(env_extra)
        r = subprocess.run(["bash", "-c", script], cwd=tmp, env=env, capture_output=True, text=True, timeout=60)
        outputs = dict(l.split("=", 1) for l in outf.read_text().splitlines() if "=" in l)
        return r.returncode, r.stdout + r.stderr, log.read_text().splitlines(), outputs


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


# --- The cases --------------------------------------------------------------

CODE = ("main.go", "pkg/x/y.go", "src/a.c", "inc/a.h", "app/src/main/kotlin/A.kt", "web/a.ts", "tools/a.py",
        "scripts/a.sh", "Makefile", "build/docker/Dockerfile", "api/a.proto", "go.mod", "go.sum",
        ".github/scripts/runner_labels.py", ".github/workflows/testdata/x-tests.py", "mk/host.mk", ".envrc")
NON_CODE = ("README.md", "docs/a/b.png", "docs/x.txt", ".changelog/123.txt", "CHANGELOG.md", "CHANGELOG",
            "LICENSE", "LICENSE-APACHE", "ROADMAP.md", ".github/workflows/ci.yml", ".github/dependabot.yml",
            ".github/ISSUE_TEMPLATE/bug.md", ".github/CODEOWNERS", ".github/PULL_REQUEST_TEMPLATE.md",
            "deploy/values.yaml", "config.toml", "x/y.json", ".env.example", ".gitignore", "sub/.gitignore",
            ".editorconfig", ".gitattributes", ".dockerignore", "pkg/changelog.d/1.md", ".github/actionlint.yaml")


def files_page(names):
    return json.dumps([{"filename": n} for n in names])


TRUSTED = "o-agent[bot]"


def live_pr(labels=(), author=TRUSTED, fork=False):
    head = "x/r" if fork else REPO
    return {"head": {"sha": HEAD, "repo": {"full_name": head}}, "base": {"ref": "main", "repo": {"full_name": REPO}},
            "user": {"login": author}, "labels": [{"name": l} for l in labels]}


def scope_routes(pages, labels=(), files_code=200, pr_code=200, author=TRUSTED, fork=False):
    routes = []
    for n, names in enumerate(pages, 1):
        routes.append([f"/pulls/7/files?*&page={n}", files_code, files_page(names)])
    routes.append(["/pulls/7/files?*", files_code, "[]"])
    routes.append(["/pulls/7", pr_code, json.dumps(live_pr(labels, author, fork))])
    return routes


def context(action, labels, code, row, label=None, draft=False, trusted="true"):
    pr = {"number": 7, "state": "open", "draft": draft, "labels": [{"name": n} for n in labels],
          "head": {"repo": {"full_name": REPO}, "sha": HEAD}, "base": {"ref": "main"}}
    event = {"action": action, "pull_request": pr}
    if label is not None:
        event["label"] = {"name": label}
    return {"github": {"server_url": GH, "repository": REPO, "event": event},
            "needs": {"scope": {"outputs": {"skip": "false", "code": code, "row": row, "trusted": trusted}},
                      "review": {"outputs": {"agent": ""}}}}


def review_runs(src, ctx):
    cond = key(job(src, "review"), "if")
    v, _ = evaluate(cond, ctx)
    return truthy(v)


def gate_routes(names, labels, verdict, author=TRUSTED, fork=False):
    reviews = [] if verdict is None else [
        {"id": 1, "state": verdict, "commit_id": HEAD, "user": {"login": REVIEWER}, "submitted_at": "2026-11-20T00:00:00Z"}]
    return [
        [f"/compare/{BASE}...{HEAD}", 200, json.dumps({"files": [{"filename": n} for n in names]})],
        ["/actions/runs/77", 200, json.dumps({"workflow_id": 5})],
        ["/actions/workflows/5/runs?*", 200, json.dumps({"workflow_runs": []})],
        ["/pulls/7/reviews?*page=1", 200, json.dumps(reviews)],
        ["/pulls/7/reviews?*", 200, "[]"],
        ["/pulls/7", 200, json.dumps(live_pr(labels, author, fork))],
    ]


def main():
    for tool in ("jq", "bash", "grep"):
        if shutil.which(tool) is None:
            fatal(f"{tool} is not on PATH")
    src = WORKFLOW.read_text()
    non_code = env_value(src, "NON_CODE_PATHS")
    row_branch = env_value(src, "ROW_BRANCH")
    base_env = {"NON_CODE_PATHS": non_code, "ROW_BRANCH": row_branch,
                "TRUSTED_AUTHORS": env_value(src, "TRUSTED_AUTHORS"), "TRUSTED_PR": env_value(src, "TRUSTED_PR")}

    # P
    rx = re.compile(non_code)
    bad = [p for p in CODE if rx.search(p)] + [p for p in NON_CODE if not rx.search(p)]
    check(not bad, f"P NON_CODE_PATHS classifies code and non-code ({bad})")
    check(src.count("NON_CODE_PATHS: '") == 1, "P1 the list is in one place")

    # S
    scope = run_script(step(job(src, "scope"), "Does the change touch code, and is it a SPEC row PR?"))
    env = dict(base_env, HEAD_REF="feature/x")
    rc, out, reqs, o = run_fake(scope, scope_routes([["docs/a.md"] * 100, ["README.md"]]), env)
    check(rc == 0 and o.get("code") == "false" and o.get("row") == "false" and any("page=2" in r for r in reqs),
          f"S1 two pages of documentation: code=false row=false, page 2 read (rc={rc}, {o})")
    rc, out, reqs, o = run_fake(scope, scope_routes([["docs/a.md"] * 100, ["docs/b.md", "main.go"]]), env)
    check(rc == 0 and o.get("code") == "true", f"S2 a code file on page 2: code=true (rc={rc}, {o})")
    rc, out, reqs, o = run_fake(scope, scope_routes([["docs/a.md"]]), dict(env, NON_CODE_PATHS=""))
    check(rc != 0 and "code" not in o, f"S0 an empty NON_CODE_PATHS fails the step (rc={rc})")
    rc, out, reqs, o = run_fake(scope, scope_routes([]), env)
    check(rc == 0 and o.get("code") == "true", f"S3 no file listed: code=true (rc={rc}, {o})")
    rc, out, reqs, o = run_fake(scope, scope_routes([["main.go"]], files_code=500), env)
    check(rc != 0 and "code" not in o, f"S4 the file list answers 500: the step fails (rc={rc}, {o})")
    rc, out, reqs, o = run_fake(scope, [["/pulls/7/files?*", 200, '{"message":"x"}'], ["/pulls/7", 200, "{}"]], env)
    check(rc != 0 and "code" not in o, f"S5 the file list is no list: the step fails (rc={rc})")
    rc, out, reqs, o = run_fake(scope, scope_routes([["main.go"]], pr_code=502), env)
    check(rc != 0 and "row" not in o, f"S6 the PR read answers 502: the step fails (rc={rc})")
    for ref, labels, want in (("row/12-thing", (), "true"), ("feature/x", ("main-fix",), "true"),
                              ("feature/x", ("code-review", "task:ready"), "false"), ("rows/12-x", (), "false"),
                              ("ci/row/12-x", (), "false"), ("row/x-12", (), "false")):
        rc, out, reqs, o = run_fake(scope, scope_routes([["main.go"]], labels), dict(base_env, HEAD_REF=ref))
        check(rc == 0 and o.get("row") == want, f"S7 branch {ref} labels {list(labels)}: row={want} (got {o.get('row')})")

    for author, fork, want, what in ((TRUSTED, False, "true", "a factory App, same repository"),
                                     ("jeremyhahn", False, "true", "the owner, same repository"),
                                     (TRUSTED, True, "false", "a fork head"),
                                     ("outsider", False, "false", "an outside author"),
                                     ("dependabot[bot]", False, "false", "dependabot"),
                                     ("evil-agent[bot]x", False, "false", "a look-alike login")):
        rc, out, reqs, o = run_fake(scope, scope_routes([["docs/a.md"]], author=author, fork=fork), env)
        check(rc == 0 and o.get("trusted") == want and o.get("code") == "false", f"S8 {what}: trusted={want} (got {o})")
    rc, out, reqs, o = run_fake(scope, scope_routes([["docs/a.md"]]), dict(env, TRUSTED_AUTHORS=""))
    check(rc == 0 and o.get("trusted") == "false", f"S9 an empty TRUSTED_AUTHORS trusts nobody (got {o})")

    # J
    ready = ("code-review", "task:ready")
    check(review_runs(src, context("opened", (), "false", "false")), "J1 a non-code PR runs the review job without labels")
    check(not review_runs(src, context("opened", (), "false", "false", draft=True)), "J2 a non-code draft does not")
    check(not review_runs(src, context("opened", ready, "true", "false")), "J3 a code PR off a row branch does not")
    check(review_runs(src, context("synchronize", ready, "true", "true")), "J4 a labelled code row PR does")
    check(not review_runs(src, context("synchronize", (), "true", "true")), "J5 an unlabelled code row PR does not")
    check(not review_runs(src, context("opened", ready, "", "")), "J6 no scope answer: no review job")
    check(not review_runs(src, context("labeled", (), "false", "false", label="dept:software")),
          "J7 an unrelated label on a non-code PR runs no review job")
    check(not review_runs(src, context("opened", (), "false", "false", trusted="false")),
          "J8 an untrusted non-code PR without labels runs no review job")
    check(review_runs(src, context("labeled", ready, "false", "false", label="code-review", trusted="false")),
          "J9 an untrusted non-code PR with code-review and task:ready is reviewed, row or not")

    # R
    review = job(src, "review")
    guard = run_script(step(review, "Check the container, the request, the head and any standing verdict"))
    m = re.search(r"(# No code changed[^\n]*\nif \[ \"\$CODE\" = false \] && [^\n]*; then\n.*?\nfi\n)", guard, re.S)
    block = m.group(1) if m else ""
    lab = guard.find("labels=$(jq -c '[.labels[]?.name]' <<<\"$pr\")")
    nc = guard.find("if [ \"$CODE\" = false ] && ")
    ret = guard.find("skip=retargeted")
    check(block and 0 < ret < nc < lab, "R1 the guard's no-code branch sits after the live PR checks, before the label checks")
    snippet = block
    for code, author, fork, nocode in (("false", TRUSTED, False, True), ("true", TRUSTED, False, False), ("", TRUSTED, False, False),
                                       ("false", TRUSTED, True, False), ("false", "outsider", False, False)):
        want = {"requested": "true", "nocode": "true"} if nocode else {}
        pre = "set -euo pipefail\npr=" + shlex.quote(json.dumps(live_pr((), author, fork))) + "\n"
        rc, out, _, o = run_fake(pre + snippet + "echo WENT_ON\n", [], dict(base_env, CODE=code))
        went = "WENT_ON" in out
        check(rc == 0 and o == want and went == (not nocode), f"R2 CODE={code!r} author {author} fork={fork}: no-code approval={nocode} (got {o}, {went})")
    env_ok = "          CODE: ${{ needs.scope.outputs.code }}\n" in review
    check(env_ok, "R3 the guard reads the scope job's code output")

    # B
    post = step(review, "Post the verdict")
    check("          NOCODE: ${{ steps.guard.outputs.nocode }}\n" in post, "B1 the post step reads nocode")
    check(f'echo "{NO_CODE_BODY}" > "$WORK/body.md"' in post and "event=APPROVED" in post.split("else", 1)[0],
          "B2 a non-code PR is approved with the no-code body")
    pos = post.find('if [ "$NOCODE" = true ]; then')
    live = post.find('pr=$(api GET "/pulls/$PR_NUM")')
    send = post.find('posted=$(api POST "/pulls/$PR_NUM/reviews"')
    check(0 < pos < live < send, "B3 the approval passes the post step's live PR checks before it is posted")
    gated = [n for n in ("Fetch the first-party modules the change requires", "Review the head with codex as uid 1000")
             if "steps.guard.outputs.nocode != 'true'" not in step(review, n)]
    check(not gated, f"B4 Codex's steps do not run on a non-code PR ({gated})")

    # G
    gate = run_script(step(job(src, "gate"), "Require a Codex approval of the head, or a no-review change"))
    genv = dict(base_env, REVIEWER=REVIEWER, EVENT_SHA=HEAD, BASE_SHA=BASE, BASE_REF="main", GITHUB_RUN_ID="77",
                SCOPE_RESULT="success", REVIEW_RESULT="skipped")
    for names in (["docs/a.md", ".github/workflows/ci.yml", "go.yaml"], ["LICENSE"]):
        rc, out, _, _ = run_fake(gate, gate_routes(names, (), None), dict(genv, HEAD_REF="feature/x"))
        check(rc == 0 and "no code changed" in out, f"G1 non-code {names}: the gate passes without a review (rc={rc})")
    rc, out, _, _ = run_fake(gate, gate_routes(["main.go"], ("code-review", "task:ready"), "APPROVED"), dict(genv, HEAD_REF="feature/x"))
    check(rc == 3 and "not a SPEC row PR" in out, f"G2 code off a row branch: the gate fails and says why (rc={rc})")
    rc, out, _, _ = run_fake(gate, gate_routes(["main.go"], ("main-fix",), "APPROVED"), dict(genv, HEAD_REF="feature/x"))
    past = lambda out: "at least one is code" in out and "not a SPEC row PR" not in out
    check(past(out), f"G3 code under main-fix: past the row check to the verdict (rc={rc})")
    rc, out, _, _ = run_fake(gate, gate_routes(["main.go", "README.md"], (), "APPROVED"), dict(genv, HEAD_REF="row/12-x"))
    check(past(out), f"G4 code on a row branch: past the row check to the verdict (rc={rc})")
    rc, out, _, _ = run_fake(gate, gate_routes(["main.go"], (), None), dict(genv, HEAD_REF="row/12-x"))
    check(rc == 3 and past(out), f"G5 code on a row branch, no approval: fails at the verdict (rc={rc})")
    rc, out, _, _ = run_fake(gate, gate_routes(["docs/a.md"], (), None), dict(genv, HEAD_REF="row/12-x", NON_CODE_PATHS=""))
    check(rc == 3, f"G7 an empty NON_CODE_PATHS fails the gate (rc={rc})")
    for author, fork, what in ((TRUSTED, True, "a fork head"), ("outsider", False, "an outside author")):
        rc, out, _, _ = run_fake(gate, gate_routes(["docs/a.md"], (), None, author, fork), dict(genv, HEAD_REF="feature/x"))
        check(rc == 3 and "fork or an untrusted author" in out and "no code changed, so" not in out,
              f"G8 non-code from {what}, no approval: not exempt, the gate fails (rc={rc})")
        rc, out, _, _ = run_fake(gate, gate_routes(["docs/a.md"], (), "APPROVED", author, fork), dict(genv, HEAD_REF="feature/x"))
        check("fork or an untrusted author" in out and "not a SPEC row PR" not in out,
              f"G9 non-code from {what}: the normal review path, no row rule (rc={rc})")
    rc, out, _, _ = run_fake(gate, gate_routes(["docs/a.md"], (), None, "jeremyhahn"), dict(genv, HEAD_REF="feature/x"))
    check(rc == 0 and "no code changed" in out, f"G10 non-code from the owner, same repository: passes (rc={rc})")
    rc, out, _, _ = run_fake(gate, gate_routes(["docs/a.md"], (), None), dict(genv, HEAD_REF="feature/x", TRUSTED_PR=""))
    check(rc == 3, f"G11 an empty TRUSTED_PR trusts nobody (rc={rc})")
    rc, out, _, _ = run_fake(gate, [["/compare/*", 500, "{}"]], dict(genv, HEAD_REF="row/12-x"))
    check(rc == 3, f"G6 the change cannot be read: fails closed (rc={rc})")

    print(f"{'ALL PASS' if not FAILS else f'{len(FAILS)} FAILED'}")
    sys.exit(1 if FAILS else 0)


main()
