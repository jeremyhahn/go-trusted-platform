"""code-review-v51215-tests.py -- the regression tests for code-review.yml
v5.12.15: an incomplete review is not a finding.

The blocks are read out of the workflow and run under bash and jq with codex
stubbed; nothing reaches the network.

  F. findings_ok (lib.sh): the shape findings.schema.json states, with
     `unread` a list of paths; the image before `unread` still passes.
  C. The review step: files codex left unread get one more pass, on those
     files only, in the time the job has left (at most the first pass's
     limit, none under 600 s); only paths of the change count; the merged
     answer keeps both passes' findings and the files still unread.
  V. The post step: P0/P1 findings request changes; no P0/P1 with files
     unread posts nothing and fails with the reason; nothing unread and no
     P0/P1 approves. No finding is read by its text.
  B. The review body names the files not read in full.
  P. The prompt never asks for a finding about an unread file.

Run: python3 -I code-review-v51215-tests.py [workflow]
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
    return once(r"\n      - name: " + re.escape(name) + r"\n(.*?)(?=\n      - (?:name|uses): |\n      # |\Z)", text, f"the step '{name}'")


def dedent(block):
    return "\n".join(l[10:] if l.startswith(" " * 10) else l.strip() for l in block.split("\n"))


def bash(script, work, env=None):
    p = subprocess.run(["bash", "-c", script, "bash", work], capture_output=True, text=True,
                       env=dict(os.environ, **(env or {})), timeout=60)
    return p.returncode, p.stdout + p.stderr


def doc(findings=(), unread=None, summary="s"):
    d = {"summary": summary, "findings": list(findings)}
    if unread is not None:
        d["unread"] = unread if isinstance(unread, str) else list(unread)
    return d


def finding(priority, title="t", file="a.go", line=1):
    return {"priority": priority, "title": title, "body": "b", "file": file, "line": line}


def main():
    src = WORKFLOW.read_text()
    review = job(src, "review")
    lib = dedent(once(r"cat > \"\$WORK/lib\.sh\" <<'LIB'\n(.*?)\n          LIB\n", review, "lib.sh"))
    fok = once(r"\n(findings_ok\(\) \{\n.*?\n\})\n", lib, "findings_ok")
    codex = step(review, "Review the head with codex as uid 1000")
    post = step(review, "Post the verdict")
    cont = dedent(once(r"\n(          unread=\$\(jq -r '\(\.unread // \[\]\)\[\]'.*?printf '%s' \"\$unread\" > \"\$WORK/unread\"\n)",
                       codex, "the continuation block"))
    verdict = dedent(once(r"\n(            findings_ok \"\$WORK/findings\.json\" \|\|\n.*?\n            fi\n)", post, "the verdict block"))
    body_prog = once(r"--arg o \"\$resume\" --arg n \"\$unread\" '\n(.*?)' \\\n\s*\"\$WORK/findings\.json\" > \"\$WORK/body\.md\"",
                     post, "the body program")

    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp)

        # ---- F ---------------------------------------------------------------
        def shape(d):
            f = work / "f.json"
            f.write_text(d if isinstance(d, str) else json.dumps(d))
            rc, _ = bash("set -euo pipefail\n" + fok + '\nfindings_ok "$1/f.json"', tmp)
            return rc == 0

        check(shape(doc([finding("P1")], [])), "F1 findings with an empty unread list pass")
        check(shape(doc([], ["a.go", "b.go"])), "F2 an incomplete review as unread paths passes")
        check(shape(doc([finding("P2")])), "F3 the image before `unread` (no key) still passes")
        check(not shape(doc([], "a.go")), "F4 unread as a string fails")
        check(not shape(doc([], [1])), "F5 unread holding a number fails")
        check(not shape(dict(doc([], []), verdict="APPROVED")), "F6 an extra top-level key fails")
        check(not shape(doc([finding("P4")], [])), "F7 priority P4 fails")
        check(not shape("The change looks good."), "F8 prose fails")
        check(codex.count('findings_ok "$dest"') == 1 and post.count('findings_ok "$WORK/findings.json"') == 1
              and src.count("findings_ok() {") == 1,
              "F9 one shape check, in lib.sh, used by both the review and the post step")

        # ---- C ---------------------------------------------------------------
        files = "a.go\nb.go\nc.go\ndocs/x.md"

        def cont_run(first, second=None, left=4000, limit=1500):
            (work / "findings.json").write_text(json.dumps(first))
            (work / "second.json").write_text(json.dumps(second if second is not None else doc([], [])))
            for f in ("calls", "unread", "prompt2.md"):
                (work / f).unlink(missing_ok=True)
            (work / "prompt.md").write_text("PROMPT\n")
            (work / "job-start").write_text(str(int(__import__("time").time()) - 4500 + left + 470))
            harness = f"""set -euo pipefail
WORK=$1; JOB_BUDGET=4500; limit={limit}; mark=m4rk
files=$'{files.replace(chr(10), "\\n")}'
die() {{ echo "DIE: $*"; exit 7; }}
codex_pass() {{ echo "$1 $2 $3" >> "$WORK/calls"; cp "$WORK/second.json" "$3"; }}
{cont}
"""
            rc, out = bash(harness, tmp)
            calls = (work / "calls").read_text().splitlines() if (work / "calls").exists() else []
            unread = (work / "unread").read_text() if (work / "unread").exists() else None
            merged = json.loads((work / "findings.json").read_text())
            return rc, out, calls, unread, merged

        rc, out, calls, unread, _ = cont_run(doc([finding("P2")], []))
        check(rc == 0 and calls == [] and unread == "", f"C1 nothing unread: no second pass, an empty list (rc={rc} {out})")
        rc, out, calls, unread, _ = cont_run(doc([finding("P2")]))
        check(rc == 0 and calls == [] and unread == "", "C2 the image before `unread`: nothing unread")
        rc, out, calls, unread, merged = cont_run(doc([finding("P2", "first")], ["a.go", "b.go"], "one"),
                                                  doc([finding("P1", "second", "b.go", 9)], [], "two"))
        check(rc == 0 and len(calls) == 1 and calls[0].split()[2].endswith("findings2.json"),
              f"C3 unread files: one more pass (rc={rc} {calls} {out})")
        p2 = (work / "prompt2.md").read_text() if (work / "prompt2.md").exists() else ""
        check("BEGIN-UNREAD-m4rk\na.go\nb.go\nEND-UNREAD-m4rk" in p2 and "c.go" not in p2.split("BEGIN-UNREAD")[1],
              "C4 the second pass is given only the unread files, fenced as data")
        check(sorted(f["title"] for f in merged["findings"]) == ["first", "second"] and merged["unread"] == []
              and unread == "" and merged["summary"] == "one\n\ntwo",
              f"C5 the merged answer keeps both passes' findings; nothing unread after it ({merged})")
        rc, out, calls, unread, merged = cont_run(doc([], ["a.go", "b.go"]), doc([], ["b.go", "c.go"]))
        check(rc == 0 and unread == "b.go" and merged["unread"] == ["b.go"],
              f"C6 still unread after the second pass: only files the first left unread count ({unread!r})")
        rc, out, calls, unread, _ = cont_run(doc([], ["/etc/passwd", "not/in/change.go"]))
        check(rc == 0 and calls == [] and unread == "", f"C7 paths outside the change are ignored ({calls} {unread!r})")
        rc, out, calls, unread, _ = cont_run(doc([], ["a.go"]), left=599)
        check(rc == 0 and calls == [] and unread == "a.go" and "No time left" in out,
              f"C8 under 600 s left: no second pass, the file stays unread ({calls} {out})")
        rc, out, calls, unread, _ = cont_run(doc([], ["a.go"]), left=4000, limit=1500)
        check(len(calls) == 1 and calls[0].split()[1] == "1500", f"C9 the second pass gets at most the first's limit ({calls})")
        rc, out, calls, unread, _ = cont_run(doc([], ["a.go"]), left=900, limit=1500)
        check(len(calls) == 1 and 880 <= int(calls[0].split()[1]) <= 900, f"C10 ... and no more than the job has left ({calls})")
        check(codex.count("codex_pass ") == 2 + codex.count("codex_pass() {") - 1 and codex.count("\n          codex_pass \"$WORK/prompt.md\"") == 1
              and codex.count("codex_pass \"$WORK/prompt2.md\"") == 1, "C11 codex runs at most twice per job")

        # ---- V ---------------------------------------------------------------
        def decide(d, unread):
            (work / "findings.json").write_text(json.dumps(d))
            (work / "error").unlink(missing_ok=True)
            if unread is None:
                (work / "unread").unlink(missing_ok=True)
            else:
                (work / "unread").write_text(unread)
            harness = f"""set -euo pipefail
WORK=$1
die() {{ echo "DIE: $*"; exit 7; }}
{fok}
{verdict}
echo "EVENT=$event"
"""
            return bash(harness, tmp)

        rc, out = decide(doc([finding("P1")], ["a.go"]), "a.go")
        check(rc == 0 and "EVENT=REQUEST_CHANGES" in out, f"V1 a real P1 with a file unread: REQUEST_CHANGES ({out})")
        rc, out = decide(doc([finding("P2")], ["a.go", "b.go"]), "a.go\nb.go")
        check(rc == 7 and "review incomplete: 2 changed files still unread" in out and "a.go b.go" in out and "EVENT=" not in out,
              f"V2 no P0/P1 with files unread: no verdict, the step fails with the reason ({out})")
        rc, out = decide(doc([finding("P2")], []), "")
        check(rc == 0 and "EVENT=APPROVED" in out, f"V3 nothing unread, no P0/P1: APPROVED ({out})")
        rc, out = decide(doc([finding("P1", "The required whole-file review remains incomplete.")], []), "")
        check(rc == 0 and "EVENT=REQUEST_CHANGES" in out,
              "V4 a P1 is decided by its priority, never by its text")
        rc, out = decide(doc([], []), None)
        check(rc == 7 and "no list of unread files" in out, f"V5 no unread list from the review step: fails ({out})")
        check(not re.search(r"incomplet|whole-file", verdict, re.I) or "review incomplete:" in verdict
              and not re.search(r"test\(\"[^\"]*incomplet", src, re.I),
              "V6 no finding is matched by its text anywhere in the workflow")

        # ---- B ---------------------------------------------------------------
        def body(n):
            p = subprocess.run(["jq", "-r", "--arg", "e", "REQUEST_CHANGES", "--arg", "s", "a" * 40, "--arg", "m", "m",
                                "--arg", "f", "high", "--arg", "u", "https://example.invalid/run", "--arg", "p", "",
                                "--arg", "x", "", "--arg", "r", "1", "--arg", "t", "", "--arg", "o", "",
                                "--arg", "n", n, body_prog], input=json.dumps(doc([finding("P1")], [])),
                               capture_output=True, text=True)
            return p.stdout

        b = body("a.go\nb.go")
        check("### Not read in full" in b and "`a.go`, `b.go`" in b, "B1 the body names the files not read in full")
        check("Not read in full" not in body(""), "B2 ... and says nothing when every file was read")

        # ---- P ---------------------------------------------------------------
        check("say so in one P1 finding" not in codex and "list it in `unread`, never as a finding" in codex,
              "P1 the large-head prompt lists unread files in `unread`, never as a finding")

    print(f"{'ALL PASS' if not FAILS else f'{len(FAILS)} FAILED'}")
    sys.exit(1 if FAILS else 0)


main()
