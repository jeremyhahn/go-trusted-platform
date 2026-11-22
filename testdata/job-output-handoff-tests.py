#!/usr/bin/env python3
"""Tests for ci-template v1.53: no registry address in a job output.

The Tenant Agent's read of the Codex P1 on go-trusted-platform #2311. v1.53's
LAN mask (ci-mask-lan.sh) registers each internal registry address as a
secret. GitHub drops a job output that contains a masked value, so a
producer job that exported `image_ref=<registry>/<repo>/it-image:<id>` gave
its consumer legs an empty reference: they failed with no verified
integration image.

The rule. Between jobs, a job passes only an unmasked identifier, such as a
tag, a digest or its hex suffix. Each consumer rebuilds the reference from
the Actions secret `CI_IMAGE_REGISTRY` (for a copy, its own `*_REGISTRY`
secret; never a `vars` value, which the step's log header prints) and masks
it in its own job: the mask step sets `CI_IMAGE_REGISTRY`, and this step runs
before any step that names the reference.

H1  The template has no job output whose value is built from a registry.
    The registry can come from a `*REGISTRY*` variable, `vars`/`env`/`secrets`, or a
    shell variable assigned from one.
H2  The check flags the go-trusted-platform #2311 shape: `image_ref` built
    from `$IT_REGISTRY` and exported through `$GITHUB_OUTPUT`. It also
    flags an output set straight from `vars.CI_IMAGE_REGISTRY`.
H3  The check passes the v1.53 shape. The producer exports `image_tag`
    only. The consumer reads the `CI_IMAGE_REGISTRY` secret in its mask step and
    rebuilds the reference after it.
H4  The handoff, simulated with the real ci-mask-lan.sh. GitHub drops an
    output that contains a mask. A reference output arrives empty. A tag
    output arrives intact, and the consumer's rebuilt reference equals the
    reference the producer pushed.
H5  In the v1.53 fixture, a consumer that rebuilds the reference runs
    ci-mask-lan.sh before that step, with `CI_IMAGE_REGISTRY` set.

  python3 -I software/templates/github-actions/testdata/job-output-handoff-tests.py [ci.yml ...]

With paths, it also checks each named workflow against H1. Use it on a
repository's copy: it exits 1 and names each job output that carries a
registry address.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATES = os.path.dirname(HERE)
# v1.53 (Codex P2 on go-trusted-platform #2311): the same file runs in the
# handbook (testdata/ beside the template) and in a carrier (testdata/ at the
# repository root), so each path is the template's, else the carrier's.
def first(*paths):
    return next((p for p in paths if os.path.exists(p)), paths[0])


CI = first(os.path.join(TEMPLATES, "ci.yml"), os.path.join(TEMPLATES, ".github", "workflows", "ci.yml"))
MASK = first(os.path.join(TEMPLATES, "ci-mask-lan.sh"), os.path.join(TEMPLATES, "scripts", "ci-mask-lan.sh"))
STEP_RUN = "scripts/ci-mask-lan.sh"

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def jobs(text):
    """{name: [lines]} for each job under `jobs:`."""
    lines = text.split("\n")
    j0 = lines.index("jobs:")
    starts = [i for i in range(j0 + 1, len(lines)) if re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[i])]
    out = {}
    for k, a in enumerate(starts):
        e = starts[k + 1] if k + 1 < len(starts) else len(lines)
        out[lines[a].strip().rstrip(":")] = lines[a:e]
    return out


def job_outputs(jl):
    """{output: expression} from a job's `outputs:` map (4-space key)."""
    out = {}
    i = next((n for n, l in enumerate(jl) if l.rstrip() == "    outputs:"), -1)
    if i < 0:
        return out
    for l in jl[i + 1:]:
        if l.strip() == "" or l.lstrip().startswith("#"):
            continue
        if not l.startswith("      "):
            break
        m = re.match(r"^      ([A-Za-z0-9_-]+):\s*(.*)$", l)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def steps(jl):
    """[step text] for each `- ` step of a job."""
    st = [n for n, l in enumerate(jl) if l.startswith("      - ")]
    return ["\n".join(jl[st[m]:(st[m + 1] if m + 1 < len(st) else len(jl))]) for m in range(len(st))]


def step_id(s):
    m = re.search(r"(?:^      - |\n        )id:\s*([A-Za-z0-9_-]+)", s)
    return m.group(1) if m else None


def env_names(block):
    """Env names in a block whose value reads a *REGISTRY* var or env."""
    return {m.group(1) for m in re.finditer(r"^\s+([A-Z0-9_]+):\s*\$\{\{[^}]*\b(?:vars|env|secrets)\.[A-Z0-9_]*REGISTRY[A-Z0-9_]*\b", block, re.M)}


REG = re.compile(r"REGISTRY")


def tainted_names(text, seed):
    """Shell names whose value carries a registry: any *REGISTRY* name, the
    seed (env from vars/env/secrets registries), and names assigned from them."""
    t = set(seed)
    def hit(expr):
        return any(REG.search(v) or v in t for v in re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", expr)) or \
            re.search(r"\b(?:vars|env|secrets)\.[A-Z0-9_]*REGISTRY", expr) is not None
    changed = True
    while changed:
        changed = False
        for m in re.finditer(r"(?:^|[\s;(])(?:local |export |readonly )?([A-Za-z_][A-Za-z0-9_]*)=(\S.*)$", text, re.M):
            n, rhs = m.group(1), m.group(2)
            if n not in t and hit(rhs):
                t.add(n)
                changed = True
    return t, hit


def findings(text):
    """[(job, output, why)] for each job output that carries a registry."""
    out = []
    for name, jl in jobs(text).items():
        outs = job_outputs(jl)
        if not outs:
            continue
        jenv = env_names("\n".join(jl[:next((n for n, l in enumerate(jl) if l.startswith("    steps:")), len(jl))]))
        by_id = {step_id(s): s for s in steps(jl) if step_id(s)}
        for o, expr in outs.items():
            if re.search(r"\b(?:vars|env|secrets)\.[A-Z0-9_]*REGISTRY", expr):
                out.append((name, o, "set from a registry variable"))
                continue
            m = re.search(r"steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)", expr)
            if not m or m.group(1) not in by_id:
                continue
            s = by_id[m.group(1)]
            t, hit = tainted_names(s, jenv | env_names(s))
            for w in re.finditer(r"(?:echo|printf)[^\n]*?\b" + re.escape(m.group(2)) + r"=([^\n]*?)(?:\"|')?\s*>>\s*\"?\$\{?GITHUB_OUTPUT", s):
                if hit(w.group(1)):
                    out.append((name, o, f"steps.{m.group(1)}.outputs.{m.group(2)} is written from a registry: {m.group(2)}={w.group(1).strip()}"))
                    break
    return out


BAD = """\
jobs:
  integration-image:
    runs-on: bigdisk
    env:
      IT_REGISTRY: ${{ vars.CI_IMAGE_REGISTRY }}
    outputs:
      image_id: ${{ steps.build.outputs.image_id }}
      image_ref: ${{ steps.push.outputs.image_ref }}
    steps:
      - name: Build
        id: build
        run: |
          echo "image_id=sha256:abc" >> "$GITHUB_OUTPUT"
      - name: Push
        id: push
        run: |
          ref="$IT_REGISTRY/go-trusted-platform/it-image:${IT_LEASE_ID#sha256:}"
          docker push "$ref"
          echo "image_ref=$ref" >> "$GITHUB_OUTPUT"
  direct:
    runs-on: bigdisk
    outputs:
      registry: ${{ vars.CI_IMAGE_REGISTRY }}
    steps:
      - run: true
"""

GOOD = """\
jobs:
  integration-image:
    runs-on: bigdisk
    outputs:
      image_tag: ${{ steps.push.outputs.image_tag }}
    steps:
      - name: Mask LAN addresses
        env:
          CI_IMAGE_REGISTRY: ${{ runner.environment != 'github-hosted' && secrets.CI_IMAGE_REGISTRY || '' }}
        run: scripts/ci-mask-lan.sh
      - name: Push
        id: push
        env:
          IT_REGISTRY: ${{ runner.environment != 'github-hosted' && secrets.CI_IMAGE_REGISTRY || '' }}
        run: |
          tag=${IT_LEASE_ID#sha256:}
          ref="$IT_REGISTRY/go-trusted-platform/it-image:$tag"
          docker push "$ref"
          echo "image_tag=$tag" >> "$GITHUB_OUTPUT"
  integration:
    runs-on: bigdisk
    needs: integration-image
    steps:
      - name: Mask LAN addresses
        env:
          CI_IMAGE_REGISTRY: ${{ runner.environment != 'github-hosted' && secrets.CI_IMAGE_REGISTRY || '' }}
        run: scripts/ci-mask-lan.sh
      - name: Pull the integration image
        env:
          IT_REGISTRY: ${{ runner.environment != 'github-hosted' && secrets.CI_IMAGE_REGISTRY || '' }}
          IT_IMAGE_TAG: ${{ needs.integration-image.outputs.image_tag }}
        run: |
          ref="$IT_REGISTRY/go-trusted-platform/it-image:$IT_IMAGE_TAG"
          docker pull "$ref"
"""


GUARD = "${{ runner.environment != 'github-hosted' && secrets.CI_IMAGE_REGISTRY || '' }}"


def mask_values(env):
    r = subprocess.run(["bash", MASK], env=dict(PATH=os.environ.get("PATH", "/usr/bin:/bin"), **env),
                       capture_output=True, text=True)
    check(r.returncode == 0, f"ci-mask-lan.sh exited {r.returncode}: {r.stderr}")
    return [l[len("::add-mask::"):] for l in r.stdout.split() if l.startswith("::add-mask::")]


def github_output(masks, value):
    """GitHub's rule: a job output that contains a masked value is dropped."""
    return "" if any(m and m in value for m in masks) else value


def handoff_cases():
    reg = "10.4.4.4:5000"
    lease = "sha256:0123456789abcdef"
    tag = lease[len("sha256:"):]
    pushed = f"{reg}/go-trusted-platform/it-image:{tag}"
    producer = mask_values({"CI_IMAGE_REGISTRY": reg, "IT_REGISTRY": reg})
    check(reg in producer, f"H4: the producer's mask does not cover the registry: {producer}")
    check(github_output(producer, pushed) == "",
          "H4: a reference output survived the mask; the simulation no longer matches GitHub")
    got = github_output(producer, tag)
    check(got == tag, f"H4: the tag output did not arrive intact: {got!r}")
    consumer = mask_values({"CI_IMAGE_REGISTRY": reg})
    check(reg in consumer, "H4: the consumer's own mask does not cover the registry it rebuilds from")
    rebuilt = f"{reg}/go-trusted-platform/it-image:{got}"
    check(rebuilt == pushed, f"H4: the consumer rebuilt {rebuilt}, the producer pushed {pushed}")


def consumer_cases(text):
    """H5: a consumer step that reads a needs.*.outputs.* id and a registry
    runs after the job's mask step, which sets CI_IMAGE_REGISTRY from the secret."""
    seen = 0
    for name, jl in jobs(text).items():
        ss = steps(jl)
        mask = next((i for i, s in enumerate(ss) if re.search(r"run:\s*" + re.escape(STEP_RUN) + r"\s*$", s, re.M)), -1)
        for i, s in enumerate(ss):
            if re.search(r"needs\.[A-Za-z0-9_-]+\.outputs\.", s) and env_names(s):
                seen += 1
                check(0 <= mask < i, f"H5: job {name} rebuilds a reference before (or without) its mask step")
                check(mask >= 0 and "CI_IMAGE_REGISTRY: " + GUARD in ss[mask], f"H5: job {name}'s mask step does not set CI_IMAGE_REGISTRY from the guarded secret")
    return seen


def main():
    for need in (CI, MASK):
        if not os.path.exists(need):
            print(f"FAIL: no {os.path.relpath(need, TEMPLATES)}: carry it from the handbook template")
            sys.exit(1)
    with open(CI) as f:
        tmpl = f.read()
    f1 = findings(tmpl)
    check(f1 == [], f"H1: the template exports a registry in a job output: {f1}")
    check(len([n for n, jl in jobs(tmpl).items() if job_outputs(jl)]) >= 1,
          "H1: the parse found no job with outputs in the template")
    bad = {(j, o) for j, o, _ in findings(BAD)}
    check(("integration-image", "image_ref") in bad, f"H2: the #2311 shape is not flagged: {bad}")
    check(("direct", "registry") in bad, f"H2: an output set from vars.CI_IMAGE_REGISTRY is not flagged: {bad}")
    check(("integration-image", "image_id") not in bad, "H2: a digest output is flagged")
    check(findings(GOOD) == [], f"H3: the v1.53 handoff is flagged: {findings(GOOD)}")
    handoff_cases()
    check(consumer_cases(GOOD) == 1, "H5: the parse did not find the fixture's consumer step")
    for p in sys.argv[1:]:
        with open(p) as f:
            for j, o, why in findings(f.read()):
                failures.append(f"{p}: job {j} output {o}: {why}")
    for m in failures:
        print("FAIL:", m)
    print(f"job-output-handoff-tests: {len(failures)} failure(s)")
    sys.exit(1 if failures else 0)


main()
