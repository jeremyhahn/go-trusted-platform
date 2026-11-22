#!/usr/bin/env python3
"""Tests for ci-template v1.44 (Tenant Agent ruling 887): the LAN mask.

Internal addresses stay out of public repositories, and their CI logs count.
A pool runner's environment names LAN addresses (the DEVCACHE_* package
caches, GOPROXY's module proxy, the LAN CI registry); a BuildKit build echoes
its build arguments and `go env` prints GOPROXY. ci-mask-lan.sh prints
::add-mask:: for each private-address entry, and every template job that
builds runs it right after the credential mask, before its first build step,
so a job a repository routes to a pool is masked from its first build on.

  python3 -I software/templates/github-actions/testdata/ci-mask-lan-tests.py
"""
import os
import tempfile
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


SCRIPT = first(os.path.join(TEMPLATES, "ci-mask-lan.sh"), os.path.join(TEMPLATES, "scripts", "ci-mask-lan.sh"))
CI = first(os.path.join(TEMPLATES, "ci.yml"), os.path.join(TEMPLATES, ".github", "workflows", "ci.yml"))
STEP_RUN = "scripts/ci-mask-lan.sh"
BUILD = re.compile(r"(^|[\s;&|(`])(make|docker|go|scripts/in-toolchain-image\.sh|scripts/ci-image\.sh|scripts/ci-image-cache\.sh)(\s|$)")

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def script_cases():
    if not os.path.exists(SCRIPT):
        failures.append("no ci-mask-lan.sh beside the template or at scripts/ci-mask-lan.sh: carry it from the handbook template")
        return
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "DEVCACHE_APT_PROXY": "http://192.168.77.7:3142",
        "DEVCACHE_APK_MIRROR": "http://192.168.77.7:3143/alpine",
        "GOPROXY": "http://10.200.0.17:3300|https://proxy.golang.org,direct",
        "CI_REGISTRY": "172.20.0.5:5005",
        # the forge's release registry and its own host, which image
        # publishing and resolving name (Codex P1 on go-xkms #2273)
        "RELEASE_REGISTRY": "172.21.0.9:5443",
        "GITHUB_SERVER_URL": "http://10.9.8.7:8443",
        "OTHER": "http://192.168.9.9:1",
    }
    out = subprocess.run(["bash", SCRIPT], env=env, capture_output=True, text=True)
    check(out.returncode == 0, f"ci-mask-lan.sh exited {out.returncode}: {out.stderr}")
    lines = out.stdout.split()
    for want in ["::add-mask::http://192.168.77.7:3142", "::add-mask::192.168.77.7:3142", "::add-mask::192.168.77.7",
                 "::add-mask::http://192.168.77.7:3143/alpine", "::add-mask::192.168.77.7:3143",
                 "::add-mask::http://10.200.0.17:3300", "::add-mask::10.200.0.17",
                 "::add-mask::172.20.0.5:5005", "::add-mask::172.20.0.5",
                 "::add-mask::172.21.0.9:5443", "::add-mask::172.21.0.9",
                 "::add-mask::http://10.9.8.7:8443", "::add-mask::10.9.8.7:8443", "::add-mask::10.9.8.7"]:
        check(want in lines, f"the script does not print {want}")
    for l in lines:
        check("proxy.golang.org" not in l and "direct" not in l and "192.168.9.9" not in l,
              f"the script masks {l}: a public host, a keyword or a variable outside the list")
    # v1.53: internal host names are masked as well as private addresses.
    names = dict(PATH=env["PATH"], DEVCACHE_APT_PROXY="http://build-node-2:3142",
                 GOPROXY="http://mirror.example.corp:3000|https://proxy.golang.org,direct,off",
                 CI_REGISTRY="registry.lan:5005", RELEASE_REGISTRY="ghcr.io",
                 GITHUB_SERVER_URL="https://github.com")
    out = subprocess.run(["bash", SCRIPT], env=names, capture_output=True, text=True)
    got = out.stdout.split()
    for want in ["::add-mask::http://build-node-2:3142", "::add-mask::build-node-2:3142", "::add-mask::build-node-2",
                 "::add-mask::mirror.example.corp:3000", "::add-mask::mirror.example.corp",
                 "::add-mask::registry.lan:5005", "::add-mask::registry.lan"]:
        check(want in got, f"the script does not mask the internal host name: {want}")
    for l in got:
        check(not any(k in l for k in ("proxy.golang.org", "direct", "::add-mask::off", "ghcr.io", "github.com")),
              f"the script masks {l}: a public host or a keyword")
    # v1.53 (Tenant Agent on go-quicbaas #2667): every *_REGISTRY variable,
    # a secret's copy in the mask step's env included.
    regs = dict(PATH=env["PATH"], LAN_REGISTRY="registry.lan:5005", IT_REGISTRY="10.4.4.4:5000",
                CI_IMAGE_REGISTRY="build-node-3:5000", CI_REGISTRY_OWNER="someowner", CI_IMAGE_NAMESPACE="ghcr.io/someowner")
    got = subprocess.run(["bash", SCRIPT], env=regs, capture_output=True, text=True).stdout.split()
    for want in ["::add-mask::registry.lan:5005", "::add-mask::registry.lan", "::add-mask::10.4.4.4:5000",
                 "::add-mask::10.4.4.4", "::add-mask::build-node-3:5000", "::add-mask::build-node-3"]:
        check(want in got, f"the script does not mask a _REGISTRY variable: {want}")
    check(not any("someowner" in l for l in got), f"the script masks a non-host variable: {got}")
    empty = subprocess.run(["bash", SCRIPT], env={"PATH": env["PATH"]}, capture_output=True, text=True)
    check(empty.returncode == 0 and empty.stdout == "", "on a hosted runner (no pool variables) the script prints nothing")
    public = subprocess.run(["bash", SCRIPT], env={"PATH": env["PATH"], "GITHUB_SERVER_URL": "https://github.com"}, capture_output=True, text=True)
    check(public.returncode == 0 and public.stdout == "", f"on github.com the script masks {public.stdout!r}: want nothing")


def jobs(text):
    """(name, [step blocks]) for each job of the template's ci.yml."""
    lines = text.split("\n")
    j0 = lines.index("jobs:")
    starts = [i for i in range(j0 + 1, len(lines)) if re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[i])]
    out = []
    for k, a in enumerate(starts):
        e = starts[k + 1] if k + 1 < len(starts) else len(lines)
        st = [i for i in range(a, e) if lines[i].startswith("      - ")]
        blocks = ["\n".join(lines[st[m]:(st[m + 1] if m + 1 < len(st) else e)]) for m in range(len(st))]
        out.append((lines[a].strip().rstrip(":"), blocks))
    return out


def run_of(block):
    m = re.search(r"\n\s+run: \|\n((?:\s{10,}.*\n?)*)", block + "\n")
    if m:
        return m.group(1)
    m = re.search(r"(?:^|\n)\s+(?:- )?run: (.+)", block)
    return m.group(1) if m else ""


def template_cases(text):
    building = 0
    for name, blocks in jobs(text):
        runs = [run_of(b) for b in blocks]
        build = next((i for i, r in enumerate(runs) if BUILD.search(r)), -1)
        if build < 0:
            continue
        building += 1
        mask = next((i for i, r in enumerate(runs) if r.strip() == STEP_RUN), -1)
        check(mask >= 0, f"job {name} builds and never runs {STEP_RUN}")
        check(mask < 0 or mask < build, f"job {name} runs a build step before {STEP_RUN}")
    check(building >= 4, f"found {building} jobs that build; the parse found too little")


VARS_REG = re.compile(r"\bvars\.([A-Z0-9_]*REGISTRY)\b")
SECRET_REG = re.compile(r"\bsecrets\.([A-Z0-9_]*REGISTRY)\b")
GUARD = "runner.environment != 'github-hosted' && secrets."
REG_HOST = "registry.lan"
REG = REG_HOST + ":5005"


def code(text):
    """The workflow without its comment lines."""
    return "\n".join(l for l in text.split("\n") if not l.lstrip().startswith("#"))


def env_of(block, indent):
    """{NAME: raw value} of the env: map at `indent` spaces in a block."""
    lines = block.split("\n")
    out = {}
    for k, l in enumerate(lines):
        if l == " " * indent + "env:":
            for m in lines[k + 1:]:
                if m.strip() == "" or m.lstrip().startswith("#"):
                    continue
                if len(m) - len(m.lstrip()) <= indent:
                    break
                kv = re.match(r"\s+([A-Za-z0-9_]+):\s*(.*)$", m)
                if kv:
                    out[kv.group(1)] = kv.group(2)
            break
    return out


def evaluate(raw, ctx):
    """A `${{ }}` value under ctx, enough of the Actions expression language
    for env lines: contexts, string literals, ==, !=, &&, || (operand-valued
    as in Actions)."""
    def expr(src):
        toks = re.findall(r"'[^']*'|&&|\|\||!=|==|[A-Za-z_][A-Za-z0-9_.-]*", src)
        py = []
        for tk in toks:
            if tk == "&&": py.append(" and ")
            elif tk == "||": py.append(" or ")
            elif tk in ("!=", "=="): py.append(f" {tk} ")
            elif tk.startswith("'"): py.append(repr(tk[1:-1]))
            else: py.append(repr(ctx.get(tk, "")))
        return eval("".join(py) or "''", {"__builtins__": {}})
    return re.sub(r"\$\{\{(.*?)\}\}", lambda m: str(expr(m.group(1))), raw)


def contexts(runner):
    ctx = {"runner.environment": runner}
    for n in ("CI_IMAGE_REGISTRY", "CI_REGISTRY", "RELEASE_REGISTRY", "OTHER_REGISTRY"):
        ctx["vars." + n] = REG
        ctx["secrets." + n] = REG
    return ctx


def headers(text, runner):
    """[(job, step, NAME, value as the log header prints it)]. Actions prints
    the job env and the step env before the run body; a secret's value is
    printed as *** from the first byte, a variable's in plaintext."""
    ctx = contexts(runner)
    out = []
    for name, blocks in jobs(text):
        jtext = "\n".join(text.split("\n")[text.split("\n").index("  " + name + ":"):]).split("\n    steps:")[0]
        jenv = env_of(jtext, 4)
        for i, b in enumerate(blocks):
            env = dict(jenv, **env_of(b, 8))
            for k, raw in env.items():
                val = evaluate(raw, ctx)
                if SECRET_REG.search(raw) and val:
                    secret_vals = {ctx["secrets." + s] for s in SECRET_REG.findall(raw)}
                    for s in secret_vals:
                        val = val.replace(s, "***")
                out.append((name, i, k, raw, val))
    return out


def registry_cases(text, where="the template", template=True):
    """M1 no job reads a registry from vars (header leak). M2 every secret
    registry read is guarded so a hosted run receives none. M3 the rendered
    step headers show no registry host on a self-hosted or a hosted run, and
    on a hosted run every *REGISTRY env is empty. M4 (template) each mask
    step sets CI_IMAGE_REGISTRY from the guarded secret."""
    c = code(text)
    for v in sorted(set(VARS_REG.findall(c))):
        failures.append(f"M1 {where} reads vars.{v}: Actions prints it in the step's log header before any add-mask")
    for m in re.finditer(r"^\s+([A-Z0-9_]+):\s*(\$\{\{.*\}\})\s*$", c, re.M):
        if SECRET_REG.search(m.group(2)) and GUARD not in m.group(2):
            failures.append(f"M2 {where} env {m.group(1)} reads a registry secret without the github-hosted guard: {m.group(2)}")
    for runner in ("self-hosted", "github-hosted"):
        for job, i, k, raw, val in headers(text, runner):
            if REG_HOST in val:
                failures.append(f"M3 {where} job {job} step {i} header prints {k}={val} on a {runner} run")
            if runner == "github-hosted" and k.endswith("REGISTRY") and re.search(r"\b(?:vars|secrets)\.", raw) and val:
                failures.append(f"M3 {where} job {job} step {i}: a hosted run receives {k}={val}")
    if not template:
        return
    masked = 0
    for name, blocks in jobs(text):
        runs = [run_of(b) for b in blocks]
        mask = next((i for i, r in enumerate(runs) if r.strip() == STEP_RUN), -1)
        if mask < 0:
            continue
        masked += 1
        raw = env_of(blocks[mask], 8).get("CI_IMAGE_REGISTRY", "")
        check(GUARD + "CI_IMAGE_REGISTRY" in raw, f"M4 job {name}'s mask step does not set CI_IMAGE_REGISTRY from the guarded secret")
    check(masked >= 4, f"found {masked} jobs with the mask step; the parse found too little")


def caught(fn, *a, **k):
    before = len(failures)
    fn(*a, **k)
    got = len(failures) > before
    del failures[before:]
    return got


# M5: a consumer of the integration image, as a copy carries it. The log is
# simulated: the header first (secrets as ***, variables plaintext), then the
# run body's output (docker echoes its reference), with the runner's masks:
# the secrets the job reads, and each ::add-mask:: printed by an earlier step.
CONSUMER = """\
jobs:
  integration:
    runs-on: bigdisk
    steps:
      - name: Mask the LAN addresses
        env:
          CI_IMAGE_REGISTRY: ${{ runner.environment != 'github-hosted' && secrets.CI_IMAGE_REGISTRY || '' }}
        run: scripts/ci-mask-lan.sh
      - name: Pull the integration image
        env:
          IT_REGISTRY: ${{ runner.environment != 'github-hosted' && secrets.CI_IMAGE_REGISTRY || '' }}
          IT_IMAGE_TAG: abc123
        run: |
          [ -n "$IT_REGISTRY" ] || { echo "no registry: artifact path"; exit 0; }
          docker pull "$IT_REGISTRY/repo/it-image:$IT_IMAGE_TAG"
"""


def simulate_log(text, runner):
    ctx = contexts(runner)
    fake = tempfile.mkdtemp(prefix="ci-mask-lan-")
    with open(os.path.join(fake, "docker"), "w") as f:
        f.write('#!/bin/sh\necho "docker $*"\necho "Error response from daemon: Get https://$IT_REGISTRY/v2/: dial tcp"\n')
    os.chmod(os.path.join(fake, "docker"), 0o755)
    log = []
    for name, blocks in jobs(text):
        masks = {ctx["secrets." + s] for b in blocks for s in SECRET_REG.findall(b)
                 if runner != "github-hosted"}
        for b in blocks:
            env = {k: evaluate(v, ctx) for k, v in env_of(b, 8).items()}
            hdr = [f"  {k}: {v}" for k, v in env.items()]
            body = run_of(b)
            if body.strip() == STEP_RUN:
                r = subprocess.run(["bash", SCRIPT], env=dict(PATH=os.environ["PATH"], **env), capture_output=True, text=True)
            else:
                r = subprocess.run(["bash", "-c", body], env=dict(PATH=fake + ":" + os.environ["PATH"], **env), capture_output=True, text=True)
            out = r.stdout.split("\n")
            def m(l):
                for s in sorted(masks, key=len, reverse=True):
                    if s:
                        l = l.replace(s, "***")
                return l
            log += [m(l) for l in hdr]
            for l in out:
                if l.startswith("::add-mask::"):
                    masks.add(l[len("::add-mask::"):])
                    continue
                log.append(m(l))
    return log


def log_cases():
    for runner in ("self-hosted", "github-hosted"):
        log = simulate_log(CONSUMER, runner)
        leak = [l for l in log if REG_HOST in l]
        check(not leak, f"M5 the {runner} log of the v1.53 consumer shows the registry: {leak}")
    hosted = simulate_log(CONSUMER, "github-hosted")
    check(any("artifact path" in l for l in hosted), f"M5 a hosted run received a registry: {hosted}")
    selfh = simulate_log(CONSUMER, "self-hosted")
    check(any("docker pull ***/repo/it-image:abc123" in l for l in selfh), f"M5 the self-hosted pull did not use the masked registry: {selfh}")
    # Mutations: the #2311 head 2b940111 shape (registry from vars, add-mask
    # in the run body) leaks in the header; an unguarded secret reaches a
    # hosted run.
    bad = CONSUMER.replace("runner.environment != 'github-hosted' && secrets.CI_IMAGE_REGISTRY || ''", "vars.CI_IMAGE_REGISTRY")
    check(any(REG_HOST in l for l in simulate_log(bad, "self-hosted")), "M5 a registry from vars does not leak in the simulated header: the simulation no longer matches Actions")
    check(caught(registry_cases, bad, "fixture", False), "M1 a consumer reading vars.CI_IMAGE_REGISTRY passes")
    ungarded = CONSUMER.replace("runner.environment != 'github-hosted' && secrets.CI_IMAGE_REGISTRY || ''", "secrets.CI_IMAGE_REGISTRY")
    check(caught(registry_cases, ungarded, "fixture", False), "M2 an unguarded registry secret passes")
    check(not caught(registry_cases, CONSUMER, "fixture", False), "M1-M3 flag the v1.53 consumer")


def mutation_cases(text):
    check(caught(registry_cases, text.replace("secrets.CI_IMAGE_REGISTRY || ''", "vars.CI_IMAGE_REGISTRY || ''", 1)),
          "M1 a mask step reading vars.CI_IMAGE_REGISTRY passes")
    i = text.index("        run: " + STEP_RUN + "\n")
    j = text.index("      - ", i)
    extra = "      - name: Pull\n        env:\n          IT_REGISTRY: ${{ secrets.OTHER_REGISTRY }}\n        run: echo pull\n"
    check(caught(registry_cases, text[:j] + extra + text[j:]), "M2 a step reading an unguarded registry secret passes")
    extra = "      - name: Pull\n        env:\n          IT_REGISTRY: ${{ vars.OTHER_REGISTRY }}\n        run: echo pull\n"
    check(caught(registry_cases, text[:j] + extra + text[j:]), "M1/M3 a step reading vars.OTHER_REGISTRY passes")
    check(caught(registry_cases, text.replace("          CI_IMAGE_REGISTRY: ${{ runner.environment != 'github-hosted' && secrets.CI_IMAGE_REGISTRY || '' }}\n", "", 1)),
          "M4 a mask step without CI_IMAGE_REGISTRY passes")
    # The check catches a job that loses the step.
    gone = text.replace("        run: " + STEP_RUN + "\n", "        run: echo gone\n", 1)
    check(caught(template_cases, gone), "removing the mask step from a job passes the template check")


script_cases()
if not os.path.exists(CI):
    print(f"FAIL no {os.path.relpath(CI, TEMPLATES)}: carry it from the handbook template")
    sys.exit(1)
ci = open(CI).read()
template_cases(ci)
registry_cases(ci)
if STEP_RUN in ci:
    mutation_cases(ci)
log_cases()
for p in sys.argv[1:]:
    with open(p) as f:
        registry_cases(f.read(), p, False)
if failures:
    for f in failures:
        print("FAIL", f)
    sys.exit(1)
print("ci-mask-lan: all checks pass")
