# release-common-template: v1.1.0 (2026-10-08). The one implementation behind
# the three release recipes of release-versioning.md §1a, all of which tag main.
# v1.1.0 adds release-candidate.mk and renames release-public.mk to release.mk
# (target `make release`), per the owner's rulings of 2026-10-07 (§1a). v1.0.0
# (2026-09-27 — automatethethings#173) had two recipes.
#
#   release-alpha.mk      make release-alpha     VERSION=vX.Y.Z-alpha   internal, Gitea only
#   release-candidate.mk  make release-candidate VERSION=vX.Y.Z-rc.N    a pre-release of the public vX.Y.Z
#   release.mk            make release           VERSION=vX.Y.Z         the Gitea tag a public release is published from
#
# Each recipe file includes this one from its own directory, so an adopter
# copies release-common.mk beside whichever recipes it uses and includes only
# the recipes. Including several recipes includes this file several times,
# which is harmless: it defines no rules, and every definition is idempotent.
#
# Neither recipe pushes to GitHub. Publication is
# software/scripts/github-publish.sh, gated on the owner's per-push approval
# (version-control.md §5a). These recipes push to RELEASE_REMOTE (Gitea) only.
#
# The security and correctness history of every guard below is recorded in
# release-alpha.mk's header (v2.3–v2.3.9); it was written against the alpha
# recipe and applies unchanged here, because this IS that recipe's body,
# factored out. Read it before changing a guard.
#
# INPUTS (all settable; each crosses into the recipe once, below):
#   VERSION           the release tag, v-prefixed; its form is checked per recipe
#   RELEASE_REMOTE    the Gitea remote (origin in every fleet repo, 2026-08-27)
#   REPO_NAME         the literal repo name: the signing identity agent-<repo>
#   AGENT_GIT         agent-git.sh, resolved from PATH (never a baked absolute path)
#   LOCKSTEP_MODULES  nested modules tagged in lockstep with the root
#                     (release-versioning.md §6), e.g. `sdk/go xkey`. Each entry
#                     is a repo-relative directory with a TRACKED go.mod; the
#                     recipe tags <dir>/VERSION on the release commit beside
#                     VERSION and pushes all of them in one atomic push. Empty
#                     (the default) tags the root only. Listed explicitly, never
#                     discovered: fleet repos carry nested go.mod files that are
#                     not released (web/desktop, test/performance/*).
#
# SECURITY — the v2.3.3/v2.3.7/v2.3.8 rules, extended to the new names:
#  - every settable input reaches the recipe as $(value ...) through an
#    `override export` target-specific variable, and the body reads only $$REL_*;
#  - every settable input AND every internal REL_* alias is `unexport`ed;
#  - the canned sequences are `override define`d and unexported too. A canned
#    sequence is a Make variable, and a command-line `RELEASE_CUT=...` would
#    otherwise replace the recipe body wholesale.
#
# ADOPTER CHECK: over each recipe BODY, `grep -P '(?<!\$)\$\((?!\()'` may match
# ONLY the canned sequences defined here (RELEASE_GUARDS, RELEASE_PIN_GATE,
# RELEASE_CUT, RELEASE_LOCKSTEP_COMPLETE, RELEASE_MONOTONIC, RELEASE_MAJOR_GATE,
# and inside them RELEASE_MODFILES and RELEASE_REQUIRES) — and every settable
# input must be on the `unexport` lines.

unexport VERSION RELEASE_REMOTE REPO_NAME AGENT_GIT LOCKSTEP_MODULES
unexport REL_VERSION REL_REMOTE REL_REPO REL_AGENT_GIT REL_MODULES REL_VERSION_ORIGIN
unexport RELEASE_GUARDS RELEASE_PIN_GATE RELEASE_CUT RELEASE_MODFILES RELEASE_REQUIRES RELEASE_LOCKSTEP_COMPLETE RELEASE_MONOTONIC RELEASE_MAJOR_GATE

release-alpha release-candidate release: override export REL_VERSION   := $(value VERSION)
release-alpha release-candidate release: override export REL_REMOTE    := $(value RELEASE_REMOTE)
release-alpha release-candidate release: override export REL_REPO      := $(value REPO_NAME)
release-alpha release-candidate release: override export REL_AGENT_GIT := $(value AGENT_GIT)
release-alpha release-candidate release: override export REL_MODULES   := $(value LOCKSTEP_MODULES)
# Where VERSION came from. `unexport` stops a command-line value from being
# re-exported, but it does not stop an EXPORTED environment variable (or
# `make -e`) from supplying the Make variable in the first place, so a bare
# `make release` could inherit a stale VERSION. The candidate and release recipes
# require it to come from the command line. $(origin) yields a fixed word.
release-candidate release: override export REL_VERSION_ORIGIN := $(origin VERSION)

# RELEASE_GUARDS — everything that must hold before VERSION is written. Runs
# after the recipe has checked the form of $$REL_VERSION for its release kind.
# The module list is validated FIRST, so every later line may word-split it.
override define RELEASE_GUARDS
@test "$$(git rev-parse --abbrev-ref HEAD)" = main || { echo "ERROR: releases are cut from main; you are on $$(git rev-parse --abbrev-ref HEAD). 'push $$REL_REMOTE HEAD' would publish this branch."; exit 1; }
@test -n "$$REL_REPO" || { echo 'ERROR: REPO_NAME is empty — set it to the literal repo name in the Makefile, never $$(notdir $$(CURDIR))'; exit 1; }
@ag="$$(command -v -- "$$REL_AGENT_GIT")" && test -f "$$ag" && test -x "$$ag" || { echo 'ERROR: AGENT_GIT does not resolve (as a path, or by name on PATH) to an executable agent-git.sh — every git write in this recipe signs through it, and a bad value must fail before VERSION is written'; exit 1; }
@test -n "$$REL_REMOTE" || { echo 'ERROR: RELEASE_REMOTE is empty — set it to the Gitea remote (origin in every fleet repo as of 2026-08-27)'; exit 1; }
@git remote get-url "$$REL_REMOTE" >/dev/null 2>&1 || { echo "ERROR: no git remote named $$REL_REMOTE. Set RELEASE_REMOTE to the Gitea remote; the duplicate-tag check below cannot answer against a remote that does not resolve"; exit 1; }
@test "$$REL_REMOTE" != github || { echo 'ERROR: RELEASE_REMOTE is github. These recipes push to Gitea only; publishing is github-publish.sh, on the owner'"'"'s per-push instruction (version-control.md §5a)'; exit 1; }; \
urls="$$(git remote get-url --all "$$REL_REMOTE" && git remote get-url --push --all "$$REL_REMOTE")" || { echo "ERROR: could not resolve the URLs of $$REL_REMOTE"; exit 1; }; \
if printf '%s\n' "$$urls" | grep -qi 'github\.com'; then echo "ERROR: $$REL_REMOTE fetches from or pushes to github.com (insteadOf/pushInsteadOf and pushurl included). These recipes push to Gitea only; publishing is github-publish.sh, on the owner's per-push instruction (version-control.md §5a)"; exit 1; fi
@if git ls-files --error-unmatch -- go.mod >/dev/null 2>&1 && ! test -f go.mod; then echo "ERROR: go.mod is tracked but not checked out (a sparse checkout?); the release gates would skip the root module. Check out the whole tree"; exit 1; fi
@seen=' '; set -f; for m in $$REL_MODULES; do \
  printf '%s' "$$m" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$$' || { echo "ERROR: LOCKSTEP_MODULES entry is not a plain repo-relative directory: $$m"; exit 1; }; \
  case "$$seen" in *" $$m "*) echo "ERROR: LOCKSTEP_MODULES lists $$m twice"; exit 1 ;; esac; seen="$$seen$$m "; \
  git ls-files --error-unmatch -- "$$m/go.mod" >/dev/null 2>&1 || { echo "ERROR: LOCKSTEP_MODULES entry $$m has no tracked go.mod — a lockstep tag must name a real nested module"; exit 1; }; \
  test -f "$$m/go.mod" || { echo "ERROR: $$m/go.mod is tracked but not checked out (a sparse checkout?); the release gates would skip it. Check out the whole tree"; exit 1; }; \
done
@for t in "$$REL_VERSION" $$(for m in $$REL_MODULES; do printf '%s/%s ' "$$m" "$$REL_VERSION"; done); do \
  git check-ref-format "refs/tags/$$t" || { echo "ERROR: refs/tags/$$t is not a valid tag name; fix LOCKSTEP_MODULES before anything is written"; exit 1; }; \
  ! git rev-parse -q --verify "refs/tags/$$t" >/dev/null || { echo "ERROR: tag $$t already exists locally"; exit 1; }; \
  rc=0; git ls-remote --exit-code --tags "$$REL_REMOTE" "refs/tags/$$t" >/dev/null 2>&1 || rc=$$?; \
  case "$$rc" in \
    0) echo "ERROR: tag $$t already exists on $$REL_REMOTE (a local check alone would miss this and fail the push AFTER committing VERSION)"; exit 1 ;; \
    2) : ;; \
    *) echo "ERROR: could not reach $$REL_REMOTE to check whether tag $$t exists. Refusing to continue: an unreachable remote is not an absent tag"; exit 1 ;; \
  esac; \
done
@test -z "$$(git status --porcelain)" || { echo 'ERROR: working tree not clean'; exit 1; }
@ver="## [$${REL_VERSION#v}]"; awk -v ver="$$ver" ' \
  function fence(s,   i, n) { \
    i = 1; while (i <= 3 && substr(s, i, 1) == " ") i++; \
    fch = substr(s, i, 1); if (fch != "~" && fch != "\140") return 0; \
    n = 0; while (substr(s, i + n, 1) == fch) n++; \
    info = substr(s, i + n); return n >= 3 ? n : 0 } \
  { n = fence($$0) } \
  open { if (n >= open && fch == opench && info ~ /^[ \t]*$$/) open = 0; next } \
  n && !(fch == "\140" && index(info, "\140")) { open = n; opench = fch; next } \
  index($$0, ver) == 1 { f = 1 } \
  END { exit f ? 0 : 1 }' CHANGELOG.md || { echo "ERROR: CHANGELOG.md has no \"$$ver\" section heading. Matched LITERALLY and anchored at the line start, exactly as .github/workflows/release.yml matches it — an unanchored prose mention does not count, neither does a near-miss heading, and neither does a heading quoted inside a fenced code block"; exit 1; }
endef

# RELEASE_LOCKSTEP_COMPLETE — used by release-candidate and release, whose tag is the one a
# public release is built from. Every nested module that has
# EVER been tagged on the remote (a <dir>/v* tag) and still has a tracked
# <dir>/go.mod must be in LOCKSTEP_MODULES; otherwise its pins would not move
# and its tag would not be cut, and the omission would only surface at
# github-publish.sh, after the root tag is already immutable. Not applied to
# release-alpha, whose adopters may still tag modules by their own targets.
override define RELEASE_LOCKSTEP_COMPLETE
@refs="$$(git ls-remote --tags --refs "$$REL_REMOTE")" || { echo "ERROR: could not list tags on $$REL_REMOTE to check the lockstep module set"; exit 1; }; \
for d in $$(printf '%s\n' "$$refs" | sed -n 's|^[0-9a-f]*[[:space:]]*refs/tags/\(.*\)/v[0-9][^/]*$$|\1|p' | sort -u); do \
  git ls-files --error-unmatch -- "$$d/go.mod" >/dev/null 2>&1 || continue; \
  case " $$REL_MODULES " in *" $$d "*) ;; *) echo "ERROR: $$d is a released module ($$d/v* tags exist on $$REL_REMOTE) but is not in LOCKSTEP_MODULES; it would be left out of this release"; exit 1 ;; esac; \
done
endef

# RELEASE_MONOTONIC — used by release-candidate and release. The new version
# must order strictly ABOVE every release tag already on the remote, by SemVer
# 2.0.0 §11 precedence (release-versioning.md §3: a published version never
# goes backwards, and neither may a pin re-pinned to it). Alphas and releases
# are compared across the whole tag set, so v1.2.0 is refused once v1.2.1-alpha
# exists. Only v-prefixed MAJOR.MINOR.PATCH tags with an optional pre-release
# take part: the root's, and each lockstep
# module's <dir>/v... (a module versioned ahead of the root must not be tagged
# backwards either). It must also not order below the VERSION file (§3: never
# lower a VERSION file); equal is allowed. This is the "real SemVer §11 comparator" release-alpha.mk's
# v2.3.4 note asks for before numbered pre-releases are walked: numeric
# identifiers compare numerically (by digit count, then digits, so no size
# limit or float rounding), alphanumeric ones in ASCII order, numeric
# below alphanumeric, and a longer identifier list ranks higher when equal so far.
override define RELEASE_MONOTONIC
@refs="$$(git ls-remote --tags --refs "$$REL_REMOTE")" || { echo "ERROR: could not list tags on $$REL_REMOTE to check version ordering"; exit 1; }; \
semver_awk=' \
  function cmpid(a, b) { \
    if (a ~ /^[0-9]+$$/ && b ~ /^[0-9]+$$/) { \
      sub(/^0+/, "", a); sub(/^0+/, "", b); \
      if (length(a) != length(b)) return (length(a) < length(b)) ? -1 : 1; \
      return (a "" < b "") ? -1 : (a "" > b ""); } \
    if (a ~ /^[0-9]+$$/) return -1; \
    if (b ~ /^[0-9]+$$/) return 1; \
    return (a "" < b "") ? -1 : (a "" > b ""); } \
  function cmp(x, y,   xp, yp, xc, yc, xa, ya, i, n, m, r) { \
    sub(/^v/, "", x); sub(/^v/, "", y); xp = yp = ""; \
    if (i = index(x, "-")) { xp = substr(x, i + 1); x = substr(x, 1, i - 1) } \
    if (i = index(y, "-")) { yp = substr(y, i + 1); y = substr(y, 1, i - 1) } \
    split(x, xc, "."); split(y, yc, "."); \
    for (i = 1; i <= 3; i++) { r = cmpid(xc[i], yc[i]); if (r) return r } \
    if (xp == "" || yp == "") return (xp == "" && yp == "") ? 0 : (xp == "" ? 1 : -1); \
    n = split(xp, xa, "."); m = split(yp, ya, "."); \
    for (i = 1; i <= n && i <= m; i++) { r = cmpid(xa[i], ya[i]); if (r) return r } \
    return (n < m) ? -1 : (n > m); }'; \
above="$$(printf '%s\n' "$$refs" | LC_ALL=C awk -v new="$$REL_VERSION" -v mods=" $$REL_MODULES " "$$semver_awk"' \
  { t = $$2; sub(/^refs\/tags\//, "", t); v = t; i = match(v, /\/v[0-9][^\/]*$$/); \
    if (i) { if (index(mods, " " substr(v, 1, i - 1) " ") == 0) next; v = substr(v, i + 1) } } \
  v ~ /^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$$/ && cmp(new, v) <= 0 { printf " %s", t }')" || exit 1; \
test -z "$$above" || { echo "ERROR: $$REL_VERSION does not order above existing release tags on $$REL_REMOTE:$$above. A version never goes backwards (release-versioning.md §3); choose a higher one"; exit 1; }; \
test -f VERSION || exit 0; \
test "$$(grep -c '' VERSION)" = 1 || { echo "ERROR: VERSION must be exactly one line holding one SemVer version"; exit 1; }; \
cur="v$$(cat VERSION)"; printf '%s' "$$cur" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$$' || { echo "ERROR: VERSION does not hold a SemVer version, so this recipe cannot tell whether writing $${REL_VERSION#v} lowers it"; exit 1; }; \
lower="$$(printf 'x refs/tags/%s\n' "$$cur" | LC_ALL=C awk -v new="$$REL_VERSION" "$$semver_awk"' { t = $$2; sub(/^refs\/tags\//, "", t) } cmp(new, t) < 0 { print t }')" || exit 1; \
test -z "$$lower" || { echo "ERROR: VERSION is $$(cat VERSION), above $$REL_VERSION; this release would lower it (release-versioning.md §3: never lower a VERSION file)"; exit 1; }
endef

# RELEASE_MAJOR_GATE — used by release-candidate and release. Go accepts a
# vN tag (N >= 2) only for a module whose path ends in /vN, and a v0/v1 tag
# only for one whose path does not (semantic import versioning;
# release-versioning.md §1, post-1.0 MAJOR). Every published go.mod must agree
# with the release's major, or the immutable tags would be unusable.
override define RELEASE_MAJOR_GATE
@$(RELEASE_MODFILES) \
major="$${REL_VERSION#v}"; major="$${major%%.*}"; \
for f in $$files; do \
  mod="$$(awk '$$1 == "module" { print $$2; exit }' "$$f")"; \
  suffix="$$(printf '%s' "$$mod" | sed -n 's|.*/v\([0-9][0-9]*\)$$|\1|p')"; \
  case "$$major" in \
    0|1) test -z "$$suffix" || { echo "ERROR: $$f declares $$mod, but $$REL_VERSION is a v$$major release; a v0/v1 module path carries no /vN suffix (Go allows /vN only for N >= 2)"; exit 1; } ;; \
    *) test "$$suffix" = "$$major" || { echo "ERROR: $$f declares $$mod, but a $$REL_VERSION tag needs the module path to end in /v$$major"; exit 1; } ;; \
  esac; \
done
endef

# RELEASE_MODFILES — shell fragment: sets $$files to the go.mod files the
# release publishes (the root's and each lockstep module's, where present) and
# $$own to their module paths, space-delimited. A repo with no go.mod has none.
override define RELEASE_MODFILES
own=' '; files=''; for f in go.mod $$(for m in $$REL_MODULES; do printf '%s/go.mod ' "$$m"; done); do   [ -f "$$f" ] || continue; files="$$files $$f";   own="$$own$$(awk '$$1 == "module" { print $$2; exit }' "$$f") "; done;
endef

# RELEASE_REQUIRES — awk program printing "path version" for every require in
# the go.mod named after it, single-line and block form, comments stripped.
override define RELEASE_REQUIRES
awk '   { sub(/\/\/.*/, "") }   blk && $$1 == ")" { blk = 0; next }   blk && NF >= 2 { print $$1, $$2; next }   $$1 == "require" && $$2 == "(" { blk = 1; next }   $$1 == "require" && NF >= 3 { print $$2, $$3 }'
endef

# RELEASE_PIN_GATE — the upstream gate. Every first-party requirement
# (github.com/jeremyhahn/...) in the published go.mod files must name a version
# matching the shell variable $$pin_re, which the recipe sets on the same line.
# v0.0.0 is refused whatever pin_re says: it is the legacy placeholder
# (dependency-resolution.md), never a real release. The repo's OWN modules
# are exempt here because RELEASE_CUT rewrites them.
override define RELEASE_PIN_GATE
$(RELEASE_MODFILES) \
bad=''; for f in $$files; do \
  pins="$$($(RELEASE_REQUIRES) "$$f")" || { echo "ERROR: could not read $$f"; exit 1; }; \
  bad="$$bad$$(printf '%s\n' "$$pins" | while read -r p v; do \
    case "$$p" in github.com/jeremyhahn/*) ;; *) continue ;; esac; \
    case "$$own" in *" $$p "*) continue ;; esac; \
    { [ "$$v" != v0.0.0 ] && printf '%s' "$$v" | grep -Eq "$$pin_re"; } || printf ' %s:%s@%s' "$$f" "$$p" "$$v"; \
  done)"; \
done; \
test -z "$$bad" || { echo "ERROR: first-party dependencies are not at an allowed release for this kind of release (release-versioning.md §1a):$$bad"; exit 1; }
endef

# RELEASE_CUT — write VERSION, and move every requirement one published
# module has on ANOTHER of the repo's own modules to the release version, in
# the same commit (dependency-resolution.md §5: "fixing both go.mod files in
# one commit and cutting both tags on that commit"; check-reciprocal-pins.sh:
# the version bump and the pins must move together). Without it, sdk/go tagged
# at the new version still requires the root at the previous one, and every
# outside consumer gets a stale sibling. Then commit, tag the root and every
# lockstep module on that commit (annotated, signed through agent-git.sh), and
# push the commit and exactly those tags in one atomic push. --no-follow-tags:
# see v2.3.9(a). When VERSION and the pins already read the release version
# there is nothing to commit, and HEAD itself is tagged. The pins are rewritten with `go mod edit`, so a repo whose
# modules pin each other needs the go toolchain to release; one whose modules
# do not never invokes it. Every edit is first tried on a copy, so a toolchain
# that cannot edit a module fails before VERSION or any go.mod is touched.
override define RELEASE_CUT
@$(RELEASE_MODFILES) \
tmp="$$(mktemp -d)" || exit 1; trap 'rm -rf "$$tmp"' EXIT; \
for f in $$files; do \
  for p in $$($(RELEASE_REQUIRES) "$$f" | awk '{ print $$1 }'); do \
    case "$$own" in *" $$p "*) ;; *) continue ;; esac; \
    command -v go >/dev/null 2>&1 || { echo "ERROR: $$f requires $$p, which this release re-pins to $$REL_VERSION with go mod edit, and go is not on PATH. Nothing was written"; exit 1; }; \
    cp "$$f" "$$tmp/go.mod" && GOTOOLCHAIN=local GOFLAGS= go mod edit -require="$$p@$$REL_VERSION" "$$tmp/go.mod" \
      || { echo "ERROR: go mod edit cannot re-pin $$p in $$f (tried on a copy). Nothing was written"; exit 1; }; \
  done; \
done
@printf '%s\n' "$${REL_VERSION#v}" > VERSION
@$(RELEASE_MODFILES) \
for f in $$files; do \
  for p in $$($(RELEASE_REQUIRES) "$$f" | awk '{ print $$1 }'); do \
    case "$$own" in *" $$p "*) ;; *) continue ;; esac; \
    GOTOOLCHAIN=local GOFLAGS= go mod edit -require="$$p@$$REL_VERSION" "$$f" || { echo "ERROR: could not re-pin $$p in $$f"; exit 1; }; \
    echo "re-pinned $$p to $$REL_VERSION in $$f"; \
  done; \
done; \
"$$REL_AGENT_GIT" "$$REL_REPO" add -- VERSION $$files
@if git diff --cached --quiet; then echo "VERSION and pins already read $$REL_VERSION; tagging HEAD without a release commit"; else "$$REL_AGENT_GIT" "$$REL_REPO" commit -m "chore(release): $$REL_VERSION"; fi
for t in "$$REL_VERSION" $$(for m in $$REL_MODULES; do printf '%s/%s ' "$$m" "$$REL_VERSION"; done); do "$$REL_AGENT_GIT" "$$REL_REPO" tag -a "$$t" -m "$$t" || exit 1; done
"$$REL_AGENT_GIT" "$$REL_REPO" push --atomic --no-follow-tags "$$REL_REMOTE" HEAD "refs/tags/$$REL_VERSION" $$(for m in $$REL_MODULES; do printf 'refs/tags/%s/%s ' "$$m" "$$REL_VERSION"; done)
@echo "Released $$REL_VERSION$$(for m in $$REL_MODULES; do printf ' + %s/%s' "$$m" "$$REL_VERSION"; done) (signed, annotated; only these tags pushed)"
endef
