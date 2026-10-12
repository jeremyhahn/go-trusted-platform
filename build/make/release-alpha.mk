# release-alpha-template: v2.4.0 (2026-09-25 — automatethethings#173): the recipe
# BODY moved to release-common.mk, shared with the new release-public.mk
# (release-versioning.md §1a). Behaviour is unchanged for a
# repo that sets nothing new; copy release-common.mk beside this file, since
# this file now includes it from its own directory. New, opt-in:
# LOCKSTEP_MODULES (e.g. `sdk/go xkey`) tags each nested module at the same
# version on the release commit and pushes all the tags in one atomic push.
# Regression tests: testdata/release-alpha-tests.sh (both recipes).
# v2.3.9 (2026-09-22 — two recipe defects, go-quicbaas#967,
# found by codex adopting v2.3.8 verbatim in go-truststrap PR #72; regression
# tests in testdata/release-alpha-tests.sh run this recipe against a real remote):
#  (a) --no-follow-tags on the release push. With push.followTags=true (a common
#      GLOBAL setting) git also pushes every missing annotated tag reachable from
#      HEAD, whatever the refspecs name — and --atomic does not narrow that set.
#      "Pushes ONLY the named tag" was false on any host with that setting.
#  (b) The CHANGELOG guard counts a heading only OUTSIDE a fenced code block. A
#      fenced example quoting "## [X.Y.Z-alpha]" at column 1 satisfied the literal
#      match, so a release with no real section was cut and pushed. Fences follow
#      CommonMark: 0-3 spaces of indent, 3+ backticks or tildes; closed only by
#      the SAME character at least as long with nothing after it; an unclosed
#      fence runs to end of file. A naive toggle is not enough — a ``` line inside
#      a ```` block would "close" it and re-admit the quoted heading.
#  This header is on line 1 so the first line always names the CURRENT revision;
#  v2.3.6-v2.3.8 were stamped lower down and #967 read this file as v2.3.5.
# release-alpha-template: v2.3.5 (guidance only). Two release-WORKFLOW safety
# patterns from go-blockstore #8, for any repo whose pipeline re-validates VERSION
# or splits validate/publish across jobs:
#  (a) VERIFY VERSION EXACTLY, never normalize. `tr -d '[:space:]'` accepts
#      '0.3. 1-alpha', a split-across-lines file, or a missing trailing newline —
#      all publish a VERSION that does not match the tag. Compare BYTES against the
#      writer inverted: `printf '%s\n' "$VER" | cmp -s - VERSION` (writer and
#      checker one statement in two directions); on mismatch dump `od -c VERSION`.
#  (b) SPLIT validate/publish jobs share a TOCTOU: a tag is immutable only by
#      convention, and a force-move BETWEEN the jobs passes any self-consistency
#      check (tag and checkout agree — on the NEW commit). validate must EXPORT the
#      commit it approved and publish must REFUSE anything else (and refuse an
#      ABSENT value — an empty guard is not a passing guard); FAIL, do not fall back
#      to the validated commit — a mid-release tag move is an immutability breach a
#      human should see.
# release-alpha-template: v2.3.4 (guidance only — no recipe change). If your repo
# ALSO ships a release WORKFLOW that walks tags to compute a previous release for
# notes/compare links, the set the validator ACCEPTS must equal the set the
# sorter can ORDER. git's `--sort=v:refname` is NOT SemVer for prerelease
# identifiers (orders alpha2 before alpha10; SemVer says alpha10 first), and
# `versionsort.suffix=-` only places prereleases before their stable — it does
# NOT make identifier comparison SemVer-correct (measured go-blockstore #8;
# corrects that lane's own round-3 overstatement). Since release-versioning.md §1
# says the sanctioned TAG vocabulary is BARE (X.Y.Z, -alpha, -beta, -rc; numbered
# -alpha.N is never tagged), narrow BOTH the release-form gate AND the walk to it:
#   num='(0|[1-9][0-9]*)'; sanctioned="^v${num}\.${num}\.${num}(-(alpha|beta|rc))?$"
#   PREV="$(git -c versionsort.suffix=- tag --list 'v*' --sort=v:refname \
#           | grep -E "$sanctioned" | awk -v cur="$TAG" '$0==cur{exit}{print}' | tail -n1 || true)"
# Excluding an unorderable/off-vocabulary tag from the walk only ever WIDENS the
# notes range (cosmetic dupes), never truncates it — the safe failure direction.
# If a repo ever needs numbered prereleases, the gate widens and the walk needs a
# real SemVer §11 comparator FIRST.
# release-alpha-template: v2.3.8 (2026-09-01 — SECURITY: `override` + unexport on the
# internal REL_* names too. v2.3.7 sanitised the four public inputs and left their
# four internal aliases settable from the command line, where they both executed
# and outranked the sanitised value. Measured; see the block at the recipe.)
# v2.3.7 (2026-09-01 — SECURITY: $(value ...) on all four
# release inputs, not just VERSION, AND `unexport` of those four — $(value) alone
# does not close the injection, because a command-line variable is auto-exported
# into every recipe environment and building that environment expands it. Measured
# GNU Make 4.3; automatethethings#14. Do not re-measure this with `make -n` — under
# -n no recipe runs, no environment is built, and an injectable Makefile looks clean).
# v2.3.6 (2026-09-01 — no baked AGENT_GIT path: it published a developer path, a private repo name and its layout into every mirrored adopter; plus the pre-existing-VERSION shadowing check that made a guard unreachable. Measured go-luks2 #19/#20). v2.3.3 (SECURITY — Make-variable command-injection fix; see the v2.3.3 block at the recipe). v2.3.2 (--atomic on the release push — without it git permits PARTIAL success: an update-hook/branch-protection rejection of main can land the tag alone, unretractable; measured in go-blockstore #8 round 3, and note the harness subtlety: a pre-receive hook CANNOT exhibit this bug — it runs once per push — the correct model of branch protection is the per-ref update hook). v2.3.1 (adds the AGENT_GIT-executable guard from go-blockstore — a bad AGENT_GIT path must fail before VERSION is written, not at the first signed write). v2.3 — replaces the defective v1 recipe found in all 16
# product repos on 2026-08-26 (go-enclave #10). The v1 recipe: auto-incremented
# PATCH only (an API addition ships labeled as a bugfix), created LIGHTWEIGHT
# UNSIGNED tags as the OWNER's local identity (violating the per-agent-principal
# ratification and signed-tag discipline), pushed EVERY local tag, and `|| true`
# swallowed a failed VERSION commit so a tag could disagree with its own VERSION
# file. None of it failed loudly; it was wrong only when you looked.
#
# v2 contract:
#   - The version is EXPLICIT: `make release-alpha VERSION=v0.3.0-alpha`.
#     No auto-increment — the human/agent cutting a release decides
#     patch-vs-minor-vs-major per conventions/release-versioning.md and
#     states it. The recipe refuses to guess.
#   - All git write operations go through agent-git.sh (identity + SSH
#     signing as agent-<repo>); the tag is ANNOTATED and signed.
#   - Pushes ONLY the release commit and the named tag. Never --tags.
#   - Cut from `main` ONLY — a branch guard, since `push <remote> HEAD`
#     publishes whatever branch is checked out (go-enclave, 2026-08-26: v2
#     caught this residual before the 15-repo adoption).
#   - REPO_NAME is the LITERAL repo name (identity/signing), never derived
#     from the directory; a duplicate-tag check hits the REMOTE not just
#     local refs; the CHANGELOG guard anchors on a section heading, not a
#     substring (all three: reviewer-enclave-9, 2026-08-26, before the
#     v0.3.0-alpha cut).
#   - Fail-closed end to end: no `|| true`; any failing step aborts before
#     the tag exists.
#   - Error messages are SINGLE-quoted, deliberately. A double-quoted `echo`
#     is a live command-substitution context, and error strings are exactly
#     what people edit casually — a backtick or $(...) added there gets
#     EXECUTED at the moment a release is already failing. Never put backticks
#     or $(...) inside a recipe error message (reviewer-enclave-9, 2026-08-26:
#     the v2.2 branch-guard shipped with backticks and ran `push dev HEAD`).
#   - CHANGELOG discipline: refuses to cut if CHANGELOG.md lacks an entry
#     for $(VERSION) (repos without a CHANGELOG delete that guard when
#     adopting, consciously).
#   - Repos with a sdk/go module keep their existing lockstep checks
#     (check-tag-lockstep etc.) as prerequisites of this target.
#
# ------------------------------------------------------------------------------
# v2.3 (2026-08-27) — FOUR CORRECTIONS. v2.2 COULD NOT WORK AS WRITTEN in any
# fleet repo; each defect below was measured on go-blockstore #8, whose Makefile
# is the reference implementation, before the six queued adoptions (go-auth #22,
# go-frost #17, go-codec #10, go-libsignal #39, go-objstore #32, go-luks2 #19).
# None of the four is a preference:
#
#   1. VERSION is written UNPREFIXED — `$(VERSION:v%=%)`. v2.2 wrote the
#      v-prefixed tag string verbatim into the VERSION file, contradicting
#      conventions/release-versioning.md §2, whose table is normative: VERSION
#      is unprefixed, the TAG carries the `v`. Every repo in the portfolio
#      follows the table, and the v-prefixed form also breaks the standard
#      reconciliation `VERSION=$${GITHUB_REF#refs/tags/v}` that release.yml
#      validates against (§5).
#
#   2. The CHANGELOG guard matches the UNPREFIXED heading LITERALLY, via an
#      index-based awk predicate anchored at column 1. v2.2's
#      `grep -Eq '^#+ +\[?$(VERSION)\]?'` fails two ways at once. It demands the
#      `v` prefix, which no Keep-a-Changelog heading carries — so on its own it
#      REFUSES EVERY WELL-FORMED RELEASE. And it is a REGEX: the dots of a
#      version are wildcards and `#+ +\[?` admits heading shapes the release
#      workflow does not, so `## [0x3x2-alpha]` and `### 0.3.2-alpha` pass
#      (measured), the tag gets cut and pushed, and only then does the
#      workflow's literal lookup fail — on a tag that can no longer be
#      retracted (§3: published tags are immutable). A pre-flight check that is
#      not IDENTICAL to the thing it clears for is not a check.
#
#   3. The remote duplicate-tag check reads the EXIT CODE, not `!`.
#      `git ls-remote --exit-code` answers three different things and v2.2's
#      `! git ls-remote … || { error }` collapsed them to two: 0 = the tag
#      exists, 2 = it does not, anything else (128 on an unreachable,
#      unauthenticated or NONEXISTENT remote) = the question was never
#      answered. Under `!` that third case read as "tag absent" — the check
#      FAILED OPEN — and the recipe went on to commit VERSION and create the
#      tag before the push failed, which is the exact half-released state the
#      check exists to prevent. Codes verified against Gitea 2026-08-27, not
#      assumed.
#
#   4. RELEASE_REMOTE ?= origin replaces the hardcoded `dev`. NO FLEET REPO HAS
#      A `dev` REMOTE — go-blockstore, go-objstore, go-qrdb, go-quicbaas and
#      go-xkms all reach Gitea through `origin` (measured 2026-08-27), whatever
#      conventions/version-control.md calls the remote. Hardcoded, `push dev`
#      failed AFTER VERSION was already committed, and defect 3 made the
#      duplicate-tag check pass vacuously against a remote name that does not
#      resolve. It stays a VARIABLE, not a renamed constant, so a future
#      dev-remote rollout is one line per repo. Its existence is asserted
#      before it is trusted (also from go-blockstore #8): defect 3 already
#      blocks on rc 128, and this turns that into a diagnosis.
#
# SUPPLY CHAIN — for the release WORKFLOW that pairs with this target: any
# third-party action it uses MUST be pinned to a full commit SHA, never a
# mutable tag. A tag is a ref whoever controls the action can move, and a
# release job holds write-scoped tokens. All four existing fleet release.yml
# files use mutable tags today; tracked on go-objstore #37. When bumping a pin,
# read the ANNOTATED-TAG PEEL TRAP note in
# templates/github-actions/nightly.yml — `git ls-remote --tags --refs` returns
# the TAG OBJECT's sha for an annotated tag, which does not resolve as a pin
# and fails at checkout; take the `^{}` peeled line instead.
# ------------------------------------------------------------------------------
#
# AGENT_GIT resolves the signing wrapper; repos adopting this template set these
# near the top of their Makefile. REPO_NAME MUST be the literal repo name — NOT
# $(notdir $(CURDIR)), which derives the signing IDENTITY from the checkout
# directory, so a worktree/CI-workspace/clone named anything but the repo signs
# and attributes the release as the wrong agent (measured go-enclave 2026-08-26:
# a dir named `mk` → agent-mk):
#   AGENT_GIT ?= agent-git.sh      # RESOLVED FROM PATH — see v2.3.6 below
#   REPO_NAME ?= go-enclave        # the literal repo name; never $(notdir $(CURDIR))
#   RELEASE_REMOTE ?= origin       # the Gitea remote; see v2.3 correction 4
#
# v2.3.6 (2026-09-01, measured in go-luks2 #19/#20) — TWO defects every adopter
# inherits from earlier revisions. Both were found by adopting this template into
# a repo with a PUBLIC MIRROR, which is the condition that makes the first one
# matter and the second one visible.
#
#  (a) DO NOT BAKE AN ABSOLUTE PATH INTO AGENT_GIT. Earlier revisions suggested
#      a literal `/home/<user>/sources/automatethethings/software/scripts/...`
#      default. In a mirrored repo that single line publishes a developer's
#      username, the private company repo's name, and its checkout layout —
#      exactly the class of leak go-luks2 #20 exists to remove, shipped BY the
#      template into every adopter. Resolve from PATH instead. The v2.3.1
#      `test -x "$$REL_AGENT_GIT"` guard already makes an unresolvable value
#      fail closed BEFORE VERSION is written, so nothing is lost by dropping the
#      default: the failure mode is a clear error, not a silent wrong signer.
#
#  (b) CHECK FOR A PRE-EXISTING `VERSION` VARIABLE BEFORE ADOPTING. This recipe
#      takes the release version as `make release-alpha VERSION=v0.3.0-alpha`.
#      Many Makefiles ALREADY define `VERSION` for `-ldflags -X main.Version=`.
#      When they do, that definition shadows the argument: `make release-alpha`
#      with no argument inherits the build version, sails straight past the
#      "state the version explicitly" guard — the guard written to give the
#      clearest possible message becomes UNREACHABLE — and dies several steps
#      later on a confusing grammar error about a value the operator never
#      typed. Rename the build variable (`BUILD_VERSION`), not this one.
#      Measured in go-luks2, where `make release-alpha` did exactly this.
#
#      Grep before adopting:  grep -n '^VERSION' Makefile

# v2.3.3 — SECURITY: every settable Make variable crosses into the recipe ONCE,
# via a target-specific export, and the body references only shell parameters
# ($$REL_*). Before this, $(VERSION) was expanded into double-quoted recipe TEXT
# before the grammar guard ran, so `make release-alpha 'VERSION=v0.0.0-alpha`cmd`'`
# executed the backtick at the first guard line (measured go-blockstore #8 r4:
# canaries via VERSION backtick, VERSION embedded-quote, and RELEASE_REMOTE
# backtick — quoting is no boundary against a value that becomes recipe source).
# `$(value VERSION)` also stops the double-evaluation the export otherwise adds.
#
# v2.3.7 — the above was true but INCOMPLETE on two counts, both measured on
# GNU Make 4.3 (automatethethings#14; the issue's own analysis was wrong in the
# other direction and the correction is recorded there).
#
#  1. `$(value ...)` MUST be on all four inputs, not just VERSION. It was on
#     VERSION alone; RELEASE_REMOTE, REPO_NAME and AGENT_GIT were plain `$(...)`
#     and so were live injection points on a release path:
#       make release-alpha VERSION=v1.2.3-alpha 'RELEASE_REMOTE=$(shell id >&2)origin'
#     ran `id` before any guard.
#
#  2. `$(value ...)` ALONE DOES NOT CLOSE IT. A variable set on the make command
#     line is automatically exported into EVERY recipe's environment, and
#     BUILDING that environment expands it — so the payload fires even though
#     the assignment never expanded it, and even in a Makefile that names the
#     variable NOWHERE. `unexport` is the half that closes it:
#
#       makefile shape                          payload fires?
#       ----------------------------------      --------------
#       plain $(RELEASE_REMOTE)                  yes (twice)
#       $(value RELEASE_REMOTE)                  yes (once, via the env export)
#       unexport + $(value RELEASE_REMOTE)       NO
#       variable not mentioned in the makefile   yes (any recipe that runs)
#
#     Hence the `unexport` line below. It does not affect ordinary use: the
#     guards still receive the operator's literal text, and a value carrying a
#     $(shell ...) simply arrives as raw characters and fails the grammar,
#     remote-resolves or -x guard instead of executing.
#
# MEASURE IT WITH A REAL RECIPE, NOT `make -n`. Under `-n` no recipe runs, so no
# recipe environment is built and NOTHING fires — `-n` makes an injectable
# Makefile look clean. That is precisely the mistake that made this look
# unreproducible and nearly got this warning deleted.
#
# ADOPTER CHECK: `grep -P '(?<!\$)\$\((?!\()' ` over the recipe BODY must be empty
# — no $(...) carrying a settable value below the export lines — AND every
# settable input named on the `unexport` line.
.PHONY: release-alpha
# v2.4.0: the export/unexport lines that stood here, and every guard after the
# version-form check, now live in release-common.mk — one implementation for
# the alpha and public recipes. The `override` explanation kept below is
# why those lines look the way they do there:
#
#   make release-alpha VERSION=v1.2.3-alpha 'REL_REMOTE=$(shell id >&2)origin'
#
# Measured on GNU Make 4.3 against the v2.3.7 recipe: that fired the payload AND
# won the assignment (REL_REMOTE came out as the attacker's plain 'origin', the
# $(value ...) discarded). v2.3.7 closed the four public names and left their
# four internal aliases open — a fix that moves the hole rather than shutting
# it. With `override` the same command yields an EMPTY REL_REMOTE and no
# execution, so the existing empty-value guard rejects it.
include $(dir $(lastword $(MAKEFILE_LIST)))release-common.mk
release-alpha:
	@test -n "$$REL_VERSION" || { echo 'ERROR: state the version explicitly: make release-alpha VERSION=vX.Y.Z-alpha (release-versioning.md decides patch/minor/major — the recipe refuses to guess)'; exit 1; }
	@printf '%s' "$$REL_VERSION" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-alpha$$' || { echo "ERROR: VERSION is not of the form vX.Y.Z-alpha (no leading zeroes): $$REL_VERSION"; exit 1; }
	$(RELEASE_GUARDS)
	$(RELEASE_MONOTONIC)
	$(RELEASE_CUT)
