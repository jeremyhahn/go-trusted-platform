// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package arch

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// The integration image is named by its content, `make -s it-image`
// (ci-standard.md §9, #1272): every job and run of one tree on a daemon shares
// the tag, so no job removes it and only scripts/reap-stale-ci-stacks.sh (v5)
// does. A tag is safe from that reaper only while a lease, a created container,
// names its image, and the lease and every re-tag are taken under the daemon's
// image lock, which the reaper's image loop holds too (#1146). The toolchain
// image has no reaper prefix, so its build needs no lease, but it must not run
// between the integration build and that lease. The image job holds its lease
// only across the build and the save: its toolchain work runs after the
// release.
const (
	ciDockerBuild    = "make docker-build"
	ciToolchainBuild = "make docker-build-toolchain"
	ciToolchainRun   = "in-toolchain-image.sh"
	ciLeaseCreate    = `docker create --pull never --name "$IT_LEASE"`
	ciTemplateLease  = `docker create --pull never --name "$lease"`
	ciLeaseRemove    = `docker rm "$IT_LEASE"`
	ciImageRemove    = "docker image rm"
	ciImageRetag     = "docker tag "
	ciNameImage      = "make -s it-image"
	// ciTakeLease, ciImageLock and ciImageUnlock are the calls of the
	// template's lease functions, which each step defines or sources.
	ciTakeLease   = "take_lease"
	ciImageLock   = "image_lock ||"
	ciImageUnlock = "image_unlock"
	ciDeclareFns  = "declare -f"
)

// ciCoupledBuild matches `make docker-build` itself, which builds the
// integration image and then the toolchain image in one call, so no lease
// can be taken between them.
var ciCoupledBuild = regexp.MustCompile(`make docker-build(\s|$)`)

// ciImageUse matches a use of IT_IMAGE itself, not of IT_IMAGE_ID or
// IT_IMAGE_IDENTITY.
var ciImageUse = regexp.MustCompile(`\$\{?IT_IMAGE\b`)

// ImageLeaseError reports a ci.yml job whose integration image is not held
// by a lease for the job's lifetime, or whose tag another job can remove.
type ImageLeaseError struct {
	File   string
	Line   int
	Job    string
	Reason string
}

func (e *ImageLeaseError) Error() string {
	return fmt.Sprintf("%s:%d: job %s: %s (#1146)", e.File, e.Line, e.Job, e.Reason)
}

// imageLeaseFindings reports, for every job of the workflow:
//   - an IT_IMAGE in the job env, or a step that uses IT_IMAGE before a step
//     names it with `make -s it-image`: a tag that is not the content's own
//     can name another tree's image;
//   - a `make docker-build*` step that does not lease the image after the
//     build, in the same step;
//   - a build that starts before the image an earlier build in the step
//     made is leased, `make docker-build` itself included: the reaper can
//     remove that image while the later build runs;
//   - a lease or a `docker tag` outside the image lock, where the reaper can
//     remove the tag between the job's check and its lease;
//   - a `docker image rm`: the content tag is shared, and only the reaper
//     removes it;
//   - toolchain work (its build or in-toolchain-image.sh) while the job holds
//     a lease, which spans only the build and the save;
//   - a lease that no `if: always()` step removes.
func imageLeaseFindings(wf ciWorkflow) []error {
	var findings []error
	jobs := mappingValue(wf.Doc, "jobs")
	for _, job := range wf.Jobs {
		finding := func(line int, reason string) {
			findings = append(findings, &ImageLeaseError{File: wf.File, Line: line, Job: job.ID, Reason: reason})
		}
		def := mappingValue(jobs, job.ID)
		named := false
		if image := mappingValue(mappingValue(def, "env"), "IT_IMAGE"); image != nil {
			finding(image.Line, "names IT_IMAGE in the job env, not with `make -s it-image` (ci-standard.md §9)")
			named = true
		}
		leased, holding := false, false
		for _, step := range job.Steps {
			if strings.Contains(step.Run, ciNameImage) {
				named = true
			} else if !named && ciImageUse.MatchString(step.Run) {
				finding(step.RunLine, "uses IT_IMAGE before a step names it with `make -s it-image`")
				named = true
			}
			built, locked, inFunction := false, false, false
			for i, line := range strings.Split(step.Run, "\n") {
				trimmed := strings.TrimSpace(line)
				// The template's function definitions run nothing where
				// they stand; their calls below are what count.
				if strings.HasSuffix(trimmed, "() {") {
					inFunction = true
				}
				if inFunction {
					inFunction = trimmed != "}"
					continue
				}
				if strings.HasPrefix(trimmed, "#") {
					continue
				}
				if holding && (strings.Contains(line, ciToolchainBuild) || strings.Contains(line, ciToolchainRun)) {
					finding(step.RunLine+i, "runs toolchain work while it holds the integration image lease, which spans only the build and the save")
				}
				switch {
				case ciCoupledBuild.MatchString(line):
					finding(step.RunLine+i, "builds the toolchain image after the integration image in one make call, before a lease can hold it")
					built = true
				case strings.Contains(line, ciDockerBuild):
					if built {
						finding(step.RunLine+i, "starts a build before the image built above it is leased")
					}
					built = built || !strings.Contains(line, ciToolchainBuild)
				case strings.Contains(line, ciLeaseCreate), strings.Contains(line, ciTemplateLease),
					strings.Contains(line, ciTakeLease) && !strings.Contains(line, ciDeclareFns):
					if !locked {
						finding(step.RunLine+i, "takes the lease outside the image lock, where the reaper can remove the tag first")
					}
					leased, holding, built = true, true, false
				case strings.HasPrefix(trimmed, ciImageLock):
					locked = true
				case trimmed == ciImageUnlock:
					locked = false
				case strings.Contains(line, ciImageRetag) && !locked:
					finding(step.RunLine+i, "re-tags the image outside the image lock, where the reaper can remove the tag first")
				case strings.Contains(line, ciLeaseRemove):
					holding = false
				case strings.Contains(line, ciImageRemove):
					finding(step.RunLine+i, "removes an image tag, which every job and run of its tree shares; only the reaper removes it")
				}
			}
			if built {
				finding(step.RunLine, "builds an image it does not lease after the build in the same step")
			}
		}
		if leased && !leaseRemovedAlways(def) {
			finding(job.Line, "leases an image and no `if: always()` step removes the lease")
		}
	}
	return findings
}

// leaseRemovedAlways reports whether a step of the job definition removes
// the lease under `if: always()`, so a failed or cancelled job releases it.
func leaseRemovedAlways(def *yaml.Node) bool {
	steps := mappingValue(def, "steps")
	if steps == nil {
		return false
	}
	for _, step := range steps.Content {
		cond, run := mappingValue(step, "if"), mappingValue(step, "run")
		if cond != nil && run != nil && strings.Contains(cond.Value, "always()") && strings.Contains(run.Value, ciLeaseRemove) {
			return true
		}
	}
	return false
}

func TestCIImagesAreLeasedForTheJobsLifetime(t *testing.T) {
	wf := loadCIWorkflow(t, repoRoot(t), ciWorkflowFile)
	for _, finding := range imageLeaseFindings(wf) {
		t.Error(finding)
	}
}

func TestImageLeaseFindingsRejectUnleasedAndUnlockedImages(t *testing.T) {
	const workflow = `name: CI
on:
  push:
jobs:
  image:
    runs-on: bigdisk
    env:
      IT_IMAGE: ci-it:${{ github.run_id }}
    steps:
      - name: Build
        run: |
          make docker-build-integration IT_IMAGE="$IT_IMAGE"
      - name: Tear down
        if: always()
        run: docker image rm "$IT_IMAGE"
  legs:
    runs-on: bigdisk
    steps:
      - name: Lease
        run: |
          docker create --pull never --name "$IT_LEASE" "$IT_IMAGE_ID" true
          docker tag "$IT_IMAGE_ID" "$IT_IMAGE"
      - name: Name
        run: echo "IT_IMAGE=$(make -s it-image)" >> "$GITHUB_ENV"
      - name: Tear down
        run: docker rm "$IT_LEASE"
  sound:
    runs-on: bigdisk
    strategy:
      matrix:
        leg: [1, 2]
    steps:
      - name: Name
        run: echo "IT_IMAGE=$(make -s it-image)" >> "$GITHUB_ENV"
      - name: Lease
        run: |
          image_lock() {
            docker create --pull never --name "$lock" "$lock:base" true && return 0
          }
          take_lease() {
            docker create --pull never --name "$lease" "$id" true || return 1
          }
          image_lock || exit 1
          if ! take_lease; then
            image_unlock
            make docker-build-it IT_IMAGE="$IT_IMAGE" BUILDX_CLIENT_LOAD=1
            image_lock || exit 1
            take_lease || exit 1
          fi
          docker tag "$IT_LEASE_ID" "$IT_IMAGE"
          image_unlock
      - name: Tear down
        if: always()
        run: docker rm "$IT_LEASE"
  coupled:
    runs-on: bigdisk
    steps:
      - name: Name
        run: echo "IT_IMAGE=$(make -s it-image)" >> "$GITHUB_ENV"
      - name: Build
        run: |
          make docker-build IT_IMAGE="$IT_IMAGE"
          image_lock || exit 1
          take_lease
      - name: Tear down
        if: always()
        run: docker rm "$IT_LEASE"
  interleaved:
    runs-on: bigdisk
    steps:
      - name: Name
        run: echo "IT_IMAGE=$(make -s it-image)" >> "$GITHUB_ENV"
      - name: Build
        run: |
          make docker-build-integration IT_IMAGE="$IT_IMAGE"
          make docker-build-toolchain
          image_lock || exit 1
          take_lease
      - name: Tear down
        if: always()
        run: docker rm "$IT_LEASE"
  held:
    runs-on: bigdisk
    steps:
      - name: Name
        run: echo "IT_IMAGE=$(make -s it-image)" >> "$GITHUB_ENV"
      - name: Build
        run: |
          make docker-build-integration IT_IMAGE="$IT_IMAGE"
          image_lock || exit 1
          take_lease
          image_unlock
      - name: Build the toolchain image
        run: make docker-build-toolchain
      - name: Lint
        run: scripts/in-toolchain-image.sh "$TOOLCHAIN_IMAGE" make lint
      - name: Tear down
        if: always()
        run: docker rm "$IT_LEASE"
  released:
    runs-on: bigdisk
    steps:
      - name: Name
        run: echo "IT_IMAGE=$(make -s it-image)" >> "$GITHUB_ENV"
      - name: Build
        run: |
          make docker-build-integration IT_IMAGE="$IT_IMAGE"
          image_lock || exit 1
          take_lease
          image_unlock
      - name: Release the lease
        if: always()
        run: docker rm "$IT_LEASE"
      - name: Build the toolchain image
        run: make docker-build-toolchain
      - name: Lint
        run: scripts/in-toolchain-image.sh "$TOOLCHAIN_IMAGE" make lint
  unnamed:
    runs-on: bigdisk
    steps:
      - name: Soak
        run: make integration-test IT_IMAGE="$IT_IMAGE"
      - name: Name
        run: echo "IT_IMAGE=$(make -s it-image)" >> "$GITHUB_ENV"
`
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, ".github", "workflows"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".github", "workflows", "ci.yml"), []byte(workflow), 0o644))

	findings := imageLeaseFindings(loadCIWorkflow(t, root, ".github/workflows/ci.yml"))
	var got []string
	for _, finding := range findings {
		var ile *ImageLeaseError
		require.ErrorAs(t, finding, &ile)
		got = append(got, fmt.Sprintf("%s:%d", ile.Job, ile.Line))
	}
	require.Equal(t, []string{
		"image:8", "image:12", "image:15",
		"legs:21", "legs:21", "legs:22", "legs:16",
		"coupled:62", "interleaved:76", "held:94", "held:96", "unnamed:122",
	}, got)
	require.Contains(t, findings[0].Error(), ".github/workflows/ci.yml:8: job image: names IT_IMAGE in the job env")
	require.Contains(t, findings[1].Error(), "ci.yml:12: job image: builds an image it does not lease")
	require.Contains(t, findings[2].Error(), "ci.yml:15: job image: removes an image tag")
	require.Contains(t, findings[3].Error(), "ci.yml:21: job legs: uses IT_IMAGE before a step names it")
	require.Contains(t, findings[4].Error(), "ci.yml:21: job legs: takes the lease outside the image lock")
	require.Contains(t, findings[5].Error(), "ci.yml:22: job legs: re-tags the image outside the image lock")
	require.Contains(t, findings[6].Error(), "ci.yml:16: job legs: leases an image and no `if: always()` step removes the lease")
	require.Contains(t, findings[7].Error(), "ci.yml:62: job coupled: builds the toolchain image after the integration image in one make call")
	require.Contains(t, findings[8].Error(), "ci.yml:76: job interleaved: starts a build before the image built above it is leased")
	require.Contains(t, findings[9].Error(), "ci.yml:94: job held: runs toolchain work while it holds the integration image lease")
	require.Contains(t, findings[10].Error(), "ci.yml:96: job held: runs toolchain work")
	require.Contains(t, findings[11].Error(), "ci.yml:122: job unnamed: uses IT_IMAGE before a step names it")
}

// A leg on another runner's daemon loads the image job's `docker save`. The
// load keeps the image but not its id, which is the config digest on the
// classic image store and the manifest digest on the containerd store (run
// 70938), so the leg leases what the load restored and compares the image
// job's identity, a hash of the layers' diff ids, which every store keeps.
// Its fallback build skips the warm build cache that took a leg past its
// timeout.
const (
	ciArtifactLoad    = "docker load -i"
	ciImageIDLease    = ciLeaseCreate + ` "$IT_IMAGE_ID"`
	ciLayerIdentity   = `docker image inspect -f '{{json .RootFS.Layers}}'`
	ciIdentityCompare = `= "$IT_IMAGE_IDENTITY" ]`
	ciIdentityOutput  = "image_identity=$("
	ciColdBuild       = "IT_WARM_CACHE=0"

	reasonImageIDLease      = "leases the image job's daemon-local IT_IMAGE_ID after the load; another image store gives the loaded image another id"
	reasonNoLayerCompare    = "does not compare the loaded image's layer identity with IT_IMAGE_IDENTITY"
	reasonIdentityNotLayers = "computes image_identity from something other than the layers' diff ids, which only those keep across image stores"
	reasonWarmFallback      = "builds the fallback image with the warm build cache, which took a leg past its timeout"
)

// legLoadFindings reports each way a workflow's artifact load or the
// identity it compares depends on the image store.
func legLoadFindings(wf ciWorkflow) []error {
	var findings []error
	for _, job := range wf.Jobs {
		finding := func(line int, reason string) {
			findings = append(findings, &ImageLeaseError{File: wf.File, Line: line, Job: job.ID, Reason: reason})
		}
		for _, step := range job.Steps {
			loads := strings.Contains(step.Run, ciArtifactLoad)
			for i, line := range strings.Split(step.Run, "\n") {
				switch {
				case strings.Contains(line, ciIdentityOutput) && !strings.Contains(line, ciLayerIdentity):
					finding(step.RunLine+i, reasonIdentityNotLayers)
				case loads && strings.Contains(line, ciImageIDLease):
					finding(step.RunLine+i, reasonImageIDLease)
				case loads && strings.Contains(line, dockerBuildIt) && !strings.Contains(line, ciColdBuild):
					finding(step.RunLine+i, reasonWarmFallback)
				}
			}
			if loads && (!strings.Contains(step.Run, ciLayerIdentity) || !strings.Contains(step.Run, ciIdentityCompare)) {
				finding(step.RunLine, reasonNoLayerCompare)
			}
		}
	}
	return findings
}

func TestCILegsLeaseTheImageTheirLoadRestored(t *testing.T) {
	wf := loadCIWorkflow(t, repoRoot(t), ciWorkflowFile)
	for _, finding := range legLoadFindings(wf) {
		t.Error(finding)
	}
}

func TestLegLoadFindingsRejectStoreDependentLoads(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), ciWorkflowFile))
	require.NoError(t, err)
	workflow := string(data)

	cases := []struct {
		name, old, new, reason string
	}{
		{
			name:   "lease by the image job's id",
			old:    `"$IT_LEASE" "$loaded_id"`,
			new:    `"$IT_LEASE" "$IT_IMAGE_ID"`,
			reason: reasonImageIDLease,
		},
		{
			name:   "compare the daemon-local id",
			old:    `[ "$loaded_identity" = "$IT_IMAGE_IDENTITY" ]`,
			new:    `[ "$loaded_id" = "$IT_IMAGE_ID" ]`,
			reason: reasonNoLayerCompare,
		},
		{
			name:   "hash the loaded image's id",
			old:    `'{{json .RootFS.Layers}}' "$loaded_id"`,
			new:    `'{{.Id}}' "$loaded_id"`,
			reason: reasonNoLayerCompare,
		},
		{
			name:   "image job publishes its id as the identity",
			old:    `'{{json .RootFS.Layers}}' "$image_id"`,
			new:    `'{{.Id}}' "$image_id"`,
			reason: reasonIdentityNotLayers,
		},
		{
			name:   "fallback build warms the cache",
			old:    "BUILDX_CLIENT_LOAD=1 " + ciColdBuild,
			new:    "BUILDX_CLIENT_LOAD=1",
			reason: reasonWarmFallback,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, 1, strings.Count(workflow, tc.old), "the workflow no longer carries %q", tc.old)
			mutated := strings.Replace(workflow, tc.old, tc.new, 1)
			wf, err := parseCIWorkflow(ciWorkflowFile, []byte(mutated))
			require.NoError(t, err)

			findings := legLoadFindings(wf)
			require.Len(t, findings, 1)
			var lease *ImageLeaseError
			require.ErrorAs(t, findings[0], &lease)
			require.Equal(t, tc.reason, lease.Reason)
		})
	}
}

// ImageArchiveError is a ci.yml step that leaves the integration image's
// `docker save` archive where the checkout copy of every toolchain step, or
// a build context, picks it up (#1272).
type ImageArchiveError struct {
	File   string
	Line   int
	Job    string
	Reason string
}

func (e *ImageArchiveError) Error() string {
	return fmt.Sprintf("%s:%d: job %s: %s (#1272)", e.File, e.Line, e.Job, e.Reason)
}

const (
	ciArchive       = "it-image.tar"
	ciArchiveSave   = `docker save -o "$RUNNER_TEMP/it-image.tar"`
	ciArchiveRemove = `"$RUNNER_TEMP/it-image.tar"`
	ciArchiveCopy   = `IN_IMAGE_COPY="$RUNNER_TEMP/it-image.tar:`
	ciArchiveTrivy  = "trivy image (integration image)"
)

// ciArchiveTemp is a path to the archive under the runner's temp directory.
var ciArchiveTemp = regexp.MustCompile(`(\$\{\{ *runner\.temp *\}\}|\$\{?RUNNER_TEMP\}?)/([\w.-]+/)*it-image\.tar`)

// imageArchiveFindings lists the steps that name it-image.tar outside
// $RUNNER_TEMP, give it to a toolchain step other than the trivy image step,
// or save it with no `if: always()` step removing it.
func imageArchiveFindings(wf ciWorkflow) []error {
	var findings []error
	jobs := mappingValue(wf.Doc, "jobs")
	for _, job := range wf.Jobs {
		finding := func(line int, reason string) {
			findings = append(findings, &ImageArchiveError{File: wf.File, Line: line, Job: job.ID, Reason: reason})
		}
		steps := mappingValue(mappingValue(jobs, job.ID), "steps")
		if steps == nil {
			continue
		}
		saved, removed := false, false
		for _, step := range steps.Content {
			var name, run, path string
			if node := mappingValue(step, "name"); node != nil {
				name = node.Value
			}
			if node := mappingValue(step, "run"); node != nil {
				run = node.Value
			}
			if node := mappingValue(mappingValue(step, "with"), "path"); node != nil {
				path = node.Value
			}
			for _, text := range []string{run, path} {
				if strings.Count(text, ciArchive) > len(ciArchiveTemp.FindAllString(text, -1)) {
					finding(step.Line, "names it-image.tar outside $RUNNER_TEMP, where the checkout copy and the build context pick it up")
				}
			}
			toolchain := strings.Contains(run, ciToolchainRun)
			if toolchain && strings.Contains(run, ciArchive) && name != ciArchiveTrivy {
				finding(step.Line, "gives it-image.tar to a toolchain step other than "+ciArchiveTrivy)
			}
			if name == ciArchiveTrivy && (!toolchain || !strings.Contains(run, ciArchiveCopy)) {
				finding(step.Line, "runs trivy without IN_IMAGE_COPY of $RUNNER_TEMP/it-image.tar")
			}
			saved = saved || strings.Contains(run, ciArchiveSave)
			cond := mappingValue(step, "if")
			if cond != nil && strings.Contains(cond.Value, "always()") && strings.Contains(run, "rm -f") && strings.Contains(run, ciArchiveRemove) {
				removed = true
			}
		}
		if saved && !removed {
			finding(job.Line, "saves it-image.tar and no `if: always()` step removes it")
		}
	}
	return findings
}

func TestCIKeepsTheImageArchiveOutOfTheCheckout(t *testing.T) {
	root := repoRoot(t)
	for _, finding := range imageArchiveFindings(loadCIWorkflow(t, root, ciWorkflowFile)) {
		t.Error(finding)
	}
	data, err := os.ReadFile(filepath.Join(root, ciWorkflowFile))
	require.NoError(t, err)
	require.Contains(t, string(data), ciArchiveSave, "the trivy save step writes the archive under $RUNNER_TEMP")
	require.Contains(t, string(data), "name: "+ciArchiveTrivy)
}

func TestImageArchiveFindingsRejectAnArchiveInTheCheckout(t *testing.T) {
	const workflow = `name: CI
on:
  push:
jobs:
  relative:
    runs-on: bigdisk
    steps:
      - name: Save the integration image for trivy
        run: docker save -o it-image.tar "$IT_IMAGE"
      - name: trivy image (integration image)
        run: scripts/in-toolchain-image.sh "$TOOLCHAIN_IMAGE" trivy image --input it-image.tar
      - name: Tear down
        if: always()
        run: rm -f it-image.tar
  leaky:
    runs-on: bigdisk
    steps:
      - name: Save the integration image for trivy
        run: docker save -o "$RUNNER_TEMP/it-image.tar" "$IT_IMAGE"
      - name: Lint
        run: IN_IMAGE_COPY="$RUNNER_TEMP/it-image.tar:/src/x.tar" scripts/in-toolchain-image.sh "$TOOLCHAIN_IMAGE" make lint
      - name: Upload
        with:
          path: it-image.tar
  sound:
    runs-on: bigdisk
    steps:
      - name: Save the integration image for trivy
        run: docker save -o "$RUNNER_TEMP/it-image.tar" "$IT_IMAGE"
      - name: trivy image (integration image)
        run: |
          IN_IMAGE_COPY="$RUNNER_TEMP/it-image.tar:/src/integration-image.tar" \
          scripts/in-toolchain-image.sh "$TOOLCHAIN_IMAGE" trivy image --input /src/integration-image.tar
      - name: Upload
        with:
          path: ${{ runner.temp }}/it-image.tar
      - name: Tear down
        if: always()
        run: rm -f "$RUNNER_TEMP/gomodauth.env" "$RUNNER_TEMP/it-image.tar"
`
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, ".github", "workflows"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".github", "workflows", "ci.yml"), []byte(workflow), 0o644))

	findings := imageArchiveFindings(loadCIWorkflow(t, root, ".github/workflows/ci.yml"))
	var got []string
	for _, finding := range findings {
		var iae *ImageArchiveError
		require.ErrorAs(t, finding, &iae)
		got = append(got, fmt.Sprintf("%s:%d", iae.Job, iae.Line))
	}
	require.Equal(t, []string{
		"relative:8", "relative:10", "relative:10", "relative:12",
		"leaky:20", "leaky:22", "leaky:15",
	}, got)
	require.Contains(t, findings[0].Error(), "ci.yml:8: job relative: names it-image.tar outside $RUNNER_TEMP")
	require.Contains(t, findings[2].Error(), "ci.yml:10: job relative: runs trivy without IN_IMAGE_COPY")
	require.Contains(t, findings[3].Error(), "ci.yml:12: job relative: names it-image.tar outside $RUNNER_TEMP")
	require.Contains(t, findings[4].Error(), "ci.yml:20: job leaky: gives it-image.tar to a toolchain step other than trivy image (integration image)")
	require.Contains(t, findings[5].Error(), "ci.yml:22: job leaky: names it-image.tar outside $RUNNER_TEMP")
	require.Contains(t, findings[6].Error(), "ci.yml:15: job leaky: saves it-image.tar and no `if: always()` step removes it")
}
