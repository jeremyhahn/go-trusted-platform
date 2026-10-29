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
)

// A CI image tag is safe from the stale-stack reaper and from other jobs'
// teardowns only while a container names its image (#1146). The reaper
// removes a prefixed image no container names once its Created time is past
// the min-age, and a warm BuildKit cache can hand back an image whose Created
// time is far older than the job that built it. `docker image rm <tag>`
// untags an image that has another tag even while containers use it, so a
// tag shared by a matrix's jobs can be removed under a job that still runs
// in it. The toolchain image has no reaper prefix, so its build needs no
// lease, but it must not run between the integration build and that lease.
const (
	ciDockerBuild    = "make docker-build"
	ciToolchainBuild = "make docker-build-toolchain"
	ciLeaseCreate    = `docker create --pull never --name "$IT_LEASE"`
	ciLeaseRemove    = `docker rm "$IT_LEASE"`
	ciImageRemove    = "docker image rm"
	// ciClaimCreate claims the run's images for scripts/reap-stale-ci-stacks.sh,
	// which keeps every image of a run with a live claim (#1146).
	ciClaimCreate = `docker volume create --label "ci.claim=${{ github.run_id }}-${{ github.run_attempt }}" "$IT_CLAIM"`
)

// ciCoupledBuild matches `make docker-build` itself, which builds the
// integration image and then the toolchain image in one call, so no lease
// can be taken between them.
var ciCoupledBuild = regexp.MustCompile(`make docker-build(\s|$)`)

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
//   - a job with an IT_IMAGE that uses it in a step before the step that
//     claims its run (ciClaimCreate): the reaper keeps a claimed run's
//     images, and only the claim covers a tag before its lease names it;
//   - a `make docker-build*` step that does not lease the image after the
//     build, in the same step;
//   - a build that starts before the image an earlier build in the step
//     made is leased, `make docker-build` itself included: the reaper can
//     remove that image while the later build runs;
//   - a lease that no step removes, or a `docker image rm` before the lease
//     is removed (refused while the lease names the image, so it is left);
//   - a matrix job whose IT_IMAGE does not name the matrix, so its jobs share
//     the tag their compose stacks run under.
func imageLeaseFindings(wf ciWorkflow) []error {
	var findings []error
	jobs := mappingValue(wf.Doc, "jobs")
	for _, job := range wf.Jobs {
		finding := func(line int, reason string) {
			findings = append(findings, &ImageLeaseError{File: wf.File, Line: line, Job: job.ID, Reason: reason})
		}
		def := mappingValue(jobs, job.ID)
		// A job with an image claims its run before any step touches the
		// image: a tag published before the claim is one the reaper can take
		// before the lease names it.
		claimed := mappingValue(mappingValue(def, "env"), "IT_IMAGE") == nil
		leased, released := false, false
		for _, step := range job.Steps {
			if strings.Contains(step.Run, ciClaimCreate) {
				claimed = true
			} else if !claimed && strings.Contains(step.Run, "IT_IMAGE") {
				finding(step.RunLine, "uses the image before claiming its run, so a reaper can remove the tag before the lease names it")
				claimed = true
			}
			built := false
			for i, line := range strings.Split(step.Run, "\n") {
				switch {
				case ciCoupledBuild.MatchString(line):
					finding(step.RunLine+i, "builds the toolchain image after the integration image in one make call, before a lease can hold it")
					built = true
				case strings.Contains(line, ciDockerBuild):
					if built {
						finding(step.RunLine+i, "starts a build before the image built above it is leased")
					}
					built = built || !strings.Contains(line, ciToolchainBuild)
				case strings.Contains(line, ciLeaseCreate):
					leased, built = true, false
				case strings.Contains(line, ciLeaseRemove):
					released = true
				case strings.Contains(line, ciImageRemove) && leased && !released:
					finding(step.RunLine+i, "removes the image before its lease, which keeps it")
				}
			}
			if built {
				finding(step.RunLine, "builds an image it does not lease after the build in the same step")
			}
		}
		if leased && !released {
			finding(job.Line, "leases an image and never removes the lease")
		}
		if mappingValue(mappingValue(def, "strategy"), "matrix") == nil {
			continue
		}
		if image := mappingValue(mappingValue(def, "env"), "IT_IMAGE"); image != nil && !strings.Contains(image.Value, "matrix.") {
			finding(image.Line, "IT_IMAGE does not name the matrix, so its jobs share the tag their compose stacks run under")
		}
	}
	return findings
}

func TestCIImagesAreLeasedForTheJobsLifetime(t *testing.T) {
	wf := loadCIWorkflow(t, repoRoot(t), ciWorkflowFile)
	for _, finding := range imageLeaseFindings(wf) {
		t.Error(finding)
	}
}

func TestImageLeaseFindingsRejectUnleasedAndSharedImages(t *testing.T) {
	const workflow = `name: CI
on:
  push:
jobs:
  image:
    runs-on: bigdisk
    steps:
      - name: Build
        run: |
          make docker-build-integration IT_IMAGE="$IT_IMAGE"
      - name: Tear down
        run: docker image rm "$IT_IMAGE"
  legs:
    runs-on: bigdisk
    strategy:
      matrix:
        leg: [1, 2]
    env:
      IT_IMAGE: ci-it:1-1-legs
    steps:
      - name: Lease
        run: docker create --pull never --name "$IT_LEASE" "$IT_IMAGE_ID" true
      - name: Tear down
        run: |
          docker image rm "$IT_IMAGE"
          docker rm "$IT_LEASE"
  leaked:
    runs-on: bigdisk
    steps:
      - name: Build
        run: |
          make docker-build-it IT_IMAGE="$IT_IMAGE" BUILDX_CLIENT_LOAD=1
          docker create --pull never --name "$IT_LEASE" "$IT_IMAGE" true
  sound:
    runs-on: bigdisk
    strategy:
      matrix:
        leg: [1, 2]
    env:
      IT_IMAGE: ci-it:1-1-leg${{ matrix.leg }}
    steps:
      - name: Claim
        run: docker volume create --label "ci.claim=${{ github.run_id }}-${{ github.run_attempt }}" "$IT_CLAIM"
      - name: Build
        run: |
          make docker-build-it IT_IMAGE="$IT_IMAGE" BUILDX_CLIENT_LOAD=1
          docker create --pull never --name "$IT_LEASE" "$IT_IMAGE" true
      - name: Tear down
        run: |
          docker rm "$IT_LEASE"
          docker image rm "$IT_IMAGE"
  coupled:
    runs-on: bigdisk
    steps:
      - name: Build
        run: |
          make docker-build IT_IMAGE="$IT_IMAGE"
          docker create --pull never --name "$IT_LEASE" "$IT_IMAGE" true
      - name: Tear down
        run: docker rm "$IT_LEASE"
  interleaved:
    runs-on: bigdisk
    steps:
      - name: Build
        run: |
          make docker-build-integration IT_IMAGE="$IT_IMAGE"
          make docker-build-toolchain
          docker create --pull never --name "$IT_LEASE" "$IT_IMAGE" true
      - name: Tear down
        run: docker rm "$IT_LEASE"
  split:
    runs-on: bigdisk
    steps:
      - name: Build
        run: |
          make docker-build-integration IT_IMAGE="$IT_IMAGE"
          docker create --pull never --name "$IT_LEASE" "$IT_IMAGE" true
          make docker-build-toolchain
      - name: Tear down
        run: docker rm "$IT_LEASE"
  unclaimed:
    runs-on: bigdisk
    env:
      IT_IMAGE: ci-it:1-1-soak
    steps:
      - name: Soak
        run: make integration-test IT_IMAGE="$IT_IMAGE"
      - name: Claim
        run: docker volume create --label "ci.claim=${{ github.run_id }}-${{ github.run_attempt }}" "$IT_CLAIM"
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
	require.Equal(t, []string{"image:10", "legs:22", "legs:25", "legs:19", "leaked:27", "coupled:57", "interleaved:67", "unclaimed:87"}, got)
	require.Contains(t, findings[0].Error(), ".github/workflows/ci.yml:10: job image: builds an image it does not lease")
	require.Contains(t, findings[1].Error(), "ci.yml:22: job legs: uses the image before claiming its run")
	require.Contains(t, findings[5].Error(), "ci.yml:57: job coupled: builds the toolchain image after the integration image in one make call")
	require.Contains(t, findings[6].Error(), "ci.yml:67: job interleaved: starts a build before the image built above it is leased")
	require.Contains(t, findings[7].Error(), "ci.yml:87: job unclaimed: uses the image before claiming its run")
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
