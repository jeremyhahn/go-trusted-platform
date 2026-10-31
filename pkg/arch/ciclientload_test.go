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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The CI jobs build the integration image on the project's named BuildKit
// builder, whose node need not run on the daemon the job's `docker` talks to
// (run 68044). `--load` imports the image into the builder node's daemon, so
// the job's own `docker image inspect`, `docker save` or `docker create` then
// finds no image there. BUILDX_CLIENT_LOAD=1 streams the image to the job's
// `docker load` instead (#1146).
const (
	dockerBuildIt    = "make docker-build-it"
	buildxClientLoad = "BUILDX_CLIENT_LOAD=1"
)

// ClientLoadError reports a ci.yml `make docker-build-it` that loads the
// image into the builder's daemon rather than the job's.
type ClientLoadError struct {
	File string
	Line int
	Job  string
}

func (e *ClientLoadError) Error() string {
	return fmt.Sprintf("%s:%d: job %s runs %#q without %s: --load imports the image into the builder node's daemon, which need not be the one this job's docker talks to (#1146)",
		e.File, e.Line, e.Job, dockerBuildIt, buildxClientLoad)
}

// clientLoadFindings reports every `make docker-build-it` line of the
// workflow's run scripts that does not set BUILDX_CLIENT_LOAD=1.
func clientLoadFindings(wf ciWorkflow) []error {
	var findings []error
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			for i, line := range strings.Split(step.Run, "\n") {
				if strings.Contains(line, dockerBuildIt) && !strings.Contains(line, buildxClientLoad) {
					findings = append(findings, &ClientLoadError{File: wf.File, Line: step.RunLine + i, Job: job.ID})
				}
			}
		}
	}
	return findings
}

func TestCIImageBuildsLoadIntoTheJobsDaemon(t *testing.T) {
	wf := loadCIWorkflow(t, repoRoot(t), ciWorkflowFile)
	for _, finding := range clientLoadFindings(wf) {
		t.Error(finding)
	}
}

func TestClientLoadFindingsRejectABuilderLoad(t *testing.T) {
	const workflow = `name: CI
on:
  push:
jobs:
  image:
    runs-on: bigdisk
    steps:
      - name: Build
        run: |
          echo building
          make docker-build-it IT_IMAGE="$IT_IMAGE"
          docker save -o it.tar "$IT_IMAGE"
  leg:
    runs-on: bigdisk
    steps:
      - name: Build
        run: make docker-build-it IT_IMAGE="$IT_IMAGE" BUILDX_CLIENT_LOAD=1
`
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, ".github", "workflows"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".github", "workflows", "ci.yml"), []byte(workflow), 0o644))

	findings := clientLoadFindings(loadCIWorkflow(t, root, ".github/workflows/ci.yml"))
	require.Len(t, findings, 1)
	var cle *ClientLoadError
	require.ErrorAs(t, findings[0], &cle)
	require.Equal(t, "image", cle.Job)
	require.Equal(t, 11, cle.Line)
	require.Contains(t, findings[0].Error(), ".github/workflows/ci.yml:11:")
}
