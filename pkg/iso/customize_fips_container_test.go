// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package iso

import (
	"context"
	"errors"
	"strings"
	"testing"
)

var errFIPSBuilder = errors.New("exit status 1")

// recordingContainerRuntime records each runtime invocation as one line and
// fails the first whose subcommand is failOn.
type recordingContainerRuntime struct {
	calls  []string
	failOn string
}

func (r *recordingContainerRuntime) run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if r.failOn != "" && args[0] == r.failOn {
		return nil, errFIPSBuilder
	}
	return nil, nil
}

func TestRunBuilderContainerCopiesOutputWithoutBindMounts(t *testing.T) {
	rec := &recordingContainerRuntime{}
	out := t.TempDir()
	if err := runBuilderContainer(context.Background(), rec.run, "docker", "FIPS kernel", "kernel-img:1", out, "make build"); err != nil {
		t.Fatal(err)
	}

	var verbs []string
	for _, call := range rec.calls {
		verbs = append(verbs, strings.Fields(call)[1])
		// "rm -f -v" removes the anonymous volumes; only create/start could mount.
		if strings.Contains(call, " create ") && strings.Contains(call, " -v ") {
			t.Errorf("host bind mount in %q", call)
		}
	}
	if got := strings.Join(verbs, ","); got != "create,start,cp,rm" {
		t.Fatalf("calls = %s, want create,start,cp,rm", got)
	}
	if !strings.HasSuffix(rec.calls[0], " kernel-img:1") {
		t.Errorf("create = %q", rec.calls[0])
	}
	if !strings.Contains(rec.calls[2], ":/output/. "+out) {
		t.Errorf("cp out = %q", rec.calls[2])
	}
}

func TestRunBuilderContainerReportsTheBuildHint(t *testing.T) {
	rec := &recordingContainerRuntime{failOn: "start"}
	err := runBuilderContainer(context.Background(), rec.run, "docker", "FIPS kernel", "kernel-img:1", t.TempDir(), "make build")

	var cmdErr *CommandOutputError
	if !errors.As(err, &cmdErr) {
		t.Fatalf("error = %T %v, want *CommandOutputError", err, err)
	}
	if !errors.Is(err, errFIPSBuilder) {
		t.Errorf("error %v does not wrap the runtime failure", err)
	}
	if !strings.Contains(cmdErr.Msg, "FIPS kernel using container kernel-img:1") || !strings.Contains(cmdErr.Detail, "make build") {
		t.Errorf("error = %+v", cmdErr)
	}
	if last := rec.calls[len(rec.calls)-1]; !strings.Contains(last, " rm -f -v ") {
		t.Errorf("failed build left its container behind; last call %q", last)
	}
}
