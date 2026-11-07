package runner

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var errBoom = errors.New("boom")

// recorder is a Runner that logs each call as one line and fails the first
// call whose joined arguments contain failOn.
type recorder struct {
	calls  []string
	failOn string
}

func (r *recorder) run(_ context.Context, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)
	if r.failOn != "" && strings.Contains(line, r.failOn) {
		return []byte("failed"), errBoom
	}
	return nil, nil
}

func (r *recorder) verbs() []string {
	verbs := make([]string, 0, len(r.calls))
	for _, call := range r.calls {
		verbs = append(verbs, strings.Fields(call)[1])
	}
	return verbs
}

func sampleContainer(t *testing.T) Container {
	t.Helper()
	return Container{
		Image:      "builder:1",
		CreateArgs: []string{"-e", "A=1", "-v", "cache:/build/src"},
		Command:    []string{"build", "--fast"},
		In:         []Copy{{Host: "/host/keys", Container: "/keys"}},
		Out:        []Copy{{Host: filepath.Join(t.TempDir(), "out"), Container: "/output"}},
	}
}

func TestContainerRunSequence(t *testing.T) {
	rec := &recorder{}
	c := sampleContainer(t)
	if err := c.Run(context.Background(), rec.run, "docker"); err != nil {
		t.Fatal(err)
	}

	want := []string{"create", "cp", "start", "cp", "rm"}
	if got := rec.verbs(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("calls = %v, want %v", got, want)
	}
	create := rec.calls[0]
	for _, part := range []string{"-e A=1", "-v cache:/build/src", "builder:1 build --fast"} {
		if !strings.Contains(create, part) {
			t.Errorf("create %q missing %q", create, part)
		}
	}
	if !strings.HasSuffix(rec.calls[1], "/host/keys/. "+containerOf(rec.calls[0])+":/keys") {
		t.Errorf("cp in = %q", rec.calls[1])
	}
	if !strings.Contains(rec.calls[3], containerOf(rec.calls[0])+":/output/. ") {
		t.Errorf("cp out = %q", rec.calls[3])
	}
	if !strings.HasSuffix(rec.calls[4], "rm -f -v "+containerOf(rec.calls[0])) {
		t.Errorf("rm = %q", rec.calls[4])
	}
}

func TestContainerRunHasNoHostBindMount(t *testing.T) {
	rec := &recorder{}
	if err := sampleContainer(t).Run(context.Background(), rec.run, "docker"); err != nil {
		t.Fatal(err)
	}
	for _, call := range rec.calls {
		if strings.Contains(call, " --mount") {
			t.Errorf("host --mount in %q", call)
		}
		fields := strings.Fields(call)
		for i, f := range fields {
			if f == "-v" && strings.HasPrefix(fields[i+1], "/") && strings.Contains(fields[i+1], ":") {
				t.Errorf("host bind mount %q in %q", fields[i+1], call)
			}
		}
	}
}

func TestContainerRunFailureCopiesNothingOutAndStillRemoves(t *testing.T) {
	rec := &recorder{failOn: "start -a"}
	c := sampleContainer(t)
	err := c.Run(context.Background(), rec.run, "docker")

	var cErr *ContainerError
	if !errors.As(err, &cErr) || !errors.Is(err, errBoom) {
		t.Fatalf("error = %T %v, want *ContainerError wrapping the runner error", err, err)
	}
	if cErr.Step != "running the container" {
		t.Errorf("step = %q", cErr.Step)
	}
	want := []string{"create", "cp", "start", "rm"}
	if got := rec.verbs(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("calls = %v, want %v (no cp out after a failed run)", got, want)
	}
}

func TestContainerRunStepFailures(t *testing.T) {
	tests := map[string]struct {
		failOn string
		step   string
		verbs  string
	}{
		"create": {failOn: "create", step: "creating the container", verbs: "create"},
		"cp in":  {failOn: "/host/keys", step: "copying /host/keys in", verbs: "create,cp,rm"},
		"cp out": {failOn: ":/output", step: "copying /output out", verbs: "create,cp,start,cp,rm"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{failOn: tt.failOn}
			err := sampleContainer(t).Run(context.Background(), rec.run, "docker")
			var cErr *ContainerError
			if !errors.As(err, &cErr) || cErr.Step != tt.step {
				t.Fatalf("error = %v, want step %q", err, tt.step)
			}
			if got := strings.Join(rec.verbs(), ","); got != tt.verbs {
				t.Errorf("calls = %s, want %s", got, tt.verbs)
			}
		})
	}
}

// An output directory that cannot be created on the host fails the run before
// anything is copied out, and the container is still removed.
func TestContainerRunOutputDirectoryFailure(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	host := filepath.Join(file, "out")
	c := sampleContainer(t)
	c.Out = []Copy{{Host: host, Container: "/output"}}

	rec := &recorder{}
	err := c.Run(context.Background(), rec.run, "docker")

	var cErr *ContainerError
	if !errors.As(err, &cErr) || cErr.Step != "creating "+host {
		t.Fatalf("error = %v, want step %q", err, "creating "+host)
	}
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) {
		t.Errorf("error = %v, want the wrapped *fs.PathError", err)
	}
	if got := strings.Join(rec.verbs(), ","); got != "create,cp,start,rm" {
		t.Errorf("calls = %s, want create,cp,start,rm", got)
	}
}

func TestContainerErrorMessage(t *testing.T) {
	tests := map[string]struct {
		err  *ContainerError
		want string
	}{
		"create": {
			err:  &ContainerError{Step: "creating the container", Err: errBoom},
			want: "runner: creating the container: " + errBoom.Error(),
		},
		"cp out": {
			err:  &ContainerError{Step: "copying /output out", Err: errors.New("no such container")},
			want: "runner: copying /output out: no such container",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
			if !errors.Is(tt.err, tt.err.Err) {
				t.Errorf("errors.Is does not reach the wrapped error")
			}
		})
	}
}

func TestContainerRunReportsRemovalFailure(t *testing.T) {
	rec := &recorder{failOn: "rm -f"}
	err := sampleContainer(t).Run(context.Background(), rec.run, "docker")
	var cErr *ContainerError
	if !errors.As(err, &cErr) || cErr.Step != "removing the container" {
		t.Fatalf("error = %v, want the removal failure", err)
	}
}

func TestContainerRunRemovesAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var removeCtxErr error
	run := func(c context.Context, _ string, args ...string) ([]byte, error) {
		switch args[0] {
		case "start":
			cancel()
			return nil, c.Err()
		case "rm":
			removeCtxErr = c.Err()
		}
		return nil, nil
	}
	if err := sampleContainer(t).Run(ctx, run, "docker"); err == nil {
		t.Fatal("cancelled run succeeded")
	}
	if removeCtxErr != nil {
		t.Errorf("rm ran with a cancelled context: %v", removeCtxErr)
	}
}

func TestContainerNamesAreUnique(t *testing.T) {
	a, err := containerName()
	if err != nil {
		t.Fatal(err)
	}
	b, err := containerName()
	if err != nil {
		t.Fatal(err)
	}
	if a == b || !strings.HasPrefix(a, "builder-") {
		t.Errorf("names %q %q", a, b)
	}
}

// containerOf extracts the name given to `create --name`.
func containerOf(create string) string {
	fields := strings.Fields(create)
	for i, f := range fields {
		if f == "--name" {
			return fields[i+1]
		}
	}
	return ""
}
