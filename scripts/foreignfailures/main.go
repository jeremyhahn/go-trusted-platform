// Command foreignfailures decides whether a failed integration suite failed
// only where the foreign-failure baseline says it may (Company Agent ruling
// 125). It reads the suite's combined output, as make integration-test
// prints it, and the baseline (.github/foreign-failures.tsv), and exits 0
// only when every failed leaf test is listed. Anything it cannot attribute to
// a leaf test (a build failure, a panic or timeout, a package that failed with
// no failing test, a target that failed outside go test, a log without the
// runner's closing summary) gates: it fails closed.
//
// -job fips decides the FIPS job's `make test` log against its own baseline,
// .github/foreign-failures-fips.tsv, which lists panics only. A panic is
// foreign only when the panicking test, the panic message and a stack frame
// are all one row's and nothing else in the run failed. A panic kills its
// test binary, so each attributed package's other top-level tests then run
// again by explicit name under the same fips140=only environment and build
// tags, and the job passes only when they pass.
//
// Usage:
//
//	foreignfailures [-baseline .github/foreign-failures.tsv] <suite log>
//	foreignfailures -job fips -tags "<make -s print-build-tags WITH_FIPS=1>" -skip-tests "<TEST_SKIP>" <make test log>
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// Exit codes.
const (
	exitOK     = 0 // every failure is in the baseline
	exitGating = 1 // a failure the baseline does not list, or cannot be attributed
	exitUsage  = 2 // the arguments, the baseline or the log cannot be read
	exitOutput = 3 // the output could not be written
)

// defaultModule is this repository's module path; baseline packages are
// relative to it.
const defaultModule = "github.com/jeremyhahn/go-trusted-platform"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main with its inputs and outputs injected.
func run(args []string, stdout, stderr io.Writer) int {
	return runIn(hostEnvironment(), args, stdout, stderr)
}

// environment is what a job reaches outside its log and baseline: the
// process environment and the go command a FIPS rerun runs.
type environment struct {
	getenv func(string) string
	goCmd  func(goBin string) goCommand
}

// hostEnvironment is the real process environment and go binary.
func hostEnvironment() environment {
	return environment{getenv: os.Getenv, goCmd: execGo}
}

// options are a run's flags.
type options struct {
	module    string
	tags      string
	skipTests string
	goBin     string
}

// job is one CI job's baseline file and check. Each job reads only its own
// row format, so a row of one job's file never excuses the other's failure.
type job struct {
	defaultBaseline string
	loadBaseline    func(path string) (*baseline, error)
	check           func(ctx context.Context, env environment, opts options, b *baseline, logPath string, stdout io.Writer) (*verdict, error)
	failedLine      string
	passedLine      string
}

// jobs maps each -job value to its job.
var jobs = map[string]job{
	"integration": {
		defaultBaseline: ".github/foreign-failures.tsv",
		loadBaseline:    loadBaseline,
		check:           checkIntegration,
		failedLine:      "the integration suite failed outside the foreign-failure baseline",
		passedLine:      "every integration failure is in the foreign-failure baseline",
	},
	"fips": {
		defaultBaseline: ".github/foreign-failures-fips.tsv",
		loadBaseline:    loadFIPSBaseline,
		check:           checkFIPS,
		failedLine:      "the FIPS unit tests failed outside the FIPS foreign-failure baseline",
		passedLine:      "every FIPS failure is in the FIPS foreign-failure baseline, and every rerun passed under fips140=only",
	},
}

// runIn parses args, checks the log against the job's baseline and
// reports the verdict.
func runIn(env environment, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("foreignfailures", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jobName := flags.String("job", "integration", "the CI job whose log this is: integration or fips")
	baselinePath := flags.String("baseline", "", "the job's foreign-failure baseline (default: the job's file under .github/)")
	module := flags.String("module", defaultModule, "the module path go test prints in front of each package")
	tags := flags.String("tags", "", "fips: the run's build tags, for the reruns (make -s print-build-tags WITH_FIPS=1)")
	skipTests := flags.String("skip-tests", "", "fips: the run's go test -skip pattern; the reruns leave out the top-level tests it matches")
	goBin := flags.String("go", "go", "fips: the go command the reruns run")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 1 {
		return fail(stderr, ErrUsage)
	}
	j, ok := jobs[*jobName]
	if !ok {
		return fail(stderr, &JobError{Job: *jobName})
	}
	if *baselinePath == "" {
		*baselinePath = j.defaultBaseline
	}
	b, err := j.loadBaseline(*baselinePath)
	if err != nil {
		return fail(stderr, err)
	}
	opts := options{module: *module, tags: *tags, skipTests: *skipTests, goBin: *goBin}
	v, err := j.check(context.Background(), env, opts, b, flags.Arg(0), stdout)
	if err != nil {
		return fail(stderr, err)
	}
	return report(v, j, stdout, stderr)
}

// checkIntegration decides an Integration suite log.
func checkIntegration(_ context.Context, _ environment, opts options, b *baseline, logPath string, _ io.Writer) (*verdict, error) {
	log, err := readSuiteLog(logPath, opts.module)
	if err != nil {
		return nil, err
	}
	return decide(log, b), nil
}

// checkFIPS decides a `make test` log the FIPS job wrote, then reruns the
// other tests of each package an attributed panic killed. The reruns run
// only when nothing else gates: the verdict cannot turn green otherwise.
func checkFIPS(ctx context.Context, env environment, opts options, b *baseline, logPath string, stdout io.Writer) (*verdict, error) {
	if !fipsOnly(env.getenv) {
		return nil, ErrNotFIPSMode
	}
	var skip *regexp.Regexp
	if opts.skipTests != "" {
		re, err := regexp.Compile(opts.skipTests)
		if err != nil {
			return nil, &SkipPatternError{Pattern: opts.skipTests, Err: err}
		}
		skip = re
	}
	log, err := readGoTestLog(logPath, opts.module)
	if err != nil {
		return nil, err
	}
	v, reruns := decideFIPS(log, b)
	if v.gating() {
		return v, nil
	}
	rr := &rerunner{goCmd: env.goCmd(opts.goBin), module: opts.module, tags: opts.tags, skip: skip, baseline: b, stdout: stdout}
	for _, r := range reruns {
		rounds, hidden, err := rr.settle(ctx, r)
		v.Reran = append(v.Reran, rounds...)
		v.settleRerun(b, r, hidden)
		if err != nil {
			v.Unattributable = append(v.Unattributable, err.Error())
		}
	}
	return v, nil
}

// fipsOnly reports whether the environment runs Go in strict FIPS mode,
// as `make test-fips` does.
func fipsOnly(getenv func(string) string) bool {
	if getenv("GOFIPS140") == "" {
		return false
	}
	for _, setting := range strings.Split(getenv("GODEBUG"), ",") {
		if strings.TrimSpace(setting) == "fips140=only" {
			return true
		}
	}
	return false
}

// readSuiteLog opens and parses the suite log at path.
func readSuiteLog(path, module string) (*suiteLog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, &ReadError{Path: path, Err: err}
	}
	defer f.Close()
	return parseSuiteLog(path, module, f)
}

// report prints the verdict and returns the exit code.
func report(v *verdict, j job, stdout, stderr io.Writer) int {
	out, errOut := &reportWriter{w: stdout}, &reportWriter{w: stderr}
	code := writeReport(v, j, out, errOut)
	if out.err != nil || errOut.err != nil {
		return exitOutput
	}
	return code
}

// writeReport writes the verdict's lines and returns its exit code.
func writeReport(v *verdict, j job, out, errOut *reportWriter) int {
	if len(v.Hits) > 0 {
		out.printf("foreign-failure baseline (ruling 125): %d listed failures in this run\n", len(v.Hits))
		for _, line := range v.hitsByUpstream() {
			out.printf("  %s\n", line)
		}
	}
	for _, line := range v.Reran {
		out.printf("rerun: %s\n", line)
	}
	if len(v.Stale) > 0 {
		out.printf("notice: %d baseline entries did not fail in this run; remove each in the PR that adopts its closing release:\n", len(v.Stale))
		for _, e := range v.Stale {
			out.printf("  %s\t%s\t%s\t%s\n", e.Kind, e.Package, e.Name, e.Upstream)
		}
	}
	for _, f := range v.Unlisted {
		errOut.printf("FAIL not in the baseline: %s %s\n", f.Package, f.Name)
	}
	for _, reason := range v.Unattributable {
		errOut.printf("FAIL cannot be attributed to a listed test: %s\n", reason)
	}
	if v.gating() {
		errOut.printf("%v\n", j.failedLine)
		return exitGating
	}
	out.printf("%v\n", j.passedLine)
	return exitOK
}

// fail writes err to stderr and returns exitUsage, or exitOutput when stderr
// cannot be written.
func fail(stderr io.Writer, err error) int {
	if _, werr := fmt.Fprintf(stderr, "%v\n", err); werr != nil {
		return exitOutput
	}
	return exitUsage
}

// reportWriter writes lines to one stream and keeps the first write error;
// later lines are skipped once a write has failed.
type reportWriter struct {
	w   io.Writer
	err error
}

func (r *reportWriter) printf(format string, args ...any) {
	if r.err != nil {
		return
	}
	_, r.err = fmt.Fprintf(r.w, format, args...)
}
