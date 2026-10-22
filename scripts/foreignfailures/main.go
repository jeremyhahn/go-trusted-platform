// Command foreignfailures decides whether a failed integration suite failed
// only where the foreign-failure baseline says it may (Company Agent ruling
// 125). It reads the suite's combined output, as make integration-test
// prints it, and the baseline (.github/foreign-failures.tsv), and exits 0
// only when every failed leaf test is listed. Anything it cannot attribute to
// a leaf test (a build failure, a panic or timeout, a package that failed with
// no failing test, a target that failed outside go test, a log without the
// runner's closing summary) gates: it fails closed.
//
// Usage:
//
//	foreignfailures [-baseline .github/foreign-failures.tsv] <suite log>
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// Exit codes.
const (
	exitOK     = 0 // every failure is in the baseline
	exitGating = 1 // a failure the baseline does not list, or cannot be attributed
	exitUsage  = 2 // the arguments, the baseline or the log cannot be read
)

// defaultModule is this repository's module path; baseline packages are
// relative to it.
const defaultModule = "github.com/jeremyhahn/go-trusted-platform"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main with its inputs and outputs injected.
func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("foreignfailures", flag.ContinueOnError)
	flags.SetOutput(stderr)
	baselinePath := flags.String("baseline", ".github/foreign-failures.tsv", "the foreign-failure baseline")
	module := flags.String("module", defaultModule, "the module path go test prints in front of each package")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(stderr, ErrUsage)
		return exitUsage
	}
	b, err := loadBaseline(*baselinePath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	log, err := readSuiteLog(flags.Arg(0), *module)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	return report(decide(log, b), stdout, stderr)
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
func report(v *verdict, stdout, stderr io.Writer) int {
	if len(v.Hits) > 0 {
		fmt.Fprintf(stdout, "foreign-failure baseline (ruling 125): %d listed failures in this run\n", len(v.Hits))
		for _, line := range v.hitsByUpstream() {
			fmt.Fprintf(stdout, "  %s\n", line)
		}
	}
	if len(v.Stale) > 0 {
		fmt.Fprintf(stdout, "notice: %d baseline entries did not fail in this run; remove each in the PR that adopts its closing release:\n", len(v.Stale))
		for _, e := range v.Stale {
			fmt.Fprintf(stdout, "  %s\t%s\t%s\t%s\n", e.Kind, e.Package, e.Name, e.Upstream)
		}
	}
	for _, f := range v.Unlisted {
		fmt.Fprintf(stderr, "FAIL not in the baseline: %s %s\n", f.Package, f.Name)
	}
	for _, reason := range v.Unattributable {
		fmt.Fprintf(stderr, "FAIL cannot be attributed to a listed test: %s\n", reason)
	}
	if v.gating() {
		fmt.Fprintln(stderr, "the integration suite failed outside the foreign-failure baseline")
		return exitGating
	}
	fmt.Fprintln(stdout, "every integration failure is in the foreign-failure baseline")
	return exitOK
}
