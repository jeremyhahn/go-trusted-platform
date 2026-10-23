package main

import (
	"fmt"
	"strings"
)

// rerun is a panicked package whose other tests must run again: the panic
// killed its binary, so every test after the panicking one never ran.
type rerun struct {
	Package string // module-relative import path
	Exclude string // the listed test that panicked
}

// decideFIPS sorts a FIPS run's failures against b, a FIPS baseline. It
// fails closed: a failure is foreign only when it is a listed test's panic,
// with the row's message and frame, in a package nothing else failed in.
// Each foreign panic returns a rerun; the run passes only once those pass.
func decideFIPS(log *goTestLog, b *baseline) (*verdict, []rerun) {
	v := &verdict{}
	hit := map[*entry]bool{}
	var reruns []rerun
	if !log.Finished {
		v.Unattributable = append(v.Unattributable, "the go test run has no closing FAIL line: it did not finish")
	}
	v.Unattributable = append(v.Unattributable, log.Problems...)
	if len(log.Failed) == 0 {
		v.Unattributable = append(v.Unattributable, "no package failed: the run failed outside go test")
	}
	for _, p := range log.Failed {
		if p.Panic == nil {
			decideFIPSFailure(v, p, b)
			continue
		}
		e, reason := attributePanic(log.module, p, b)
		if e == nil {
			v.Unattributable = append(v.Unattributable, reason)
			continue
		}
		hit[e] = true
		reruns = append(reruns, rerun{Package: p.Package, Exclude: e.Name})
	}
	v.settle(b, hit)
	return v, reruns
}

// decideFIPSFailure sorts a package that failed without a panic. The FIPS
// baseline lists panics only, so every such failure gates.
func decideFIPSFailure(v *verdict, p *packageRun, b *baseline) {
	for _, problem := range p.Problems {
		v.Unattributable = append(v.Unattributable, fmt.Sprintf("%s: %s", p.Package, problem))
	}
	if !p.BinaryFailed {
		v.Unattributable = append(v.Unattributable, fmt.Sprintf("%s: the test binary did not run to the end", p.Package))
		return
	}
	failed := leaves(p.FailedTests)
	if len(failed) == 0 {
		v.Unattributable = append(v.Unattributable, fmt.Sprintf("%s: the package failed with no failing test", p.Package))
		return
	}
	for _, name := range failed {
		if _, listed := b.tests[testKey{Package: p.Package, Name: name}]; listed {
			v.Unattributable = append(v.Unattributable, fmt.Sprintf("%s %s: listed as a panic but failed without one", p.Package, name))
			continue
		}
		v.Unlisted = append(v.Unlisted, failure{Package: p.Package, Name: name})
	}
}

// attributePanic returns the row a panicked package's failure is, or nil
// and the reason it is not. Every condition must hold.
func attributePanic(module string, p *packageRun, b *baseline) (*entry, string) {
	if len(p.Problems) > 0 {
		return nil, fmt.Sprintf("%s: a panic beside %s", p.Package, strings.Join(p.Problems, "; "))
	}
	if p.BinaryFailed {
		return nil, fmt.Sprintf("%s: a panic line in a test binary that ran to its end", p.Package)
	}
	failed := leaves(p.FailedTests)
	if len(failed) != 1 {
		return nil, fmt.Sprintf("%s: a panic with %d failing tests %v: only one listed test's panic is attributable", p.Package, len(failed), failed)
	}
	name := failed[0]
	e, listed := b.tests[testKey{Package: p.Package, Name: name}]
	if !listed {
		return nil, fmt.Sprintf("%s %s: panicked and is not in the FIPS baseline: %s", p.Package, name, strings.Join(p.Panic.Messages, "; "))
	}
	for _, message := range p.Panic.Messages {
		if message != e.Message {
			return nil, fmt.Sprintf("%s %s: panic %q is not the row's %q", p.Package, name, message, e.Message)
		}
	}
	if !hasFrame(p.Panic.Frames, e.Frame) {
		return nil, fmt.Sprintf("%s %s: the panicking goroutine's stack does not pass through %s", p.Package, name, e.Frame)
	}
	if testFrame := module + "/" + p.Package + "." + name; !hasFrame(p.Panic.Frames, testFrame) {
		return nil, fmt.Sprintf("%s %s: the panicking goroutine's stack does not pass through %s: the panic is not the listed test's", p.Package, name, testFrame)
	}
	return e, ""
}

// hasFrame reports whether frames holds a call of function, which a stack
// trace prints as the function followed by its argument list.
func hasFrame(frames []string, function string) bool {
	for _, frame := range frames {
		if strings.HasPrefix(frame, function+"(") {
			return true
		}
	}
	return false
}
