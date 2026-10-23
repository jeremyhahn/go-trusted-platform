package main

import (
	"fmt"
	"sort"
)

// failure is one failed leaf test the baseline does not list.
type failure struct {
	Package string
	Name    string
}

// verdict is the checker's decision over one suite log.
type verdict struct {
	// Unlisted are failed leaves the baseline does not list.
	Unlisted []failure
	// Unattributable are failures no leaf test carries; each fails closed.
	Unattributable []string
	// Hits are the baseline entries that failed in this run.
	Hits []*entry
	// Stale are baseline entries that did not fail in this run.
	Stale []*entry
	// Reran are the FIPS job's reruns of panicked packages, one line each.
	Reran []string
}

// gating reports whether the suite's failure stands.
func (v *verdict) gating() bool {
	return len(v.Unlisted) > 0 || len(v.Unattributable) > 0
}

// decide attributes every failed target of the suite to baseline entries.
// Anything it cannot attribute to a listed leaf test or job gates.
func decide(log *suiteLog, b *baseline) *verdict {
	v := &verdict{}
	hit := map[*entry]bool{}
	if !log.summarySeen {
		v.Unattributable = append(v.Unattributable, "the runner's closing summary is missing: the suite did not finish")
	}
	failedTargets := 0
	for _, target := range log.summaryRows {
		if log.summary[target] != "FAIL" {
			continue
		}
		failedTargets++
		if e, ok := b.jobs[target]; ok {
			hit[e] = true
			continue
		}
		decideTarget(v, hit, target, log.sections[target], b)
	}
	if log.summarySeen && failedTargets == 0 {
		v.Unattributable = append(v.Unattributable, "the summary lists no failed target: the suite failed outside its tests")
	}
	v.settle(b, hit)
	return v
}

// settle splits b's entries into those that failed in this run and those
// that did not.
func (v *verdict) settle(b *baseline, hit map[*entry]bool) {
	for _, e := range b.entries {
		if hit[e] {
			v.Hits = append(v.Hits, e)
		} else {
			v.Stale = append(v.Stale, e)
		}
	}
}

// decideTarget attributes one failed target's section.
func decideTarget(v *verdict, hit map[*entry]bool, target string, s *section, b *baseline) {
	if s == nil {
		v.Unattributable = append(v.Unattributable, fmt.Sprintf("%s: failed outside go test (no test section in the log)", target))
		return
	}
	for _, problem := range s.Problems {
		v.Unattributable = append(v.Unattributable, fmt.Sprintf("%s: %s", target, problem))
	}
	if len(s.Problems) > 0 {
		return
	}
	if !s.Ended {
		v.Unattributable = append(v.Unattributable, fmt.Sprintf("%s: the section has no closing PASS/FAIL line", target))
		return
	}
	if len(s.Failed) == 0 {
		v.Unattributable = append(v.Unattributable, fmt.Sprintf("%s: no package FAIL result: the target failed outside its tests", target))
		return
	}
	for _, p := range s.Failed {
		decidePackage(v, hit, target, p, b)
	}
}

// decidePackage attributes one failed package's leaves.
func decidePackage(v *verdict, hit map[*entry]bool, target string, p *packageResult, b *baseline) {
	if !p.BinaryFailed {
		v.Unattributable = append(v.Unattributable, fmt.Sprintf("%s: %s: the test binary did not run to the end", target, p.Package))
		return
	}
	failed := leaves(p.FailedTests)
	if len(failed) == 0 {
		v.Unattributable = append(v.Unattributable, fmt.Sprintf("%s: %s: the package failed with no failing test", target, p.Package))
		return
	}
	for _, name := range failed {
		if e, ok := b.tests[testKey{Package: p.Package, Name: name}]; ok {
			hit[e] = true
			continue
		}
		v.Unlisted = append(v.Unlisted, failure{Package: p.Package, Name: name})
	}
}

// hitsByUpstream counts the hits per upstream issue, sorted by upstream.
func (v *verdict) hitsByUpstream() []string {
	counts := map[string]int{}
	for _, e := range v.Hits {
		counts[e.Upstream]++
	}
	upstreams := make([]string, 0, len(counts))
	for u := range counts {
		upstreams = append(upstreams, u)
	}
	sort.Strings(upstreams)
	lines := make([]string, 0, len(upstreams))
	for _, u := range upstreams {
		lines = append(lines, fmt.Sprintf("%s: %d", u, counts[u]))
	}
	return lines
}
