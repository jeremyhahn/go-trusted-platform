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
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// The race job runs on the persistent bigdisk runner only for code from this
// repository: a push to main or a same-repository pull request. Fork code
// on that runner could persist across jobs, so everything else gets a
// hosted runner. These tests evaluate race's runs-on expression, not just
// look for the label in it.

const (
	raceJobID      = "race"
	raceRepository = "jeremyhahn/go-trusted-platform"
)

var (
	bigdiskLabels = []string{"self-hosted", "linux", "x64", "bigdisk"}
	hostedLabels  = []string{"ubuntu-latest"}
)

// ghContext is the slice of the GitHub context race's runs-on reads.
type ghContext map[string]string

// ghValue is an expression value: a string, a bool or a string array.
type ghValue struct {
	str   string
	bool  bool
	array []string
	kind  string // "string", "bool" or "array"
}

func (v ghValue) truthy() bool {
	switch v.kind {
	case "bool":
		return v.bool
	case "array":
		return true
	default:
		return v.str != ""
	}
}

// labels is the runner label list runs-on resolves to.
func (v ghValue) labels() ([]string, error) {
	switch v.kind {
	case "array":
		return v.array, nil
	case "string":
		return []string{v.str}, nil
	default:
		return nil, fmt.Errorf("runs-on resolves to a %s, not a label or a label list", v.kind)
	}
}

type ghToken struct {
	kind string // "str", "ident", "op", "(", ")"
	text string
}

func tokenizeGHExpr(src string) ([]ghToken, error) {
	var toks []ghToken
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '(' || c == ')':
			toks = append(toks, ghToken{kind: string(c)})
			i++
		case c == '\'':
			// A literal ends at a lone quote; '' is an escaped quote.
			var b strings.Builder
			j := i + 1
			for {
				if j >= len(src) {
					return nil, fmt.Errorf("unterminated string literal at %d", i)
				}
				if src[j] == '\'' {
					if j+1 < len(src) && src[j+1] == '\'' {
						b.WriteByte('\'')
						j += 2
						continue
					}
					break
				}
				b.WriteByte(src[j])
				j++
			}
			toks = append(toks, ghToken{kind: "str", text: b.String()})
			i = j + 1
		case strings.HasPrefix(src[i:], "=="), strings.HasPrefix(src[i:], "&&"), strings.HasPrefix(src[i:], "||"):
			toks = append(toks, ghToken{kind: "op", text: src[i : i+2]})
			i += 2
		case c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			j := i
			for j < len(src) && (src[j] == '_' || src[j] == '.' || src[j] >= 'a' && src[j] <= 'z' || src[j] >= 'A' && src[j] <= 'Z' || src[j] >= '0' && src[j] <= '9') {
				j++
			}
			toks = append(toks, ghToken{kind: "ident", text: src[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("unsupported token %q at %d", src[i:], i)
		}
	}
	return toks, nil
}

// ghParser evaluates exactly the expression subset race's runs-on uses.
// Anything else is an error, never a silent accept.
type ghParser struct {
	toks []ghToken
	pos  int
	ctx  ghContext
}

func (p *ghParser) peek() (ghToken, bool) {
	if p.pos >= len(p.toks) {
		return ghToken{}, false
	}
	return p.toks[p.pos], true
}

func (p *ghParser) expect(kind string) error {
	tok, ok := p.peek()
	if !ok || tok.kind != kind {
		return fmt.Errorf("expected %q at token %d", kind, p.pos)
	}
	p.pos++
	return nil
}

func (p *ghParser) isOp(op string) bool {
	tok, ok := p.peek()
	return ok && tok.kind == "op" && tok.text == op
}

// or and and return an operand, not a bool, as GitHub's do.
func (p *ghParser) or() (ghValue, error) {
	left, err := p.and()
	if err != nil {
		return ghValue{}, err
	}
	for p.isOp("||") {
		p.pos++
		right, err := p.and()
		if err != nil {
			return ghValue{}, err
		}
		if !left.truthy() {
			left = right
		}
	}
	return left, nil
}

func (p *ghParser) and() (ghValue, error) {
	left, err := p.eq()
	if err != nil {
		return ghValue{}, err
	}
	for p.isOp("&&") {
		p.pos++
		right, err := p.eq()
		if err != nil {
			return ghValue{}, err
		}
		if left.truthy() {
			left = right
		}
	}
	return left, nil
}

func (p *ghParser) eq() (ghValue, error) {
	left, err := p.primary()
	if err != nil {
		return ghValue{}, err
	}
	if !p.isOp("==") {
		return left, nil
	}
	p.pos++
	right, err := p.primary()
	if err != nil {
		return ghValue{}, err
	}
	if left.kind != "string" || right.kind != "string" {
		return ghValue{}, fmt.Errorf("== compares a %s with a %s", left.kind, right.kind)
	}
	// GitHub compares strings case-insensitively.
	return ghValue{kind: "bool", bool: strings.EqualFold(left.str, right.str)}, nil
}

func (p *ghParser) primary() (ghValue, error) {
	tok, ok := p.peek()
	if !ok {
		return ghValue{}, fmt.Errorf("expression ends early")
	}
	p.pos++
	switch tok.kind {
	case "(":
		v, err := p.or()
		if err != nil {
			return ghValue{}, err
		}
		return v, p.expect(")")
	case "str":
		return ghValue{kind: "string", str: tok.text}, nil
	case "ident":
		if tok.text == "fromJSON" {
			if err := p.expect("("); err != nil {
				return ghValue{}, err
			}
			arg, ok := p.peek()
			if !ok || arg.kind != "str" {
				return ghValue{}, fmt.Errorf("fromJSON takes a string literal")
			}
			p.pos++
			var arr []string
			if err := json.Unmarshal([]byte(arg.text), &arr); err != nil {
				return ghValue{}, fmt.Errorf("fromJSON(%q) is not a JSON string array: %w", arg.text, err)
			}
			return ghValue{kind: "array", array: arr}, p.expect(")")
		}
		v, known := p.ctx[tok.text]
		if !known {
			return ghValue{}, fmt.Errorf("unsupported context path or function %q", tok.text)
		}
		return ghValue{kind: "string", str: v}, nil
	default:
		return ghValue{}, fmt.Errorf("unexpected token %q %q", tok.kind, tok.text)
	}
}

// resolveRunsOn evaluates a runs-on value against ctx to its label list.
func resolveRunsOn(runsOn string, ctx ghContext) ([]string, error) {
	src := strings.TrimSpace(runsOn)
	if !strings.HasPrefix(src, "${{") {
		if strings.Contains(src, "${{") {
			return nil, fmt.Errorf("runs-on %q mixes text and an expression", runsOn)
		}
		return []string{src}, nil
	}
	if !strings.HasSuffix(src, "}}") {
		return nil, fmt.Errorf("runs-on %q is not one ${{ }} expression", runsOn)
	}
	toks, err := tokenizeGHExpr(src[3 : len(src)-2])
	if err != nil {
		return nil, err
	}
	p := &ghParser{toks: toks, ctx: ctx}
	v, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("trailing tokens after position %d", p.pos)
	}
	return v.labels()
}

type raceRoutingCase struct {
	name      string
	event     string
	ref       string
	headRepo  string
	wantLabel []string
}

var raceRoutingCases = []raceRoutingCase{
	{"push to main", "push", "refs/heads/main", "", bigdiskLabels},
	{"push to another branch", "push", "refs/heads/feature", "", hostedLabels},
	{"same-repository pull request", "pull_request", "refs/pull/1/merge", raceRepository, bigdiskLabels},
	{"fork pull request", "pull_request", "refs/pull/1/merge", "someone/go-trusted-platform", hostedLabels},
	{"workflow_dispatch on main", "workflow_dispatch", "refs/heads/main", "", hostedLabels},
	{"schedule on main", "schedule", "refs/heads/main", "", hostedLabels},
}

func (c raceRoutingCase) context() ghContext {
	return ghContext{
		"github.event_name": c.event,
		"github.ref":        c.ref,
		"github.repository": raceRepository,
		"github.event.pull_request.head.repo.full_name": c.headRepo,
	}
}

// raceRoutingMismatches names each case runsOn routes differently from the
// table, or fails to evaluate.
func raceRoutingMismatches(runsOn string) []string {
	var out []string
	for _, c := range raceRoutingCases {
		got, err := resolveRunsOn(runsOn, c.context())
		switch {
		case err != nil:
			out = append(out, fmt.Sprintf("%s: %v", c.name, err))
		case strings.Join(got, ",") != strings.Join(c.wantLabel, ","):
			out = append(out, fmt.Sprintf("%s: runs on %v, want %v", c.name, got, c.wantLabel))
		}
	}
	return out
}

func raceJob(t *testing.T, wf ciWorkflow) ciJob {
	t.Helper()
	for _, job := range wf.Jobs {
		if job.ID == raceJobID {
			return job
		}
	}
	t.Fatalf("%s has no %s job", wf.File, raceJobID)
	return ciJob{}
}

func TestRaceRunsOnTheBigdiskRunnerOnlyForThisRepositorysCode(t *testing.T) {
	wf := loadCIWorkflow(t, repoRoot(t), ciWorkflowFile)
	runsOn := raceJob(t, wf).RunsOn
	for _, mismatch := range raceRoutingMismatches(runsOn) {
		t.Error(mismatch)
	}
}

func TestRaceRoutingRejectsAnUnconditionalBigdiskRunsOn(t *testing.T) {
	unconditional := `${{ fromJSON('["self-hosted","linux","x64","bigdisk"]') }}`
	mismatches := raceRoutingMismatches(unconditional)
	require.Contains(t, mismatches, "fork pull request: runs on [self-hosted linux x64 bigdisk], want [ubuntu-latest]")
}

func TestResolveRunsOnRejectsUnsupportedExpressions(t *testing.T) {
	ctx := raceRoutingCases[0].context()
	for _, expr := range []string{
		`${{ github.actor == 'x' && 'a' || 'b' }}`,
		`${{ !github.ref }}`,
		`${{ github.ref != 'refs/heads/main' }}`,
		`${{ contains(github.ref, 'main') }}`,
		`${{ fromJSON('{"a":1}') }}`,
		`${{ (github.ref == 'x' }}`,
		`${{ github.ref == 'x' }}`,
		`prefix-${{ github.ref }}`,
	} {
		_, err := resolveRunsOn(expr, ctx)
		require.Error(t, err, expr)
	}
}

func TestRaceCheckoutDoesNotPersistCredentials(t *testing.T) {
	wf := loadCIWorkflow(t, repoRoot(t), ciWorkflowFile)
	steps := mappingValue(mappingValue(mappingValue(wf.Doc, "jobs"), raceJobID), "steps")
	require.NotNil(t, steps, "%s: job %s has no steps", wf.File, raceJobID)
	require.Equal(t, yaml.SequenceNode, steps.Kind)

	checkouts := 0
	for _, step := range steps.Content {
		uses := mappingValue(step, "uses")
		if uses == nil || !strings.HasPrefix(uses.Value, "actions/checkout@") {
			continue
		}
		checkouts++
		persist := mappingValue(mappingValue(step, "with"), "persist-credentials")
		if persist == nil || persist.Kind != yaml.ScalarNode || persist.Value != "false" ||
			(persist.Tag != "!!bool" && persist.Tag != "!!str") {
			t.Errorf("%s:%d: race's actions/checkout step must set with: persist-credentials: false", wf.File, uses.Line)
		}
	}
	require.Positive(t, checkouts, "%s: job %s has no actions/checkout step", wf.File, raceJobID)
}
