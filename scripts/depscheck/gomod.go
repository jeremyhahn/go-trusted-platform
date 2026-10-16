package main

import (
	"strconv"
	"strings"
)

const (
	kindRequire = "require"
	kindReplace = "replace"
)

// directive is one require or replace line of a go.mod file.
type directive struct {
	Kind string
	Line int
	// Path and Version name the module required, or the module replaced.
	// A replace's Version is empty unless it replaces one version only.
	Path    string
	Version string
	// NewPath and NewVersion are the replacement. NewVersion is empty when
	// the replacement is a local directory.
	NewPath    string
	NewVersion string
	Indirect   bool
	// Comment is the text of the comment lines directly above the line plus
	// its trailing comment, without the "indirect" marker.
	Comment string
}

// parseGoMod reads the require and replace directives of a go.mod file, in
// both the single-line and the block form. A comment belongs to a line when
// it trails the line or sits directly above it with no blank line between;
// a comment above a "require (" block belongs to no line in it.
func parseGoMod(file string, data []byte) ([]directive, error) {
	var (
		directives []directive
		above      []string
		block      string
		blockLine  int
	)
	for i, raw := range strings.Split(string(data), "\n") {
		lineNo := i + 1
		text := strings.TrimSpace(raw)
		if text == "" {
			above = nil
			continue
		}
		if strings.HasPrefix(text, "//") {
			above = append(above, strings.TrimSpace(strings.TrimPrefix(text, "//")))
			continue
		}
		body, trailing := splitComment(text)
		fields := strings.Fields(body)
		args := fields
		kind := block
		switch {
		case block != "" && body == ")":
			block = ""
			above = nil
			continue
		case block == "" && len(fields) == 2 && fields[1] == "(":
			block, blockLine = fields[0], lineNo
			above = nil
			continue
		case block == "":
			kind, args = fields[0], fields[1:]
		}
		d, ok, err := parseDirective(file, lineNo, text, kind, args)
		if err != nil {
			return nil, err
		}
		if ok {
			d.Indirect, trailing = splitIndirect(trailing)
			d.Comment = strings.TrimSpace(strings.Join(append(above, trailing), " "))
			directives = append(directives, d)
		}
		above = nil
	}
	if block != "" {
		return nil, &ParseError{File: file, Line: blockLine, Text: block + " ( has no closing )"}
	}
	return directives, nil
}

// parseDirective parses the arguments of one directive. ok is false for the
// directives deps-check does not read (module, go, toolchain, exclude, ...).
func parseDirective(file string, lineNo int, text, kind string, args []string) (directive, bool, error) {
	bad := &ParseError{File: file, Line: lineNo, Text: text}
	d := directive{Kind: kind, Line: lineNo}
	switch kind {
	case kindRequire:
		if len(args) != 2 {
			return d, false, bad
		}
		d.Path, d.Version = args[0], args[1]
	case kindReplace:
		arrow := -1
		for i, arg := range args {
			if arg == "=>" {
				arrow = i
			}
		}
		left, right := args, []string(nil)
		if arrow >= 0 {
			left, right = args[:arrow], args[arrow+1:]
		}
		if len(left) < 1 || len(left) > 2 || len(right) < 1 || len(right) > 2 {
			return d, false, bad
		}
		d.Path, d.NewPath = left[0], right[0]
		if len(left) == 2 {
			d.Version = left[1]
		}
		if len(right) == 2 {
			d.NewVersion = right[1]
		}
	default:
		return d, false, nil
	}
	var err error
	if d.Path, err = unquote(d.Path); err != nil {
		return d, false, bad
	}
	if d.NewPath, err = unquote(d.NewPath); err != nil {
		return d, false, bad
	}
	return d, true, nil
}

// splitComment splits a line into its directive text and trailing comment.
func splitComment(text string) (body, comment string) {
	i := strings.Index(text, "//")
	if i < 0 {
		return text, ""
	}
	return strings.TrimSpace(text[:i]), strings.TrimSpace(text[i+2:])
}

// splitIndirect strips the "indirect" marker go mod tidy writes, which can
// be followed by "; reason". The marker itself is not a reason.
func splitIndirect(comment string) (bool, string) {
	if comment == "indirect" {
		return true, ""
	}
	if rest, ok := strings.CutPrefix(comment, "indirect;"); ok {
		return true, strings.TrimSpace(rest)
	}
	return false, comment
}

// unquote returns a go.mod path written as a Go string literal unquoted.
func unquote(path string) (string, error) {
	if !strings.HasPrefix(path, `"`) {
		return path, nil
	}
	return strconv.Unquote(path)
}

// dependency is a module version a go.mod file holds, with the comment that
// would justify holding it below latest.
type dependency struct {
	File string
	Kind string
	Line int
	// Module is the module path in the build list; Path and Version are the
	// module version in effect, which a replace makes differ from Module.
	Module  string
	Path    string
	Version string
	Reason  string
}

// dependencies selects what deps-check compares: every direct require that
// no replace overrides, and every replace onto a module version. Indirect
// requires follow from the direct ones, and a local-directory replace (the
// intra-repo sdk/go reference) has no published version to be behind.
func dependencies(file string, directives []directive) []dependency {
	replaced := make(map[string]bool)
	var deps []dependency
	for _, d := range directives {
		if d.Kind != kindReplace {
			continue
		}
		replaced[d.Path+"@"+d.Version] = true
		if d.NewVersion != "" {
			deps = append(deps, dependency{File: file, Kind: kindReplace, Line: d.Line, Module: d.Path, Path: d.NewPath, Version: d.NewVersion, Reason: d.Comment})
		}
	}
	for _, d := range directives {
		if d.Kind != kindRequire || d.Indirect || replaced[d.Path+"@"] || replaced[d.Path+"@"+d.Version] {
			continue
		}
		deps = append(deps, dependency{File: file, Kind: kindRequire, Line: d.Line, Module: d.Path, Path: d.Path, Version: d.Version, Reason: d.Comment})
	}
	return deps
}
