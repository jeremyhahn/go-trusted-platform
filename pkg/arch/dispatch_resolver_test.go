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

// Static resolver behind the dispatch-stub check (dispatch_stub_test.go).
//
// The check must know, for every operation a transport serves, which function
// definition handles it. This file resolves that from source alone: it parses
// only the packages the walk reaches, evaluates build constraints against the
// tag set the test binary was built with, binds every qualifier to the import
// path its own file declares, and infers just enough types (receivers,
// parameters, locals, struct fields, constructor and method results) to
// resolve method calls. Nothing resolves by bare identifier: an unqualified
// name resolves in its own package and a qualified one in the package its
// file imported, so two packages defining the same constructor never collide.
package arch_test

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// grpcCodesImport is the only package whose Unimplemented code is a stub
// marker; a local constant named Unimplemented is not one.
const grpcCodesImport = "google.golang.org/grpc/codes"

// maxTypeDepth bounds alias, embedding and binding chains.
const maxTypeDepth = 8

var (
	// dispatchConstant matches the opcode and sub-opcode names a dispatch
	// switch cases on (OpDeviceGetState, SubOpTPM2LDevIDCSR, req.Opcode,
	// DeviceProfileSubAssign).
	dispatchConstant = regexp.MustCompile(`^(Sub)?Op[A-Z0-9]|SubOp|Opcode$|[a-z]Sub[A-Z]`)
	// registerServer matches generated gRPC registration functions.
	registerServer = regexp.MustCompile(`^Register(\w+)Server$`)
	majorVersion   = regexp.MustCompile(`^v[0-9]+$`)
)

// mcpToolPrefix marks the string cases of the MCP tool-name switch.
const mcpToolPrefix = "platform_"

// DispatchSourceError reports an in-module package the resolver could not
// load. The check cannot vouch for operations it could not read.
type DispatchSourceError struct {
	Path  string
	Cause error
}

func (e *DispatchSourceError) Error() string {
	return "load package " + e.Path + ": " + e.Cause.Error()
}

func (e *DispatchSourceError) Unwrap() error { return e.Cause }

// typeRef names a declared type by import path and type name. The zero value
// means unknown: builtin, unnamed, or not inferable.
type typeRef struct {
	pkg  string
	name string
}

func (t typeRef) known() bool { return t.name != "" }

// funcKey names a function definition; Recv is empty for a package function.
type funcKey struct {
	Pkg  string
	Recv string
	Name string
}

func (k funcKey) local() string {
	if k.Recv == "" {
		return k.Name
	}
	return k.Recv + "." + k.Name
}

func (k funcKey) String() string {
	if k.Recv == "" {
		return k.Pkg + "." + k.Name
	}
	return k.Pkg + ".(*" + k.Recv + ")." + k.Name
}

type dispatchFile struct {
	rel     string            // module-relative, slash-separated
	syntax  *ast.File         //
	aliases map[string]string // explicit import name -> import path
	plain   []string          // imports without an explicit name
	pkg     *dispatchPackage
}

type dispatchFunc struct {
	decl *ast.FuncDecl
	file *dispatchFile
	key  funcKey
}

type dispatchVar struct {
	spec  *ast.ValueSpec
	index int
	file  *dispatchFile
}

type dispatchType struct {
	spec *ast.TypeSpec
	file *dispatchFile
}

type dispatchPackage struct {
	path  string
	name  string
	order []*dispatchFunc // declaration order, for deterministic walks
	funcs map[string]*dispatchFunc
	types map[string]*dispatchType
	vars  map[string]*dispatchVar
}

// localBinding is one way a local name gets its value: a declared type, or
// an assigned value (result selects among a multi-value call's results).
type localBinding struct {
	typ    ast.Expr
	value  ast.Expr
	result int
}

// dispatchScope resolves names inside one function body or one package-level
// initializer. Locals are flow-insensitive: the first binding whose type is
// inferable wins.
type dispatchScope struct {
	file   *dispatchFile
	locals map[string][]localBinding
	busy   map[string]bool
}

func (s *dispatchScope) isLocal(name string) bool {
	_, ok := s.locals[name]
	return ok
}

func (s *dispatchScope) bind(name string, b localBinding) {
	if name == "_" {
		return
	}
	s.locals[name] = append(s.locals[name], b)
}

func (s *dispatchScope) bindFields(list *ast.FieldList) {
	if list == nil {
		return
	}
	for _, field := range list.List {
		for _, name := range field.Names {
			s.bind(name.Name, localBinding{typ: field.Type})
		}
	}
}

func (s *dispatchScope) bindAssign(lhs []*ast.Ident, rhs []ast.Expr) {
	for i, id := range lhs {
		switch {
		case len(rhs) == len(lhs):
			s.bind(id.Name, localBinding{value: rhs[i]})
		case len(rhs) == 1:
			s.bind(id.Name, localBinding{value: rhs[0], result: i})
		default:
			s.bind(id.Name, localBinding{})
		}
	}
}

// dispatchIndex loads in-module packages on demand and answers name, type
// and method questions about them.
type dispatchIndex struct {
	root     string
	module   string
	fset     *token.FileSet
	build    build.Context
	pkgs     map[string]*dispatchPackage
	names    map[string]string
	scopes   map[*dispatchFunc]*dispatchScope
	varBusy  map[*dispatchVar]bool
	bindings map[typeRef]typeRef
	errs     []error
}

func newDispatchIndex(root, module string, tags []string) *dispatchIndex {
	ctx := build.Default
	ctx.BuildTags = tags
	return &dispatchIndex{
		root:     root,
		module:   module,
		fset:     token.NewFileSet(),
		build:    ctx,
		pkgs:     map[string]*dispatchPackage{},
		names:    map[string]string{},
		scopes:   map[*dispatchFunc]*dispatchScope{},
		varBusy:  map[*dispatchVar]bool{},
		bindings: map[typeRef]typeRef{},
	}
}

func (ix *dispatchIndex) inModule(importPath string) bool {
	return importPath == ix.module || strings.HasPrefix(importPath, ix.module+"/")
}

func (ix *dispatchIndex) dir(importPath string) (string, string) {
	rel := strings.TrimPrefix(strings.TrimPrefix(importPath, ix.module), "/")
	return filepath.Join(ix.root, filepath.FromSlash(rel)), rel
}

// pkg returns an in-module package, loading it on first use. It returns nil
// for external packages and for packages that failed to load.
func (ix *dispatchIndex) pkg(importPath string) *dispatchPackage {
	if p, ok := ix.pkgs[importPath]; ok {
		return p
	}
	ix.pkgs[importPath] = nil
	if !ix.inModule(importPath) {
		return nil
	}
	p, err := ix.load(importPath)
	if err != nil {
		ix.errs = append(ix.errs, &DispatchSourceError{Path: importPath, Cause: err})
		return nil
	}
	ix.pkgs[importPath] = p
	return p
}

// sourceFiles lists the non-test .go files of a directory that the build
// context selects.
func (ix *dispatchIndex) sourceFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		match, err := ix.build.MatchFile(dir, name)
		if err != nil {
			return nil, err
		}
		if match {
			files = append(files, name)
		}
	}
	return files, nil
}

func (ix *dispatchIndex) load(importPath string) (*dispatchPackage, error) {
	dir, rel := ix.dir(importPath)
	names, err := ix.sourceFiles(dir)
	if err != nil {
		return nil, err
	}
	p := &dispatchPackage{
		path:  importPath,
		funcs: map[string]*dispatchFunc{},
		types: map[string]*dispatchType{},
		vars:  map[string]*dispatchVar{},
	}
	for _, name := range names {
		syntax, err := parser.ParseFile(ix.fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		p.name = syntax.Name.Name
		file := &dispatchFile{
			rel:     filepath.ToSlash(filepath.Join(rel, name)),
			syntax:  syntax,
			aliases: map[string]string{},
			pkg:     p,
		}
		if err := p.add(file); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *dispatchPackage) add(f *dispatchFile) error {
	for _, spec := range f.syntax.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return err
		}
		switch {
		case spec.Name == nil:
			f.plain = append(f.plain, importPath)
		case spec.Name.Name != "_" && spec.Name.Name != ".":
			f.aliases[spec.Name.Name] = importPath
		}
	}
	for _, decl := range f.syntax.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			fn := &dispatchFunc{decl: d, file: f, key: funcKey{Pkg: p.path, Recv: receiverName(d), Name: d.Name.Name}}
			p.funcs[fn.key.local()] = fn
			p.order = append(p.order, fn)
		case *ast.GenDecl:
			p.addSpecs(f, d)
		}
	}
	return nil
}

func (p *dispatchPackage) addSpecs(f *dispatchFile, d *ast.GenDecl) {
	for _, spec := range d.Specs {
		switch s := spec.(type) {
		case *ast.TypeSpec:
			p.types[s.Name.Name] = &dispatchType{spec: s, file: f}
		case *ast.ValueSpec:
			if d.Tok != token.VAR {
				continue
			}
			for i, name := range s.Names {
				p.vars[name.Name] = &dispatchVar{spec: s, index: i, file: f}
			}
		}
	}
}

func receiverName(d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return ""
	}
	return embeddedName(d.Recv.List[0].Type)
}

// embeddedName is the type name a (possibly pointer, generic or qualified)
// type expression names.
func embeddedName(e ast.Expr) string {
	for {
		switch x := e.(type) {
		case *ast.StarExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.IndexListExpr:
			e = x.X
		case *ast.SelectorExpr:
			return x.Sel.Name
		case *ast.Ident:
			return x.Name
		default:
			return ""
		}
	}
}

// packageName is the declared name of an in-module package (read from its
// package clause) or the conventional name of an external one.
func (ix *dispatchIndex) packageName(importPath string) string {
	if name, ok := ix.names[importPath]; ok {
		return name
	}
	name := conventionalName(importPath)
	if ix.inModule(importPath) {
		if declared, ok := ix.declaredName(importPath); ok {
			name = declared
		}
	}
	ix.names[importPath] = name
	return name
}

func (ix *dispatchIndex) declaredName(importPath string) (string, bool) {
	dir, _ := ix.dir(importPath)
	names, err := ix.sourceFiles(dir)
	if err != nil || len(names) == 0 {
		return "", false
	}
	syntax, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, names[0]), nil, parser.PackageClauseOnly)
	if err != nil {
		return "", false
	}
	return syntax.Name.Name, true
}

func conventionalName(importPath string) string {
	elems := strings.Split(importPath, "/")
	name := elems[len(elems)-1]
	if len(elems) > 1 && majorVersion.MatchString(name) {
		name = elems[len(elems)-2]
	}
	name = strings.TrimPrefix(name, "go-")
	return strings.ReplaceAll(name, "-", "_")
}

// importPath returns the import path a file binds qualifier to.
func (ix *dispatchIndex) importPath(f *dispatchFile, qualifier string) (string, bool) {
	if importPath, ok := f.aliases[qualifier]; ok {
		return importPath, true
	}
	for _, importPath := range f.plain {
		if ix.packageName(importPath) == qualifier {
			return importPath, true
		}
	}
	return "", false
}

// qualifiedPath returns the import path of x in a qualified reference x.Sel,
// or false when x is a local or not an import qualifier.
func (ix *dispatchIndex) qualifiedPath(sc *dispatchScope, x ast.Expr) (string, bool) {
	id, ok := x.(*ast.Ident)
	if !ok || sc.isLocal(id.Name) {
		return "", false
	}
	return ix.importPath(sc.file, id.Name)
}

func (ix *dispatchIndex) funcByKey(key funcKey) *dispatchFunc {
	p := ix.pkg(key.Pkg)
	if p == nil {
		return nil
	}
	return p.funcs[key.local()]
}

// scopeOf returns the (memoised) name scope of a function body.
func (ix *dispatchIndex) scopeOf(fn *dispatchFunc) *dispatchScope {
	if sc, ok := ix.scopes[fn]; ok {
		return sc
	}
	sc := newScope(fn.file)
	sc.bindFields(fn.decl.Recv)
	sc.bindFields(fn.decl.Type.Params)
	sc.bindFields(fn.decl.Type.Results)
	if fn.decl.Body != nil {
		ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
			collectLocal(sc, n)
			return true
		})
	}
	ix.scopes[fn] = sc
	return sc
}

func newScope(f *dispatchFile) *dispatchScope {
	return &dispatchScope{file: f, locals: map[string][]localBinding{}, busy: map[string]bool{}}
}

func collectLocal(sc *dispatchScope, n ast.Node) {
	switch x := n.(type) {
	case *ast.FuncLit:
		sc.bindFields(x.Type.Params)
		sc.bindFields(x.Type.Results)
	case *ast.AssignStmt:
		var lhs []*ast.Ident
		for _, e := range x.Lhs {
			if id, ok := e.(*ast.Ident); ok {
				lhs = append(lhs, id)
			}
		}
		if len(lhs) == len(x.Lhs) {
			sc.bindAssign(lhs, x.Rhs)
		}
	case *ast.ValueSpec:
		if x.Type != nil {
			for _, name := range x.Names {
				sc.bind(name.Name, localBinding{typ: x.Type})
			}
			return
		}
		sc.bindAssign(x.Names, x.Values)
	case *ast.RangeStmt:
		for _, e := range []ast.Expr{x.Key, x.Value} {
			if id, ok := e.(*ast.Ident); ok {
				sc.bind(id.Name, localBinding{})
			}
		}
	}
}

// typeOf resolves a type expression written in file f.
func (ix *dispatchIndex) typeOf(f *dispatchFile, e ast.Expr) typeRef {
	switch x := e.(type) {
	case *ast.StarExpr:
		return ix.typeOf(f, x.X)
	case *ast.ParenExpr:
		return ix.typeOf(f, x.X)
	case *ast.IndexExpr:
		return ix.typeOf(f, x.X)
	case *ast.IndexListExpr:
		return ix.typeOf(f, x.X)
	case *ast.Ident:
		if f.pkg.types[x.Name] != nil {
			return typeRef{pkg: f.pkg.path, name: x.Name}
		}
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			if importPath, ok := ix.importPath(f, id.Name); ok {
				return typeRef{pkg: importPath, name: x.Sel.Name}
			}
		}
	}
	return typeRef{}
}

// exprType infers the named type of a value expression.
func (ix *dispatchIndex) exprType(sc *dispatchScope, e ast.Expr) typeRef {
	return ix.exprResult(sc, e, 0)
}

func (ix *dispatchIndex) exprResult(sc *dispatchScope, e ast.Expr, result int) typeRef {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return ix.exprResult(sc, x.X, result)
	case *ast.StarExpr:
		return ix.exprType(sc, x.X)
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			return ix.exprType(sc, x.X)
		}
	case *ast.CompositeLit:
		if x.Type != nil {
			return ix.typeOf(sc.file, x.Type)
		}
	case *ast.TypeAssertExpr:
		if x.Type != nil && result == 0 {
			return ix.typeOf(sc.file, x.Type)
		}
	case *ast.Ident:
		return ix.identType(sc, x.Name)
	case *ast.SelectorExpr:
		return ix.selectorType(sc, x)
	case *ast.CallExpr:
		if fn := ix.resolveFunc(sc, x.Fun); fn != nil {
			return ix.resultType(fn, result)
		}
		if t, ok := ix.typeExpr(sc, x.Fun); ok && result == 0 {
			return t
		}
	}
	return typeRef{}
}

func (ix *dispatchIndex) identType(sc *dispatchScope, name string) typeRef {
	bindings, ok := sc.locals[name]
	if !ok {
		if v := sc.file.pkg.vars[name]; v != nil {
			return ix.varType(v)
		}
		return typeRef{}
	}
	if sc.busy[name] {
		return typeRef{}
	}
	sc.busy[name] = true
	defer delete(sc.busy, name)
	for _, b := range bindings {
		var t typeRef
		switch {
		case b.typ != nil:
			t = ix.typeOf(sc.file, b.typ)
		case b.value != nil:
			t = ix.exprResult(sc, b.value, b.result)
		}
		if t.known() {
			return t
		}
	}
	return typeRef{}
}

func (ix *dispatchIndex) selectorType(sc *dispatchScope, x *ast.SelectorExpr) typeRef {
	if importPath, ok := ix.qualifiedPath(sc, x.X); ok {
		if p := ix.pkg(importPath); p != nil && p.vars[x.Sel.Name] != nil {
			return ix.varType(p.vars[x.Sel.Name])
		}
		return typeRef{}
	}
	return ix.fieldType(ix.exprType(sc, x.X), x.Sel.Name, 0)
}

func (ix *dispatchIndex) varType(v *dispatchVar) typeRef {
	if v.spec.Type != nil {
		return ix.typeOf(v.file, v.spec.Type)
	}
	if ix.varBusy[v] {
		return typeRef{}
	}
	ix.varBusy[v] = true
	defer delete(ix.varBusy, v)
	sc := newScope(v.file)
	switch {
	case len(v.spec.Values) == len(v.spec.Names):
		return ix.exprType(sc, v.spec.Values[v.index])
	case len(v.spec.Values) == 1:
		return ix.exprResult(sc, v.spec.Values[0], v.index)
	}
	return typeRef{}
}

func (ix *dispatchIndex) resultType(fn *dispatchFunc, result int) typeRef {
	results := fn.decl.Type.Results
	if results == nil {
		return typeRef{}
	}
	n := 0
	for _, field := range results.List {
		count := max(1, len(field.Names))
		if result < n+count {
			return ix.typeOf(fn.file, field.Type)
		}
		n += count
	}
	return typeRef{}
}

// typeExpr reports whether e names a declared type (T, *T, (*T), pkg.T) and
// which. It never treats a local, a variable or a function as a type.
func (ix *dispatchIndex) typeExpr(sc *dispatchScope, e ast.Expr) (typeRef, bool) {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return ix.typeExpr(sc, x.X)
	case *ast.StarExpr:
		return ix.typeExpr(sc, x.X)
	case *ast.Ident:
		if !sc.isLocal(x.Name) && sc.file.pkg.types[x.Name] != nil {
			return typeRef{pkg: sc.file.pkg.path, name: x.Name}, true
		}
	case *ast.SelectorExpr:
		if importPath, ok := ix.qualifiedPath(sc, x.X); ok {
			if p := ix.pkg(importPath); p != nil && p.types[x.Sel.Name] != nil {
				return typeRef{pkg: importPath, name: x.Sel.Name}, true
			}
		}
	}
	return typeRef{}, false
}

// declaredType returns the declaration of an in-module named type.
func (ix *dispatchIndex) declaredType(t typeRef) *dispatchType {
	if !t.known() {
		return nil
	}
	p := ix.pkg(t.pkg)
	if p == nil {
		return nil
	}
	return p.types[t.name]
}

// structOf follows alias and defined-type chains to a struct declaration.
func (ix *dispatchIndex) structOf(t typeRef) (*ast.StructType, *dispatchFile) {
	for range maxTypeDepth {
		ts := ix.declaredType(t)
		if ts == nil {
			return nil, nil
		}
		if st, ok := ts.spec.Type.(*ast.StructType); ok {
			return st, ts.file
		}
		t = ix.typeOf(ts.file, ts.spec.Type)
	}
	return nil, nil
}

// fieldType resolves a field selector, promoting through embedded fields.
func (ix *dispatchIndex) fieldType(t typeRef, name string, depth int) typeRef {
	if depth > maxTypeDepth {
		return typeRef{}
	}
	st, file := ix.structOf(t)
	if st == nil {
		return typeRef{}
	}
	for _, field := range st.Fields.List {
		if len(field.Names) == 0 && embeddedName(field.Type) == name {
			return ix.typeOf(file, field.Type)
		}
		for _, id := range field.Names {
			if id.Name == name {
				return ix.typeOf(file, field.Type)
			}
		}
	}
	for _, field := range st.Fields.List {
		if len(field.Names) != 0 {
			continue
		}
		if ft := ix.fieldType(ix.typeOf(file, field.Type), name, depth+1); ft.known() {
			return ft
		}
	}
	return typeRef{}
}

// methodOf finds the definition a method call on t reaches: t's own method,
// a method promoted from an embedded field, the aliased type's method, or —
// for an interface — the bound implementation's method.
func (ix *dispatchIndex) methodOf(t typeRef, name string, depth int) *dispatchFunc {
	if depth > maxTypeDepth || !t.known() {
		return nil
	}
	p := ix.pkg(t.pkg)
	if p == nil {
		return nil
	}
	if fn := p.funcs[t.name+"."+name]; fn != nil {
		return fn
	}
	if impl, ok := ix.bindings[t]; ok {
		return ix.methodOf(impl, name, depth+1)
	}
	ts := p.types[t.name]
	if ts == nil {
		return nil
	}
	st, ok := ts.spec.Type.(*ast.StructType)
	if !ok {
		if ts.spec.Assign.IsValid() {
			return ix.methodOf(ix.typeOf(ts.file, ts.spec.Type), name, depth+1)
		}
		return nil
	}
	for _, field := range st.Fields.List {
		if len(field.Names) != 0 {
			continue
		}
		if fn := ix.methodOf(ix.typeOf(ts.file, field.Type), name, depth+1); fn != nil {
			return fn
		}
	}
	return nil
}

// resolveFunc resolves a call target or function reference to its in-module
// definition: f (this package), pkg.F (the file's import), recv.M (the
// inferred receiver type), or a method expression (*T).M.
func (ix *dispatchIndex) resolveFunc(sc *dispatchScope, e ast.Expr) *dispatchFunc {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return ix.resolveFunc(sc, x.X)
	case *ast.IndexExpr:
		return ix.resolveFunc(sc, x.X)
	case *ast.IndexListExpr:
		return ix.resolveFunc(sc, x.X)
	case *ast.Ident:
		if sc.isLocal(x.Name) {
			return nil
		}
		return sc.file.pkg.funcs[x.Name]
	case *ast.SelectorExpr:
		if recv, ok := ix.typeExpr(sc, x.X); ok {
			return ix.methodOf(recv, x.Sel.Name, 0)
		}
		if importPath, ok := ix.qualifiedPath(sc, x.X); ok {
			if p := ix.pkg(importPath); p != nil {
				return p.funcs[x.Sel.Name]
			}
			return nil
		}
		return ix.methodOf(ix.exprType(sc, x.X), x.Sel.Name, 0)
	}
	return nil
}

// resolveVar resolves a reference to an in-module package-level variable.
func (ix *dispatchIndex) resolveVar(sc *dispatchScope, e ast.Expr) *dispatchVar {
	switch x := e.(type) {
	case *ast.Ident:
		if sc.isLocal(x.Name) {
			return nil
		}
		return sc.file.pkg.vars[x.Name]
	case *ast.SelectorExpr:
		if importPath, ok := ix.qualifiedPath(sc, x.X); ok {
			if p := ix.pkg(importPath); p != nil {
				return p.vars[x.Sel.Name]
			}
		}
	}
	return nil
}

// position renders a node position as module-relative file:line.
func (ix *dispatchIndex) position(pos token.Pos) string {
	p := ix.fset.Position(pos)
	rel, err := filepath.Rel(ix.root, p.Filename)
	if err != nil {
		rel = p.Filename
	}
	return filepath.ToSlash(rel) + ":" + strconv.Itoa(p.Line)
}

// exprLabel renders a case value or route pattern as an operation name.
func exprLabel(e ast.Expr) string {
	if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		if s, err := strconv.Unquote(lit.Value); err == nil {
			return s
		}
	}
	return types.ExprString(e)
}
