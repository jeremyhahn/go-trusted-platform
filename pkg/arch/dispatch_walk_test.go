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

// Walker and stub rule behind the dispatch-stub check (dispatch_stub_test.go).
//
// The walker starts at each transport's served entry point and follows every
// call and function reference it can resolve (dispatch_resolver_test.go)
// inside the API packages. An operation is a dispatch-switch arm, a dispatch
// map entry, a registered route, or a registered gRPC method; the operation
// label follows the walk into the handlers it reaches.
//
// A handler is a stub when its last statement returns, or is, an expression
// carrying a stub marker: codes.Unimplemented, a *NotImplemented* name
// (StatusNotImplemented, ErrXNotImplemented), a "not yet supported" string,
// or a call to a one-line function that returns one of those. Only the last
// statement counts, so capability checks that answer 501 on one branch and
// do the work on the next are not stubs. Unknown-opcode fallbacks are not
// stubs either: they answer requests no table serves.
package arch_test

import (
	"go/ast"
	"go/token"
	"regexp"
	"sort"
	"strings"
)

// unimplementedServer matches the generated gRPC fallback types whose
// methods answer codes.Unimplemented until the embedding type overrides them.
var unimplementedServer = regexp.MustCompile(`^Unimplemented\w*Server$`)

// DispatchStubError reports a served operation that reaches a stub and has no
// exception.
type DispatchStubError struct {
	Operation string
	At        string
	Kind      string
}

func (e *DispatchStubError) Error() string {
	return e.At + ": " + e.Operation + " reaches a stub (" + e.Kind + "); implement it, or add a stubExceptions entry"
}

// StaleStubExceptionError reports an exception that no live stub matches. The
// stub was fixed or moved: delete the entry and lower stubExceptionCeiling.
type StaleStubExceptionError struct {
	Operation string
	At        string
}

func (e *StaleStubExceptionError) Error() string {
	return e.At + ": stale stub exception for " + e.Operation + "; delete it and lower stubExceptionCeiling"
}

// DispatchUnresolvedError reports a served operation whose handler the check
// could not resolve, so it cannot say whether the handler is real.
type DispatchUnresolvedError struct {
	Operation string
	At        string
	What      string
}

func (e *DispatchUnresolvedError) Error() string {
	return e.At + ": " + e.Operation + ": cannot resolve " + e.What
}

// DispatchBindingError reports an interface binding the daemon no longer
// wires the way the check's configuration says.
type DispatchBindingError struct {
	Interface string
	Impl      string
	WiredIn   string
}

func (e *DispatchBindingError) Error() string {
	return e.WiredIn + " no longer passes " + e.Impl + " as " + e.Interface + "; update dispatchBinding"
}

// dispatchFinding is one served operation that reaches a stub.
type dispatchFinding struct {
	Operation string
	At        string
	Kind      string
}

// dispatchBinding states which implementation an interface-typed handler
// field holds. The check verifies it at the wiring site instead of trusting
// it: WiredIn must call Into with an Impl value as argument Arg.
type dispatchBinding struct {
	Interface typeRef
	Impl      typeRef
	WiredIn   funcKey
	Into      funcKey
	Arg       int
}

// dispatchTransport names one transport's served entry points. A root whose
// Name is "*" stands for every method of Recv.
type dispatchTransport struct {
	Name     string
	Roots    []funcKey
	Register []string // packages whose Register<X>Server calls are served
}

// dispatchConfig describes the served dispatch surface. Package paths are
// module-relative.
type dispatchConfig struct {
	Root       string
	Module     string
	Tags       []string
	Scope      []string
	Bindings   []dispatchBinding
	Transports []dispatchTransport
}

// dispatchReport is the outcome of one check run.
type dispatchReport struct {
	Findings   []dispatchFinding
	Operations map[string]int // operations reached, per transport
	Errs       []error
}

type dispatchWalker struct {
	ix        *dispatchIndex
	scope     []string
	transport string
	visited   map[*dispatchFunc]bool
	vars      map[*dispatchVar]bool
	producers map[*dispatchFunc]bool
	ops       map[string]bool
	report    *dispatchReport
	seen      map[dispatchFinding]bool
}

// runDispatchCheck walks every configured transport and returns the stubs
// its operations reach.
func runDispatchCheck(cfg dispatchConfig) *dispatchReport {
	ix := newDispatchIndex(cfg.Root, cfg.Module, cfg.Tags)
	rep := &dispatchReport{Operations: map[string]int{}}
	var scope []string
	for _, s := range cfg.Scope {
		scope = append(scope, cfg.Module+"/"+s)
	}
	seen := map[dispatchFinding]bool{}
	producers := map[*dispatchFunc]bool{}
	for _, b := range cfg.Bindings {
		if err := ix.bind(qualifyBinding(cfg.Module, b)); err != nil {
			rep.Errs = append(rep.Errs, err)
		}
	}
	for _, tr := range cfg.Transports {
		w := &dispatchWalker{
			ix:        ix,
			scope:     scope,
			transport: tr.Name,
			visited:   map[*dispatchFunc]bool{},
			vars:      map[*dispatchVar]bool{},
			producers: producers,
			ops:       map[string]bool{},
			report:    rep,
			seen:      seen,
		}
		w.roots(cfg.Module, tr)
		rep.Operations[tr.Name] = len(w.ops)
	}
	rep.Errs = append(rep.Errs, ix.errs...)
	sort.Slice(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.At != b.At {
			return a.At < b.At
		}
		return a.Operation < b.Operation
	})
	return rep
}

func qualifyBinding(module string, b dispatchBinding) dispatchBinding {
	b.Interface.pkg = module + "/" + b.Interface.pkg
	b.Impl.pkg = module + "/" + b.Impl.pkg
	b.WiredIn.Pkg = module + "/" + b.WiredIn.Pkg
	b.Into.Pkg = module + "/" + b.Into.Pkg
	return b
}

// bind verifies a binding at its wiring site and records it.
func (ix *dispatchIndex) bind(b dispatchBinding) error {
	wired := ix.funcByKey(b.WiredIn)
	into := ix.funcByKey(b.Into)
	if wired == nil || into == nil || wired.decl.Body == nil {
		return &DispatchBindingError{Interface: b.Interface.name, Impl: b.Impl.name, WiredIn: b.WiredIn.String()}
	}
	sc := ix.scopeOf(wired)
	found := false
	ast.Inspect(wired.decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found || len(call.Args) <= b.Arg {
			return !found
		}
		if ix.resolveFunc(sc, call.Fun) == into && ix.exprType(sc, call.Args[b.Arg]) == b.Impl {
			found = true
		}
		return !found
	})
	if !found {
		return &DispatchBindingError{Interface: b.Interface.name, Impl: b.Impl.name, WiredIn: b.WiredIn.String()}
	}
	ix.bindings[b.Interface] = b.Impl
	return nil
}

func (w *dispatchWalker) roots(module string, tr dispatchTransport) {
	for _, root := range tr.Roots {
		root.Pkg = module + "/" + root.Pkg
		if root.Name != "*" {
			fn := w.ix.funcByKey(root)
			if fn == nil {
				w.unresolved(tr.Name, "", "root "+root.String())
				continue
			}
			w.visit(fn.key.local(), fn)
			continue
		}
		p := w.ix.pkg(root.Pkg)
		if p == nil {
			w.unresolved(tr.Name, "", "root package "+root.Pkg)
			continue
		}
		for _, fn := range p.order {
			if fn.key.Recv == root.Recv {
				w.visit(fn.key.local(), fn)
			}
		}
	}
	for _, pkg := range tr.Register {
		w.registrations(module + "/" + pkg)
	}
}

func (w *dispatchWalker) unresolved(op, at, what string) {
	w.report.Errs = append(w.report.Errs, &DispatchUnresolvedError{Operation: op, At: at, What: what})
}

func (w *dispatchWalker) found(op, at, kind string) {
	f := dispatchFinding{Operation: w.transport + " " + op, At: at, Kind: kind}
	key := dispatchFinding{Operation: f.Operation, At: f.At}
	if w.seen[key] {
		return
	}
	w.seen[key] = true
	w.report.Findings = append(w.report.Findings, f)
}

func (w *dispatchWalker) inScope(importPath string) bool {
	for _, prefix := range w.scope {
		if importPath == prefix || strings.HasPrefix(importPath, prefix+"/") {
			return true
		}
	}
	return false
}

// visit judges a reached function and walks it. A dispatcher (a function
// holding a dispatch switch) is judged arm by arm instead of by its tail.
func (w *dispatchWalker) visit(op string, fn *dispatchFunc) {
	if fn == nil || w.visited[fn] || !w.inScope(fn.key.Pkg) || fn.decl.Body == nil {
		return
	}
	w.visited[fn] = true
	if w.producer(fn) {
		return
	}
	sc := w.ix.scopeOf(fn)
	if !hasDispatchSwitch(fn.decl.Body) {
		if at, kind, ok := w.tailStub(sc, fn.decl.Body.List); ok {
			w.found(op, at, kind)
			return
		}
	}
	w.walk(op, sc, fn.decl.Body)
}

func (w *dispatchWalker) visitVar(op string, v *dispatchVar) {
	if v == nil || w.vars[v] || !w.inScope(v.file.pkg.path) || len(v.spec.Values) == 0 {
		return
	}
	w.vars[v] = true
	value := v.spec.Values[0]
	if len(v.spec.Values) == len(v.spec.Names) {
		value = v.spec.Values[v.index]
	}
	sc := newScope(v.file)
	ast.Inspect(value, func(n ast.Node) bool {
		collectLocal(sc, n)
		return true
	})
	w.walk(op, sc, value)
}

// walk follows every resolvable call and function reference under root.
func (w *dispatchWalker) walk(op string, sc *dispatchScope, root ast.Node) {
	ast.Inspect(root, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SwitchStmt:
			if isDispatchSwitch(x) {
				w.dispatchSwitch(op, sc, x)
				return false
			}
		case *ast.CallExpr:
			if router, path, handler, ok := routeCall(x); ok {
				w.walk(op, sc, x.Fun)
				w.handler(routePrefix(sc, router, 0)+exprLabel(path), sc, handler)
				return false
			}
		case *ast.CompositeLit:
			w.compositeLit(op, sc, x)
			return false
		case *ast.SelectorExpr:
			w.reference(op, sc, x)
			w.walk(op, sc, x.X)
			return false
		case *ast.Ident:
			w.reference(op, sc, x)
		}
		return true
	})
}

func (w *dispatchWalker) reference(op string, sc *dispatchScope, e ast.Expr) {
	if fn := w.ix.resolveFunc(sc, e); fn != nil {
		w.visit(op, fn)
		return
	}
	w.visitVar(op, w.ix.resolveVar(sc, e))
}

// handler walks a value served as one operation: a route handler or a
// dispatch map entry. A function literal is judged by its own tail.
func (w *dispatchWalker) handler(op string, sc *dispatchScope, e ast.Expr) {
	w.ops[op] = true
	if lit, ok := e.(*ast.FuncLit); ok && !hasDispatchSwitch(lit.Body) {
		if at, kind, ok := w.tailStub(sc, lit.Body.List); ok {
			w.found(op, at, kind)
			return
		}
	}
	w.walk(op, sc, e)
}

// compositeLit labels each entry of a dispatch map (a map literal whose value
// is a function) with its key, and walks everything else under op. Struct
// field names are never resolved as references.
func (w *dispatchWalker) compositeLit(op string, sc *dispatchScope, lit *ast.CompositeLit) {
	isMap := w.isMapLit(sc, lit)
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			w.walk(op, sc, elt)
			continue
		}
		if !isMap {
			w.walk(op, sc, kv.Value)
			continue
		}
		w.walk(op, sc, kv.Key)
		if w.isFuncValue(sc, kv.Value) {
			w.handler(exprLabel(kv.Key), sc, kv.Value)
			continue
		}
		w.walk(op, sc, kv.Value)
	}
}

func (w *dispatchWalker) isMapLit(sc *dispatchScope, lit *ast.CompositeLit) bool {
	if _, ok := lit.Type.(*ast.MapType); ok {
		return true
	}
	t, ok := w.ix.typeExpr(sc, lit.Type)
	if !ok {
		return false
	}
	ts := w.ix.declaredType(t)
	if ts == nil {
		return false
	}
	_, isMap := ts.spec.Type.(*ast.MapType)
	return isMap
}

func (w *dispatchWalker) isFuncValue(sc *dispatchScope, e ast.Expr) bool {
	if _, ok := e.(*ast.FuncLit); ok {
		return true
	}
	return w.ix.resolveFunc(sc, e) != nil
}

// dispatchSwitch judges each arm of a dispatch switch as one operation. The
// default arm answers unknown requests: it is walked, never judged.
func (w *dispatchWalker) dispatchSwitch(op string, sc *dispatchScope, sw *ast.SwitchStmt) {
	if sw.Init != nil {
		w.walk(op, sc, sw.Init)
	}
	if sw.Tag != nil {
		w.walk(op, sc, sw.Tag)
	}
	for _, stmt := range sw.Body.List {
		clause, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		if clause.List == nil {
			w.walkStmts(op, sc, clause.Body)
			continue
		}
		arm := caseLabel(clause.List)
		w.ops[arm] = true
		if at, kind, ok := w.tailStub(sc, clause.Body); ok {
			w.found(arm, at, kind)
			continue
		}
		w.walkStmts(arm, sc, clause.Body)
	}
}

func (w *dispatchWalker) walkStmts(op string, sc *dispatchScope, stmts []ast.Stmt) {
	for _, stmt := range stmts {
		w.walk(op, sc, stmt)
	}
}

func caseLabel(values []ast.Expr) string {
	labels := make([]string, 0, len(values))
	for _, v := range values {
		labels = append(labels, exprLabel(v))
	}
	return strings.Join(labels, ", ")
}

// routeCall matches router.HandleFunc(path, h) and router.Handle(path, h).
func routeCall(call *ast.CallExpr) (ast.Expr, ast.Expr, ast.Expr, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || len(call.Args) != 2 || (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") {
		return nil, nil, nil, false
	}
	return sel.X, call.Args[0], call.Args[1], true
}

// routePrefix renders the path prefixes of a subrouter built in the same
// function (r := router.PathPrefix("/cluster").Subrouter()), outermost first.
func routePrefix(sc *dispatchScope, router ast.Expr, depth int) string {
	if depth > maxTypeDepth {
		return ""
	}
	if id, ok := router.(*ast.Ident); ok {
		for _, b := range sc.locals[id.Name] {
			if b.value != nil {
				return routePrefix(sc, b.value, depth+1)
			}
		}
		return ""
	}
	call, ok := router.(*ast.CallExpr)
	if !ok {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if sel.Sel.Name == "PathPrefix" && len(call.Args) == 1 {
		return routePrefix(sc, sel.X, depth+1) + exprLabel(call.Args[0])
	}
	return routePrefix(sc, sel.X, depth+1)
}

// hasDispatchSwitch reports whether body holds a dispatch switch.
func hasDispatchSwitch(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if sw, ok := n.(*ast.SwitchStmt); ok && isDispatchSwitch(sw) {
			found = true
		}
		return !found
	})
	return found
}

// isDispatchSwitch reports whether a switch routes operations: its tag or a
// case names an opcode, or a case is an MCP tool name.
func isDispatchSwitch(sw *ast.SwitchStmt) bool {
	exprs := []ast.Expr{}
	if sw.Tag != nil {
		exprs = append(exprs, sw.Tag)
	}
	for _, stmt := range sw.Body.List {
		if clause, ok := stmt.(*ast.CaseClause); ok {
			exprs = append(exprs, clause.List...)
		}
	}
	for _, e := range exprs {
		if namesDispatchConstant(e) {
			return true
		}
	}
	return false
}

func namesDispatchConstant(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			found = found || dispatchConstant.MatchString(x.Name)
		case *ast.BasicLit:
			found = found || (x.Kind == token.STRING && strings.HasPrefix(exprLabel(x), mcpToolPrefix))
		}
		return !found
	})
	return found
}

// tailStub judges a statement list by its last statement (the one before a
// bare trailing return): a stub when it returns, or is, a marker.
func (w *dispatchWalker) tailStub(sc *dispatchScope, stmts []ast.Stmt) (string, string, bool) {
	n := len(stmts)
	if n == 0 {
		return "", "", false
	}
	tail := stmts[n-1]
	if ret, ok := tail.(*ast.ReturnStmt); ok && len(ret.Results) == 0 && n > 1 {
		tail = stmts[n-2]
	}
	switch s := tail.(type) {
	case *ast.ReturnStmt:
		if len(s.Results) == 0 {
			return "", "", false
		}
	case *ast.ExprStmt:
	default:
		return "", "", false
	}
	kind, ok := w.marker(sc, tail)
	if !ok {
		return "", "", false
	}
	return w.ix.position(tail.Pos()), kind, true
}

// marker reports the stub marker n carries, if any.
func (w *dispatchWalker) marker(sc *dispatchScope, n ast.Node) (string, bool) {
	kind := ""
	unknown := false
	ast.Inspect(n, func(node ast.Node) bool {
		switch x := node.(type) {
		case *ast.Ident:
			if strings.Contains(x.Name, "Unknown") {
				unknown = true
			}
			if kind == "" && strings.Contains(x.Name, "NotImplemented") {
				kind = x.Name
			}
		case *ast.SelectorExpr:
			if x.Sel.Name == "Unimplemented" {
				if importPath, ok := w.ix.qualifiedPath(sc, x.X); ok && importPath == grpcCodesImport && kind == "" {
					kind = "codes.Unimplemented"
				}
			}
		case *ast.BasicLit:
			if x.Kind == token.STRING && strings.Contains(strings.ToLower(x.Value), "not yet supported") && kind == "" {
				kind = `"not yet supported"`
			}
		case *ast.CallExpr:
			if fn := w.ix.resolveFunc(sc, x.Fun); fn != nil && kind == "" && w.producer(fn) {
				kind = "returns " + fn.key.local()
			}
		}
		return !unknown
	})
	return kind, kind != "" && !unknown
}

// producer reports whether fn only produces a stub error: it returns a single
// error, and its body is one return of a marker (clusterNotImplemented). A
// one-line handler returning a stub response is a stub, not a producer.
func (w *dispatchWalker) producer(fn *dispatchFunc) bool {
	if is, ok := w.producers[fn]; ok {
		return is
	}
	w.producers[fn] = false
	body := fn.decl.Body
	if body == nil || len(body.List) != 1 || !returnsOnlyError(fn.decl.Type) {
		return false
	}
	ret, ok := body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) == 0 {
		return false
	}
	_, is := w.marker(w.ix.scopeOf(fn), ret)
	w.producers[fn] = is
	return is
}

func returnsOnlyError(ft *ast.FuncType) bool {
	if ft.Results == nil || len(ft.Results.List) != 1 || len(ft.Results.List[0].Names) > 1 {
		return false
	}
	id, ok := ft.Results.List[0].Type.(*ast.Ident)
	return ok && id.Name == "error"
}

// registrations walks every Register<X>Server(server, impl) call in a
// package: each method of the X service interface is one operation, served
// by the method impl's type resolves it to.
func (w *dispatchWalker) registrations(importPath string) {
	p := w.ix.pkg(importPath)
	if p == nil {
		w.unresolved(w.transport, "", "registration package "+importPath)
		return
	}
	for _, fn := range p.order {
		if fn.decl.Body == nil {
			continue
		}
		sc := w.ix.scopeOf(fn)
		ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				w.registration(sc, call)
			}
			return true
		})
	}
}

func (w *dispatchWalker) registration(sc *dispatchScope, call *ast.CallExpr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || len(call.Args) != 2 {
		return
	}
	match := registerServer.FindStringSubmatch(sel.Sel.Name)
	if match == nil {
		return
	}
	pbPath, ok := w.ix.qualifiedPath(sc, sel.X)
	if !ok {
		return
	}
	at := w.ix.position(call.Pos())
	impl := w.ix.exprType(sc, call.Args[1])
	if !impl.known() {
		w.unresolved(match[1], at, "the registered implementation's type")
		return
	}
	if w.ix.pkg(impl.pkg) == nil {
		return
	}
	for _, method := range w.serviceMethods(pbPath, match[1], impl) {
		op := match[1] + "/" + method
		w.ops[op] = true
		fn := w.ix.methodOf(impl, method, 0)
		switch {
		case fn == nil:
			w.unresolved(op, at, impl.name+"."+method)
		case unimplementedServer.MatchString(fn.key.Recv):
			w.found(op, w.ix.position(fn.decl.Pos()), "embedded "+fn.key.Recv+" not overridden")
		default:
			w.visit(op, fn)
		}
	}
}

// serviceMethods lists a service's RPCs from the generated <X>Server
// interface, or — for a service generated outside the module — the exported
// methods the implementation declares.
func (w *dispatchWalker) serviceMethods(pbPath, service string, impl typeRef) []string {
	var methods []string
	if ts := w.ix.declaredType(typeRef{pkg: pbPath, name: service + "Server"}); ts != nil {
		if iface, ok := ts.spec.Type.(*ast.InterfaceType); ok {
			for _, field := range iface.Methods.List {
				if _, isFunc := field.Type.(*ast.FuncType); !isFunc {
					continue
				}
				for _, name := range field.Names {
					if name.IsExported() {
						methods = append(methods, name.Name)
					}
				}
			}
			return methods
		}
	}
	for _, fn := range w.ix.pkg(impl.pkg).order {
		if fn.key.Recv == impl.name && ast.IsExported(fn.key.Name) {
			methods = append(methods, fn.key.Name)
		}
	}
	return methods
}
