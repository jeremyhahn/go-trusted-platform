package main

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// checker is the small stdlib stand-in for testify the tests use, so the
// tool stays stdlib-only: assert marks the test failed and goes on,
// require stops it.
type checker struct{ fatal bool }

var (
	assert  = checker{fatal: false}
	require = checker{fatal: true}
)

func (c checker) fail(t *testing.T, msg string, extra []any) {
	t.Helper()
	if len(extra) > 0 {
		msg += ": " + fmt.Sprint(extra...)
	}
	if c.fatal {
		t.Fatal(msg)
	}
	t.Error(msg)
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Interface, reflect.Func, reflect.Chan:
		return r.IsNil()
	}
	return false
}

func (c checker) Equal(t *testing.T, want, got any, extra ...any) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		c.fail(t, fmt.Sprintf("not equal:\nwant: %#v\n got: %#v", want, got), extra)
	}
}

func (c checker) NotEqual(t *testing.T, notWant, got any, extra ...any) {
	t.Helper()
	if reflect.DeepEqual(notWant, got) {
		c.fail(t, fmt.Sprintf("should differ from %#v", notWant), extra)
	}
}

func (c checker) True(t *testing.T, v bool, extra ...any) {
	t.Helper()
	if !v {
		c.fail(t, "should be true", extra)
	}
}

func (c checker) False(t *testing.T, v bool, extra ...any) {
	t.Helper()
	if v {
		c.fail(t, "should be false", extra)
	}
}

// contains reports a substring of a string or a key of a map.
func contains(container, item any) bool {
	if s, ok := container.(string); ok {
		sub, _ := item.(string)
		return strings.Contains(s, sub)
	}
	r := reflect.ValueOf(container)
	if r.Kind() == reflect.Map {
		return r.MapIndex(reflect.ValueOf(item)).IsValid()
	}
	if r.Kind() == reflect.Slice {
		for i := 0; i < r.Len(); i++ {
			if reflect.DeepEqual(r.Index(i).Interface(), item) {
				return true
			}
		}
	}
	return false
}

func (c checker) Contains(t *testing.T, container, item any, extra ...any) {
	t.Helper()
	if !contains(container, item) {
		c.fail(t, fmt.Sprintf("%#v does not contain %#v", container, item), extra)
	}
}

func (c checker) NotContains(t *testing.T, container, item any, extra ...any) {
	t.Helper()
	if contains(container, item) {
		c.fail(t, fmt.Sprintf("%#v should not contain %#v", container, item), extra)
	}
}

func length(v any) int {
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.String, reflect.Map, reflect.Slice, reflect.Array, reflect.Chan:
		return r.Len()
	}
	return -1
}

func (c checker) Empty(t *testing.T, v any, extra ...any) {
	t.Helper()
	if !isNil(v) && length(v) > 0 {
		c.fail(t, fmt.Sprintf("should be empty: %#v", v), extra)
	}
}

func (c checker) NotEmpty(t *testing.T, v any, extra ...any) {
	t.Helper()
	if isNil(v) || length(v) <= 0 {
		c.fail(t, "should not be empty", extra)
	}
}

func (c checker) Len(t *testing.T, v any, n int, extra ...any) {
	t.Helper()
	if got := length(v); got != n {
		c.fail(t, fmt.Sprintf("length %d, want %d", got, n), extra)
	}
}

func (c checker) Nil(t *testing.T, v any, extra ...any) {
	t.Helper()
	if !isNil(v) {
		c.fail(t, fmt.Sprintf("should be nil: %#v", v), extra)
	}
}

func (c checker) NotNil(t *testing.T, v any, extra ...any) {
	t.Helper()
	if isNil(v) {
		c.fail(t, "should not be nil", extra)
	}
}

func (c checker) Error(t *testing.T, err error, extra ...any) {
	t.Helper()
	if err == nil {
		c.fail(t, "want an error", extra)
	}
}

func (c checker) NoError(t *testing.T, err error, extra ...any) {
	t.Helper()
	if err != nil {
		c.fail(t, fmt.Sprintf("unexpected error: %v", err), extra)
	}
}

func (c checker) ErrorAs(t *testing.T, err error, target any, extra ...any) {
	t.Helper()
	if !errors.As(err, target) {
		c.fail(t, fmt.Sprintf("%v is not a %T", err, target), extra)
	}
}
