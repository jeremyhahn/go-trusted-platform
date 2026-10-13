module github.com/jeremyhahn/go-trusted-platform/build/tools-src/actionlint

go 1.27.2

require (
	github.com/bmatcuk/doublestar/v4 v4.10.0
	github.com/fatih/color v1.19.0
	github.com/google/go-cmp v0.7.0
	github.com/mattn/go-colorable v0.1.14
	github.com/mattn/go-runewidth v0.0.21
	github.com/mattn/go-shellwords v1.0.12
	github.com/robfig/cron/v3 v3.0.1
	github.com/yuin/goldmark v1.7.17
	go.yaml.in/yaml/v4 v4.0.0-rc.3
	golang.org/x/net v0.60.0
	golang.org/x/sync v0.20.0
	golang.org/x/sys v0.48.0
)

require (
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/rhysd/actionlint v1.7.12
)

tool github.com/rhysd/actionlint/cmd/actionlint
