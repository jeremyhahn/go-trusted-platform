module github.com/jeremyhahn/go-trusted-platform/sdk/go

go 1.26.4

// Pin armon/go-metrics to v0.4.1 - newer versions declare as hashicorp/go-metrics
replace github.com/armon/go-metrics => github.com/armon/go-metrics v0.4.1

require (
	github.com/jeremyhahn/go-quicbaas/sdk/go v0.0.0
	github.com/jeremyhahn/go-trusted-platform v0.0.0
	github.com/stretchr/testify v1.11.1
	google.golang.org/grpc v1.79.3
	google.golang.org/protobuf v1.36.11
)

// Cross-repo dependency resolution for local development is handled by the
// parent go.work `use` directives (single source of truth: /mnt/vm-host-1).
// No cross-repo local-path replaces are committed here; the `require` versions
// above are what GitHub builds use once those modules are published.
