# shellcheck shell=sh disable=SC2034 # read by make and sourced; no use here
# Tool pins for the devcontainer image (handbook devcontainer.md §2). The
# Makefile `include`s this file and `make docker-build` passes each value to
# build/docker/devcontainer/Dockerfile as a build argument, so the toolchain
# image and the CI that runs in it use the same versions.
#
# Format: plain KEY=value lines, no spaces, no quotes, so that both make and sh
# read them identically. Sourced, never executed.
#
# golangci-lint, actionlint, gosec and swag are NOT pinned here: each is built
# from its own tools module under build/tools-src/, whose go.mod is the one
# place its version lives (the Makefile reads it with tools-module-version). The
# toolchain image downloads those modules, so `make lint` and `make gosec`
# build them offline from the same pins. swag is the OpenAPI generator `make
# build-public-html` runs in the integration image; its module raises swag's
# stale dependencies to patched versions, which `go install swag@version`
# cannot (#933).
#
# Every download carries its SHA-256. The `go install` tools need none: the Go
# checksum database verifies the module they are built from.

# The Go toolchain: the version go.mod names, on Debian bookworm (glibc). The
# integration suite needs Debian's swtpm, Open vSwitch, qemu and tpm2-tss
# packages, which Alpine does not carry (devops.md §9a).
GO_IMAGE=golang:1.27.4-bookworm

GOVULNCHECK_VERSION=v1.8.0

# trivy: a release archive, checked against these digests (upstream's
# trivy_<version>_checksums.txt) before it is unpacked.
TRIVY_VERSION=v0.75.0
TRIVY_SHA256_LINUX_AMD64=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
TRIVY_SHA256_LINUX_ARM64=a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3

# Node.js for the integration image (`make build-public-html`, the web
# Playwright suite): the official linux tar.xz, checked against these digests
# (upstream's SHASUMS256.txt) before it is unpacked. Node 24 LTS because the
# npm it bundles (11.19.1) carries the fewest known-vulnerable dependencies
# the trivy image gate reports (#933).
NODE_VERSION=v24.22.0
NODE_SHA256_LINUX_AMD64=cc2f601cee82d9a5a233302fe307abc600727035fd7d2c3a3571755989e95008
NODE_SHA256_LINUX_ARM64=fef00bb4d36e1c50104a9775a10359beee98f162b4104dd12472c75065c6a143
