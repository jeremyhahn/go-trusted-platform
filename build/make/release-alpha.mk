# release-alpha-template: v2.4.0. `make release-alpha VERSION=vX.Y.Z-alpha` cuts an alpha release; the recipe body is in release-common.mk (tests: testdata/release-alpha-tests.sh).

# Settable Make variables reach the recipe only through target-specific exports; the body uses only shell parameters ($$REL_*).
.PHONY: release-alpha
# The export and guard lines live in release-common.mk, where `override` keeps a command-line REL_* from injecting recipe text.
include $(dir $(lastword $(MAKEFILE_LIST)))release-common.mk
release-alpha:
	@test -n "$$REL_VERSION" || { echo 'ERROR: state the version explicitly: make release-alpha VERSION=vX.Y.Z-alpha (release-versioning.md decides patch/minor/major — the recipe refuses to guess)'; exit 1; }
	@printf '%s' "$$REL_VERSION" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-alpha$$' || { echo "ERROR: VERSION is not of the form vX.Y.Z-alpha (no leading zeroes): $$REL_VERSION"; exit 1; }
	$(RELEASE_GUARDS)
	$(RELEASE_MONOTONIC)
	$(RELEASE_CUT)
