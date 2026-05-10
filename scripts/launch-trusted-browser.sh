#!/usr/bin/env bash
# Copyright (c) 2025 Jeremy Hahn
# Copyright (c) 2025 Automate The Things, LLC
#
# launch-trusted-browser.sh — fetch the trusted-platform control-plane
# CA bundle, install it into xkey + the OS trust store + the chosen
# browser's trust store, then launch that browser at the platformd
# WebUI with a fully-trusted TLS connection.
#
# Supported browsers: chrome (Chromium-family, NSS DB) and firefox
# (per-profile cert9.db). Defaults to chrome.
#
# This script is the single user-facing entry point for "I want a
# browser pointed at the trusted-platform UI that won't show a TLS
# warning". It MUST work end-to-end on a fresh workstation with no
# prior trust state.
#
# Usage:
#   scripts/launch-trusted-browser.sh                           # defaults
#   scripts/launch-trusted-browser.sh --browser firefox
#   scripts/launch-trusted-browser.sh --cp 198.18.1.140
#   scripts/launch-trusted-browser.sh --url https://cp.example.com:8443/auth/webauthn
#   scripts/launch-trusted-browser.sh --no-launch               # only set up trust
#   scripts/launch-trusted-browser.sh --skip-os-trust           # skip sudo step
#
# Trust is installed in three layers:
#
#   1. xkey trust store — the platform's own trust registry. Records
#      the bundle with purpose "bootstrap-ca" and source path so xkey
#      knows where the anchor came from.
#
#   2. OS system trust store — /usr/local/share/ca-certificates/ +
#      update-ca-certificates. Makes curl, wget, Java, Firefox-on-
#      OS-trust-mode, and any other tool that consumes the system
#      bundle accept the CA.
#
#   3. Browser-specific trust store — Chrome's NSS DB at
#      ~/.pki/nssdb (via certutil) OR each Firefox profile's
#      cert9.db. Chromium-family browsers (Chrome, Brave, Edge on
#      Linux, etc.) all share the NSS DB. Firefox does NOT consult
#      the OS trust store on Linux; it only trusts what's in its
#      per-profile NSS DB, so the script writes to every profile it
#      finds under ~/.mozilla/firefox/.
#
# The browser-launch step uses a dedicated user-data-dir for Chrome
# (so an already-running Chrome's NSS lock doesn't block the cert
# import) and waits to confirm the trust write succeeded. Firefox
# profiles must NOT be running while certutil writes; the script
# offers to terminate the running browser process first.

set -euo pipefail

# -----------------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------------

BROWSER="chrome"
CP_HOST=""                       # auto-derived from URL or default to lab-node-2
CP_BUNDLE_PORT="9443"            # CP serves /api/v1/acme/ca-bundle on this port
URL=""                           # auto-derived from CP_HOST if not provided
BUNDLE_PATH="${HOME}/.config/trusted-platform/ca/cp-ca-bundle.pem"
NICKNAME="trusted-platform-cp-ca"
PROFILE_DIR_CHROME="${HOME}/.config/trusted-platform/chrome-profile"
SKIP_OS_TRUST=0
NO_LAUNCH=0
ASSUME_YES=0
QUIET=0

# Dual-domain default: cp.example.com is the public-facing CN; 8443 is
# the REST + WebUI port on a typical trusted-platform CP install.
DEFAULT_CP_HOST="198.18.1.140"
DEFAULT_URL_TEMPLATE="https://cp.example.com:8443/"

usage() {
	cat <<USAGE
Fetch the trusted-platform CP CA bundle, import into xkey + OS + browser
trust stores, and launch the browser at the platformd WebUI.

Usage: $0 [flags]

Flags:
  --browser {chrome|firefox}    Target browser (default: chrome)
  --cp <host-or-ip>             Control-plane host that serves the CA
                                bundle endpoint. Default: ${DEFAULT_CP_HOST}
  --bundle-port <port>          CP CA-bundle endpoint port (default: 9443)
  --url <url>                   URL to open in the browser
                                (default: ${DEFAULT_URL_TEMPLATE})
  --bundle <path>               Where to save / read the bundle
                                (default: ${BUNDLE_PATH})
  --nickname <name>             Trust-store nickname for the CA
                                (default: ${NICKNAME})
  --no-launch                   Set up trust only; don't launch a browser
  --skip-os-trust               Don't touch /usr/local/share/ca-certificates
                                (no sudo prompt)
  -y, --yes                     Don't prompt; assume yes for browser-kill
  -q, --quiet                   Suppress informational logs
  -h, --help                    This help

Environment:
  TRUSTED_PLATFORM_CP           Same as --cp
  TRUSTED_PLATFORM_BROWSER      Same as --browser
USAGE
}

log()  { [ "${QUIET}" -eq 1 ] || echo "[trusted-browser] $*" >&2; }
warn() { echo "[trusted-browser] WARN: $*" >&2; }
err()  { echo "[trusted-browser] ERROR: $*" >&2; exit 1; }

confirm() {
	local prompt="$1"
	if [ "${ASSUME_YES}" -eq 1 ]; then return 0; fi
	read -r -p "${prompt} [y/N] " ans
	case "${ans:-}" in
		y|Y|yes|YES) return 0 ;;
		*) return 1 ;;
	esac
}

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------

CP_HOST="${TRUSTED_PLATFORM_CP:-${DEFAULT_CP_HOST}}"
BROWSER="${TRUSTED_PLATFORM_BROWSER:-${BROWSER}}"

while [ $# -gt 0 ]; do
	case "$1" in
		--browser)        BROWSER="$2"; shift 2 ;;
		--cp)             CP_HOST="$2"; shift 2 ;;
		--bundle-port)    CP_BUNDLE_PORT="$2"; shift 2 ;;
		--url)            URL="$2"; shift 2 ;;
		--bundle)         BUNDLE_PATH="$2"; shift 2 ;;
		--nickname)       NICKNAME="$2"; shift 2 ;;
		--no-launch)      NO_LAUNCH=1; shift ;;
		--skip-os-trust)  SKIP_OS_TRUST=1; shift ;;
		-y|--yes)         ASSUME_YES=1; shift ;;
		-q|--quiet)       QUIET=1; shift ;;
		-h|--help)        usage; exit 0 ;;
		*) err "unknown flag: $1 (try --help)" ;;
	esac
done

case "${BROWSER}" in
	chrome|firefox) ;;
	*) err "--browser must be 'chrome' or 'firefox' (got '${BROWSER}')" ;;
esac

[ -n "${URL}" ] || URL="${DEFAULT_URL_TEMPLATE}"

# -----------------------------------------------------------------------------
# Step 1: fetch the CA bundle from CP
# -----------------------------------------------------------------------------

fetch_bundle() {
	local url="https://${CP_HOST}:${CP_BUNDLE_PORT}/api/v1/acme/ca-bundle"
	log "fetching CP CA bundle from ${url}"
	mkdir -p "$(dirname "${BUNDLE_PATH}")"
	# -k: this is the trust-anchor bootstrap; verifying is what we're
	# trying to enable. Caller can pin via SPKI by re-running with
	# --bundle pointing at a pre-validated copy.
	if ! curl -sk --max-time 10 --fail "${url}" -o "${BUNDLE_PATH}"; then
		err "could not fetch CA bundle from ${url}"
	fi
	if ! grep -q "BEGIN CERTIFICATE" "${BUNDLE_PATH}"; then
		err "fetched file is not a PEM certificate (got $(wc -c < "${BUNDLE_PATH}") bytes)"
	fi
	local count
	count=$(grep -c "BEGIN CERTIFICATE" "${BUNDLE_PATH}")
	local subject
	subject=$(openssl x509 -in "${BUNDLE_PATH}" -noout -subject 2>/dev/null | sed 's/^subject=//')
	log "bundle: ${count} cert(s), $(wc -c < "${BUNDLE_PATH}") bytes — ${subject}"
}

# -----------------------------------------------------------------------------
# Step 2: install into xkey trust store
# -----------------------------------------------------------------------------

install_xkey_trust() {
	if ! command -v xkey >/dev/null 2>&1; then
		warn "xkey not in PATH — skipping xkey trust store install"
		return 0
	fi
	log "adding bundle to xkey trust store"
	# bootstrap-ca is the canonical purpose for trust anchors received
	# during platform enrollment. xkey's trust list will show the
	# fingerprint + subject + source path so operators can audit.
	xkey trust add "${BUNDLE_PATH}" \
		--purpose bootstrap-ca \
		--source "file:$(basename "${BUNDLE_PATH}")" 2>&1 | sed 's/^/  xkey: /' || true
}

# -----------------------------------------------------------------------------
# Step 3: install into OS system trust store (Debian/Ubuntu/RHEL/Arch)
# -----------------------------------------------------------------------------

install_os_trust() {
	if [ "${SKIP_OS_TRUST}" -eq 1 ]; then
		log "skipping OS trust store install (--skip-os-trust)"
		return 0
	fi
	# Pick the right anchor dir + update tool for this distribution.
	# Debian-derived: /usr/local/share/ca-certificates + .crt extension
	# Red Hat-derived: /etc/pki/ca-trust/source/anchors + .pem extension
	# Arch: /etc/ca-certificates/trust-source/anchors + .pem extension
	local anchor_dir update_cmd dest_name
	if [ -d /usr/local/share/ca-certificates ] && command -v update-ca-certificates >/dev/null 2>&1; then
		anchor_dir="/usr/local/share/ca-certificates"
		update_cmd="update-ca-certificates"
		dest_name="${NICKNAME}.crt"
	elif [ -d /etc/pki/ca-trust/source/anchors ] && command -v update-ca-trust >/dev/null 2>&1; then
		anchor_dir="/etc/pki/ca-trust/source/anchors"
		update_cmd="update-ca-trust"
		dest_name="${NICKNAME}.pem"
	elif [ -d /etc/ca-certificates/trust-source/anchors ] && command -v update-ca-trust >/dev/null 2>&1; then
		anchor_dir="/etc/ca-certificates/trust-source/anchors"
		update_cmd="update-ca-trust"
		dest_name="${NICKNAME}.pem"
	else
		warn "could not detect OS trust-store layout — skipping OS install"
		return 0
	fi

	log "installing CA into OS trust store (${anchor_dir}/${dest_name})"
	if ! sudo cp "${BUNDLE_PATH}" "${anchor_dir}/${dest_name}"; then
		err "sudo cp into ${anchor_dir} failed"
	fi
	if ! sudo "${update_cmd}" >/dev/null 2>&1; then
		warn "${update_cmd} returned non-zero — bundle is staged but trust hash links may not be updated"
	fi
	log "OS trust store updated"
}

# -----------------------------------------------------------------------------
# Step 4: install into the browser's NSS DB (Chrome) or each Firefox profile
# -----------------------------------------------------------------------------

# kill_running_browser stops the named browser if it's running, with
# an optional confirmation prompt. NSS DB is locked while the browser
# runs; certutil add will fail with SEC_ERROR_INVALID_ARGS otherwise.
#
# Takes a pipe-separated list of cmdline patterns; each is passed to
# pgrep/pkill -f independently because pgrep's -E (extended regex)
# isn't universally available across distributions, and -F (literal)
# doesn't accept multiple patterns at once. Iterating gives us
# portable behaviour without depending on shell regex flavour.
kill_running_browser() {
	local proc_patterns="$1"
	local human_name="$2"
	local IFS='|'
	# shellcheck disable=SC2206
	local patterns=(${proc_patterns})

	# First, check if any pattern matches.
	local found=0
	for p in "${patterns[@]}"; do
		if pgrep -f "${p}" >/dev/null 2>&1; then
			found=1
			break
		fi
	done
	[ "${found}" -eq 1 ] || return 0

	warn "${human_name} is running — its NSS DB is locked"
	if ! confirm "  terminate ${human_name} now?"; then
		err "${human_name} must be closed before its NSS DB can be modified"
	fi

	# Send TERM to every matching process across all patterns. Crash
	# handlers and renderer subprocesses re-spawn from the parent if
	# the parent itself is still alive, so issue TERM to all matches
	# rather than walking by process tree.
	for p in "${patterns[@]}"; do
		pkill -TERM -f "${p}" 2>/dev/null || true
	done

	# Wait up to 10 seconds for processes to exit and release the DB
	# lock. Poll instead of fixed-sleep so a fast quit doesn't waste
	# time and a slow one doesn't trip certutil with SEC_ERROR_INVALID_ARGS.
	local waited=0
	while [ "${waited}" -lt 10 ]; do
		local still_alive=0
		for p in "${patterns[@]}"; do
			if pgrep -f "${p}" >/dev/null 2>&1; then
				still_alive=1
				break
			fi
		done
		[ "${still_alive}" -eq 0 ] && break
		sleep 1
		waited=$((waited + 1))
	done

	# If they're still hanging on, escalate to KILL.
	for p in "${patterns[@]}"; do
		if pgrep -f "${p}" >/dev/null 2>&1; then
			warn "  ${p}: still running after TERM, sending KILL"
			pkill -KILL -f "${p}" 2>/dev/null || true
		fi
	done
	sleep 1
}

install_chrome_trust() {
	if ! command -v certutil >/dev/null 2>&1; then
		err "certutil not in PATH — install libnss3-tools (Debian/Ubuntu) or nss-tools (RHEL/Fedora)"
	fi

	# Chromium-family browsers all share ~/.pki/nssdb on Linux.
	local nssdb="${HOME}/.pki/nssdb"
	mkdir -p "${nssdb}"

	# Initialize the DB if it doesn't exist yet (fresh user, no Chrome
	# ever launched). Empty password is what Chrome uses by default.
	if [ ! -f "${nssdb}/cert9.db" ]; then
		log "initializing fresh Chrome NSS DB at ${nssdb}"
		certutil -d "sql:${nssdb}" -N --empty-password
	fi

	kill_running_browser "/opt/google/chrome|/usr/bin/google-chrome|chromium-browser|/usr/bin/chrome" "Chrome"

	# Remove any existing entry so certutil -A doesn't fail on
	# duplicate-nickname collisions during re-runs.
	if certutil -d "sql:${nssdb}" -L -n "${NICKNAME}" >/dev/null 2>&1; then
		log "removing existing Chrome trust entry '${NICKNAME}'"
		certutil -d "sql:${nssdb}" -D -n "${NICKNAME}" || true
	fi

	log "adding CA to Chrome NSS DB (${nssdb})"
	if ! certutil -d "sql:${nssdb}" -A -t "TC,," -n "${NICKNAME}" -i "${BUNDLE_PATH}"; then
		err "certutil -A failed (is Chrome still running?)"
	fi

	# Verify by listing back the entry.
	if certutil -d "sql:${nssdb}" -L | grep -q "${NICKNAME}"; then
		log "Chrome trust entry installed: $(certutil -d "sql:${nssdb}" -L | grep "${NICKNAME}")"
	else
		err "Chrome trust entry NOT visible after install — check NSS DB permissions"
	fi
}

install_firefox_trust() {
	if ! command -v certutil >/dev/null 2>&1; then
		err "certutil not in PATH — install libnss3-tools (Debian/Ubuntu) or nss-tools (RHEL/Fedora)"
	fi

	# Firefox stores per-profile NSS DBs under ~/.mozilla/firefox/<profile>/cert9.db
	# (Snap/Flatpak Firefox use different paths but most distros still
	# write under ~/.mozilla/firefox; --browser firefox-snap could be
	# added later if needed.)
	local fx_root="${HOME}/.mozilla/firefox"
	if [ ! -d "${fx_root}" ]; then
		warn "Firefox profile root ${fx_root} not found — has Firefox been run at least once?"
		warn "Run Firefox once to create a default profile, then re-run this script"
		return 1
	fi

	# Profile dirs end in .default, .default-release, .dev-edition, etc.
	# Walk every dir that has a cert9.db so the user gets the cert in
	# whichever profile they actually use.
	local profile_count=0
	while IFS= read -r -d '' profile; do
		profile_count=$((profile_count + 1))
		log "Firefox profile: $(basename "${profile}")"

		kill_running_browser "firefox.*${profile}|firefox-bin|/usr/lib/firefox" "Firefox"

		if certutil -d "sql:${profile}" -L -n "${NICKNAME}" >/dev/null 2>&1; then
			log "  removing existing entry '${NICKNAME}'"
			certutil -d "sql:${profile}" -D -n "${NICKNAME}" || true
		fi

		if ! certutil -d "sql:${profile}" -A -t "TC,," -n "${NICKNAME}" -i "${BUNDLE_PATH}"; then
			warn "  certutil -A failed for $(basename "${profile}") (skipping)"
			continue
		fi
		log "  CA added to $(basename "${profile}")"
	done < <(find "${fx_root}" -maxdepth 2 -name cert9.db -printf '%h\0' 2>/dev/null)

	if [ "${profile_count}" -eq 0 ]; then
		warn "no Firefox profiles with cert9.db found under ${fx_root}"
		return 1
	fi
}

# -----------------------------------------------------------------------------
# Step 5: launch the browser
# -----------------------------------------------------------------------------

launch_chrome() {
	local bin
	for cand in google-chrome google-chrome-stable chromium chromium-browser brave-browser; do
		if command -v "${cand}" >/dev/null 2>&1; then
			bin="${cand}"; break
		fi
	done
	[ -n "${bin}" ] || err "no Chromium-family browser binary found in PATH"

	log "launching ${bin} → ${URL}"
	# --user-data-dir keeps us in a clean profile that doesn't conflict
	# with the user's normal Chrome session AND uses ~/.pki/nssdb for
	# certificate trust (the system-wide NSS DB Chromium reads on Linux).
	mkdir -p "${PROFILE_DIR_CHROME}"

	# Pre-seed the profile so the first-run dialogs (default-browser
	# prompt, "Sign in to Chrome", and the Welcome / metrics opt-in
	# tab) are skipped. These dialogs steal focus and block the
	# automation flow until clicked through, and we don't want any
	# of them in a single-purpose trust-platform profile anyway:
	#
	#   - First Run sentinel    : tells Chrome the welcome flow ran.
	#   - "Local State"         : disables UMA/usage-stats opt-in.
	#   - "Default/Preferences" : suppresses default-browser prompt
	#                             and disables the sign-in promo.
	#
	# These are written ONCE per profile-dir; subsequent launches
	# leave existing prefs alone. cat is fine here — Chrome rewrites
	# both files on first launch, so we only need a valid baseline.
	touch "${PROFILE_DIR_CHROME}/First Run"
	if [ ! -f "${PROFILE_DIR_CHROME}/Local State" ]; then
		mkdir -p "${PROFILE_DIR_CHROME}"
		printf '%s\n' '{"user_experience_metrics":{"reporting_enabled":false},"browser":{"enabled_labs_experiments":[]}}' \
			> "${PROFILE_DIR_CHROME}/Local State"
	fi
	if [ ! -f "${PROFILE_DIR_CHROME}/Default/Preferences" ]; then
		mkdir -p "${PROFILE_DIR_CHROME}/Default"
		printf '%s\n' '{"browser":{"check_default_browser":false,"has_seen_welcome_page":true},"profile":{"default_content_setting_values":{},"exit_type":"Normal"},"signin":{"allowed":false},"sync_promo":{"user_skipped":true,"show_on_first_run_allowed":false},"distribution":{"do_not_create_desktop_shortcut":true,"do_not_create_quicklaunch_shortcut":true,"do_not_create_taskbar_shortcut":true,"do_not_launch_chrome":false,"import_bookmarks":false,"import_history":false,"import_search_engine":false,"make_chrome_default":false,"make_chrome_default_for_user":false,"suppress_first_run_bubble":true,"suppress_first_run_default_browser_prompt":true,"system_level":false,"verbose_logging":false}}' \
			> "${PROFILE_DIR_CHROME}/Default/Preferences"
	fi

	# Runtime flags reinforce the same suppressions on every launch
	# in case the user nukes the profile dir between runs:
	#   --no-first-run                    skip the first-run experience
	#   --no-default-browser-check        skip "make Chrome default" prompt
	#   --disable-features=...            disable sign-in promos and welcome page
	exec "${bin}" \
		--user-data-dir="${PROFILE_DIR_CHROME}" \
		--no-first-run \
		--no-default-browser-check \
		--disable-features=ChromeWhatsNewUI,SigninPromoBubble,SyncDisabledForRecoverable,SyncPromoAfterSigninIntercept,WelcomePageOnOSIntegrationFlow \
		"${URL}"
}

launch_firefox() {
	command -v firefox >/dev/null 2>&1 || err "firefox not in PATH"
	log "launching firefox → ${URL}"
	exec firefox --new-tab "${URL}"
}

# -----------------------------------------------------------------------------
# main
# -----------------------------------------------------------------------------

fetch_bundle
install_xkey_trust
install_os_trust

case "${BROWSER}" in
	chrome)  install_chrome_trust ;;
	firefox) install_firefox_trust ;;
esac

if [ "${NO_LAUNCH}" -eq 1 ]; then
	log "trust setup complete (--no-launch); skipping browser launch"
	log "manual launch: ${BROWSER} ${URL}"
	exit 0
fi

log ""
log "=== trust setup complete; launching ${BROWSER} ==="
log "  CP host:     ${CP_HOST}"
log "  Bundle:      ${BUNDLE_PATH}"
log "  URL:         ${URL}"
log ""

case "${BROWSER}" in
	chrome)  launch_chrome ;;
	firefox) launch_firefox ;;
esac
