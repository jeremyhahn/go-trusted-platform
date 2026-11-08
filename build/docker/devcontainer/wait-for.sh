#!/bin/bash
# wait-for.sh: bounded readiness polling for the integration harness (#964).
#
# Sourced by entrypoint.sh, run-integration-tests.sh and the per-suite
# run-tests.sh scripts. A harness wait polls the condition it is waiting for
# under a deadline; it never sleeps a fixed time hoping the condition holds.

# WAIT_FOR_INTERVAL is the poll interval in seconds.
WAIT_FOR_INTERVAL="${WAIT_FOR_INTERVAL:-0.2}"

# wait_for <timeout_s> <description> <cmd...> runs cmd until it succeeds and
# returns 0 the moment it does. At the deadline it reports what it awaited and
# how long it waited, and returns 1.
wait_for() {
    local timeout_s="$1"
    local description="$2"
    shift 2
    local start=$SECONDS
    while ! "$@" > /dev/null 2>&1; do
        if [ $((SECONDS - start)) -ge "$timeout_s" ]; then
            echo "wait_for: ${description} not ready after $((SECONDS - start))s (deadline ${timeout_s}s)" >&2
            return 1
        fi
        sleep "$WAIT_FOR_INTERVAL"
    done
    return 0
}

# process_gone <pid> succeeds once pid has exited. A zombie counts as gone:
# kill -0 still succeeds on one, but it no longer runs.
process_gone() {
    local stat
    stat=$(cat "/proc/$1/stat" 2> /dev/null) || return 0
    stat="${stat##*) }"
    [ "${stat%% *}" = "Z" ]
}

# no_process_matching <pattern> succeeds once no process command line
# matches pattern (pgrep -f).
no_process_matching() {
    ! pgrep -f "$1" > /dev/null
}
