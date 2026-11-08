#!/usr/bin/env bash
# Remove this repo's stopped CI leftovers on the runner host.
#
#   usage: scripts/reap-stale-ci-stacks.sh <prefix> [min-age-seconds]
#
# v1 (ci-template v1.18, 2026-10-12); v2 and v3 below. An integration job's
# `if: always()` teardown runs only while the job process lives. When the host
# or its Docker daemon dies mid-job, the job is gone and so is its teardown: the
# compose stack stays behind, exited, with its networks and volumes (11 stacks
# on ci-node-1 and ci-node-2 after the 2026-10-11/12 restarts). Nothing else
# removes them, so the first step of every integration job runs this.
#
# What it removes, on the Docker host the job talks to:
#   - a compose project (label com.docker.compose.project) whose name starts
#     with <prefix>, when EVERY container in it is stale; then the project's
#     networks and volumes (same label);
#   - a container outside compose whose name starts with <prefix>, when stale,
#     with its anonymous volumes.
# v2 (ci-template v1.23, Company Agent m674 item 3, 2026-10-18; the go-qrdb
# #814 pattern): images too. The integration image is named by its content,
# <prefix>it:<hash> (`make -s it-image`, ci-standard.md §9), and every job and
# run of that tree on this runner reuses it, so no job removes it. This
# removes a <prefix>it image created at least REAP_IMAGE_MIN_AGE seconds ago,
# default 7200 (2 h: the longest full-tier run plus headroom), so an image a
# run still needs is not old enough. `docker image rm` without force refuses
# an image a container (running or stopped) uses, so a live stack's image is
# never removed. Age alone does not protect a reused image older than that,
# so every job that needs the image holds a lease on it: a created, never
# started container named <prefix>lease-<run>-..., removed at its Tear down
# (ci.yml). A lease a dead job leaves is stale like any other container
# outside compose, and goes after <min-age-seconds>; its image goes on the
# reap after that.
# v3 (ci-template v1.23.1, 2026-10-19): an image's age runs
# from the later of its `.Created` and its last tag time
# (`.Metadata.LastTagTime`). A rebuild from a full cache keeps the old
# `.Created` but re-tags the image, so v2 saw a just-rebuilt image as stale and
# a parallel job's reaper removed it between its build and its lease
# (go-quicraft main runs 57389 and 57484).
# v4 (ci-template v1.25.2, 2026-10-21, from a Codex review): a tag is kept
# while any container, running or created, uses its image id. Two trees that
# differ only in a file the build ignores get two <prefix>it tags on one cached
# image id. `docker image rm <tag>` on such an image only untags it, and it
# succeeds even while a lease holds the id, so v3 could remove the tag a leased
# job later saves or runs. Now the reaper resolves the tag's id and skips the
# tag, with a log line, when `docker ps -a --filter ancestor=<id>` lists a
# container. A failed lookup also keeps the tag.
# v5 (ci-template v1.25.3, 2026-10-21, from a Codex review): the image loop
# runs under the daemon's image lock. v4's in-use check and its `docker image
# rm` were two calls, so a job could take its lease and re-tag between them
# and still lose the tag. The lock is a created, never-started container
# named <prefix>image-lock, made from <prefix>image-lock:base (an empty
# image this script imports when it is missing); the daemon refuses a second
# container of that name, so one holder at a time. The ci.yml lease step and
# every re-tag take the same lock. A lock created more than 600 s ago is a
# dead holder's and is removed by its id. The reaper waits up to
# REAP_LOCK_WAIT seconds (default 60) for it, and without it removes no
# image that run. v5 also reads the tag time as a string: on Docker 29
# `{{.Metadata.LastTagTime.Unix}}` is a template error, the inspect line came
# back without an id, and v3 and v4 then removed the tag whatever its age or
# lease. An image the inspect gives no id for is now kept.
#
# Stale: exited or dead and finished at least <min-age-seconds> ago, or
# created and never started at least that long ago. A project with any
# container running, paused, restarting or removing is never touched.
#
# <min-age-seconds> defaults to 11100: the runners' 3h job timeout plus 5 min,
# so no job that could still own the stack is alive. Pass the job's own
# timeout-minutes * 60 plus a margin only if you know every runner's timeout.
#
# The prefix is the repo's own (`qrdb-int`, `recountly-ci-`): the name the job
# gives its compose project, without the run id. Never a prefix another repo's
# projects could start with.
#
# A failed removal is reported and skipped: the reaper never fails the job.
# REAP_DRY_RUN=1 prints what would be removed and removes nothing.
set -u

prefix=${1:-}
min_age=${2:-11100}
case $prefix in
  '' | *[!A-Za-z0-9_.-]*) echo "usage: $0 <prefix [A-Za-z0-9_.-]> [min-age-seconds]" >&2; exit 2 ;;
esac
case $min_age in
  '' | *[!0-9]*) echo "min-age-seconds must be a number: $min_age" >&2; exit 2 ;;
esac
image_min_age=${REAP_IMAGE_MIN_AGE:-7200}
case $image_min_age in
  '' | *[!0-9]*) echo "REAP_IMAGE_MIN_AGE must be a number: $image_min_age" >&2; exit 2 ;;
esac

lock_wait=${REAP_LOCK_WAIT:-60}
case $lock_wait in
  '' | *[!0-9]*) echo "REAP_LOCK_WAIT must be a number: $lock_wait" >&2; exit 2 ;;
esac

now=$(date +%s)

# run <command...>: the command, or only its echo under REAP_DRY_RUN=1.
run() {
  if [ "${REAP_DRY_RUN:-0}" = 1 ]; then echo "dry   $*"; else "$@" >/dev/null; fi
}

# stale <container>: 0 when the container is stale (as above), 1 otherwise.
stale() {
  local state finished created t
  read -r state finished created < <(docker inspect -f '{{.State.Status}} {{.State.FinishedAt}} {{.Created}}' "$1" 2>/dev/null) || return 1
  case $state in
    exited | dead) t=$finished ;;
    created) t=$created ;;
    *) return 1 ;;
  esac
  t=$(date -d "$t" +%s 2>/dev/null) || return 1
  [ $((now - t)) -ge "$min_age" ]
}

# image_lock: take the daemon's image lock (v5, above), waiting up to
# REAP_LOCK_WAIT seconds; 1 when it is not taken. image_unlock drops it.
lock="${prefix}image-lock"
lock_id=
image_lock() {
  local base="$lock:base" held at t i
  for ((i = 0; i < lock_wait; i++)); do
    docker image inspect "$base" >/dev/null 2>&1 ||
      head -c 1024 /dev/zero | docker import - "$base" >/dev/null 2>&1
    lock_id=$(docker create --pull never --name "$lock" "$base" true 2>/dev/null) && return 0
    lock_id=
    if read -r held at < <(docker inspect -f '{{.Id}} {{.Created}}' "$lock" 2>/dev/null) &&
      t=$(date -d "$at" +%s 2>/dev/null) && [ $(($(date +%s) - t)) -ge 600 ]; then
      echo "lock  removing the stale $lock (created $at)"
      docker rm "$held" >/dev/null 2>&1
      continue
    fi
    sleep 1
  done
  return 1
}
image_unlock() {
  [ -z "$lock_id" ] || docker rm "$lock_id" >/dev/null 2>&1
  lock_id=
}
trap image_unlock EXIT

reaped=0
# The projects the loop below saw with containers, space separated; the
# orphan sweep (go-trusted-platform, below) skips them.
seen=" "

# Compose projects.
for project in $(docker ps -a --filter label=com.docker.compose.project \
    --format '{{.Label "com.docker.compose.project"}}' | sort -u); do
  case $project in "$prefix"*) ;; *) continue ;; esac
  seen="$seen$project "
  ids=$(docker ps -aq --filter "label=com.docker.compose.project=$project")
  keep=0
  for id in $ids; do stale "$id" || { keep=1; break; }; done
  if [ "$keep" = 1 ]; then
    echo "keep  $project (a container is live or stopped within ${min_age}s)"
    continue
  fi
  # shellcheck disable=SC2086 # one id per word
  set -- $ids
  echo "reap  $project: $# container(s)"
  run docker rm -v "$@" || echo "warn  $project: container removal failed"
  for net in $(docker network ls -q --filter "label=com.docker.compose.project=$project"); do
    run docker network rm "$net" || echo "warn  $project: network $net not removed"
  done
  for vol in $(docker volume ls -q --filter "label=com.docker.compose.project=$project"); do
    run docker volume rm "$vol" || echo "warn  $project: volume $vol not removed"
  done
  reaped=$((reaped + 1))
done

# Containers outside compose.
docker ps -a --filter "name=^$prefix" \
    --format '{{.ID}} {{.Names}} {{.Label "com.docker.compose.project"}}' |
  while read -r id name project; do
    [ -z "$project" ] || continue
    case $name in "$prefix"*) ;; *) continue ;; esac
    if stale "$id"; then
      echo "reap  container $name"
      run docker rm -v "$id" || echo "warn  container $name not removed"
    fi
  done

# --- go-trusted-platform: orphaned networks and volumes (not in the template) ---
# The ci-template's v5 has no CUSTOMIZE block; this section is this repo's own
# and is kept out of the template's numbered versions above (Codex review 8438
# on #1292). A cancelled or killed job need not run its teardown, and once its
# containers are gone the compose loop above never sees the project, so its
# network stays and holds an address block of the daemon's pools (m1250), and
# its volume holds disk. A network or volume is removed only when it is
# labelled with a compose project that starts with <prefix>, the loop above did
# not see that project with containers, no container of any state uses it, and
# it was created at least <min-age-seconds> ago.
orphans=0

# old <timestamp>: 0 when <timestamp> is at least <min-age-seconds> ago, 1 when
# it is younger or does not parse.
old() {
  local t
  t=$(date -d "$1" +%s 2>/dev/null) || return 1
  [ $((now - t)) -ge "$min_age" ]
}

# reap_orphan network|volume <name> <created> [project]: remove one leftover.
reap_orphan() {
  local kind=$1 name=$2 created=$3 project=${4:-} users
  case $project in "$prefix"*) ;; *) return 0 ;; esac
  case $seen in *" $project "*) return 0 ;; esac
  if ! users=$(docker ps -aq --filter "$kind=$name"); then
    echo "warn  $kind $name: cannot list its containers, kept"
    return 0
  fi
  if [ -n "$users" ]; then
    echo "keep  $kind $name (a container uses it)"
    return 0
  fi
  if ! old "$created"; then
    echo "keep  $kind $name (created within ${min_age}s)"
    return 0
  fi
  echo "reap  $kind $name (project $project has no containers)"
  if run docker "$kind" rm "$name"; then
    orphans=$((orphans + 1))
  else
    echo "warn  $kind $name not removed"
  fi
}

# A network's Created is a Go time.Time, which a bare {{.Created}} prints with
# spaces in it ("2006-01-02 15:04:05.999 +0000 UTC") and splits across read's
# fields, so it is formatted RFC 3339. A volume's CreatedAt is already an
# RFC 3339 string.
for net in $(docker network ls -q --filter label=com.docker.compose.project); do
  read -r name created project < <(docker network inspect \
    -f '{{.Name}} {{.Created.Format "2006-01-02T15:04:05Z07:00"}} {{index .Labels "com.docker.compose.project"}}' "$net" 2>/dev/null) ||
    { echo "warn  network $net: inspect failed, kept"; continue; }
  reap_orphan network "$name" "$created" "$project"
done
for vol in $(docker volume ls -q --filter label=com.docker.compose.project); do
  read -r created project < <(docker volume inspect \
    -f '{{.CreatedAt}} {{index .Labels "com.docker.compose.project"}}' "$vol" 2>/dev/null) ||
    { echo "warn  volume $vol: inspect failed, kept"; continue; }
  reap_orphan volume "$vol" "$created" "$project"
done
# --- end go-trusted-platform ---

# Content-addressed integration images (v2, above), under the image lock (v5).
images=0
refs=
if [ "${REAP_DRY_RUN:-0}" = 1 ] || image_lock; then
  refs=$(docker images --filter "reference=${prefix}it" --format '{{.Repository}}:{{.Tag}}')
else
  echo "keep  every ${prefix}it image (the image lock was not free within ${lock_wait}s)"
fi
for ref in $refs; do
  case $ref in "${prefix}it:"*) ;; *) continue ;; esac
  id='' created=''
  read -r id created < <(docker image inspect -f '{{.Id}} {{.Created}}' "$ref" 2>/dev/null)
  if [ -z "$id" ] || [ -z "$created" ]; then
    echo "keep  image $ref (docker image inspect gave no id)"
    continue
  fi
  t=$(date -d "$created" +%s 2>/dev/null) || continue
  # Go prints the tag time as "2026-10-21 00:35:47.26 +0000 UTC"; date -d
  # takes it without the fraction and the zone name. A never-tagged image
  # reports the zero time, a large negative number.
  tagged=$(docker image inspect -f '{{.Metadata.LastTagTime}}' "$ref" 2>/dev/null | sed -E 's/\.[0-9]+//; s/ [A-Z]+$//')
  tagged=$(date -d "$tagged" +%s 2>/dev/null) || tagged=
  case $tagged in ''|*[!0-9]*) ;; *) [ "$tagged" -le "$t" ] || t=$tagged ;; esac
  if [ $((now - t)) -lt "$image_min_age" ]; then
    echo "keep  image $ref (created or tagged within ${image_min_age}s)"
    continue
  fi
  # v4: a container on the id (a lease or a stack) keeps every tag of it.
  if ! users=$(docker ps -a -q --filter "ancestor=$id" 2>/dev/null); then
    echo "keep  image $ref (could not list the containers on $id)"
    continue
  fi
  if [ -n "$users" ]; then
    echo "keep  image $ref (in use: $(echo "$users" | wc -l) container(s) on $id)"
    continue
  fi
  echo "reap  image $ref"
  if run docker image rm "$ref"; then images=$((images + 1)); else echo "warn  image $ref not removed (in use?)"; fi
done
image_unlock

if [ "${REAP_DRY_RUN:-0}" = 1 ]; then done_as="would be removed"; else done_as=removed; fi
echo "reaper: $reaped compose project(s) and $images image(s) $done_as for prefix '$prefix'"
echo "reaper: $orphans orphaned network(s) or volume(s) $done_as for prefix '$prefix'"
exit 0
