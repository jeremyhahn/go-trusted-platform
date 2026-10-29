#!/usr/bin/env bash
# Remove this repo's stopped CI leftovers on the runner host.
#
#   usage: scripts/reap-stale-ci-stacks.sh <prefix> [min-age-seconds]
#
# v1 (ci-template v1.18, dept-infra 2026-10-12). An integration job's
# `if: always()` teardown runs only while the job process lives. When the host
# or its Docker daemon dies mid-job, the job is gone and so is its teardown: the
# compose stack stays behind, exited, with its networks and volumes. Nothing
# else removes them, so the first step of every job that starts containers
# runs this.
#
# What it removes, on the Docker host the job talks to:
#   - a compose project (label com.docker.compose.project) whose name starts
#     with <prefix>, when EVERY container in it is stale; then the project's
#     networks and volumes (same label);
#   - a network or volume of such a project that outlived its containers (a
#     cancelled job's teardown never ran), when no container of any state uses
#     it and it was created at least <min-age-seconds> ago;
#   - a container outside compose whose name starts with <prefix>, when stale,
#     with its anonymous volumes;
#   - a claim volume (label ci.claim) whose name starts with <prefix>, when no
#     container uses it and it was created at least <min-age-seconds> ago;
#   - an image whose reference starts with <prefix>, when no container of any
#     state names it, no live claim names its run and it was created at least
#     <min-age-seconds> ago.
# Stale: exited or dead and finished at least <min-age-seconds> ago, or
# created and never started at least that long ago. A project with any
# container running, paused, restarting or removing is never touched.
#
# <min-age-seconds> defaults to 11100: the runners' 3h job timeout plus 5 min,
# so no job that could still own the stack is alive. Pass the job's own
# timeout-minutes * 60 plus a margin only if you know every runner's timeout.
#
# The prefix is this repo's own, `go-trusted-platform-ci-`: the name the jobs
# give their compose projects and toolchain containers, without the run id.
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
  old "$t"
}

# old <timestamp>: 0 when <timestamp> is at least <min-age-seconds> ago, 1 when
# it is younger or does not parse.
old() {
  local t
  t=$(date -d "$1" +%s 2>/dev/null) || return 1
  [ $((now - t)) -ge "$min_age" ]
}

reaped=0
# The projects the loop below saw with containers, space separated.
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

# Networks and volumes a compose project left without containers. A cancelled
# job need not run its teardown, and once its containers are gone the loop
# above never sees the project, so its network stays and holds an address
# block of the daemon's pools (m1250). One is removed only when no container
# of any state uses it and it was created at least <min-age-seconds> ago.
orphans=0

# reap_orphan network|volume <name> <created> [project]: remove one leftover.
reap_orphan() {
  local kind=$1 name=$2 created=$3 project=${4:-}
  case $project in "$prefix"*) ;; *) return 0 ;; esac
  case $seen in *" $project "*) return 0 ;; esac
  if reap_unused "$kind" "$kind" "$name" "$created"; then orphans=$((orphans + 1)); fi
}

# reap_unused network|volume|image <ps-filter> <name> <created>: remove one
# object that no container of any state uses (`docker ps --filter
# <ps-filter>=<name>` lists none) and that was created at least
# <min-age-seconds> ago. 0 when it was removed, 1 when it was kept.
reap_unused() {
  local kind=$1 filter=$2 name=$3 created=$4 users
  if ! users=$(docker ps -aq --filter "$filter=$name"); then
    echo "warn  $kind $name: cannot list its containers, kept"
    return 1
  fi
  if [ -n "$users" ]; then
    echo "keep  $kind $name (a container uses it)"
    return 1
  fi
  if ! old "$created"; then
    echo "keep  $kind $name (created within ${min_age}s)"
    return 1
  fi
  echo "reap  $kind $name (no containers)"
  if run docker "$kind" rm "$name"; then
    return 0
  fi
  echo "warn  $kind $name not removed"
  return 1
}

# A network's Created is a Go time.Time, which a bare {{.Created}} prints with
# spaces in it ("2006-01-02 15:04:05.999 +0000 UTC") and splits across read's
# fields, so it is formatted RFC 3339. A container's and a volume's times are
# already RFC 3339 strings.
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

# Images. Every image whose reference starts with <prefix> is one run's
# (go-trusted-platform-ci-it:<run id>-<attempt>-<job>), which that run's
# teardown removes where it can. No teardown reaches the integration-image
# job's copy when every leg ran on another daemon, or when the artifact upload
# failed and no leg ran (#1146), and neither --rm nor buildx prune removes a
# tagged image. One is removed when no container of any state names it (a
# job's lease is one), no claim of its run is live, and it was created at
# least <min-age-seconds> ago.
#
# A claim is what makes publishing an image safe against this loop (#1146). A
# warm build cache can return an image created long before the job that
# tagged it, and a job tags or loads its image before its lease can name it,
# so neither Created nor the lease covers the moment between the two. Every
# job that publishes or adopts a <prefix> image therefore first creates a
# claim: a volume named <prefix>...-claim, labelled ci.claim=<run id>-<attempt>.
# The tag list is read before the claims, so a tag on it was published after
# its job's claim, and that claim is on the claim list read afterwards unless
# its job tore it down, done with the image. A claim older than
# <min-age-seconds> outlived any job (the 3h runner limit) and is removed.
images=0
claims=0
if ! refs=$(docker image ls --format '{{.Repository}}:{{.Tag}}'); then
  echo "warn  images: cannot list them, kept"
  refs=
fi
# The live claims' runs, space separated; read only after the tag list. A
# claim that cannot be listed or read might be live, so then no image is
# removed this pass.
claimed=" "
unread=0
if ! vols=$(docker volume ls -q --filter label=ci.claim); then
  echo "warn  claims: cannot list them, every image kept"
  unread=1
  vols=
fi
for vol in $vols; do
  case $vol in "$prefix"*) ;; *) continue ;; esac
  read -r created run < <(docker volume inspect \
    -f '{{.CreatedAt}} {{index .Labels "ci.claim"}}' "$vol" 2>/dev/null) ||
    { echo "warn  claim $vol: inspect failed, kept with every image"; unread=1; continue; }
  [ -n "${run:-}" ] || continue
  if old "$created"; then
    if reap_unused volume volume "$vol" "$created"; then claims=$((claims + 1)); continue; fi
  fi
  claimed="$claimed$run "
done
[ "$unread" = 0 ] || refs=
for ref in $refs; do
  case $ref in "$prefix"*) ;; *) continue ;; esac
  case $ref in *:'<none>') continue ;; esac
  # <run id>-<attempt> from the tag <run id>-<attempt>-<job>.
  tag=${ref#*:}
  rest=${tag#*-}
  run="${tag%%-*}-${rest%%-*}"
  case $claimed in
    *" $run "*) echo "keep  image $ref (run $run claims it)"; continue ;;
  esac
  created=$(docker image inspect -f '{{.Created}}' "$ref" 2>/dev/null) ||
    { echo "warn  image $ref: inspect failed, kept"; continue; }
  if reap_unused image ancestor "$ref" "$created"; then images=$((images + 1)); fi
done

if [ "${REAP_DRY_RUN:-0}" = 1 ]; then done_as="would be removed"; else done_as=removed; fi
echo "reaper: $reaped compose project(s) and $orphans orphaned network(s) or volume(s) $done_as for prefix '$prefix'"
echo "reaper: $images stale image(s) and $claims expired claim(s) $done_as for prefix '$prefix'"
exit 0
