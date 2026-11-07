# Gateway services supervisor model

> **Status: DRAFT** · Scope: `pkg/sdn/gateway/`, `pkg/sdn/gateway/process/`, `pkg/sdn/gateway/ipc/`, `cmd/gatewayd`, the platformd supervisor · Last verified: 2026-10-28
> The design for #1191. Where it differs from [architecture.md](architecture.md) §"The supervisor seam" or [engineering.md](engineering.md) §"The process model", those sections describe the code today and this file describes the target.
> Part of the gateway feature folder: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

## The decision

Ruling 240 item 4, verbatim:

> Gateway services architecture (owner decision, go-trusted-platform): the network services (bgp, dhcp, dns and the rest) ship as one build artifact, a multi-call binary, and run as one OS process per service, each in its own cgroup with minimal capabilities; platformd is the single supervisor with a restart policy with backoff, sd_notify-style readiness and health; one process owns the kernel routing state (the zebra role) so a BGP crash does not withdraw routes, and BGP implements graceful restart per RFC 4724; this is a move with history and tests, not a rewrite: services keep their code and gain a process boundary and an IPC seam over the platform local transport. go-trusted-platform gets a SPEC row and a design PR for the supervisor model, routed by Software as the next docs item after #1190 lands; reported to the owner at open and at merge.

#557 proposed systemd template units as the supervisor. This decision settles
that: platformd is the supervisor, and one process owns the routing state.
Where #557's open questions and this design differ, this design supersedes them.
This file covers item 4 and nothing beyond it; what item 4 leaves open is under
[Owner questions](#owner-questions).

## Current state

Line numbers are 1-based, at the commit this file lands on.

| Question | Today |
|---|---|
| Which services run as supervised children | Five processes, each a `Definition` in the class table `pkg/sdn/gateway/process/class.go:104-190`: `datapath` (`class.go:106`: `firewall`, `nat`, `load-balancer`, `nat64`, `hostfw`, `tunnels`, `overlay`), `routing` (`class.go:130`: `transit`, the BGP speaker), `proxy` (`class.go:144`), `provisioning` (`class.go:157`: `dhcp`, `pxe`, `edge`) and `vpn` (`class.go:171`: `management-vpn`). All five carry `Supervised: true`. A process hosts several services, not one. |
| Who supervises them | `gatewayd serve` itself. `process.Supervisor` (`pkg/sdn/gateway/process/supervisor.go:1385` asserts it implements `gateway.ServiceSupervisor`, `pkg/sdn/gateway/supervised.go:30-56`) re-executes the gatewayd binary as `gatewayd service run <process>` (`pkg/sdn/gateway/process/launcher.go:159`, `pkg/sdn/gateway/commands/service.go:56-64`). The parent registers a `supervisedServiceHandler` per relayed section (`supervised.go:64-67`) when `GatewayConfig.Supervisor` is set (`pkg/sdn/gateway/types.go:1483`). gatewayd itself is an OpenRC service that platformd's first boot writes (`pkg/firstboot/gatewayd.go:36`, `command=` at `:43`, `command_args="serve ..."` at `:44`); platformd does not start, watch or restart it. |
| Restart and readiness | Exponential backoff from `DefaultRestartBackoff` 500 ms to `DefaultRestartBackoffMax` 30 s, a budget of `DefaultRestartBudget` 5 restarts in `DefaultRestartWindow` 5 min (`supervisor.go:44-51`), applied in `noteRestart` (`supervisor.go:727`). Readiness is polled: `awaitService` (`supervisor.go:580`) calls the child's `Status` every `readyPollInterval` 25 ms (`supervisor.go:644`) until `DefaultReadyTimeout` 10 s (`supervisor.go:39`). Health is `ServiceReports()` (`supervised.go:123-138`), one `ServiceReport{Name, Active, Health}` (`supervised.go:114-118`) per handler. No `NOTIFY_SOCKET` / sd_notify exists anywhere in `pkg/`. |
| Isolation | One cgroup v2 leaf per process under `cgroup-parent` (`DefaultCgroupParent` `gatewayd`, `pkg/sdn/gateway/process/settings.go:28`; `CgroupManager`, `pkg/sdn/gateway/process/cgroup.go:34`), `memory.max` and `cpu.max` from the class table. The child-side drop is `EnterHardened` (`pkg/sdn/gateway/process/child.go:45`): no_new_privs, bounding set, uid drop for the parser class, capability sets, seccomp. The parent-death signal is `SIGKILL` (`launcher.go:196`), so a supervisor crash leaves the datapath in place ([engineering.md](engineering.md) §"The process model"). |
| The IPC | `pkg/sdn/gateway/ipc/proto/ipc.proto`: gRPC over one Unix socket per child, authenticated only by `SO_PEERCRED` (`ipc.proto:8`; `pkg/util/peercred/peercred.go:188`, shared with platformd's Unix transport, `pkg/api/daemon/initonly.go:224`). Three services: `ProcessControlService` (`Status`, `Snapshot`, `ipc.proto:24`), `DatapathService` (`ApplyDesired`, `InstallVPNPeer`, `RemoveVPNPeer`, `ipc.proto:37`) and `GatewayServicesService` (load balancer, NAT64 and perf reads and controls for platformd, `ipc.proto:58`). The per-method uid table is `ipc.Policy`. |
| What owns kernel routes | No single owner. The `tunnels` service writes them in the `datapath` child: `tunnel.UplinkManager` installs each uplink's table routes and source rules (`pkg/sdn/tunnel/uplink.go:183`, `RouteReplace` at `:185`), and the TUN and WireGuard-client paths replace their own routes (`pkg/sdn/tunnel/tun.go:142`, `pkg/sdn/tunnel/wireguard_client.go:217`). The BGP speaker writes none: `pkg/sdn/bgp` uses no netlink ([engineering.md](engineering.md) line 1332); its routes live in the GoBGP RIB only. Graceful restart is configured (`BGPConfig.GracefulRestart`, on by default, `pkg/sdn/bgp/types.go:579-585`; `DefaultGracefulRestartTime` 120 s, `types.go:39`), so peers keep this speaker's routes when its session drops without a Cease. |
| Multi-call entry point | None by argv[0]. `cmd/gatewayd/main.go:22` calls `commands.Execute()`; the cobra root `gatewayd` (`pkg/sdn/gateway/commands/root.go:38`) has `serve`, `service` and `version` (`root.go:80-82`), and `service run <process>` is the subcommand dispatch the supervisor uses today. DNS is not a gatewayd service: it is `pkg/dns` (CoreDNS) inside platformd ([architecture.md](architecture.md) §"IPv6-only clients"). |

## (a) The multi-call binary

One build artifact, `gatewayd`, carries every network service. A process
selects its service in one of two equivalent ways:

| Invocation | Meaning |
|---|---|
| `gatewayd service run <service>` | the subcommand form; what platformd execs |
| `<service>` as argv[0] (a symlink `gatewayd-<service>` → `gatewayd`) | the multi-call form, resolved to the same `service run <service>` before cobra parses |

The dispatch table is the class table: argv[0] `gatewayd-<name>` is accepted
only when `<name>` is a `Definition.Name`; an unknown name is refused with a
typed error before any configuration is read. The argv[0] form is
for operators and process listings (`ps` shows `gatewayd-bgp`); platformd
always execs the subcommand form with an absolute path, so a symlink is never
part of the trust chain.

Mapped to today's gatewayd:

- `gatewayd service run <process>` stays; its argument changes from a process
  hosting several services to one service (`routing` becomes `bgp`,
  `provisioning` becomes `dhcp`, `pxe`, `edge`).
- `gatewayd serve` stops being a supervisor. It remains for one release as a
  compatibility entry that runs every enabled service in one process, exactly
  as with `process.enabled: false` today, and is how a node without the
  platformd supervisor still runs (see Owner questions).
- `gatewayd version` is unchanged.

## (b) One OS process per service

Each service is its own process, in its own cgroup v2 leaf
`<cgroup-parent>/<service>`, with the capabilities in the table and nothing
else. Capabilities are granted the way they are today: the supervisor sets the
ambient set at clone time and the child runs `EnterHardened` before it reads
configuration. The seccomp filter, the address-family allow list
(`AF_UNIX`, `AF_INET`, `AF_INET6`, `AF_NETLINK`, never `AF_PACKET`) and the
`CLONE_NEW*` denial stay per class.

| Service | Process / cgroup | Class | Runs as (uid) | Capabilities | Why |
|---|---|---|---|---|---|
| zebra role (route owner, see (d)) | `rib` | kernel | 0 | `CAP_NET_ADMIN` | the only installer of kernel routes and `ip rule`s (`RTM_NEWROUTE`, `RTM_NEWRULE`); the supervisor deletes by protocol number only while no `rib` runs (d) |
| `bgp` / `transit` | `bgp` | parser | `user` (`gatewayd`) | `CAP_NET_BIND_SERVICE` | TCP 179; writes no kernel state, hands routes to `rib` |
| `dhcp` | `dhcp` | parser | `user` (`gatewayd`) | `CAP_NET_BIND_SERVICE` | UDP 67; `SO_BINDTODEVICE` needs no capability since Linux 5.7 |
| `pxe` | `pxe` | parser | `user` (`gatewayd`) | `CAP_NET_BIND_SERVICE` | TFTP 69, HTTP 80 |
| `edge` | `edge` | parser | `user` (`gatewayd`) | none | outbound device verification only |
| `dns` | `dns` | parser | `user` (`gatewayd`) | `CAP_NET_BIND_SERVICE` | UDP and TCP 53 (see Owner questions: it moves out of platformd) |
| `proxy` | `proxy` | parser | `user` (`gatewayd`) | `CAP_NET_BIND_SERVICE` | 443 and the configured listeners |
| `management-vpn` | `management-vpn` | parser | `user` (`gatewayd`) | none | its admission listener (4433) is unprivileged; peers are installed through the datapath seam |
| `firewall`, `nat`, `load-balancer`, `overlay` | see Owner questions | kernel | 0 | `CAP_NET_ADMIN`, `CAP_NET_RAW` | OVS flows on the bridge whose base pipeline one runtime owns |
| `nat64` | `nat64` | kernel | 0 | `CAP_NET_ADMIN` | drives the Jool kernel translator: renders its configuration and execs `jool` (Generic Netlink), so this class keeps `execve`; the module is loaded by the init path (`modprobe jool`) before the service starts, so the process needs no `CAP_SYS_MODULE` |
| `hostfw` | `hostfw` | kernel | 0 | `CAP_NET_ADMIN` | replaces its nftables table in one netlink transaction |
| `tunnels` | `tunnels` | kernel | 0 | `CAP_NET_ADMIN` | GRE, WireGuard and IPsec links and XFRM state; its uplink routes and rules move to `rib` |

**Credentials and identity.** The uids stay what they are today. The parser
class drops to one configured uid and gid shared by every parser process
(the one `user` account, default `gatewayd`,
`pkg/sdn/gateway/process/settings.go:32`, `:46`, resolved into `Config.UID`,
`pkg/sdn/gateway/process/supervisor.go:80-81`;
the drop is `dropCredentials` under `if def.Unprivileged` in `harden`,
`pkg/sdn/gateway/process/launcher.go:383-387`, which `EnterHardened`,
`pkg/sdn/gateway/process/child.go:45`, runs; `Unprivileged: true` is set only
on the parser definitions, `pkg/sdn/gateway/process/class.go:137`, `:151`,
`:164`, `:177`). Every kernel-class process (`rib`, `tunnels`, `hostfw`,
`nat64`, the OVS services) keeps uid 0 with its bounded capabilities, as the
`datapath` process does today, and so does the supervisor. A uid therefore
names no service, and the IPC does not use it as one: a caller is identified
by the service the supervisor registered for its process ((f)).

**Network namespaces.** Every service process runs in the host's root network
namespace, as today; none creates one (the seccomp filter refuses
`CLONE_NEW*`, [engineering.md](engineering.md) §"The process model"). The
namespace seams that exist (`nftables.WithNetNSFd`, the netns integration
suites) are test fixtures, not a runtime need. Per-tenant VRFs (#721) are
outside item 4.

## (c) platformd as the single supervisor

platformd on the gateway node is the one supervisor. It execs each enabled
service's process, owns its cgroup leaf, and is the parent-death target. The
existing `process.Supervisor`, `Launcher`, `CgroupManager` and `EnterHardened`
are moved, not rewritten: the package is reached from platformd's assembly
instead of `gatewayd serve`'s, and its `Definition` table becomes one entry per
service.

**Restart policy with backoff.** Today's policy, per process: exponential
backoff from 500 ms doubling to 30 s, a budget of 5 restarts in a 5 minute
window, the history reset when a process stays up longer than the window
(`noteRestart`). A process over its budget is left down and reported
`ErrRestartBudgetExhausted`; nothing restarts it until an operator or a
configuration change does; for `rib`, the supervisor then enforces the
route-retention deadlines itself ((d), "Retention across `rib` failure"). A
planned stop sends `SIGTERM` and waits
`DefaultStopTimeout`; a supervisor crash kills every child with `SIGKILL`, so no
child runs its withdraw path, and the successor starts every producer's
retention clock at its own start ((d), "A supervisor restart").

**sd_notify-style readiness and health.** platformd passes each child a
`NOTIFY_SOCKET`, an `AF_UNIX` `SOCK_DGRAM` socket per child in its runtime
directory, and reads the sd_notify(3) wire format: newline-separated
`KEY=value` assignments. The child sends:

| Message | When | Supervisor action |
|---|---|---|
| `READY=1` | the service is serving (listener bound, backend started) | readiness reached; `StartService` returns |
| `STATUS=<text>` | any time | kept as the service's last status line |
| `WATCHDOG=1` | every half of `WATCHDOG_USEC`, which platformd sets | a missed deadline is a failure, restarted under the policy |
| `STOPPING=1` | on an orderly stop | the exit that follows is not a crash |
| `ERRNO=<n>` | a start that failed | recorded as the failure cause |

A datagram is accepted only when its `SCM_CREDENTIALS` pid is the child's pid
(the kernel fills them in), so a service can only report itself. Readiness
not reached within `DefaultReadyTimeout` is a failed start. The gRPC `Status`
call stays the detailed health source; the notify socket replaces the 25 ms
polling loop for readiness and adds liveness between calls.

**What platformd reports.** One record per service, the shape
`ServiceReport{Name, Active, Health}` already has, extended with the
supervisor's view: process state (starting, ready, stopping, down,
budget-exhausted), pid, restart count in the window, current backoff, last exit
status and last `STATUS=`, and the cgroup's `memory.current`, `memory.peak` and
`memory.events` counters `CgroupManager.Memory` reads today. It is served
through platformd's existing health and gateway telemetry surfaces on every
transport; the per-service health replaces the reports gatewayd sends today.

## (d) The zebra-role process

`rib` owns the kernel routing state: it is the only process that installs
routes and routing rules, as zebra is in FRR. The one other writer is the
supervisor, which only deletes producers' routes at their deadlines while no
`rib` runs ([Retention across `rib` failure](#retention-across-rib-failure)). It is a kernel-class process
with `CAP_NET_ADMIN` alone and parses nothing from the network.

**How producers hand it routes.** Each producer (`bgp`, `tunnels` for its
uplink tables and source rules, and any later static or overlay producer)
calls `RouteService` on `rib` over the platform local transport (see (f)).
A route is keyed by producer, table and prefix; the producer sends the whole
set it wants per table (`SyncRoutes`) or a delta (`AddRoutes`,
`WithdrawRoutes`). `rib` resolves the best entry per prefix across producers by
administrative distance (BGP below a connected or static route, as in FRR) and
writes the winners with `RTM_NEWROUTE`, tagging each with a routing protocol
number (`rtm_protocol`) per producer, and each rule with the same number in
`FRA_PROTOCOL`, so a successor `rib` adopts its own routes
from the kernel at start rather than flushing them.

**Why a BGP crash does not withdraw routes.** When a producer's session to
`rib` drops without a `STOPPING=1` from that producer, `rib` marks its
routes stale and keeps them installed, forwarding on them unchanged (RFC 4724
§4.1 and §4.2: stale and fresh routes are not told apart in forwarding).
`rib` then holds the stale entries under two deadlines per producer, one after
the other:

- **Recovery deadline.** It is an absolute time: the producer's loss plus
  the producer's restart time (for `bgp`, its configured
  `graceful-restart-time`, default 120 seconds). The loss is the moment the
  producer stopped being in sync with `rib`, and the supervisor records it
  (see [Retention across `rib` failure](#retention-across-rib-failure)), so a
  `rib` restart never moves it. If the producer has not reconnected and re-registered
  by then, `rib` removes its stale entries, as a Receiving Speaker deletes a
  peer's stale routes when the session is not re-established within the
  Restart Time (§4.2). Restart Time bounds only the wait for the session to
  come back; it says nothing about how long route selection takes after it
  has.
- **Convergence deadline.** When the producer reconnects and re-registers,
  `rib` cancels the recovery deadline and starts the convergence deadline.
  It lasts the producer's selection-deferral bound plus its selection
  allowance, both declared at registration, and is measured from the
  re-registration. The producer's `EndOfSync` ends it early. While it runs,
  `rib` replaces stale entries with what the producer sends, and it sweeps
  the entries still stale only on `EndOfSync` or when the convergence
  deadline expires, never at the restart time.

**The selection bounds `bgp` declares.**

- **Selection-deferral bound.** This is the Selection_Deferral_Timer of
  RFC 4724 §4.1, under the configuration key
  `graceful-restart-deferral-time`, default 360 seconds, configurable (ruling
  244(b)). The RFC leaves the value to configuration: "To put an upper bound
  on the amount of time a router defers its route selection, an
  implementation MUST support a (configurable) timer that imposes this upper
  bound. This timer is referred to as the "Selection_Deferral_Timer". The
  value of this timer should be large enough, so as to provide all the peers
  of the Restarting Speaker with enough time to send all the routes to the
  Restarting Speaker." (§4.1), and §6 adds that "the upper bound for deferring
  route selection may need to be tuned as more deployment experience is
  gained". The 360 seconds is GoBGP's own default for its `deferral-time`
  (`github.com/osrg/gobgp/v4@v4.9.0/pkg/config/oc/default.go:225`, the version
  this repository pins). The key does not exist yet; step 4 of the move plan
  adds it to `BGPConfig` and passes it to GoBGP's `deferral-time`.
- **Selection allowance.** Under the configuration key
  `graceful-restart-selection-allowance`, default 60 seconds, configurable.
  It bounds the time from the end of selection deferral to `EndOfSync`: route
  selection itself, then `SyncRoutes` and `EndOfSync` to `rib`. Without it,
  a restart in which a peer never sends End-of-RIB ends selection deferral
  only when the Selection_Deferral_Timer expires (§4.1 (b)), and `bgp`'s
  `SyncRoutes` would arrive just after a convergence deadline of the same
  length had swept the routes it replaces. Step 4 adds this key to
  `BGPConfig` with the deferral key.

**Timer origins.** `bgp` starts its Selection_Deferral_Timer when the process
starts in restarting mode, before it has any session to `rib` or to a peer.
`rib` starts the convergence deadline at the re-registration, which comes
after that process start. So `rib`'s convergence deadline (deferral bound plus
allowance, from re-registration) always ends at least one allowance after
`bgp`'s deferral can have expired, and a `SyncRoutes` and `EndOfSync` sent
within the allowance of deferral expiry always arrive before it.

The timers are split by owner. `bgp` owns selection deferral: after a restart
it defers route selection until End-of-RIB from its peers or its
Selection_Deferral_Timer (§4.1), and sends `SyncRoutes` and then `EndOfSync`
only after selection completes, the point at which §4.1 says the forwarding
state is updated and stale information removed. While it runs, `rib` enforces
both deadlines itself, so that a producer that hangs before reconnecting, or
after reconnecting but before `EndOfSync`, cannot pin stale routes forever:
the recovery deadline as the supervisor passes it at `rib`'s start and as
`rib` reports each new loss, the convergence deadline from the selection
bounds the producer declares when it registers. If the producer's session
drops again before `EndOfSync` while the same `rib` runs, `rib` removes the
entries still stale from the earlier restart, and that drop is a new loss
with a new recovery deadline, as §4.2 requires for consecutive restarts.

A planned stop (`STOPPING=1`, or a configuration
that disables the producer) withdraws its routes at once.

### Retention across `rib` failure

A `rib` crash withdraws nothing: the routes are in the kernel, and the
successor adopts them by protocol number. Adoption recovers which producer
owns a route, but not whether it was stale or its deadlines; those lived in
the dead process. So the retention record lives in the supervisor, which
outlives every child, and every deadline in it is an absolute
`CLOCK_BOOTTIME` instant that no `rib` restart moves.

**The loss record.** The supervisor keeps one entry per configured producer:
in sync, lost at `L`, or re-registered at `G`, with the deadline in force:

| Phase | Deadline in force |
|---|---|
| in sync | none |
| lost at `L` | recovery: `L` + the producer's restart time |
| re-registered at `G` | convergence: `G` + its selection-deferral bound + its selection allowance |

The restart time and both selection bounds are the producer's configuration,
which the supervisor already reads (for `bgp`, `graceful-restart-time`,
`graceful-restart-deferral-time` and `graceful-restart-selection-allowance`).
The supervisor moves an entry:

- to lost at `L` when it reaps the producer process (a crash or a watchdog
  kill), or when `rib` reports the producer's session dropped while the
  process lives, with the drop time `rib` saw;
- to lost at `L` for every producer in sync when it reaps `rib`: `rib`'s
  death ends every producer's session, and every route it installed is
  stale from that instant;
- to lost at `S` for every producer in sync, or with no entry, when the
  supervisor itself starts (see "A supervisor restart" below);
- to re-registered at `G` when `rib` reports the producer's registration
  while the entry is lost;
- to in sync when `rib` reports the producer's `EndOfSync`, or on a planned
  stop of the producer, which withdraws its routes at once.

An entry already lost or re-registered is never moved to a later anchor by a
`rib` death, nor by the producer's re-registration with a successor `rib`: a
re-registered entry keeps its `G` until `EndOfSync`. `rib` reports a drop, a
registration and an `EndOfSync` on its notify socket ((c)) as
`X_PRODUCER=<name> <dropped|registered|synced> <boottime-usec>`, the `X_`
prefix sd_notify(3) leaves to applications, accepted only from `rib`'s pid as
every notify datagram is. A report lost with a crashing `rib` errs short: the
entry stays at its earlier phase, whose deadline is never later. The
supervisor writes the record to its runtime directory (tmpfs, cleared at
boot, as `CLOCK_BOOTTIME` restarts) by write-and-rename on every change, so a
platformd restart reads it back.

**The route record.** Each entry also carries, per address family (IPv4
unicast is `AF_INET`, IPv6 unicast `AF_INET6`), the forwarding state the
producer has installed: the number of its routes in that family and a SHA-256
digest over them, each route encoded as its table, destination prefix, next
hop and output interface index, sorted. `rib` computes both from the routes it
has installed for the producer and reports them on the same notify socket as
`X_ROUTES=<name> <inet|inet6> <count> <sha256-hex>`, after the kernel
acknowledges each change to that family: every `AddRoutes`, `WithdrawRoutes`
and `SyncRoutes` the producer sends, every stale sweep, and every removal at a
deadline or a planned stop. The supervisor stores the pair in the entry, in
the same write-and-rename, and deletes every family pair of a producer whose
routes it removes itself ((d), "While no `rib` runs"). The start transition
keeps the pairs of an entry it moves to lost, and an entry it creates has
none. A report lost with a crashing `rib`, or a change the kernel made after
the last report, leaves a pair that no longer matches the kernel, which errs
towards F clear ((e), "The Forwarding State bit"), never towards F set. A
match is never enough on its own: once the record is frozen, the route
notification of any change to a recorded entry invalidates the family when
`rib` reads it, whatever the kernel holds afterwards ((f), "Kernel
changes").

**`bgp`'s forwarding set.** `bgp` may advertise a prefix that another
producer's better route forwards ((e), "Exports wait for `rib`"), so for `bgp`
the pair covers more than the routes under its own protocol number: it covers
its forwarding set, the effective kernel entry behind every prefix `rib` has
acknowledged to `bgp` as installed, whichever producer owns it, and the entry
behind every prefix it originates ("Locally originated prefixes" below). Every
learned prefix `bgp` exports is one of those, since nothing unacknowledged is
exported. For
`bgp` each route is encoded as its table, destination prefix, next hop, output
interface index and owning `rtm_protocol`, sorted, and the set holds every
route `rib` installed under `bgp`'s protocol number, as before, plus, for each
acknowledged prefix another producer's entry backs, that entry. While the
record is live (below), `rib` reports a new pair after any change to an entry
in the set, the other producer's `AddRoutes`, `WithdrawRoutes`, `SyncRoutes`
or removal included. A count and digest name no prefixes, so `rib` also keeps
the backing list, the table and prefix of each acknowledged prefix another
producer's entry backs, per family, in a file in the runtime directory,
written by write-and-rename before the report that covers it; a successor
`rib` reads it at start. A list that is missing, or newer than the pair
because `rib` crashed before its report, yields a digest that does not match,
which errs towards F clear.

**Locally originated prefixes.** A peer that sees F set keeps forwarding
through this node every route it holds from it in that family, the Announce
prefixes this node originates as much as the routes it learned. An Announce
prefix is advertised without `rib`'s acknowledgement ((e), "Exports wait for
`rib`"), but its forwarding still rests on a kernel entry `bgp` did not
install: the route the kernel holds for exactly that prefix in the table it
is forwarded from, under any protocol. For a prefix on one of this node's
interfaces that is the connected route (`RTPROT_KERNEL`) the interface
address creates, so removing the address, or the interface, removes it; for
any other it is the static or other producer's route that covers it exactly.
`bgp` declares its Announce prefixes per family in `RouteService.Register`
and again whenever the set changes, and `rib` adds each one to the backing
list as a local entry, its table and prefix recorded as for another
producer's entry. It is then recorded at registration and while live
alongside the rib-acknowledged prefixes, encoded with its owning
`rtm_protocol` in the same pair, and nothing else about the record changes:
a change to that entry while `bgp` is down is a change to an entry behind a
prefix in the backing list, which sets the invalidation flag ("The frozen
baseline" below), and the comparison at registration ((e), "Preserved")
finds a lost or changed local entry as it finds a learned one, even when
every learned route is unchanged. An Announce prefix with no kernel entry
for its table and prefix (an aggregate the node originates with no route of
its own, or an address not yet configured) has no forwarding state that can
be shown preserved: while one lacks it, `rib` reports
`X_ROUTES=bgp <inet|inet6> unestablished` instead of a pair, and the
supervisor deletes that family's pair, so the family has none until the entry
appears and a live `rib` reports the pair again; while frozen, no pair can
return. **The rule:** a family is preserved for `bgp` only if every Announce
prefix it originates in that family is backed by a recorded kernel entry
that is still installed as recorded; when that cannot be established, F is
clear for that family, whatever its learned routes show.

**The frozen baseline.** The pairs and the backing list are the evidence of
what `bgp` forwarded before it was lost, so a loss freezes them; a
recording made after the loss would describe what survived, not what
existed, and a reduced kernel would match it. `bgp`'s record has two states:

- **Live** while `bgp` is up and registered: its entry is re-registered or in
  sync. `rib` reports pairs and writes the backing list as above, and the
  supervisor stores each pair it receives.
- **Frozen** from `bgp`'s loss: the supervisor moving the entry to lost (the
  reap of the `bgp` process, or `rib`'s `dropped` report of a lapsed
  registration), and, in `rib`, the close of `bgp`'s connection or the lapse
  of its registration, whichever `rib` sees first. Before it reports a pair
  for `bgp`, `rib` polls `bgp`'s pidfd ((f), "Admission"), and a readable one
  freezes the record instead. While frozen, `rib` reports no pair and writes
  no backing list for `bgp`, except the report of its removal at the
  deadline in force, which ends the recovery (below) and which the
  supervisor accepts only once that deadline has passed; the supervisor ignores
  any other pair for `bgp` that reaches it while the entry is lost, so a
  report racing the reap leaves the older pair, which errs towards F clear. A start transition
  ((d), "A supervisor restart") freezes as any other loss does.

While frozen, any change to an entry in `bgp`'s forwarding set (a route under
`bgp`'s protocol number, or the entry behind a prefix in the backing list,
whichever producer's request or kernel event causes it) sets that family's
**invalidation flag**. `rib` reports it on the notify socket as
`X_ROUTES_INVALID=bgp <inet|inet6>`; for a change `rib` makes, before it
writes the change to the kernel, so a `rib` that crashes after the write has
already queued the report; for any other change, as soon as `rib` reads its
route notification, on the event and before any dump ("Kernel changes" in
(f)), so a change reverted before `rib` read it still sets the flag. A
dump never clears the flag or stands in for the event. A change `rib` cannot have
observed, made while no `rib` watched or in a gap in its watch, sets no flag;
the continuity rule below, not the digest, covers it. The
supervisor stores the flag in `bgp`'s entry by the same write-and-rename, so it
survives a `rib` restart and a supervisor restart, and passes it to every
`rib` it launches ("A `rib` restart"). The flag is set even when the change is
later reverted: the kernel then matches the frozen digest again, but the
forwarding was interrupted, and §4.1 allows F only if the forwarding state
"has indeed been preserved for that address family during the restart".

**Monitoring continuity.** The invalidation flag is only as complete as
`rib`'s watch of the kernel: a change `rib` never observed sets no flag, and a
dump shows what the kernel holds when it is taken, not what happened before
it, so a route removed and restored while nothing watched leaves a kernel that
matches the frozen digest and a flag that is clear. **The rule:** a frozen
record is evidence that forwarding was preserved only while one `rib` process
has watched the kernel's route notifications (`RTNLGRP_IPV4_ROUTE`,
`RTNLGRP_IPV6_ROUTE`, "Kernel changes" in (f)) without a gap since the record
was frozen. A gap is any of:

- the `rib` process holding the watch exiting, or reopening its route
  notification socket; a platformd restart is one, since the parent-death
  `SIGKILL` ((c)) kills `rib` with it, and so is a freeze while no `rib` runs,
  as no watch spans it;
- `ENOBUFS` on that socket: the kernel dropped notifications `rib` will never
  read;
- a resynchronising dump that stands in for notifications `rib` did not
  receive, rather than following one it did, `rib`'s own start included.

After a gap the record is **unverifiable**: F is clear for every family it
covers, whatever the invalidation flag and the kernel dump show, until a new
record is frozen under an unbroken watch, that is, until `bgp` next reaches
in sync and is lost again while one `rib` watches. A digest match after a gap
is not evidence. The record carries the watch as a **watch generation**: the
supervisor numbers each `rib` it launches with a counter kept in the record,
advanced and written by write-and-rename before each exec of `rib`, and passes
the number to it as `--watch-generation=<n>`; every pair it stores is stamped
with the generation of the `rib` that reported it, a freeze keeps the stamp
of the pair it freezes, and a freeze while no `rib` runs stores the record
already unverifiable. A successor `rib` detects the gap from its launch
arguments ("A `rib` restart"): a pair whose stamp is not its own generation
was frozen under a watch that has ended, which, as the counter advances
before every exec, is every frozen pair it is given, so it holds those
families unverifiable from its start. A `rib` that sees a gap in its own watch
(`ENOBUFS`, or a reopened socket) marks every frozen family unverifiable
before the dump that follows, and clears every preserved flag of a registered
`bgp` ((e), "Revalidated before every OPEN"); it holds the mark in memory, as
its exit is itself a gap the next generation detects.

The record returns to live when `bgp` registers, and the flag clears when
recovery completes, and only then:

- `bgp`'s `EndOfSync`, after which `rib` sweeps what stayed stale; this is the
  point at which RFC 4724 §4.1 requires that "the forwarding state of the
  speaker MUST be updated and any previously marked stale information MUST be
  removed", and after which `bgp` sends End-of-RIB to each peer (§4.1, §2);
- the removal of `bgp`'s routes at the deadline in force, by `rib` or by the
  supervisor ((d), "While no `rib` runs"), the analogue of §4.2's "If the
  session does not get re-established within the "Restart Time" ... the
  Receiving Speaker MUST delete all the stale routes": the pairs are
  replaced by a count of zero or deleted, so F is clear for the family
  whatever the flag says.

A re-registration does not clear the flag: a `bgp` that registers, takes its
report and crashes again before `EndOfSync` finds the flag still set at its
next registration, and F stays clear for that family.

**A supervisor restart.** A platformd crash leaves the record as the dead
supervisor last wrote it, and the parent-death `SIGKILL` ((c)) has killed
every child with it, so no producer is in sync with anything any more, and the
dead supervisor could record no loss. So the successor's first act, after it
reads the record and before it launches any child, is the start transition:

- every entry still in sync, and every configured producer with no entry (as
  after a boot), moves to lost at `S`, the successor's start, with its
  recovery deadline `S` + the producer's restart time (for `bgp`,
  `graceful-restart-time`, RFC 4724 §4.1 and §4.2); an entry created here
  for a producer with no entry is also marked unrecorded, since no record
  says its routes were ever installed this boot, and stays unrecorded until
  it next reaches in sync ((e), "The Forwarding State bit");
- every entry already lost or re-registered keeps its `L` or `G` and the
  absolute deadline in force; a start never moves an anchor.

`S` is the successor's own `clock_gettime(CLOCK_BOOTTIME)` read at start,
the clock every deadline in the record uses. The crash instant is unknown, as
the dead supervisor recorded nothing, and `S` is later than it, so an adopted
route is held at most platformd's own downtime longer than a loss recorded at
the crash, and still for one restart time from `S`. Every producer is then
relaunched as after a crash (for `bgp`, in restarting mode, (e) §4.1), and the
deadlines are enforced as below.

The start transition is written, by write-and-rename, before the successor
does anything else, so the next successor reads the entry as lost at `S` and
keeps it: a crash loop of the supervisor itself never re-anchors an entry, and
a producer that never returns has its routes removed at the first successor's
`S` plus one restart time, however often platformd restarts after that. A
successor that crashes before that rename has launched no child and enforced
nothing, and leaves the record as it found it; the next one anchors at its own
start, which it records before it acts. A loop that never gets past the
rename is a supervisor that never starts: no process runs to enforce any
deadline, a lost entry's included, so no record bounds it.

**A `rib` restart.** The supervisor launches `rib` with every entry that is
not in sync, as `<producer>=<phase>,<deadline>` launch arguments, with a
third field `,unrecorded` on an unrecorded entry, and one field
`,<inet|inet6>=<count>:<sha256-hex>:<generation>` per family pair in the
route record, the last part the pair's watch generation, one field
`,unverifiable=<inet|inet6>` per family the record already holds unverifiable,
and one field `,invalid=<inet|inet6>` per family whose invalidation flag is
set ("The frozen baseline"), beside its own `--watch-generation` ("Monitoring
continuity"). At start `rib` holds those pairs as the producer's
route record, frozen for a producer that is lost, and the flags with it, marks every
adopted route stale, holds each producer's under the
deadline passed for it (after a `rib` death no producer is in sync: the reap
set every in-sync entry lost; after a supervisor start, the start transition
did), removes at once the routes
of a producer whose deadline has passed and every adopted route whose protocol
number belongs to no configured producer. A producer that registers before its
recovery deadline moves under a convergence deadline from that registration;
one already re-registered keeps the convergence deadline passed. So repeated
`rib` restarts never extend retention: without a re-registration a producer's
routes are gone at `L` plus one restart time, and in the worst case at `L`
plus its restart time, deferral bound and allowance, however often `rib`
restarts in between.

**While no `rib` runs.** Between reaping one `rib` and execing the next
(through any backoff), and indefinitely once `rib` has exhausted its restart
budget ((c), `ErrRestartBudgetExhausted`), the supervisor enforces the
deadlines itself. When a producer's deadline passes, it dumps the routes
(`RTM_GETROUTE`, every table) and rules (`RTM_GETRULE`) and deletes
(`RTM_DELROUTE`, `RTM_DELRULE`) each one whose `rtm_protocol`, or the rule's
`FRA_PROTOCOL`, is that producer's number; it touches no other protocol
number. It finishes any deletion due before it execs a `rib`, so the two never
write at the same time. A failed `rib` makes every producer lost at its last
exit, so even a live `bgp`, whose routes nothing can update any more, has them
removed one restart time later, its peer sessions closed first (below); a
failed `rib` while `bgp` is down removes `bgp`'s stale routes at the recovery
deadline set by `bgp`'s own loss.

**A live `bgp` at its deadline.** Removing a live `bgp`'s routes and nothing
else would leave its peers forwarding into a node with no forwarding state:
their sessions to it stay up, so none of their RFC 4724 §4.2 timers starts,
and nothing ends it. So no retention cleanup removes the routes of a `bgp`
process that still holds peer sessions. When the deadline in force for `bgp`,
recovery or convergence, is `DefaultStopTimeout` from passing, its entry is
not in sync, and the `bgp` process lives, the supervisor makes a planned stop
of it: `SIGTERM`, and `SIGKILL` at the deadline if it has not exited. Both
processes that remove routes at a deadline, `rib` and the supervisor, read the
same absolute deadline from the record, so the stop always begins one stop
timeout before either removes a route, and an orderly exit has closed every
session by then. The rule is the same after budget exhaustion, through a long
backoff, and with a running `rib` that `bgp` failed to re-register with or
sync to in time; a stop once begun completes. Unlike other planned stops it
leaves `bgp`'s entry where it is, so the deadline in force still removes the
routes, whether or not a `rib` was there to take the withdrawal. `bgp` then stays down while no
`rib` runs, and the supervisor relaunches it once one does; that start's
registration finds the routes gone and sets F clear for every family ((e),
"The Forwarding State bit"), so no OPEN carries a report the cleanup made
false.

The speaker closes its sessions; it does not withdraw the affected
advertisements and stay up. With `rib` failed or `bgp` unsynced, no route
`bgp` learns can reach the kernel, so every learned route it would advertise
is affected, now and for as long as it stays up, and tracking which ones are
would be new logic in the speaker for a state it cannot leave on its own. A
session ended by a NOTIFICATION, by contrast, needs none: RFC 4724 §4
requires the normal BGP procedures then, and the FSM text of §5 has the
receiving peer delete every route of that connection at once, with no
graceful-restart retention. A stop that ends in `SIGKILL` sends no
NOTIFICATION, so its peers apply §4.2 and §5 instead: they keep the routes as
stale and delete them when the session is not re-established within this
node's advertised Restart Time, which, with `bgp` held down, it is not.
Unverified: that GoBGP v4.9.0 sends each established peer a Cease
NOTIFICATION from `StopBgp`, which the speaker's stop path calls
(`pkg/sdn/bgp/speaker.go:525`, the call at `:536`); its source was not
checked for this design, and step 4 of the move plan asserts it on the wire.

The supervisor holds `CAP_NET_ADMIN` already. A capability enters a child's
ambient set only if it is in the parent's permitted and inheritable sets
(capabilities(7)), so the supervisor that launches `rib`, `tunnels`, `hostfw`
and `nat64` with `CAP_NET_ADMIN` must hold it (Owner question 5); today's
supervisor, `gatewayd serve`, runs as root from its OpenRC unit, which sets
no `command_user` (`pkg/firstboot/gatewayd.go:36-44`) and admits its own uid as the control uid
(`pkg/sdn/gateway/process/supervisor.go:497`,
`pkg/sdn/gateway/commands/service.go:208`). The cleanup uses that
capability for deletions only, filtered on the producers' protocol numbers,
and reads only the kernel's netlink replies, never network input. It adds no
capability, no listener and no install path: `rib` remains the only process
that installs routes and rules.

## (e) BGP graceful restart per RFC 4724

The RFC is in [docs/reference/bgp/rfc4724.txt](../reference/bgp/rfc4724.txt).
The `bgp` process is the speaker; `rib` is where its forwarding state lives,
which is the separation RFC 4724 §6 assumes for preserving forwarding state.

**The Forwarding State bit.** RFC 4724 §4.1: "Unless allowed via
configuration, the "Forwarding State" bit for an address family in the
capability can be set only if the forwarding state has indeed been preserved
for that address family during the restart." A Receiving Speaker that sees F
clear deletes the stale routes it holds from this node for that family
(§4.2), and one that sees it set keeps forwarding through this node for the
whole of selection deferral. So F follows what the kernel holds, and what
an unbroken watch saw happen to it, not the presence of `rib`, and no
configuration overrides it:

- **The report.** `bgp` registers with `rib` (`RouteService.Register`, (f))
  before it starts GoBGP or opens any peer session, declaring its selection
  bounds and the address families it advertises. The reply carries, per
  family, whether `rib` holds that family's forwarding state as preserved.
- **Preserved** means the family's complete forwarding state, not one route
  of it: §4.1 allows F only if "the forwarding state has indeed been preserved
  for that address family", and a peer that sees F set keeps forwarding
  through this node every route it holds from it in that family, whichever
  producer's kernel entry forwards it. So `rib` compares the kernel against
  the route record ((d), "The route record" and "`bgp`'s forwarding set"),
  the per-family count and digest of `bgp`'s forwarding set: the routes `bgp`
  had installed and the entry behind every prefix it exported, learned or
  originated, which `rib`
  holds from its launch arguments across a `rib` restart and the supervisor
  holds across a platformd restart. At the moment `rib` answers the
  registration it dumps the kernel's routes (`RTM_GETROUTE`, every table) and
  takes those under `bgp`'s `rtm_protocol`, whether retained by this `rib` or
  adopted from the kernel at its start, plus, for each table and prefix in the
  backing list, the entry installed there under any protocol. A family is
  preserved for `bgp` only when all of these hold: the route record has a pair
  for that family with a count above zero; the routes taken for that family,
  encoded as the record encodes them, match that count and digest, so every
  recorded entry is still installed with its recorded next hop, output
  interface and owning protocol, an exported prefix's backing entry and an
  Announce prefix's local entry included ((d), "Locally originated
  prefixes"), and no unrecorded `bgp` route is; the
  deadline in force for `bgp` has not passed; `bgp`'s entry is not
  unrecorded ((d), "A supervisor restart"); the family's invalidation
  flag is clear, no route notification for the family's record having been
  read since the freeze, whatever the kernel now holds ((f), "Kernel
  changes"); and the record is not unverifiable: its pair carries this
  `rib`'s own watch generation and no gap has broken this `rib`'s watch since
  the record was frozen ((d), "Monitoring continuity"). The pair compared is
  the one frozen at `bgp`'s loss, never one recorded after it ((d), "The
  frozen baseline"), so a kernel reduced while `bgp` was down cannot match
  it, and a match counts only under that unbroken watch, so a kernel changed
  and restored while nothing watched cannot pass for preserved. The registration then moves `bgp`
  under its convergence deadline, so its routes stay installed until `EndOfSync`
  replaces them after selection (§4.1), or until that deadline if it never
  comes.
- **F clear.** F is clear for every family whose completeness `rib` cannot
  establish. That covers a boot with no record (the kernel tables are empty
  and the entry is unrecorded); adopted routes with no record (an unrecorded
  entry, or no pair for their family); a family `bgp` had no routes in (no
  pair, or a count of zero); a family whose routes a retention cleanup removed
  (`rib` at an expired deadline, or the supervisor while no `rib` runs, (d),
  "While no `rib` runs"); and a family that lost even one route, or gained
  one, while `bgp` was down, as when removing a tunnel interface makes the
  kernel delete the routes through it, so the dump no longer matches the
  pair; and a family in which the entry behind an exported prefix was lost or
  changed while `bgp` was down, even when another producer owned it and
  every route under `bgp`'s protocol number survived, or changed and was
  restored (the invalidation flag, set by the route notification itself, so
  a deletion and restoration `rib` read only after both happened, or an
  in-place replacement, clears F though the dump matches, (f) "Kernel
  changes"), and while a recovery that did not
  complete left that flag set; and a family with an Announce prefix whose
  local entry was lost or changed while `bgp` was down, or whose
  preservation cannot be established, even when every learned route is
  unchanged ((d), "Locally originated prefixes"); and every family of a
  record that is unverifiable ((d), "Monitoring continuity"): a `rib`
  restart, platformd's included, between `bgp`'s loss and its registration,
  a freeze while no `rib` ran, or a notification overrun in that window, even
  when the kernel matches the frozen digest. F is clear for every
  family when `rib` cannot report: the registration is refused, `rib`'s
  socket is not there, or the call fails or reaches its deadline. `bgp`
  then opens its peer sessions anyway, as a Receiving Speaker per §4.2, and
  registers with `rib` when it can. It receives routes on those sessions but
  advertises none of them until `rib` has installed them ("Exports wait for
  `rib`" below): F clear only tells a peer to drop what it retained from
  this node, and does not stop new advertisements.
- **F set** only for a family the reply names as preserved, and only while
  it stays preserved (below).
- **Revalidated before every OPEN.** Within one process start F only ever
  moves from set to clear, never back. `bgp` holds a preserved flag per
  family, taken from the report at its first registration, and every OPEN it
  sends, to a peer's first session or to one reconnecting later, carries the
  flag's current value. `rib` is the authority: it holds the same per-family
  flag for `bgp`'s registration and clears it, before it queues the event
  that tells `bgp`, on any loss the design already names:
  - a feed event that moves a `bgp` route of that family from installed to
    not installed ((f), "Install-state feed"), whatever the cause: the kernel
    deleting routes with a removed tunnel interface, a route removed outside
    `rib`, another producer's withdrawal that leaves no entry behind an
    exported prefix;
  - the loss or change of the local entry behind one of `bgp`'s Announce
    prefixes in that family, or a newly declared Announce prefix with none,
    which `rib` observes as any kernel event ((d), "Locally originated
    prefixes");
  - the family's invalidation flag being set ((d), "The frozen baseline");
  - a route notification for an entry of the family's record, an
    `RTM_DELROUTE` or an adding or replacing `RTM_NEWROUTE`, other than one
    for a change `rib` wrote on `bgp`'s own request, acted on when `rib`
    reads it and before any dump, even when the kernel ends as recorded
    ((f), "Kernel changes");
  - a gap in `rib`'s watch of the kernel, for every family ((d), "Monitoring
    continuity"): a loss the gap hid is one `rib` cannot name, so no family
    can be shown preserved across it;
  - a retention cleanup removing any of the family's routes;
  - a successor `rib`'s report at re-registration naming the family clear.

  Before each OPEN, `bgp` asks `rib` (`RouteService.Preserved`, a unary call
  on its registered connection, under the registration call's deadline) and
  sends F set for a family only when both its own flag and `rib`'s answer
  are set; the result becomes its flag. It does not rely on its feed for
  this: the feed may be behind, a queued event not yet read or a stream
  between reconnect and snapshot, but `rib` answers from its own flag, which
  it cleared before queuing the event, so the answer is never behind the
  feed. A loss event `bgp` has already read clears its flag at once, with no
  call. When `rib` cannot answer at an OPEN (no registration accepted on the
  current connection, `rib`'s socket not there, the call refused, failed or
  past its deadline), that OPEN carries F clear for every family and every
  flag stays clear for the rest of the process start. A cleanup never
  removes a live `bgp`'s routes but stops `bgp` first ((d), "A live `bgp` at
  its deadline"), so no flag outlives the routes it named.

**Exports wait for `rib`.** An advertisement draws a peer's traffic to this
node, so `bgp` advertises only a route this node can forward. It exports a
route it learned from a peer only when both of these hold:

- `rib` has accepted `bgp`'s registration from this process start; and
- `rib` has acknowledged that route as installed in the kernel, and has not
  since named it uninstalled. The acknowledgement is an event on `rib`'s
  install-state feed ((f), "Install-state feed"), which names, per route,
  whether the kernel now holds a route for that prefix in that table:
  `bgp`'s own entry written, or a better producer's entry already installed
  for it ((d), administrative distance). A route whose `RTM_NEWROUTE` failed
  is named not installed. The reply to `SyncRoutes` and `AddRoutes` carries
  the same per-route result for the request's own error handling, but `bgp`
  fills the gate only from the feed, the one ordered sequence that also
  carries every later change, so a reply can never re-admit a prefix an
  event that `rib` emitted after it has removed.

Installation is a further requirement on an export, never a permission for
one: a route reaches peer P only if P's own export policy accepts it **and**
`rib` has acknowledged it installed. `bgp` withholds by export policy, not by
holding paths back from GoBGP, and the gate narrows the per-peer statements
`pkg/sdn/bgp/policy.go` already builds rather than adding one of its own:

- **What is there.** One global export policy, `tp-export`, assigned with a
  reject default (`globalAssignments`). For each peer P and unicast family f
  it holds an allowlist prefix set, `tp-export-<P>-prefixes-<f>`, built from
  P's `export-allow` or, when that is empty, the speaker's Announce prefixes,
  and a statement `tp-export-<P>-prefixes-<f>-accept` that accepts a path
  matching both P's neighbor set `tp-peer-<P>` and that prefix set
  (`peerStatements`).
- **`rib-installed`.** `bgp` keeps, per family, the prefixes `rib` has
  acknowledged installed, and fills and empties it only from the feed: a
  prefix is a member while the latest event for it names installed the route
  `bgp` currently selects for it. It is empty, and the narrowed policy in
  place, before the first peer is added.
- **The intersection, per peer.** A statement's conditions name one prefix
  set (`api.Conditions.PrefixSet`, as `peerStatements` sets it), so the two
  sets are intersected in `bgp`, not in GoBGP: for each P and f, `bgp` builds
  `tp-export-<P>-installed-<f>`, the members of `rib-installed` that P's
  allowlist set matches (same prefix and mask-length range), and the
  statement `tp-export-<P>-installed-<f>-accept` accepts a path matching
  `tp-peer-<P>` and that set. A prefix leaving `rib-installed` leaves every
  peer's set; one entering it joins only the sets of peers whose allowlist
  matches it.
- **The allowlist statement** keeps its set but gains a route-type condition,
  local, as the import policy's `tp-import-local-origin` statement uses, so it
  admits only paths this node originates, which the gate does not cover. A
  learned path is accepted by the installed-set statement or by nothing.
- **An accept-by-default peer** (`export-default-accept`) has an allowlist
  that matches every prefix, so its installed set is the whole of
  `rib-installed`, and its `-default-accept` statement is narrowed to what the
  gate does not cover: one statement for locally originated paths and one
  for l2vpn-evpn paths, since a statement's conditions must all hold.
- **l2vpn-evpn** is admitted by its route-target statements as before; the
  gate covers the unicast families `rib` installs.

Anything no statement accepts falls to the reject default, so a route enters
no Adj-RIB-Out before its acknowledgement, whatever the order in which
sessions come up and paths arrive, and an installed prefix outside P's
allowlist is still never advertised to P: it is in `rib-installed`, not in
`tp-export-<P>-installed-<f>`, and as a learned path it fails the allowlist
statement's route-type condition. Withholding in the speaker would need its
own record of what it has not yet sent, beside GoBGP's. A prefix leaves
`rib-installed` when a feed event names it uninstalled, whatever caused the
loss (`bgp`'s own `WithdrawRoutes`, another producer's withdrawal of the
entry that backed it, a failed install, the deletion of the interface its
next hop used, or a kernel route removed outside `rib`), and when the path
`bgp` selects for it changes, until `rib` acknowledges the new one. Leaving
the set leaves every peer's installed set, so GoBGP withdraws the
advertisement from every peer that had it, and an advertisement never runs
ahead of, or outlives, the forwarding entry the kernel forwards on. Routes
this node originates, its Announce prefixes and the EVPN routes of its own VTEP
(`pkg/sdn/bgp/evpn.go`), are forwarded by the node itself, not through a route
`bgp` installs, and the gate does not apply to them. That bypass is for the
advertisement path only: their forwarding still counts toward preservation,
since the kernel entry each Announce prefix rests on is in `bgp`'s forwarding
set ((d), "Locally originated prefixes"), so F set never promises a peer
forwarding for an originated prefix the kernel lost. Verified against
`policy.go`: the statement layout above, one prefix set per statement, and the
reject default. Unverified: that GoBGP v4.9.0's global export policy applies
to every peer `bgp` adds (`pkg/sdn/bgp/policy.go:34-45` records that
route-server clients take a different path), that a route-type local
condition matches a locally originated path on export as it does on import,
and that changing a defined set re-evaluates the Adj-RIB-Out without a soft
reset; step 4 of the move plan asserts all three on the wire. Withholding is
local policy: RFC 4724 is the only BGP standard in
[docs/reference/bgp](../reference/bgp/README.md), and it does not cover which
routes a speaker may advertise. RFC 4271 §9.1.3, where the speaker applies
its export policy per peer as it fills each Adj-RIB-Out, is not copied there,
so it is cited and not quoted.

- **The fallback.** While `rib` cannot be reached, nothing is acknowledged,
  so `bgp` holds its sessions and learns routes but advertises none of them.
  It re-registers until `rib` accepts, opens the feed, then sends
  `SyncRoutes` with what it has selected, and exports each route as the feed
  acknowledges it: register, install, then export. An OPEN sent while `rib`
  cannot be reached carries F clear, and F stays clear for the rest of the
  process start ("Revalidated before every OPEN").
- **After a restart.** Selection deferral (§4.1) still ends in `SyncRoutes`;
  the initial updates to peers follow `rib`'s acknowledgements, and End-of-RIB
  to a peer follows them (§2).
- **`rib` lost mid-session.** Routes already acknowledged stay installed:
  `rib` keeps them stale and a successor adopts them ((d)), so their
  advertisements stand and still lead to a forwarding entry. Nothing learned
  or reselected after the loss is exported, since no `rib` acknowledges it,
  and a peer whose session establishes while no feed is current gets an
  empty installed set, so nothing is exported to it from the cache. When a
  successor's feed opens, its snapshot replaces `rib-installed` ((f),
  "Install-state feed"): a prefix advertised before the loss whose entry the
  snapshot does not name installed is withdrawn then. The loss is then a forwarding-state loss as (d) describes it: if no `rib`
  takes `bgp` back in sync before the deadline in force, the supervisor stops
  `bgp` and its sessions close with a NOTIFICATION before its routes go ((d),
  "A live `bgp` at its deadline"); if a successor accepts `bgp`'s
  re-registration first, `bgp` syncs to it and exports again as above.

The Restart State (R) bit and the Restart Time are unchanged by the report: R
is set exactly when platformd launches `bgp` in restarting mode (§4.1), and
the Restart Time is `graceful-restart-time` (§3). Step 4 of the move plan maps
the per-family result onto GoBGP's per-family graceful-restart capability.

| RFC 4724 | Requirement | In this design |
|---|---|---|
| §2 | End-of-RIB marker after the initial update per address family | the `bgp` process's `EndOfSync` to `rib` follows route selection; its initial updates to a peer carry only the routes `rib` has acknowledged as installed ("Exports wait for `rib`" above), and End-of-RIB to that peer follows them |
| §3 | Graceful Restart Capability: Restart State (R) bit, Restart Time, and per AFI/SAFI the Forwarding State (F) bit | the speaker advertises every enabled family (today's `MpGracefulRestart` per family) with the Restart Time `graceful-restart-time`; per family, F is set only when `rib`'s registration report names that family's complete forwarding state preserved (every entry of the family's route record installed as recorded, the routes `bgp` installed and the entry behind every prefix it exported whichever producer owns it, and no other `bgp` route) under a `rib` that has watched the kernel without a gap since `bgp`'s record was frozen, and is clear otherwise, never set merely because `rib` runs or because the kernel matches the record after a gap in that watch, or because some of the family's routes survived, and revalidated with `rib` before every OPEN, so a loss after registration clears it for every later OPEN of that process start and nothing sets it again ("The Forwarding State bit" above) |
| §4.1 | The Restarting Speaker MUST retain the forwarding state for its Loc-RIB routes and mark them stale; sets R; defers route selection until End-of-RIB from all peers or the Selection_Deferral_Timer expires; then updates the forwarding state and removes the stale information | `rib` retains and marks stale (d). platformd relaunches a crashed `bgp` process with the restarting flag, so the speaker sets R; it sets F for a family only if the forwarding state "has indeed been preserved for that address family during the restart" (§4.1), which `rib` reports at registration before any peer session opens by comparing the kernel against the family's route record (count and digest of `bgp`'s forwarding set: what it had installed and the entry behind every prefix it exported, another producer's included), so F means the family's complete forwarding state and is clear after a boot with no record, for a family with no record, after a retention cleanup removed the family's routes, when even one recorded entry is missing or changed (a removed tunnel interface, or another producer's route behind an exported prefix lost), compared against the record frozen at `bgp`'s loss and never one recorded after it, when any entry changed while `bgp` was down even if it was restored (the per-family invalidation flag, set by the change's own `RTM_DELROUTE` or adding or replacing `RTM_NEWROUTE` when `rib` reads it, before any dump, so a deletion and restoration read after both happened, or an in-place replacement, still clears F, (f) "Kernel changes"; persisted with the record and cleared only by `EndOfSync` or the removal at the deadline), for every family of a record no single `rib` has watched without a gap since it was frozen (a `rib` or platformd restart, or a netlink `ENOBUFS`, in that window; the watch generation stored with each pair, "Monitoring continuity"), and for every family when `rib` cannot report; `bgp` owns selection deferral, under its Selection_Deferral_Timer (`graceful-restart-deferral-time`, to be added, default 360 s and configurable as §4.1 requires), started when the process starts in restarting mode, and sends `SyncRoutes` and then `EndOfSync` only after selection completes, which is at the latest when that timer expires (§4.1 (b)); `rib` sweeps what stayed stale on `EndOfSync`, or at its convergence deadline if `EndOfSync` never comes: the deferral bound plus the selection allowance (`graceful-restart-selection-allowance`, default 60 s), measured from re-registration, never at the Restart Time |
| §4.2 | The Receiving Speaker retains a restarting peer's routes as stale for the Restart Time, deletes them if the session is not re-established in time or the F bit is clear, and replaces them after End-of-RIB | toward `rib`, `rib` plays this role for its producers: the recovery deadline (the Restart Time) removes a producer's stale entries only if it has not reconnected, and a reconnect moves them under the convergence deadline (d). The recovery deadline is absolute, the producer's loss plus its Restart Time, and the supervisor holds it, so after a `rib` restart every adopted route is stale under the deadline already in force and repeated `rib` restarts never extend it; while no `rib` runs, including once `rib` has exhausted its restart budget, the supervisor deletes the producer's routes at that deadline (d, "Retention across `rib` failure"). A platformd crash kills every producer with no loss recorded, so the successor moves every entry still in sync to lost at its own start, with the Restart Time from there, before it launches anything, and keeps every deadline already in force; a crash loop of platformd never re-anchors an entry (d, "A supervisor restart"). The §4.2 delete-if-not-re-established rule thus survives the loss of `rib`, and of the supervisor, itself. Toward this node's peers, the F bit is clear for every family whose forwarding state was not preserved, so a peer applies the §4.2 F-clear rule and deletes the stale routes it holds from this node instead of forwarding through a node with no forwarding state. A `bgp` that is still up when its deadline nears holds sessions on which no §4.2 timer runs, so the supervisor stops it, closing those sessions with a NOTIFICATION, one stop timeout before any of its routes is removed (d, "A live `bgp` at its deadline"); a stop that ends in `SIGKILL` leaves the peers this rule's Restart Time instead. Toward peers, GoBGP keeps a peer's stale paths in its RIB; the `bgp` process does not withdraw them from `rib` until GoBGP does, so a peer's restart leaves this node's kernel routes in place too |
| §5 | FSM: a TCP reset without a NOTIFICATION is a restart, not a Cease | a killed `bgp` process (crash, or `SIGKILL` from a dying supervisor) closes its sockets without a Cease, so peers enter §4.2; a planned stop, including the supervisor's stop of a live `bgp` before a cleanup removes its routes (d), ends each session with a NOTIFICATION, so peers follow the normal BGP procedures (§4) and delete its routes at once |
| §6 | The Restart Time, the upper bound for retaining routes, and the upper bound for deferring route selection may need tuning with deployment experience | each is a configuration key, not a constant: `graceful-restart-time`, `graceful-restart-deferral-time` and `graceful-restart-selection-allowance` (d); the retention bound holds across `rib` restarts, `rib` failure and supervisor restarts, at most the loss plus the three together, the loss being the first successor's start when the supervisor crashed while the producer was in sync |

## (f) The IPC seam over the platform local transport

The transport stays what it is: gRPC over Unix sockets, authenticated only by
what the kernel reports of the peer, through `pkg/util/peercred`, the same
code platformd's Unix transport uses. No token, no certificate. What it reads
changes: the peer's pidfd (`SO_PEERPIDFD`) beside `SO_PEERCRED`'s uid, so a
caller is the process it is and not the number it had ("Caller identity"
below).

- **Supervisor to service.** `ipc.proto` is extended, not replaced.
  `ProcessControlService` (`Status`, `Snapshot`) is served by every service
  process for platformd; `DatapathService` and `GatewayServicesService` are
  served by the process that hosts the service they name, so a call is routed
  by service, not by the old process name.
- **Producer to `rib`.** A new `RouteService` (`Register`, `SyncRoutes`,
  `AddRoutes`, `WithdrawRoutes`, `EndOfSync`, `WatchInstalled`, `ListRoutes`)
  on `rib`'s socket. `Register` carries the producer's selection bounds and
  address families, and its reply the per-family preservation result ((e),
  "The Forwarding State bit"). `WatchInstalled` is the install-state feed
  below.
- **Readiness.** The notify socket of (c), outside gRPC, as sd_notify is.

**Install-state feed.** A reply answers one request, and the `X_ROUTES`
reports go to the supervisor, so neither tells a producer that a route it was
told is installed has since gone. `RouteService.WatchInstalled` is a
server-streamed call by which `rib` tells it, on the producer's own
connection, admitted as the producer's other `RouteService` calls are
("Caller identity" below): `rib` takes the producer from the connection's
registered service, accepts the call only after it has accepted that
connection's `Register`, and ends the stream when it closes the connection
(the registration removed or replaced, or the pidfd readable).

- **Events.** Each message names a route the producer has requested and not
  withdrawn (its family, table, prefix and the next hop it asked for), and
  whether the kernel now holds an entry for that table and prefix, the
  producer's own or a better producer's. `rib` sends one whenever that answer
  changes, whatever the cause: the producer's own requests (the per-route
  result its reply also carries), another producer's `AddRoutes`,
  `WithdrawRoutes`, `SyncRoutes` or removal at a deadline that leaves no entry
  or installs one, a failed `RTM_NEWROUTE`, the kernel deleting routes with
  an interface, and a route removed outside `rib`.
- **Sequence.** Each message carries a sequence number, starting at one on
  each stream and increasing by one per message. A producer that sees a gap
  closes the stream and opens a new one; `rib` never skips a number on a
  stream, so a gap means a defect, and the resynchronisation below repairs
  it.
- **Snapshot, then deltas.** A new stream begins with a snapshot: one message
  per route `rib` holds for the producer, requested or adopted from the
  kernel at `rib`'s start, then an end-of-snapshot marker; every later
  message is a change. `bgp` builds the stream's view from the snapshot
  alone and treats `rib-installed` as empty for anything it would add until
  the marker arrives; at the marker the snapshot replaces `rib-installed`,
  and a prefix the old cache held but the snapshot does not name installed
  for the route `bgp` selects leaves it, so nothing is exported on a stale
  cache ((e), "Exports wait for `rib`").
- **Reconnect.** The stream ends with `bgp`'s connection: a `rib` crash, a
  restart, or `rib` closing it. `bgp` opens a new one after each accepted
  `Register`, before its `SyncRoutes`, and until its snapshot completes no
  feed is current ((e), "`rib` lost mid-session").
- **Back-pressure.** `rib` queues each stream's messages up to a bound; a
  producer that falls that far behind has its stream ended with an error
  rather than `rib` blocking or dropping a message, and reopens it, so the
  snapshot resynchronises it.
- **Kernel changes.** `rib` subscribes to the kernel's route and link
  notifications (`RTNLGRP_IPV4_ROUTE`, `RTNLGRP_IPV6_ROUTE`, `RTNLGRP_LINK`).
  **The rule:** a route notification invalidates on the event, not on the
  state it leaves. Every `RTM_DELROUTE`, and every `RTM_NEWROUTE` that adds
  a route or replaces one (`NLM_F_REPLACE`), whose family, table and prefix
  fall in `bgp`'s record (the table and prefix of each route `rib` holds
  under `bgp`'s protocol number, retained or adopted, and of each entry in
  the backing list, (d) "`bgp`'s forwarding set") or that carries `bgp`'s
  `rtm_protocol`, acts on that family as soon as `rib` reads the message,
  before any dump or diff runs: where the record is frozen it sets the
  family's invalidation flag ((d), "The frozen baseline"), and while `bgp`
  is registered it clears the family's preserved flag ((e), "Revalidated
  before every OPEN"). An `RTM_NEWROUTE` identical to the recorded entry
  still invalidates, as the kernel sends one only on a change: a route
  deleted and restored while `rib` had not yet read the queue arrives as an
  `RTM_DELROUTE` and an `RTM_NEWROUTE`, and either invalidates though the
  kernel ends as recorded. The one exception is the notification of a change
  `rib` wrote on `bgp`'s own request after its registration: that is `bgp`
  updating its forwarding state (§4.1), not a loss. A notification outside
  every record changes no flag.

  On an `RTM_DELROUTE` for an entry it holds, on an `RTM_DELLINK` or a link
  going down, and on `ENOBUFS` from that socket (notifications lost), it
  then dumps the routes (`RTM_GETROUTE`) and diffs them against what it
  holds, sending an event for each answer that changed. The dump only
  rebuilds that cache: it never clears an invalidation or a cleared
  preserved flag, and a dump that matches the cache never stands in for the
  event that already invalidated. `ENOBUFS`, or reopening the socket, is a gap in the watch: before that
  dump `rib` marks every frozen record unverifiable and clears every
  preserved flag of a registered `bgp`, as the dump recovers what the kernel
  holds, not the changes it lost ((d), "Monitoring continuity").
  Unverified: that the kernel sends an `RTM_DELROUTE` for each route it
  deletes with an interface; the design does not depend on it, since the
  link notification triggers the dump. Step 4 of the move plan asserts the
  outcome on the wire.

**Caller identity.** Today `ipc.Policy`
(`pkg/sdn/gateway/ipc/policy.go:36`) admits by uid alone: its control uid is
the supervisor's own uid (`pkg/sdn/gateway/commands/service.go:208`, from
`os.Getuid()` at `pkg/sdn/gateway/process/supervisor.go:497`), an empty list
means uid 0 (`admits`, `policy.go:90`), and the kernel-class child admits the
one shared parser uid (`service.go:210`). With one process per service every
kernel-class process and the supervisor are uid 0 ((b), "Credentials and
identity"), so a uid cannot tell `tunnels` from `hostfw`, nor either from the
supervisor. The IPC therefore authenticates a caller against the supervisor's
own registrations, not its uid. A uid names an account, not the process the
supervisor launched: distinct uids would still admit any other process under
the same account (a hand-run `gatewayd service run bgp`, or the `gatewayd
serve` compatibility mode), and giving each root service its own non-root uid
would add accounts and a keep-capabilities path to `harden` for classes that
do not drop today. The supervisor already holds the fact that does identify a
child: the process it launched. A pid does not name that process. The
`SO_PEERCRED` pid (`peercred.UnixCredentials.PID`,
`pkg/util/peercred/peercred.go:103`, read at `:188`) is the number the
connecting process had when it called `connect`, cached in the socket, while
`/proc/<pid>` describes whoever holds that number now. A client can connect,
pass the socket to another process and exit; once its number is reused by a
registered service, every check made through the number, its start time
included, describes that service, which never opened the connection. So the
peer is identified by a pidfd, which refers to one process for that process's
whole life and never to a later holder of its number.

- **Kernel.** `SO_PEERPIDFD` (Linux 6.5) returns a pidfd for the process that
  connected, taken at `connect`, and pidfs (Linux 6.9) gives every process
  one inode, which all pidfds for it share and no other process has during
  the boot on a 64-bit kernel, so `fstat(2)`'s `st_dev` and `st_ino` compare
  two pidfds by the process they name. The minimum is Linux 6.9. `kcmp(2)` is
  not used: `KCMP_FILE` compares open files, and two pidfds for one process
  are two files. On 6.5 to 6.8 every pidfd shares the one anonymous inode, so
  an inode comparison would match any peer to any service.
- **Older kernels fail closed.** A server refuses every connection when
  `SO_PEERPIDFD` fails or the pidfd is not on pidfs (`fstatfs(2)`
  `f_type` is not `PID_FS_MAGIC`), and the supervisor checks the same on its
  first launch and refuses to start the gateway services, so the failure is
  reported once at start and not as refused calls. A socket per service with
  a uid or group per socket is not the fallback: every kernel-class service
  is uid 0 ((b)), so a path's mode cannot tell one from another, which is the
  reason for registered identity in the first place.
- **Registration.** When it launches a service, the supervisor takes the
  child's pidfd from the fork itself (`clone3` with `CLONE_PIDFD`, which Go
  exposes as `syscall.SysProcAttr.PidFD`), so it names the child before the
  child runs and survives the child's `execve`. It keeps that pidfd until it
  reaps the child, and records the service name with the pidfd's pidfs inode.
  It pushes each server the registrations that server admits, by inode,
  through a new supervisor-only `ProcessControlService` method, `SetPeers`,
  before it waits for the server's readiness and again on every launch and
  reap: `rib` gets its producers, the process hosting `DatapathService` gets
  `management-vpn`.
- **Admission.** At accept, a server reads the peer's pidfd with
  `SO_PEERPIDFD`, binds the connection to the registered service whose inode
  matches that pidfd's, or to none, and only then checks the peer is alive:
  `poll(2)` on the pidfd with no timeout, which reports it readable once the
  process has exited. A process that has exited does not come back, so a peer
  alive after the match was alive throughout it, and a pidfd for an exited
  process never binds to a live service; the check needs no permission to
  signal the peer, as `pidfd_send_signal(2)` with signal 0 would. Each call is
  admitted by the per-method table against the bound service, failing closed
  on an unnamed method as today (`methodAdmissions`, `policy.go:69`, refused
  at `policy.go:105-107`). The server keeps the pidfd with the connection, and
  when the registration is removed or replaced, or the pidfd becomes readable,
  it closes the connection.
- **The supervisor.** A child takes a pidfd for its parent before it drops
  anything (`getppid` then `pidfd_open(2)` in `harden`,
  `pkg/sdn/gateway/process/launcher.go:375`, and `getppid` again, so the
  pidfd is for the parent that launched it) and admits as the supervisor only
  a peer whose pidfd has that inode and is alive. The parent-death signal is
  `SIGKILL` (`launcher.go:196`), re-armed after the drop (`rearmParentDeath`,
  `launcher.go:396`), so no child outlives its supervisor. A child's pidfd is
  never its parent's, whatever its uid, and `SetPeers` is supervisor-only, so
  a child can neither claim the supervisor identity nor register itself as
  another service. platformd is the supervisor, so its
  `GatewayServicesService` calls are admitted as the supervisor.

The table then names identities, not uids:

| Methods | Admitted identity |
|---|---|
| `ProcessControlService` (`Status`, `Snapshot`, `SetPeers`), `DatapathService.ApplyDesired`, `GatewayServicesService` | the supervisor |
| `DatapathService.InstallVPNPeer`, `RemoveVPNPeer` | the supervisor, `management-vpn` |
| `RouteService` writes (`Register`, `SyncRoutes`, `AddRoutes`, `WithdrawRoutes`, `EndOfSync`) | `bgp`, `tunnels`, each for its own producer key only: `rib` takes the producer from the connection's registered service and never from the request |
| `RouteService.WatchInstalled` | `bgp`, `tunnels`, each for its own producer key only, on a connection whose `Register` `rib` accepted |
| `RouteService.Preserved` | `bgp` only, for its own producer key, on a connection whose `Register` `rib` accepted |
| `RouteService.ListRoutes` | the supervisor |

Sockets keep mode `0660` in the service group under the supervisor's setgid
runtime directory, which limits who can connect at all; the registration
decides what a connection may call.

## (g) The move plan

This is a move with history and tests, not a rewrite. Each step is its own PR;
code moves with `git mv` where a file moves, so `git log --follow` and blame
survive; the tests move with their code and keep their names.

1. **platformd hosts `process.Supervisor`.** gatewayd's OpenRC unit is
   replaced by platformd's supervision; the five existing processes keep their
   current grouping. Verified by `make integration-test-proxy`
   (`TestGatewaydSupervisorDeathLeavesTheDatapath`, now killing platformd's
   supervisor) and the gateway unit tests unchanged.
2. **sd_notify readiness, the extended report and registered identity.**
   Verified by unit tests on the notify parser (a datagram from another pid
   refused), a supervisor test that a missed watchdog restarts the child, and
   policy tests on registered identity: a uid 0 child calling a
   supervisor-only method (`Status`, `SetPeers`) is refused; a peer that is
   not the child's parent is never admitted as the supervisor; a peer whose
   pidfd is not on pidfs, or a socket without `SO_PEERPIDFD`, is refused. A
   netns test covers a queued connection that outlives its connector: a
   client connects to `rib`'s socket, passes the socket over `SCM_RIGHTS` to
   a second process and exits; the test drives pid allocation
   (`ns_last_pid`, in a pid namespace of its own) until the supervisor
   launches `tunnels` under the client's old pid, and the second process then
   calls `RouteService.Register`: the connection binds to no service and the
   call is refused, though its `SO_PEERCRED` pid is now `tunnels`'. A
   connection bound while its service lives is closed when that service
   exits.
3. **The `rib` process and `RouteService`.** `tunnels`' uplink routes and rules
   move to it first (they have netns integration tests,
   `test/integration/sdn/tunnel_netns_test.go`). Verified by that suite; a
   new one that kills `tunnels` and finds its routes still in the kernel, and
   that kills `tunnels`, then `rib` until its budget is exhausted, and finds
   the supervisor has deleted `tunnels`' routes and rules by the recovery
   deadline; and policy tests on `RouteService`: a registered uid 0 service
   other than `tunnels` (`hostfw`) is refused as the `tunnels` producer, and `bgp` cannot
   withdraw a route `tunnels` produced.
4. **`bgp` alone and a route producer.** `routing` becomes `bgp`; learned routes
   reach the kernel through `rib`. Verified by a two-speaker netns suite that
   kills the `bgp` process and asserts the kernel routes and the peer's
   session state per RFC 4724 §4.1 and §4.2. The same suite exhausts `rib`'s
   budget while `bgp` runs and asserts, at the netns peer, that the session
   ends with a Cease NOTIFICATION before `bgp`'s kernel routes go, that the
   peer then holds no route from this node (RFC 4724 §4, §5) and none
   stale, and that a packet the peer sends toward one of those prefixes no
   longer reaches this node; this case also establishes the GoBGP behaviour
   (d) marks unverified. `rib`'s two deadlines and its restart policy (d) have
   unit tests on a fake clock, one per outcome:
   - the producer reconnects before its restart time and sends `EndOfSync`
     after the restart time but before the convergence deadline: the stale
     routes stay installed until `EndOfSync`, and only the entries still
     stale are then removed;
   - the producer does not reconnect before its restart time: its stale
     routes are removed at the recovery deadline;
   - the producer reconnects but sends no `EndOfSync` before the convergence
     deadline: its stale routes are removed then;
   - a peer never sends End-of-RIB, so `bgp` selects only when its
     Selection_Deferral_Timer expires, and its `SyncRoutes` and `EndOfSync`
     arrive within the selection allowance: the stale routes stay installed
     until `EndOfSync`;
   - the same, but nothing arrives by the end of the selection allowance: the
     stale routes are removed then;
   - `bgp` is down, `rib` restarts within `bgp`'s recovery window, and `bgp`
     never returns: the adopted routes are removed at `bgp`'s original
     recovery deadline (its loss plus its restart time), not later;
   - `bgp` is down and `rib` crashes repeatedly within its restart budget:
     every successor is launched with the same absolute deadline, and the
     routes are removed at `bgp`'s loss plus one restart time, whatever the
     number of `rib` restarts;
   - `bgp` re-registers, then `rib` crashes before `EndOfSync`: the successor
     keeps the convergence deadline from the first re-registration, and `bgp`
     re-registering with it does not restart it;
   - `bgp` is down and `rib` exhausts its restart budget: the supervisor
     deletes `bgp`'s routes and rules at the recovery deadline set by `bgp`'s
     loss, and no route or rule with another protocol number;
   - `rib` exhausts its budget while `bgp` runs: the supervisor sends `bgp`
     `SIGTERM` one stop timeout before `rib`'s last exit plus one restart
     time, `bgp`'s routes are removed at that deadline and not before the
     stop began, and `bgp` is not relaunched while no `rib` runs;
   - the same, but `bgp` ignores `SIGTERM`: it is killed at the deadline,
     and its routes are removed after it exits;
   - a `rib` runs and `bgp` lives but misses its convergence deadline: the
     stop again begins one stop timeout before `rib` removes the stale
     routes;
   - `bgp` is down, `rib` restarts, and `bgp` then returns and syncs: the
     adopted routes stay installed throughout;
   - platformd restarts while `bgp` is down: the loss record read back from
     the runtime directory keeps the original deadline;
   - platformd is killed while every producer is healthy and in sync, and
     the successor starts: the record shows every entry lost at the
     successor's start before any child is launched, and a producer that
     never returns has its routes and rules removed at that start plus its
     restart time, by `rib` or, with `rib` down, by the supervisor;
   - platformd is killed while every producer is in sync, then its
     successors crash repeatedly after the start transition: every later
     successor reads the same `S` and deadline, and the routes are removed at
     the first successor's start plus one restart time, whatever the number
     of supervisor restarts.

   The Forwarding State bit (e) has its own cases, asserted on the
   Graceful Restart Capability in the OPEN `bgp` sends to the netns peer:
   - a quick reboot (empty runtime directory, empty kernel tables): `bgp`
     starts in restarting mode with R set, and the OPEN carries F clear for
     every family;
   - uninterrupted watch: `bgp` alone is killed while it is in sync and its
     routes are in the kernel, `rib` runs throughout and nothing changes in
     the kernel, and the supervisor relaunches `bgp`: `rib` reports preserved
     each family whose forwarding set matches its route record, and the OPEN
     carries F set for those families;
   - platformd is killed while `bgp` is in sync and its routes are in the
     kernel, and the successor relaunches `bgp`: the kernel matches the route
     record, but the parent-death `SIGKILL` killed `rib` with platformd, so
     the successor `rib`'s watch generation differs from the pairs' stamps,
     the record is unverifiable, and the OPEN carries F clear for every
     family;
   - remove and restore while `rib` is down: `bgp` is killed while in sync,
     then `rib` is killed and held in its restart backoff; while no `rib`
     runs, the test deletes a route recorded for IPv4 unicast from the netns
     and adds it back exactly as it was, and the successor `rib` then starts
     and `bgp` restarts. The kernel matches the frozen digest and no
     invalidation flag is set, but the pair's stamp is the dead `rib`'s
     generation, so the OPEN carries F clear for every family;
   - notification overrun: `bgp` is killed while in sync, then the test
     stops `rib` with `SIGSTOP`, floods route changes in a table outside
     `bgp`'s forwarding set until the route socket's receive queue
     overflows, and resumes `rib` with `SIGCONT`, so `rib` reads `ENOBUFS`;
     every recorded entry is left as it was. The successor `bgp`'s OPEN
     carries F clear for every family; after that `bgp`'s `EndOfSync`, a
     second kill of `bgp` with `rib` running throughout and nothing changed
     gets F set again, since that freeze is under an unbroken watch;
   - remove and restore while `rib` is paused: `bgp` is killed while in
     sync, then the test stops `rib` with `SIGSTOP`, deletes a route recorded
     for IPv4 unicast and adds it back exactly as it was, two notifications,
     so the route socket's queue does not overflow, and resumes `rib` with
     `SIGCONT`; `bgp` then restarts. `rib` read no `ENOBUFS` and its watch
     is unbroken, and the dump after the `RTM_DELROUTE` matches its cache,
     but the `RTM_DELROUTE` set the IPv4 unicast invalidation flag when
     `rib` read it, so the OPEN carries F clear for IPv4 unicast ((f),
     "Kernel changes");
   - in-place replacement: `bgp` is killed while in sync, and while it is
     down the test runs `ip route replace` on a route recorded for IPv4
     unicast, so the kernel sends one `RTM_NEWROUTE` with `NLM_F_REPLACE`
     and deletes nothing; the OPEN carries F clear for IPv4 unicast, and
     F clear also when the replacement is identical to the recorded entry;
   - a change outside every record: `bgp` is killed while in sync, and
     while it is down the test deletes, adds and replaces routes in a table
     and prefixes outside `bgp`'s route record and backing list, under
     another protocol; no flag is set, and the OPEN carries F set for every
     family it carried F set for before;
   - `bgp`'s recovery deadline expires, or the supervisor deletes `bgp`'s
     routes while no `rib` runs, before `bgp` restarts: the OPEN carries F
     clear for every family whose routes were removed;
   - `bgp` had routes in IPv4 unicast only: F is set for IPv4 unicast and
     clear for IPv6 unicast;
   - partial route loss: `bgp` has several routes in IPv4 unicast, some
     through a tunnel interface; `bgp` is killed, and while it is down the
     tunnel interface is removed, so the kernel deletes the routes through it
     and the rest stay installed under `bgp`'s protocol number. The successor
     `bgp`'s OPEN carries F clear for IPv4 unicast, and the netns peer, by
     §4.2, deletes the stale routes it held from this node for IPv4 unicast;
   - mixed-producer loss: `bgp` exports two IPv4 unicast prefixes, one backed
     by its own route and one by a static route `rib` prefers by
     administrative distance, so the route record covers both entries and the
     backing list names the second; `bgp` is killed, and while it is down the
     static route is withdrawn, while every route under `bgp`'s protocol
     number stays installed. The successor `bgp`'s OPEN carries F clear for
     IPv4 unicast; the same run with the static route kept carries F set;
   - mixed-prefix loss: `bgp` advertises learned IPv4 unicast prefixes and an
     IPv4 unicast Announce prefix backed by the connected route of an
     address on a dummy interface, so the route record covers the learned
     routes and the connected route, and the backing list names the Announce
     prefix as a local entry; `bgp` is killed, and while it is down the
     address is removed, so the kernel deletes the connected route, while
     every learned route stays installed unchanged. The successor `bgp`'s
     OPEN carries F clear for IPv4 unicast;
   - mixed-prefix preserved: the same run with the address kept, so the
     learned routes and the connected route both match the record: the
     successor `bgp`'s OPEN carries F set for IPv4 unicast;
   - frozen baseline: `bgp` exports two IPv4 unicast prefixes, each backed by
     another producer's static route; `bgp` is killed, and while it is down
     one static route is withdrawn. The record the supervisor holds is still
     the pair from before the kill, the IPv4 unicast invalidation flag is set
     in it, and the successor `bgp`'s OPEN carries F clear for IPv4 unicast;
   - restored entry: the same, but the static route is added back as it was
     before `bgp` restarts, so the kernel matches the frozen digest: the flag
     is still set and the OPEN still carries F clear;
   - the flag survives restarts: the flag is set while `bgp` is down, then
     platformd is killed and `rib` restarted before `bgp` returns: the
     successor reads the flag from the runtime directory and passes it to
     `rib` (asserted on `rib`'s launch arguments, since the restarts alone
     make the record unverifiable), and the OPEN carries F clear;
   - the flag clears on recovery: after the frozen-baseline case, `bgp` sends
     `EndOfSync`; it is then killed with nothing changed while it is down,
     and the next OPEN carries F set; a `bgp` killed again after its
     registration but before `EndOfSync` instead finds the flag still set and
     F clear;
   - no record for the family: the route record of a lost `bgp` entry has no
     pair for IPv6 unicast while routes under `bgp`'s protocol number, or
     another producer's entries behind prefixes it exported, are in the
     kernel for it (as a `rib` that crashed before its report leaves them):
     the OPEN carries F clear for IPv6 unicast, whatever the kernel holds;
   - `rib` refuses or fails the registration: `bgp` still opens its peer
     sessions, with F clear for every family, and the Restart Time and R
     unchanged;
   - delayed peer reconnection after a loss: `bgp` restarts with both
     families preserved and its first peer's OPEN carries F set for both;
     the tunnel interface behind the IPv4 unicast routes is then deleted,
     and only after the feed names them uninstalled does a second netns peer
     establish. Its OPEN carries F clear for IPv4 unicast and F set for IPv6
     unicast, and a third peer establishing after `rib` restores those
     routes still gets F clear for IPv4 unicast;
   - delayed peer reconnection with no loss: the same restart, nothing
     changes in the kernel, and the second peer's OPEN carries F set for
     both families;
   - `rib` unreachable at a later OPEN: after the first peer's OPEN with F
     set, `rib` is killed and a second peer establishes before a successor
     accepts `bgp`'s re-registration: its OPEN carries F clear for every
     family, and so does a third peer's after the successor accepts it.

   The export gate (e) has its own cases, asserted on the routes the netns
   peer receives:
   - no `rib` runs when `bgp` starts: the sessions establish, a second netns
     peer's routes reach `bgp`, and the first peer receives none of them;
   - `rib` then starts: `bgp` registers and syncs, and the first peer receives
     each route only after it is in the kernel;
   - `rib` names one route not installed (its next hop's interface removed):
     that route is not advertised and the others are;
   - per-peer allowlists hold: a third netns peer has an `export-allow` that
     excludes one prefix the second peer sends. Once `rib` has installed it,
     the first peer, whose allowlist includes it, receives it, and the third
     peer never does, while it receives the installed prefixes its allowlist
     includes; an accept-by-default peer receives installed prefixes only;
   - `rib` is killed while `bgp` runs: routes advertised before stay
     advertised, a route the second peer sends afterwards is not advertised,
     and a successor `rib` that accepts `bgp`'s re-registration before the
     deadline has it advertised once installed;
   - externally caused route loss: with no request from `bgp`, the entry
     behind an advertised prefix goes, once for each cause: another
     producer withdraws the static route that backed it while `bgp`'s own
     route for it cannot be installed (its next hop's interface down), the
     interface its next hop uses is deleted, and the route is removed with
     `ip route del` outside `rib`. Each time the feed names it uninstalled
     and the first peer receives a withdrawal for that prefix alone; this
     case also establishes the netlink behaviour (f) marks unverified;
   - feed reconnect: `rib` is killed while `bgp` runs, and before the
     successor's feed opens one advertised prefix's kernel entry is removed
     and a fourth netns peer establishes. That peer receives no learned
     route until the snapshot completes; at the snapshot the first peer
     receives a withdrawal for the removed prefix and keeps the others
     without a withdrawal, and the fourth receives the others.

   `rib`'s feed has unit tests: a snapshot then deltas with contiguous
   sequence numbers; a stream opened before `Register` is accepted is
   refused; a producer whose queue reaches the bound has its stream ended,
   and its reopened stream's snapshot matches what `rib` holds; and `bgp`
   given a sequence gap reopens the stream and adds nothing to
   `rib-installed` until the new snapshot's marker. `RouteService.Preserved`
   has its own: a family answers clear from the moment its loss event is
   queued, before `bgp` reads it, and never answers set again on that
   registration, and a call before `Register` is accepted is refused.
5. **`provisioning` splits** into `dhcp`, `pxe` and `edge`, each relaying as
   today. Verified by the provisioning unit tests per service.
6. **The kernel-class split**: `hostfw`, `nat64`, `tunnels`, then the OVS
   services as the owner rules (Owner questions). Verified by the existing
   netns suites and `TestClassTable_EveryGatewayServiceIsPlaced` over the
   per-service table.
7. **`dns`** last, if the owner places it here (Owner questions).

Each step updates [architecture.md](architecture.md) and
[engineering.md](engineering.md) in the same PR, and
`TestClassTable_EveryGatewayServiceIsPlaced` keeps every service placed at
every step.

## Owner questions

Item 4 does not decide these; the design above takes no position beyond what
it states as an option.

1. **The OVS services.** `firewall`, `nat`, `load-balancer`, `overlay` (and
   the `nat64` table-27 gate) all program one bridge whose base pipeline one
   runtime owns ([architecture.md](architecture.md) §"The base OpenFlow pipeline
   is the runtime's"). Is that one service (the datapath) with one process, or
   one process each with a pipeline owner they call?
2. **Which process is the zebra role.** A new `rib` process (this design), or
   the existing kernel-class `datapath` process taking the role?
3. **BGP routes into the kernel.** Today the speaker installs no learned
   route ([engineering.md](engineering.md) line 1332). Is installing learned
   routes through `rib` in scope of #1191, or does `rib` start with the
   uplink routes only and BGP stay announce-side?
4. **DNS.** Item 4 names `dns` among the network services. Today it is
   `pkg/dns` inside platformd on every node, and DNS64 is a plugin there. Does
   it move into the multi-call binary as a supervised child, and on which node
   roles?
5. **platformd's privilege.** To grant `CAP_NET_ADMIN` and create cgroup leaves,
   the supervisor must hold those capabilities and a delegated cgroup subtree.
   The release criteria say platformd has no in-process privilege drop and
   its unit's `User=` sets the runtime user (#349). The same `CAP_NET_ADMIN` is what it
   uses to delete producers' routes while no `rib` runs ((d)). Which
   capabilities and which cgroup delegation does platformd's unit carry on a
   gateway node?
6. **Supervisor isolation.** [architecture.md](architecture.md) §"Alternatives
   rejected" rejected running edge services inside platformd because a gateway
   compromise would become a control-plane compromise. Supervising them from
   platformd keeps them out of its process; is platformd on a gateway node
   the worker role only, with no Raft member and no composed API?
7. **gatewayd on a node without platformd.** Does `gatewayd serve` (all
   services in one process) remain a supported mode, or is it removed after the
   move?
8. **Restart semantics after the budget.** Is a budget-exhausted service left
   down until an operator acts (today), or retried on a long period?
