// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package nat64

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
)

// CookieNAT64 tags every flow this service installs; CookieMask selects the
// owner prefix for bulk deletion, exactly as the firewall and NAT services
// scope theirs.
//
// The owner id must be unique across the gateway's services: every service
// tears down with DeleteFlowsByCookie under the same CookieMask, so two
// services sharing an owner id delete each other's flows. NAT64 is the
// fourth datapath service and takes …0004 — the firewall holds …0001, NAT
// …0002, the load balancer …0003 and perf …00FF.
//
// The low 32 bits carry a flow generation: each Start stamps its flows
// with a fresh one, so the flows a previous process left behind are told
// apart by cookie alone and swept only after the new set is in place.
const (
	CookieNAT64 uint64 = 0xF1BE000400000000
	CookieMask         = ovs.OwnerCookieMask
)

// Pipeline priorities.
//
// The keystone this service exists to avoid: a `goto_table:27` with nothing
// routing into 27 programs nothing at all while reporting success (#567).
// Three flows are therefore installed as one unit and only as one unit —
// the table-10 gate that admits traffic to the conntrack pipeline, the
// table-20 divert that sends prefix-addressed frames to table 27, and the
// table-27 hand-off that outputs them to the translator.
const (
	// gateTable is the base pipeline's table 10, where every datapath
	// service installs its own distinctly-prioritised gate. Identical
	// match and priority would make one service's OFPFC_ADD replace
	// another's, breaking per-service teardown, so the priority is ours
	// alone even though the action matches the firewall's and NAT's.
	gateTable = int(modes.TableVXLANDecap)

	// nat64GatePriority is the table 10 priority of the NAT64 gate.
	//
	// A table-10 gate is an EMPTY-MATCH catch-all, and OpenFlow identifies a
	// flow on OFPFC_ADD by (table, priority, match) -- the cookie is
	// deletion-scoping metadata and does not distinguish flows on install.
	// So two services sharing this priority do not get two gates: the second
	// ADD REPLACES the first, leaving one resident flow carrying one
	// service's cookie. The service that owns it then deletes the only gate
	// on Stop, taking the other still-running service's traffic off table 20
	// while it reports healthy.
	//
	// The allocation is therefore one priority per service and must stay
	// distinct: NAT 1, firewall 2, load balancer 3, NAT64 4. NAT64 shipped
	// on 3 -- the load balancer's -- and TestGatewayGates_Table10PriorityIsUnique
	// is what catches the next one.
	nat64GatePriority = 4

	// prioNAT64Divert diverts IPv6 addressed to the translation prefix out
	// of the conntrack gate and into table 27.
	//
	// It outranks the firewall's per-zone gate (100) and NAT's IPv6 pass
	// (80) deliberately, on the DNAT precedent: a frame addressed to the
	// translation prefix has no other disposition. Nothing routes
	// 64:ff9b::/96, so the alternative to translating it is dropping it for
	// want of a route, not applying zone policy to it. Zone policy is
	// instead expressed at this gate: client-zones names the zones whose
	// frames are diverted, and a zone that is not named gets no
	// translation.
	prioNAT64Divert = 210

	// prioNAT64HandoffTagged hands a VLAN-tagged diverted frame to the
	// translator port with its tag stripped: the port is a host interface,
	// and a tagged frame on it is not an IPv6 packet to the kernel.
	prioNAT64HandoffTagged = 110

	// prioNAT64Handoff hands an untagged diverted frame to the translator
	// port.
	prioNAT64Handoff = 100

	// prioNAT64Miss continues the pipeline for anything else that reaches
	// table 27, so the table is never a black hole.
	prioNAT64Miss = 0
)

// Deps carries the service's collaborators.
type Deps struct {
	// Driver programs the kernel translator.
	Driver Driver

	// Controller installs flows (the shared policy flow path).
	Controller policy.FlowController

	// OVS resolves the translator's OpenFlow port and deletes flows by
	// cookie.
	OVS ovs.ClientInterface

	// Config is the service configuration.
	Config Config

	// Logger receives lifecycle logs. Defaults to slog.Default.
	Logger *slog.Logger

	// Now is the clock; defaults to time.Now.
	Now func() time.Time

	// ReconcileInterval is how often a started service converges the
	// translator and its flows and re-reads the kernel's health. Zero
	// takes DefaultReconcileInterval.
	ReconcileInterval time.Duration
}

// DefaultReconcileInterval is the period of the service's own convergence
// loop: long enough that the jool reads it costs are noise, short enough
// that a vanished instance or a flushed flow table is reported, and
// repaired, within one telemetry window.
const DefaultReconcileInterval = 30 * time.Second

// TranslatorPort is what the hand-off needs to know about the translator's
// OVS port: where to output, and the MAC each frame must carry for the
// host stack to accept it. A frame still addressed to the zone's router MAC
// is PACKET_OTHERHOST on the translator interface, and the kernel drops it
// before netfilter, where Jool would have translated it.
type TranslatorPort struct {
	OFPort int32
	MAC    string
}

// validate checks that every required dependency is present.
func (d *Deps) validate() error {
	if d.Driver == nil {
		return ErrNilDriver
	}
	if d.Controller == nil {
		return ErrNilController
	}
	if d.OVS == nil {
		return ErrNilOVSClient
	}
	return d.Config.Validate()
}

// Health is a point-in-time snapshot of the service state. Every field is
// something the kernel or the datapath reported; none is a configuration
// value echoed back.
type Health struct {
	// Active reports whether the service is started.
	Active bool

	// InstancePresent reports whether the kernel instance existed at the
	// last check. A started service whose instance has gone is unhealthy.
	InstancePresent bool

	// Prefix is the translation prefix in use.
	Prefix string

	// Instance is the kernel instance name.
	Instance string

	// Sessions is the live translation session count.
	Sessions uint64

	// Pool4Used is the number of allocated address:port pairs.
	Pool4Used uint64

	// ModuleVersion is the translator's reported version.
	ModuleVersion string

	// FlowCount is the number of pipeline flows the service holds.
	FlowCount int

	// LastReconcile is when the translator and the flows were last
	// converged.
	LastReconcile time.Time

	// LastError is the last reconcile failure, nil when the last succeeded.
	LastError error
}

// Service owns one NAT64 translator instance and the pipeline flows that
// reach it.
type Service struct {
	deps   Deps
	logger *slog.Logger
	now    func() time.Time
	res    *resolved

	// flowCookie is the cookie this start stamped on its flows: the NAT64
	// owner and a fresh generation. Flows under the owner with any other
	// generation are stale.
	flowCookie uint64

	mu        sync.Mutex
	active    bool
	installed []zoneflows.FlowRule
	port      TranslatorPort
	stats     Stats
	lastRun   time.Time
	lastErr   error

	// loopCancel and loopDone own the reconcile goroutine; both are nil
	// while it is not running.
	loopCancel context.CancelFunc
	loopDone   chan struct{}
}

// New validates every dependency and returns an inactive service.
func New(deps Deps) (*Service, error) {
	if err := deps.validate(); err != nil {
		return nil, err
	}
	res, err := deps.Config.resolve()
	if err != nil {
		return nil, err
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.ReconcileInterval <= 0 {
		deps.ReconcileInterval = DefaultReconcileInterval
	}
	return &Service{
		deps:       deps,
		logger:     deps.Logger,
		now:        deps.Now,
		res:        res,
		flowCookie: CookieNAT64,
	}, nil
}

// instance renders the translator configuration from the resolved config.
func (s *Service) instance() Instance {
	return Instance{
		Name:     s.res.instance,
		Pool6:    s.res.prefix.String(),
		Pool4:    s.deps.Config.Pool4,
		Timeouts: s.res.timeouts,
	}
}

// FlowRules renders the whole flow set for a resolved translator port. It
// is exported so the pipeline invariant test can assert, without a running
// service, that every goto_table target this service emits is a table it
// also routes traffic into.
//
// Table 20's miss is the pipeline's, not this service's: frames the divert
// does not claim continue to table 30 through the flow every service that
// gates into table 20 shares (#614).
func (s *Service) FlowRules(port TranslatorPort) []zoneflows.FlowRule {
	prefix := s.res.prefix.String()
	rules := []zoneflows.FlowRule{
		// Table 10: admit traffic to the conntrack gate. Without this the
		// divert below is unreachable on a gateway running neither the
		// firewall nor NAT, and table 27 would be programmed but dead.
		{
			Table:    gateTable,
			Priority: nat64GatePriority,
			Actions:  fmt.Sprintf("goto_table:%d", modes.TableCTGate),
		},
	}

	// Table 20: divert frames addressed to the translation prefix.
	divert := fmt.Sprintf("goto_table:%d", modes.TableNAT64)
	if len(s.res.zones) == 0 {
		rules = append(rules, zoneflows.FlowRule{
			Table:    int(modes.TableCTGate),
			Priority: prioNAT64Divert,
			Match:    fmt.Sprintf("dl_type=0x86dd,ipv6_dst=%s", prefix),
			Actions:  divert,
		})
	} else {
		for _, z := range s.res.zones {
			rules = append(rules, zoneflows.FlowRule{
				Table:    int(modes.TableCTGate),
				Priority: prioNAT64Divert,
				Match:    fmt.Sprintf("dl_type=0x86dd,dl_vlan=%d,ipv6_dst=%s", z.VLAN, prefix),
				Actions:  divert,
			})
		}
	}

	// Table 27: hand the frame to the translator, re-addressed to the
	// translator interface and untagged, and keep the table from being a
	// black hole for anything else that lands in it.
	handoff := fmt.Sprintf("mod_dl_dst:%s,output:%d", port.MAC, port.OFPort)
	rules = append(rules,
		zoneflows.FlowRule{
			Table:    int(modes.TableNAT64),
			Priority: prioNAT64HandoffTagged,
			Match:    fmt.Sprintf("dl_type=0x86dd,vlan_vid=0x1000/0x1000,ipv6_dst=%s", prefix),
			Actions:  "strip_vlan," + handoff,
		},
		zoneflows.FlowRule{
			Table:    int(modes.TableNAT64),
			Priority: prioNAT64Handoff,
			Match:    fmt.Sprintf("dl_type=0x86dd,ipv6_dst=%s", prefix),
			Actions:  handoff,
		},
		zoneflows.FlowRule{
			Table:    int(modes.TableNAT64),
			Priority: prioNAT64Miss,
			Actions:  fmt.Sprintf("goto_table:%d", modes.TableMACLearning),
		},
	)

	cookie := fmt.Sprintf("0x%x", s.cookie())
	for i := range rules {
		rules[i].Cookie = cookie
	}
	return rules
}

// cookie is the full cookie of this start's flows: the NAT64 owner and
// the flow generation.
func (s *Service) cookie() uint64 {
	return s.flowCookie
}

// sweepStale deletes every flow under the NAT64 owner whose generation is
// not this start's: the flows a previous process installed for a
// configuration that has since changed (another prefix, a zone no longer
// listed). It runs only after the current set is installed, so frames the
// current configuration diverts are never left without a hand-off. The
// current set replaced any flow of identical (table, priority, match), so
// what is left under an older generation is exactly what no longer
// belongs.
func (s *Service) sweepStale(ctx context.Context) error {
	if err := ovs.SweepStaleGenerations(ctx, s.deps.OVS, s.res.bridge, s.cookie()); err != nil {
		return &OpError{Op: "sweep", Err: err}
	}
	return nil
}

// resolvePort reads the translator port's OpenFlow number and MAC.
func (s *Service) resolvePort(ctx context.Context) (TranslatorPort, error) {
	iface, err := s.deps.OVS.GetInterface(ctx, s.res.port)
	if err != nil {
		return TranslatorPort{}, &OpError{Op: "resolve-port", Err: err}
	}
	if iface.OFPort <= 0 {
		return TranslatorPort{}, ErrNoTranslatorOFPort
	}
	if _, err := net.ParseMAC(iface.MAC); err != nil {
		return TranslatorPort{}, &ErrTranslatorPortMAC{Port: s.res.port, MAC: iface.MAC}
	}
	return TranslatorPort{OFPort: iface.OFPort, MAC: iface.MAC}, nil
}

// Start programs the translator, then the pipeline, then starts the
// reconcile loop. The order is what makes a failed start safe: no frame is
// ever diverted to a translator that does not exist, and a translator that
// comes up without its flows translates nothing rather than blackholing
// traffic.
//
// Start also adopts what a control process that exited without stopping
// left behind. The translator instance is converged in place, keeping its
// sessions, and the flows that reach it are left alone until the current
// set is installed: the new set carries a fresh generation in its cookie,
// replaces every flow of the same identity, and only then are the flows
// still carrying an older generation swept. An adopted translator's
// sessions therefore stay reachable through every failure before that
// point (#614 review).
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.active {
		return ErrAlreadyStarted
	}

	port, err := s.resolvePort(ctx)
	if err != nil {
		return err
	}

	cookie, err := ovs.NewGenerationCookie(CookieNAT64)
	if err != nil {
		return &OpError{Op: "generation", Err: err}
	}

	created, err := s.deps.Driver.Apply(ctx, s.instance())
	if err != nil {
		return err
	}

	// Health starts from the kernel's answer, not from an assumption that
	// Apply's success means the instance is there.
	stats, err := s.deps.Driver.Stats(ctx, s.res.instance)
	if err != nil {
		return s.rollback(ctx, created, err)
	}
	if !stats.Present {
		return s.rollback(ctx, created, ErrInstanceVanished)
	}

	s.flowCookie = cookie
	rules := s.FlowRules(port)
	if err := s.deps.Controller.InstallFlows(s.res.bridge, rules); err != nil {
		return s.rollback(ctx, created, &OpError{Op: "install", Err: err})
	}

	s.port = port
	s.installed = rules
	s.active = true
	s.lastRun = s.now()
	s.lastErr = nil
	s.stats = stats
	// A sweep that fails leaves stale flows beside a working set; the
	// service is up, says so in health, and the reconcile loop retries.
	if err := s.sweepStale(ctx); err != nil {
		s.lastErr = err
		s.logger.Warn("nat64: sweeping a previous process's flows failed",
			slog.String("bridge", s.res.bridge), slog.Any("error", err))
	}
	s.startLoop()

	s.logger.Info("nat64 service started",
		slog.String("bridge", s.res.bridge),
		slog.String("instance", s.res.instance),
		slog.Bool("adopted", !created),
		slog.String("prefix", s.res.prefix.String()),
		slog.String("translator_port", s.res.port),
		slog.Int("flows", len(rules)),
	)
	return nil
}

// rollback undoes a failed start. A translator this start created is
// removed, with every flow under the NAT64 owner: nothing it could reach
// existed before. An adopted translator carries the sessions of the
// process before this one, and so do the flows that reach it, so a failed
// start leaves both exactly as found; any flow the failed batch did
// install replaced one of the same identity with the same hand-off. A
// rollback that cannot finish is reported beside the cause, never instead
// of it.
func (s *Service) rollback(ctx context.Context, created bool, cause error) error {
	if !created {
		return cause
	}
	var errs []error
	if err := s.deps.OVS.DeleteFlowsByCookie(ctx, s.res.bridge, CookieNAT64, CookieMask); err != nil {
		errs = append(errs, &OpError{Op: "rollback", Err: err})
	}
	if err := s.deps.Driver.Remove(ctx, s.res.instance); err != nil {
		errs = append(errs, &OpError{Op: "rollback", Err: err})
	}
	if len(errs) == 0 {
		return cause
	}
	return &ErrRollbackIncomplete{Cause: cause, Rollback: errors.Join(errs...)}
}

// startLoop runs the reconcile pass every ReconcileInterval until Stop. The
// caller holds s.mu.
func (s *Service) startLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.loopCancel = cancel
	s.loopDone = done

	go func() {
		defer close(done)
		ticker := time.NewTicker(s.deps.ReconcileInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.Reconcile(ctx); err != nil && ctx.Err() == nil {
					s.logger.Warn("nat64: reconcile failed",
						slog.String("instance", s.res.instance), slog.Any("error", err))
				}
			}
		}
	}()
}

// stopLoop stops the reconcile goroutine and waits for it to return. It is
// called without s.mu held, because the goroutine takes it to reconcile.
func (s *Service) stopLoop() {
	s.mu.Lock()
	cancel, done := s.loopCancel, s.loopDone
	s.loopCancel, s.loopDone = nil, nil
	s.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

// Stop removes the pipeline first, so no frame is diverted to a translator
// that is going away, then deletes the instance. It is the same clean
// shutdown every gateway datapath service performs on a gateway Stop (the
// firewall and NAT delete their flows, the runtime its pipeline). What a
// control process hands to its successor is what it leaves by exiting
// WITHOUT Stop, which Start adopts.
func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	active := s.active
	s.mu.Unlock()
	if !active {
		return ErrNotStarted
	}

	// The loop goes first: a reconcile pass that ran after the flows were
	// deleted would put them back.
	s.stopLoop()

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.deps.OVS.DeleteFlowsByCookie(ctx, s.res.bridge, CookieNAT64, CookieMask); err != nil {
		s.lastErr = &OpError{Op: "delete", Err: err}
		return s.lastErr
	}
	s.installed = nil
	// The flows are gone, so nothing reaches the translator any more and
	// no traffic is harmed. The instance is still in the kernel though, so
	// the service stays active rather than reporting a clean stop that
	// would leak it silently; the caller retries.
	if err := s.deps.Driver.Remove(ctx, s.res.instance); err != nil {
		s.lastErr = err
		return err
	}

	s.active = false
	s.stats = Stats{}

	s.logger.Info("nat64 service stopped",
		slog.String("bridge", s.res.bridge), slog.String("instance", s.res.instance))
	return nil
}

// Reconcile converges both halves: the translator instance (idempotently,
// keeping live sessions) and the pipeline flows, which are re-installed in
// place when the translator port has moved or a flow has gone missing
// underneath the service; then it re-reads the kernel's health. The
// service's own loop runs it every ReconcileInterval.
func (s *Service) Reconcile(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// A Stop that removed the flows but not the instance leaves the
	// service active with nothing installed; reconciling would re-divert
	// traffic to a translator the caller is tearing down.
	if !s.active || s.installed == nil {
		return ErrNotStarted
	}
	s.lastRun = s.now()

	port, err := s.resolvePort(ctx)
	if err != nil {
		s.lastErr = err
		return err
	}

	if _, err := s.deps.Driver.Apply(ctx, s.instance()); err != nil {
		s.lastErr = err
		return err
	}

	// The rendered (table, priority, match) set does not depend on the
	// port, so OFPFC_ADD replaces a moved port's hand-offs in place and
	// nothing stale is left behind.
	rules := s.FlowRules(port)
	if err := s.deps.Controller.InstallFlows(s.res.bridge, rules); err != nil {
		s.lastErr = &OpError{Op: "reconcile", Err: err}
		return s.lastErr
	}

	// Retry a sweep an earlier pass could not finish.
	if err := s.sweepStale(ctx); err != nil {
		s.lastErr = err
		return err
	}

	stats, err := s.deps.Driver.Stats(ctx, s.res.instance)
	if err != nil {
		s.lastErr = err
		return err
	}

	s.port = port
	s.installed = rules
	s.stats = stats
	if !stats.Present {
		s.lastErr = ErrInstanceVanished
		return s.lastErr
	}
	s.lastErr = nil

	s.logger.Debug("nat64 service reconciled",
		slog.String("instance", s.res.instance),
		slog.Int("flows", len(rules)),
		slog.Uint64("sessions", stats.Sessions),
	)
	return nil
}

// Active reports whether the service is started.
func (s *Service) Active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// Health reports the service state. It is derived from what the driver and
// the datapath last reported, never from the configuration: a started
// service whose kernel instance has disappeared reports unhealthy.
func (s *Service) Health() Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Health{
		Active:          s.active,
		InstancePresent: s.stats.Present,
		Prefix:          s.res.prefix.String(),
		Instance:        s.res.instance,
		Sessions:        s.stats.Sessions,
		Pool4Used:       s.stats.Pool4Used,
		ModuleVersion:   s.stats.ModuleVersion,
		FlowCount:       len(s.installed),
		LastReconcile:   s.lastRun,
		LastError:       s.lastErr,
	}
}
