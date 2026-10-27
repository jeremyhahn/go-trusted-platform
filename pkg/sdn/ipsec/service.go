// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ipsec

import (
	"context"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec/config"
	"github.com/vishvananda/netns"
)

const (
	// CRLRefresh is how often a Service reads its crl-files again.
	CRLRefresh = time.Minute

	// charonUID is the uid charon listens on the VICI socket as: it creates
	// the socket before it drops root.
	charonUID = 0
)

// Service runs overlay IPsec on a node from its overlay.ipsec section: the
// fail-closed floor, the controller and the runner that keeps it attached
// to charon, the watch that keeps the XFRM forward block on the fabric
// interface, and the CRLs read from crl-files.
//
// Install puts the floor in; the caller does so before anything sends on
// the fabric, and does not start without it. Run drives the rest until its
// context ends. The floor is never taken out: it stays after Run returns
// and after Close, so a node whose platformd stops keeps the fabric dark.
//
// A service from NewService has no EVPN route source, so no VTEP is
// admitted from a route (ErrNoVTEPAdmission): the peers are the static
// peers. One from NewEVPNService also follows the Type-3 routes handed to
// HandleEVPNRoute, holding an SA to every remote VTEP its admitter admits.
type Service struct {
	filter   *Filter
	block    *BlockPolicy
	identity closingIdentity
	ctl      *Controller
	runner   *Runner
	crlFiles []string
	logger   *slog.Logger
	after    func(time.Duration) <-chan time.Time
}

// closingIdentity is an IdentityProvider holding a secret it releases on
// Close.
type closingIdentity interface {
	IdentityProvider
	Close()
}

// staticPeersOnly is the Admitter of a node with no EVPN route source: it
// admits no VTEP a route names.
type staticPeersOnly struct{}

// AdmitVTEP implements Admitter.
func (staticPeersOnly) AdmitVTEP(context.Context, uint32, netip.Addr) error {
	return ErrNoVTEPAdmission
}

// NewService builds the service for an enabled section that names a
// certificate-file and crl-files. It opens netlink connections to
// nf_tables and XFRM in the current network namespace; installing the
// floor needs CAP_NET_ADMIN. The tunnel identity is refused unless its
// chain ends in a certificate of anchor, the platform anchor; a nil anchor
// is ErrMissingDependency. A nil logger discards.
func NewService(cfg *config.Config, anchor AnchorSource, logger *slog.Logger) (*Service, error) {
	return NewEVPNService(cfg, staticPeersOnly{}, anchor, logger)
}

// NewEVPNService is NewService for a node whose overlay runs EVPN: the
// controller asks admitter before it brings an SA up to a VTEP a route
// names. A nil admitter is ErrMissingDependency.
func NewEVPNService(cfg *config.Config, admitter Admitter, anchor AnchorSource, logger *slog.Logger) (*Service, error) {
	if admitter == nil || anchor == nil {
		return nil, ErrMissingDependency
	}
	if _, err := config.EnabledLocal(cfg); err != nil {
		return nil, err
	}
	if len(cfg.CRLFiles) == 0 {
		return nil, &config.ConfigError{Field: "crl-files", Err: config.ErrRequired}
	}
	file, err := NewFileIdentity(cfg)
	if err != nil {
		return nil, err
	}
	identity, err := NewAnchoredIdentity(file, anchor)
	if err != nil {
		file.Close()
		return nil, err
	}
	filter, err := NewFilter(cfg)
	if err != nil {
		identity.Close()
		return nil, err
	}
	block, err := NewBlockPolicy(cfg, netns.None())
	if err != nil {
		identity.Close()
		return nil, err
	}
	s, err := newService(cfg, admitter, filter, block, identity, NewVICIDialer(cfg.EffectiveVICISocket(), charonUID), logger)
	if err != nil {
		block.Close()
		identity.Close()
		return nil, err
	}
	return s, nil
}

func newService(cfg *config.Config, admitter Admitter, filter *Filter, block *BlockPolicy, identity closingIdentity, dialer Dialer, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	ctl, err := NewController(cfg, admitter, filter, identity)
	if err != nil {
		return nil, err
	}
	runner, err := NewRunner(ctl, dialer, logger)
	if err != nil {
		return nil, err
	}
	return &Service{
		filter:   filter,
		block:    block,
		identity: identity,
		ctl:      ctl,
		runner:   runner,
		crlFiles: slices.Clone(cfg.CRLFiles),
		logger:   logger,
		after:    time.After,
	}, nil
}

// Install puts the fail-closed floor in: the nftables table, then the XFRM
// block policies. A failure is a *FloorError, and what went in stays.
func (s *Service) Install(ctx context.Context) error {
	if err := s.filter.Apply(ctx); err != nil {
		return &FloorError{Err: err}
	}
	if err := s.block.Install(ctx); err != nil {
		return &FloorError{Err: err}
	}
	return nil
}

// Run keeps charon attached, the forward block on the fabric interface and
// the CRLs pushed until ctx ends, and returns once all three have stopped.
func (s *Service) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Go(func() { s.runner.Run(ctx) })
	wg.Go(func() { s.watch(ctx) })
	wg.Go(func() { s.feedCRLs(ctx) })
	wg.Wait()
}

// Close releases the netlink connection and the token PIN. The floor
// stays installed.
func (s *Service) Close() {
	s.block.Close()
	s.identity.Close()
}

// HandleEVPNRoute hands a Type-3 route to the controller: the SA to its
// VTEP is brought up while a route places the VTEP on a VNI, and taken
// down when the last such route is withdrawn.
func (s *Service) HandleEVPNRoute(ctx context.Context, route *bgp.EVPNRouteData) error {
	return s.ctl.HandleEVPNRoute(ctx, route)
}

// Evict cuts a peer off until Readmit: its traffic is dropped in the
// kernel and its SAs are torn down, whatever its routes say.
func (s *Service) Evict(ctx context.Context, peer netip.Addr) error {
	return s.ctl.Evict(ctx, peer)
}

// Readmit lifts an eviction, so the peer's routes bring its SA back. A
// peer that was never evicted is left as it is.
func (s *Service) Readmit(ctx context.Context, peer netip.Addr) error {
	err := s.ctl.Readmit(ctx, peer)
	if errors.Is(err, ErrNotEvicted) {
		return nil
	}
	return err
}

// watch runs BlockPolicy.Watch until ctx ends, and again after each
// failure, waiting from MinBackoff and doubling to MaxBackoff.
func (s *Service) watch(ctx context.Context) {
	backoff := MinBackoff
	for {
		err := s.block.Watch(ctx)
		if ctx.Err() != nil {
			return
		}
		s.logger.Warn("ipsec: fabric interface watch ended", "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-s.after(backoff):
		}
		backoff = min(2*backoff, MaxBackoff)
	}
}

// feedCRLs pushes the CRLs of every file now and every CRLRefresh until ctx
// ends. The controller ignores a CRL no newer than the one it holds, so a
// file only makes a change once it is replaced.
func (s *Service) feedCRLs(ctx context.Context) {
	for {
		if err := s.pushCRLs(ctx); err != nil {
			s.logger.Warn("ipsec: CRL feed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-s.after(CRLRefresh):
		}
	}
}

// pushCRLs pushes the CRLs of every file. A file that cannot be read, or a
// CRL the controller refuses, does not stop the rest; the failures are
// returned joined.
func (s *Service) pushCRLs(ctx context.Context) error {
	var errs []error
	for i, path := range s.crlFiles {
		ders, err := readCRLs(path)
		if err != nil {
			errs = append(errs, &config.ConfigError{Field: config.CRLFileField(i), Err: err})
			continue
		}
		for _, der := range ders {
			errs = append(errs, s.ctl.PushCRL(ctx, der))
		}
	}
	return errors.Join(errs...)
}

// readCRLs returns the PEM "X509 CRL" blocks in path, or, when it holds
// none, the whole file as one DER CRL.
func readCRLs(path string) ([][]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ders [][]byte
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "X509 CRL" {
			ders = append(ders, block.Bytes)
		}
	}
	if len(ders) == 0 {
		return [][]byte{data}, nil
	}
	return ders, nil
}
