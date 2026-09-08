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

package hostfw

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Deps are the service's collaborators.
type Deps struct {
	// Applier programs the kernel table.
	Applier Applier
	// Inventory reports the daemon's own listeners; merged with Config.Extra.
	Inventory ListenerInventory
	// Config is the operator-declared part of the ruleset.
	Config Config
	// Logger receives lifecycle logs. Defaults to slog.Default.
	Logger *slog.Logger
	// Now is the clock; defaults to time.Now. Tests substitute it.
	Now func() time.Time
}

func (d *Deps) validate() error {
	if d.Applier == nil {
		return ErrNilApplier
	}
	if d.Inventory == nil {
		return ErrNilInventory
	}
	return d.Config.Validate()
}

// Health is the service's reported state.
type Health struct {
	// Active reports whether the service is started.
	Active bool
	// Installed reports whether the table was present at the last check.
	Installed bool
	// Fingerprint identifies the ruleset last applied successfully.
	Fingerprint string
	// RuleCount is the number of input rules in that ruleset.
	RuleCount int
	// LastReconcile is when the ruleset was last rendered and compared.
	LastReconcile time.Time
	// LastError is the last reconcile failure, nil when the last succeeded.
	LastError error
}

// Service renders and reconciles the host filter.
type Service struct {
	deps   Deps
	logger *slog.Logger
	now    func() time.Time

	mu        sync.Mutex
	active    bool
	applied   *Rendered
	lastRun   time.Time
	lastErr   error
	installed bool
}

// New validates deps and returns an inactive service.
func New(deps Deps) (*Service, error) {
	if err := deps.validate(); err != nil {
		return nil, err
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	return &Service{deps: deps, logger: deps.Logger, now: deps.Now}, nil
}

// ruleset merges the operator's declarations with the daemon's inventory.
func (s *Service) ruleset() Ruleset {
	cfg := s.deps.Config
	listeners := append([]Listener(nil), s.deps.Inventory.Listeners()...)
	listeners = append(listeners, cfg.Extra...)
	return Ruleset{
		Listeners:  listeners,
		Peers:      cfg.Peers,
		Tunnels:    cfg.Tunnels,
		Unfiltered: cfg.Unfiltered,
		ICMP:       cfg.ICMP,
	}
}

// Start renders the ruleset, writes the install-time file when one is
// configured, and applies the table. It fails closed: a ruleset that does
// not render or apply leaves the service inactive and returns the error.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return ErrAlreadyStarted
	}
	rendered, err := Render(s.ruleset())
	if err != nil {
		return err
	}
	if err := s.writeBase(rendered); err != nil {
		return err
	}
	if err := s.deps.Applier.Apply(ctx, rendered); err != nil {
		s.lastErr = err
		return err
	}
	s.applied = rendered
	s.installed = true
	s.lastRun = s.now()
	s.lastErr = nil
	s.active = true
	s.logger.Info("hostfw: table applied", slog.String("table", TableName),
		slog.String("fingerprint", rendered.Fingerprint), slog.Int("rules", len(rendered.Rules)))
	return nil
}

// Stop removes the table. The install-time file is left in place: the boot
// window is the next boot's problem, and the file reflects the last known
// good ruleset.
func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		return ErrNotStarted
	}
	if err := s.deps.Applier.Remove(ctx); err != nil {
		s.lastErr = err
		return err
	}
	s.active = false
	s.applied = nil
	s.installed = false
	s.logger.Info("hostfw: table removed", slog.String("table", TableName))
	return nil
}

// Reconcile re-renders the ruleset from the current inventory and applies
// it when it differs from what was last applied, or when the table has gone
// missing underneath the service. An apply that fails is rolled back to
// the previous ruleset; if the rollback fails too the error names both and
// Health reports it until a later reconcile succeeds.
func (s *Service) Reconcile(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		return ErrNotStarted
	}
	s.lastRun = s.now()
	rendered, err := Render(s.ruleset())
	if err != nil {
		s.lastErr = err
		return err
	}
	present, err := s.deps.Applier.Installed(ctx)
	if err != nil {
		s.lastErr = err
		return err
	}
	s.installed = present
	if present && s.applied != nil && s.applied.Fingerprint == rendered.Fingerprint {
		s.lastErr = nil
		return nil
	}
	if !present {
		s.logger.Warn("hostfw: table missing, reinstalling", slog.String("table", TableName))
	}
	if err := s.deps.Applier.Apply(ctx, rendered); err != nil {
		if s.applied == nil {
			s.lastErr = err
			return err
		}
		if rbErr := s.deps.Applier.Apply(ctx, s.applied); rbErr != nil {
			s.lastErr = &RollbackError{Apply: err, Rollback: rbErr}
			s.installed = false
			return s.lastErr
		}
		s.lastErr = &OpError{Op: "rollback", Err: err}
		return s.lastErr
	}
	if err := s.writeBase(rendered); err != nil {
		// The live table is correct; only the boot file is stale. Report it,
		// keep the new ruleset as applied.
		s.applied = rendered
		s.installed = true
		s.lastErr = err
		return err
	}
	s.applied = rendered
	s.installed = true
	s.lastErr = nil
	s.logger.Info("hostfw: table reconciled", slog.String("fingerprint", rendered.Fingerprint), slog.Int("rules", len(rendered.Rules)))
	return nil
}

// writeBase writes the install-time file atomically (temp + rename) when a
// path is configured.
func (s *Service) writeBase(r *Rendered) error {
	path := s.deps.Config.BaseRulesetPath
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return &OpError{Op: "write-base", Err: err}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tp-host-*.nft")
	if err != nil {
		return &OpError{Op: "write-base", Err: err}
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(r.Text); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return &OpError{Op: "write-base", Err: err}
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return &OpError{Op: "write-base", Err: err}
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return &OpError{Op: "write-base", Err: err}
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return &OpError{Op: "write-base", Err: err}
	}
	return nil
}

// Active reports whether the service is started.
func (s *Service) Active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// Health reports the service state.
func (s *Service) Health() Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := Health{Active: s.active, Installed: s.installed, LastReconcile: s.lastRun, LastError: s.lastErr}
	if s.applied != nil {
		h.Fingerprint = s.applied.Fingerprint
		h.RuleCount = len(s.applied.Rules)
	}
	return h
}

// Rendered returns the ruleset last applied, or nil.
func (s *Service) Rendered() *Rendered {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applied
}
