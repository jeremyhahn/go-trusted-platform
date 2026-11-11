package trust

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"sync"
	"testing"
)

// memTOFUPinStore is an in-memory TOFUPinStore keyed by host and port.
type memTOFUPinStore struct {
	mu   sync.Mutex
	pins map[string]*TOFUPin
}

// errMemPinNotFound is returned by memTOFUPinStore.Get on a miss.
type errMemPinNotFound struct{}

func (errMemPinNotFound) Error() string { return "trust test: tofu pin not found" }

func newMemTOFUPinStore() *memTOFUPinStore {
	return &memTOFUPinStore{pins: map[string]*TOFUPin{}}
}

func memPinKey(host string, port int) string {
	return host + ":" + strconv.Itoa(port)
}

func (s *memTOFUPinStore) Get(_ context.Context, host string, port int) (*TOFUPin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pin, ok := s.pins[memPinKey(host, port)]
	if !ok {
		return nil, errMemPinNotFound{}
	}
	return pin, nil
}

func (s *memTOFUPinStore) Put(_ context.Context, pin *TOFUPin) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pins[memPinKey(pin.Host, pin.Port)] = pin
	return nil
}

func (s *memTOFUPinStore) Delete(_ context.Context, host string, port int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pins, memPinKey(host, port))
	return nil
}

func (s *memTOFUPinStore) List(_ context.Context) ([]*TOFUPin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*TOFUPin, 0, len(s.pins))
	for _, pin := range s.pins {
		out = append(out, pin)
	}
	return out, nil
}

// TestNewResolver_TOFUOptions proves WithTOFUPinStore satisfies the tofu
// pin-store requirement on both classes, alone and together with
// WithTOFUConfirmFunc, while a confirm function on its own does not.
func TestNewResolver_TOFUOptions(t *testing.T) {
	confirm := func(context.Context, *TOFUPin) error { return nil }
	tests := []struct {
		name    string
		cfg     *Config
		opts    []Option
		wantErr bool
	}{
		{
			name: "bmc tofu with pin store",
			cfg:  &Config{BMC: &ScopeConfig{Strategies: []Strategy{StrategyTOFU}}},
			opts: []Option{WithTOFUPinStore(newMemTOFUPinStore())},
		},
		{
			name: "bootstrap tofu with pin store and confirm func",
			cfg: &Config{Bootstrap: &ScopeConfig{
				Strategies: []Strategy{StrategyTOFU},
				ServerURL:  "https://cp.example.com:8443",
			}},
			opts: []Option{WithTOFUPinStore(newMemTOFUPinStore()), WithTOFUConfirmFunc(confirm)},
		},
		{
			name:    "bmc tofu with confirm func only",
			cfg:     &Config{BMC: &ScopeConfig{Strategies: []Strategy{StrategyTOFU}}},
			opts:    []Option{WithTOFUConfirmFunc(confirm)},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewResolver(tt.cfg, testLogger(), tt.opts...)
			if tt.wantErr {
				if !errors.Is(err, ErrTOFUPinStoreRequired{}) {
					t.Fatalf("expected ErrTOFUPinStoreRequired, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewResolver: %v", err)
			}
			if r == nil {
				t.Fatal("NewResolver returned a nil resolver without an error")
			}
		})
	}
}

// TestClasses_StableOrderAndDefensiveCopy proves Classes lists every class
// in order and that mutating the result does not alter the package list.
func TestClasses_StableOrderAndDefensiveCopy(t *testing.T) {
	got := Classes()
	want := []Class{ClassBootstrap, ClassBMC}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Classes() = %v, want %v", got, want)
	}
	got[0] = Class("tampered")
	if again := Classes(); !reflect.DeepEqual(again, want) {
		t.Fatalf("Classes() after caller mutation = %v, want %v", again, want)
	}
}

// TestAllowedStrategiesForClass proves the named allowlist matches the
// predicate for every strategy, in the stable order, and is empty for an
// unknown class.
func TestAllowedStrategiesForClass(t *testing.T) {
	order := []Strategy{
		StrategyDANE, StrategyNoise, StrategySPKI, StrategyEmbedded,
		StrategyCAFile, StrategyTOFU,
	}
	for _, class := range Classes() {
		t.Run(string(class), func(t *testing.T) {
			var want []Strategy
			for _, s := range order {
				if StrategyAllowedForClass(class, s) {
					want = append(want, s)
				}
			}
			got := AllowedStrategiesForClass(class)
			if len(want) == 0 {
				t.Fatalf("class %q allows no strategy", class)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("AllowedStrategiesForClass(%q) = %v, want %v", class, got, want)
			}
		})
	}

	t.Run("bootstrap exact set", func(t *testing.T) {
		want := []Strategy{StrategyDANE, StrategyNoise, StrategySPKI, StrategyEmbedded, StrategyTOFU}
		if got := AllowedStrategiesForClass(ClassBootstrap); !reflect.DeepEqual(got, want) {
			t.Fatalf("AllowedStrategiesForClass(bootstrap) = %v, want %v", got, want)
		}
	})

	t.Run("unknown class", func(t *testing.T) {
		got := AllowedStrategiesForClass(Class("unknown"))
		if got == nil || len(got) != 0 {
			t.Fatalf("AllowedStrategiesForClass(unknown) = %#v, want an empty non-nil slice", got)
		}
	})
}

// TestToGeneric_CarriesStrategyOptions proves the DANE and Noise option
// blocks reach the generic scope, the strategy chain is copied rather than
// shared, and an unset class produces no generic scope.
func TestToGeneric_CarriesStrategyOptions(t *testing.T) {
	dane := &DANEConfig{}
	noise := &NoiseConfig{}
	spki := &SPKIConfig{}
	cfg := &Config{Bootstrap: &ScopeConfig{
		Strategies: []Strategy{StrategyDANE, StrategyNoise, StrategySPKI},
		ServerURL:  "https://cp.example.com:8443",
		Hostname:   "cp.example.com",
		DANE:       dane,
		Noise:      noise,
		SPKI:       spki,
	}}

	generic := cfg.ToGeneric()
	scope, ok := generic.Scopes[string(ClassBootstrap)]
	if !ok {
		t.Fatalf("generic config has no %q scope", ClassBootstrap)
	}
	if _, ok := generic.Scopes[string(ClassBMC)]; ok {
		t.Fatalf("unset %q class produced a generic scope", ClassBMC)
	}
	if scope.DANE != dane || scope.Noise != noise || scope.SPKI != spki {
		t.Fatalf("strategy options not carried: dane=%p noise=%p spki=%p", scope.DANE, scope.Noise, scope.SPKI)
	}
	if scope.ServerURL != cfg.Bootstrap.ServerURL || scope.Hostname != cfg.Bootstrap.Hostname {
		t.Fatalf("scope fields not carried: %+v", scope)
	}

	scope.Strategies[0] = StrategyTOFU
	if cfg.Bootstrap.Strategies[0] != StrategyDANE {
		t.Fatal("generic scope shares the platform strategy slice")
	}
}

// TestSentinelErrors_MatchPointerForm proves each sentinel error matches its
// own type through errors.Is even when raised as a pointer, and never a
// different sentinel.
func TestSentinelErrors_MatchPointerForm(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
		other  error
	}{
		{"nil config", &ErrNilConfig{}, ErrNilConfig{}, ErrNilLogger{}},
		{"nil logger", &ErrNilLogger{}, ErrNilLogger{}, ErrNilConfig{}},
		{"nil anchor source", &ErrNilAnchorSource{}, ErrNilAnchorSource{}, ErrAnchorEmpty{}},
		{"anchor empty", &ErrAnchorEmpty{}, ErrAnchorEmpty{}, ErrAnchorFileUnset{}},
		{"anchor file unset", &ErrAnchorFileUnset{}, ErrAnchorFileUnset{}, ErrNilAnchorSource{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, tt.target) {
				t.Fatalf("errors.Is(%T, %T) = false, want true", tt.err, tt.target)
			}
			if errors.Is(tt.err, tt.other) {
				t.Fatalf("errors.Is(%T, %T) = true, want false", tt.err, tt.other)
			}
		})
	}
}
