// SPDX-License-Identifier: AGPL-3.0-only
package admission

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cortexproject/cortex/pkg/util/services"
)

func testConfig() Config {
	return Config{
		Enabled:                       true,
		MaxInFlightTasks:              4,
		MaxTasksPerRootQuery:          3,
		DefaultTenantMaxInFlightTasks: 10,
		DefaultTenantTaskWeight:       1,
		LeaseTTL:                      time.Minute,
		EnqueueWaitTimeout:            2 * time.Second,
		ReapInterval:                  time.Minute,
	}
}

func startTestManager(t *testing.T, cfg Config) *Manager {
	t.Helper()
	m := NewManager(cfg, log.NewNopLogger(), prometheus.NewPedanticRegistry())
	require.NoError(t, services.StartAndAwaitRunning(context.Background(), m))
	t.Cleanup(func() {
		_ = services.StopAndAwaitTerminated(context.Background(), m)
	})
	return m
}

func key(id uint64) LeaseKey {
	return LeaseKey{FrontendAddress: "frontend-1", QueryID: id}
}

func TestConfigValidate(t *testing.T) {
	// Disabled config is always valid, keeping the feature opt-in.
	disabled := Config{Enabled: false}
	require.NoError(t, disabled.Validate())

	cases := []struct {
		name   string
		modify func(*Config)
	}{
		{"zero global cap", func(c *Config) { c.MaxInFlightTasks = 0 }},
		{"zero root cap", func(c *Config) { c.MaxTasksPerRootQuery = 0 }},
		{"root cap above global cap", func(c *Config) { c.MaxTasksPerRootQuery = 5 }},
		{"zero tenant quota", func(c *Config) { c.DefaultTenantMaxInFlightTasks = 0 }},
		{"zero tenant weight", func(c *Config) { c.DefaultTenantTaskWeight = 0 }},
		{"bad tenant quota override", func(c *Config) { c.TenantMaxInFlightTasks = map[string]float64{"a": -1} }},
		{"bad tenant weight override", func(c *Config) { c.TenantTaskWeight = map[string]float64{"a": 0} }},
		{"zero ttl", func(c *Config) { c.LeaseTTL = 0 }},
		{"zero wait timeout", func(c *Config) { c.EnqueueWaitTimeout = 0 }},
		{"zero reap interval", func(c *Config) { c.ReapInterval = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			tc.modify(&cfg)
			require.Error(t, cfg.Validate())
		})
	}
}

func TestBeginRootNormalizesTenantsAndCountsAttempts(t *testing.T) {
	m := startTestManager(t, testConfig())

	attempt, err := m.BeginRoot(key(1), []string{"b", "a", "a"})
	require.NoError(t, err)
	require.EqualValues(t, 1, attempt)

	grant, err := m.Admit(context.Background(), key(1), attempt)
	require.NoError(t, err)
	// Stable, sorted, de-duplicated tenant order is used for every reservation.
	require.Equal(t, []string{"a", "b"}, grant.tenants)

	// Re-enqueue of the same root query advances the attempt.
	attempt, err = m.BeginRoot(key(1), []string{"a", "b"})
	require.NoError(t, err)
	require.EqualValues(t, 2, attempt)
	require.Equal(t, 1, m.ActiveLeases())
}

func TestAdmitRespectsGlobalAndPerRootCaps(t *testing.T) {
	cfg := testConfig()
	cfg.MaxInFlightTasks = 3
	cfg.MaxTasksPerRootQuery = 2
	m := startTestManager(t, cfg)

	attempt, err := m.BeginRoot(key(1), []string{"a"})
	require.NoError(t, err)

	g1, err := m.Admit(context.Background(), key(1), attempt)
	require.NoError(t, err)
	g2, err := m.Admit(context.Background(), key(1), attempt)
	require.NoError(t, err)
	require.Equal(t, 2, m.GlobalInflight())

	// The per-root cap blocks the third task until another grant is returned.
	admitted := make(chan *Grant, 1)
	go func() {
		g, err := m.Admit(context.Background(), key(1), attempt)
		require.NoError(t, err)
		admitted <- g
	}()

	select {
	case <-admitted:
		t.Fatal("third task must not be admitted while the per-root cap is exhausted")
	case <-time.After(100 * time.Millisecond):
	}

	m.Release(g1)

	select {
	case g3 := <-admitted:
		require.Equal(t, 2, m.GlobalInflight())
		m.Release(g2)
		m.Release(g3)
	case <-time.After(2 * time.Second):
		t.Fatal("third task was not admitted after credits were released")
	}

	require.Equal(t, 0, m.GlobalInflight())
}

func TestAdmitMultiTenantReservationIsAllOrNothing(t *testing.T) {
	cfg := testConfig()
	cfg.DefaultTenantMaxInFlightTasks = 3
	cfg.TenantTaskWeight = map[string]float64{"b": 2} // federated task costs a=1, b=2
	m := startTestManager(t, cfg)

	attempt, err := m.BeginRoot(key(1), []string{"a", "b"})
	require.NoError(t, err)

	g1, err := m.Admit(context.Background(), key(1), attempt)
	require.NoError(t, err)
	require.Equal(t, 1, m.GlobalInflight())
	require.Equal(t, 1.0, m.TenantInflight("a"))
	require.Equal(t, 2.0, m.TenantInflight("b"))

	// A second task would push tenant b to 4 > quota 3. It must wait and must
	// never leave a partial deduction behind.
	blocked := make(chan error, 1)
	go func() {
		_, err := m.Admit(context.Background(), key(1), attempt)
		blocked <- err
	}()

	time.Sleep(100 * time.Millisecond)
	require.Equal(t, 1.0, m.TenantInflight("a"), "no partial reservation while waiting")
	require.Equal(t, 2.0, m.TenantInflight("b"), "no partial reservation while waiting")

	m.Release(g1)

	select {
	case err := <-blocked:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("blocked admission did not proceed after credits returned")
	}

	require.Equal(t, 1, m.GlobalInflight())
	require.Equal(t, 1.0, m.TenantInflight("a"))
	require.Equal(t, 2.0, m.TenantInflight("b"))
}

func TestAdmitTimeout(t *testing.T) {
	cfg := testConfig()
	cfg.MaxInFlightTasks = 1
	cfg.EnqueueWaitTimeout = 50 * time.Millisecond
	m := startTestManager(t, cfg)

	attempt, err := m.BeginRoot(key(1), []string{"a"})
	require.NoError(t, err)
	g1, err := m.Admit(context.Background(), key(1), attempt)
	require.NoError(t, err)
	defer m.Release(g1)

	start := time.Now()
	_, err = m.Admit(context.Background(), key(1), attempt)
	require.ErrorIs(t, err, ErrAdmissionTimeout)
	require.GreaterOrEqual(t, time.Since(start), 40*time.Millisecond)
	require.Equal(t, 1, m.GlobalInflight(), "timed out admission reserves nothing")
}

func TestAdmitContextCanceledWhileWaiting(t *testing.T) {
	cfg := testConfig()
	cfg.MaxInFlightTasks = 1
	m := startTestManager(t, cfg)

	attempt, err := m.BeginRoot(key(1), []string{"a"})
	require.NoError(t, err)
	g1, err := m.Admit(context.Background(), key(1), attempt)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := m.Admit(ctx, key(1), attempt)
		errCh <- err
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("context cancellation did not unblock Admit")
	}

	require.Equal(t, 1, m.GlobalInflight())
	m.Release(g1)
	require.Equal(t, 0, m.GlobalInflight())
}

func TestCancelRootBlocksNewAdmitsButKeepsInflightCredits(t *testing.T) {
	m := startTestManager(t, testConfig())

	attempt, err := m.BeginRoot(key(1), []string{"a"})
	require.NoError(t, err)
	g1, err := m.Admit(context.Background(), key(1), attempt)
	require.NoError(t, err)

	m.CancelRoot(key(1))

	_, err = m.Admit(context.Background(), key(1), attempt)
	require.ErrorIs(t, err, ErrRootCanceled)
	require.Equal(t, 1, m.GlobalInflight(), "in-flight credits survive cancellation")

	// Once the in-flight task ends, the empty canceled lease is removed.
	m.Release(g1)
	require.Equal(t, 0, m.GlobalInflight())
	require.Equal(t, 0, m.ActiveLeases())
}

func TestReleaseIsIdempotentAndScopedToTheGrantToken(t *testing.T) {
	m := startTestManager(t, testConfig())

	attempt, err := m.BeginRoot(key(1), []string{"a"})
	require.NoError(t, err)
	g1, err := m.Admit(context.Background(), key(1), attempt)
	require.NoError(t, err)

	// New attempt (retry/reconnect) gets its own grant.
	attempt2, err := m.BeginRoot(key(1), []string{"a"})
	require.NoError(t, err)
	g2, err := m.Admit(context.Background(), key(1), attempt2)
	require.NoError(t, err)

	// Stale attempts cannot admit anymore.
	_, err = m.Admit(context.Background(), key(1), attempt)
	require.ErrorIs(t, err, ErrLeaseStale)

	require.Equal(t, 2, m.GlobalInflight())

	// A late completion of the old attempt can only return its own credits,
	// even if it reports completion more than once.
	m.Release(g1)
	m.Release(g1)
	require.Equal(t, 1, m.GlobalInflight(), "double release must not touch the new attempt's credit")

	_, inflight, _, ok := m.LeaseState(key(1))
	require.True(t, ok)
	require.Equal(t, 1, inflight)

	m.Release(g2)
	require.Equal(t, 0, m.GlobalInflight())
}

func TestReaperForceReclaimsExpiredGrantsAndLeases(t *testing.T) {
	cfg := testConfig()
	cfg.LeaseTTL = 80 * time.Millisecond
	cfg.ReapInterval = 30 * time.Millisecond
	cfg.EnqueueWaitTimeout = 5 * time.Second
	m := startTestManager(t, cfg)

	attempt, err := m.BeginRoot(key(1), []string{"a"})
	require.NoError(t, err)
	g1, err := m.Admit(context.Background(), key(1), attempt)
	require.NoError(t, err)
	require.Equal(t, 1, m.GlobalInflight())

	// Simulate a lost querier: nobody ever calls Release. The reaper must
	// reclaim the grant conservatively and then garbage collect the lease.
	require.Eventually(t, func() bool {
		return m.GlobalInflight() == 0 && m.ActiveLeases() == 0
	}, 3*time.Second, 25*time.Millisecond)

	require.Greater(t, promtest.ToFloat64(m.reclaimedTasks.WithLabelValues(reapReasonTTL)), 0.0)
	require.False(t, g1.released == false && m.GlobalInflight() != 0)
}

func TestStopWakesAllWaiters(t *testing.T) {
	cfg := testConfig()
	cfg.MaxInFlightTasks = 1
	m := NewManager(cfg, log.NewNopLogger(), prometheus.NewPedanticRegistry())
	require.NoError(t, services.StartAndAwaitRunning(context.Background(), m))

	attempt, err := m.BeginRoot(key(1), []string{"a"})
	require.NoError(t, err)
	g1, err := m.Admit(context.Background(), key(1), attempt)
	require.NoError(t, err)

	errCh := make(chan error, 1)
	go func() {
		_, err := m.Admit(context.Background(), key(1), attempt)
		errCh <- err
	}()

	time.Sleep(100 * time.Millisecond)
	require.NoError(t, services.StopAndAwaitTerminated(context.Background(), m))

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, ErrStopped)
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler shutdown did not release the blocked waiter")
	}

	// Grants held at shutdown are still releasable without errors and bookkeep
	// back to zero for an orderly process exit.
	m.Release(g1)
	require.Equal(t, 0, m.GlobalInflight())
}

func TestConcurrentAdmissionsNeverExceedCapsAndSettleAtZero(t *testing.T) {
	cfg := testConfig()
	cfg.MaxInFlightTasks = 6
	cfg.MaxTasksPerRootQuery = 3
	cfg.DefaultTenantMaxInFlightTasks = 6
	cfg.TenantTaskWeight = map[string]float64{"b": 2} // b quota 6 -> at most 3 federated tasks at once
	m := startTestManager(t, cfg)

	leaseKeys := []LeaseKey{key(1), key(2), key(3), key(4)}
	attempts := make([]uint64, len(leaseKeys))
	for i, lk := range leaseKeys {
		attempt, err := m.BeginRoot(lk, []string{"a", "b"})
		require.NoError(t, err)
		attempts[i] = attempt
	}

	stopChecker := make(chan struct{})
	var checkerWg sync.WaitGroup
	checkerWg.Go(func() {
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopChecker:
				return
			case <-ticker.C:
				assert.LessOrEqual(t, m.GlobalInflight(), cfg.MaxInFlightTasks)
				assert.LessOrEqual(t, m.TenantInflight("a"), cfg.DefaultTenantMaxInFlightTasks)
				assert.LessOrEqual(t, m.TenantInflight("b"), cfg.DefaultTenantMaxInFlightTasks)
				for i, lk := range leaseKeys {
					_, inflight, _, ok := m.LeaseState(lk)
					if ok {
						assert.LessOrEqual(t, inflight, cfg.MaxTasksPerRootQuery, "lease %d", i)
					}
				}
			}
		}
	})

	var wg sync.WaitGroup
	for worker := range 24 {
		wg.Go(func() {
			for round := range 5 {
				idx := (worker + round) % len(leaseKeys)
				grant, err := m.Admit(context.Background(), leaseKeys[idx], attempts[idx])
				if err != nil {
					return
				}
				time.Sleep(time.Duration(1+worker%4) * time.Millisecond)
				m.Release(grant)
			}
		})
	}
	wg.Wait()
	close(stopChecker)
	checkerWg.Wait()

	for _, lk := range leaseKeys {
		m.CancelRoot(lk)
	}
	require.Eventually(t, func() bool {
		if m.GlobalInflight() != 0 || m.ActiveLeases() != 0 {
			return false
		}
		return m.TenantInflight("a") == 0 && m.TenantInflight("b") == 0
	}, 2*time.Second, 10*time.Millisecond, "every account must return to zero")
}
