package ruler

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/exemplar"
	"github.com/prometheus/prometheus/model/histogram"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/metadata"
	"github.com/prometheus/prometheus/notifier"
	"github.com/prometheus/prometheus/promql"
	promqlparser "github.com/prometheus/prometheus/promql/parser"
	promRules "github.com/prometheus/prometheus/rules"
	"github.com/prometheus/prometheus/storage"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/user"

	"github.com/cortexproject/cortex/pkg/ring/client"
	"github.com/cortexproject/cortex/pkg/ruler/rulespb"
	"github.com/cortexproject/cortex/pkg/util/test"
	"github.com/cortexproject/cortex/pkg/util/validation"
)

const bundleTestTenant = "bundle-tenant"

// bundleMockManager is an instrumented RulesManager recording the exact
// ordering of Update/Run/Stop so tests can prove that an old generation fully
// stops before a new one starts evaluating.
type bundleMockManager struct {
	id string

	mu             sync.Mutex
	updateErr      error
	updateCalls    int
	runCalledAt    time.Time
	stopCalledAt   time.Time
	stopReturnedAt time.Time
	groups         []*promRules.Group

	running   atomic.Bool
	evalTicks atomic.Int64
	done      chan struct{}
	once      sync.Once
}

func (m *bundleMockManager) Update(_ time.Duration, _ []string, _ labels.Labels, _ string, _ promRules.GroupEvalIterationFunc) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateCalls++
	return m.updateErr
}

func (m *bundleMockManager) RuleGroups() []*promRules.Group {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.groups
}

func (m *bundleMockManager) Run() {
	m.mu.Lock()
	m.runCalledAt = time.Now()
	m.mu.Unlock()
	m.running.Store(true)
	<-m.done
}

func (m *bundleMockManager) Stop() {
	m.mu.Lock()
	m.stopCalledAt = time.Now()
	m.running.Store(false)
	m.mu.Unlock()

	m.once.Do(func() { close(m.done) })

	m.mu.Lock()
	m.stopReturnedAt = time.Now()
	m.mu.Unlock()
}

func (m *bundleMockManager) snapshot() (runAt, stopAt, stopReturnedAt time.Time, running bool, ticks int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runCalledAt, m.stopCalledAt, m.stopReturnedAt, m.running.Load(), m.evalTicks.Load()
}

type bundleTestHarness struct {
	cfg    Config
	limits *ruleLimits
	host   *DefaultMultiTenantManager
	fs     afero.Fs

	mu            sync.Mutex
	managers      []*bundleMockManager
	nextUpdateErr error
}

func bundleTestConfig(t *testing.T) Config {
	t.Helper()
	cfg := Config{
		RulePath:             t.TempDir(),
		EvaluationInterval:   time.Minute,
		NameValidationScheme: model.UTF8Validation,
		ReleaseBundles: ReleaseBundleConfig{
			Enabled:                true,
			MaxRuleGroupsPerBundle: 10,
			MaxRulesPerBundle:      100,
		},
	}
	return cfg
}

func newBundleTestHarness(t *testing.T, cfg Config, limits *ruleLimits) *bundleTestHarness {
	t.Helper()
	fs := afero.NewMemMapFs()
	h := &bundleTestHarness{cfg: cfg, limits: limits, fs: fs}

	factory := func(_ context.Context, _ string, _ *notifier.Manager, _ log.Logger, _ *client.Pool, _ prometheus.Registerer) (RulesManager, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		m := &bundleMockManager{
			id:        fmt.Sprintf("mgr-%d", len(h.managers)),
			updateErr: h.nextUpdateErr,
			done:      make(chan struct{}),
		}
		h.nextUpdateErr = nil
		h.managers = append(h.managers, m)
		return m, nil
	}

	host, err := NewDefaultMultiTenantManager(cfg, limits, factory, nil, prometheus.NewRegistry(), log.NewNopLogger())
	require.NoError(t, err)
	require.NotNil(t, host.bundles)

	// Use an in-memory filesystem for deterministic crash/recovery tests.
	host.bundles.store = newBundleStoreWithFs(fs, cfg.RulePath, log.NewNopLogger())
	h.host = host
	t.Cleanup(host.Stop)
	return h
}

func (h *bundleTestHarness) coordinator() *releaseBundleCoordinator {
	return h.host.bundles
}

func (h *bundleTestHarness) store() *bundleStore {
	return h.coordinator().store
}

func (h *bundleTestHarness) failNextManagerUpdate(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nextUpdateErr = err
}

func (h *bundleTestHarness) managerAt(i int) *bundleMockManager {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.managers[i]
}

func (h *bundleTestHarness) managerCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.managers)
}

func bundleRuleGroups(tenant string) rulespb.RuleGroupList {
	return rulespb.RuleGroupList{{
		Name:      "g1",
		Namespace: "ns1",
		User:      tenant,
		Interval:  time.Minute,
		Rules: []*rulespb.RuleDesc{
			{Record: "metric_one", Expr: "up"},
			{Alert: "AlertOne", Expr: "up == 0", For: time.Minute},
		},
	}}
}

func (h *bundleTestHarness) prepareAndCommit(t *testing.T, tenant string, groups rulespb.RuleGroupList) (string, *SwitchReport) {
	t.Helper()
	gen, manifest, err := h.host.PrepareReleaseBundle(context.Background(), tenant, groups)
	require.NoError(t, err)
	require.NotNil(t, manifest)
	report, err := h.host.CommitReleaseBundle(context.Background(), tenant, gen)
	require.NoError(t, err)
	return gen, report
}

func TestCoordinator_DisabledByDefault(t *testing.T) {
	cfg := bundleTestConfig(t)
	cfg.ReleaseBundles.Enabled = false
	host, err := NewDefaultMultiTenantManager(cfg, &ruleLimits{}, RuleManagerFactory(nil, nil), nil, prometheus.NewRegistry(), log.NewNopLogger())
	require.NoError(t, err)
	require.Nil(t, host.bundles)

	_, _, err = host.PrepareReleaseBundle(context.Background(), bundleTestTenant, bundleRuleGroups(bundleTestTenant))
	require.ErrorIs(t, err, errReleaseBundlesDisabled)
	require.ErrorIs(t, host.RecoverReleaseBundles(context.Background()), errReleaseBundlesDisabled)
}

func TestCoordinator_PrepareRejectsInvalidAndOutOfScopeInputs(t *testing.T) {
	h := newBundleTestHarness(t, bundleTestConfig(t), &ruleLimits{})

	cases := map[string]rulespb.RuleGroupList{
		"parse error": {{
			Name: "g", Namespace: "ns", User: bundleTestTenant, Interval: time.Minute,
			Rules: []*rulespb.RuleDesc{{Record: "m", Expr: "up {"}},
		}},
		"foreign tenant": {{
			Name: "g", Namespace: "ns", User: "other-tenant", Interval: time.Minute,
			Rules: []*rulespb.RuleDesc{{Record: "m", Expr: "up"}},
		}},
	}
	for name, groups := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := h.host.PrepareReleaseBundle(context.Background(), bundleTestTenant, groups)
			require.Error(t, err)
			require.Equal(t, 0, h.managerCount(), "prepare must never create a live manager")
		})
	}

	t.Run("bundle group cap", func(t *testing.T) {
		cfg := bundleTestConfig(t)
		cfg.ReleaseBundles.MaxRuleGroupsPerBundle = 1
		hCap := newBundleTestHarness(t, cfg, &ruleLimits{})
		groups := rulespb.RuleGroupList{
			{Name: "g1", Namespace: "ns", User: bundleTestTenant, Interval: time.Minute, Rules: []*rulespb.RuleDesc{{Record: "m1", Expr: "up"}}},
			{Name: "g2", Namespace: "ns", User: bundleTestTenant, Interval: time.Minute, Rules: []*rulespb.RuleDesc{{Record: "m2", Expr: "up"}}},
		}
		_, _, err := hCap.host.PrepareReleaseBundle(context.Background(), bundleTestTenant, groups)
		require.Error(t, err)
	})

	t.Run("tenant rule group limit", func(t *testing.T) {
		limits := &ruleLimits{maxRuleGroups: 1}
		hLimit := newBundleTestHarness(t, bundleTestConfig(t), limits)
		groups := rulespb.RuleGroupList{
			{Name: "g1", Namespace: "ns", User: bundleTestTenant, Interval: time.Minute, Rules: []*rulespb.RuleDesc{{Record: "m1", Expr: "up"}}},
			{Name: "g2", Namespace: "ns", User: bundleTestTenant, Interval: time.Minute, Rules: []*rulespb.RuleDesc{{Record: "m2", Expr: "up"}}},
		}
		_, _, err := hLimit.host.PrepareReleaseBundle(context.Background(), bundleTestTenant, groups)
		require.Error(t, err)
		require.Contains(t, err.Error(), "rule groups limit")
	})

	t.Run("disabled rule group", func(t *testing.T) {
		limits := &ruleLimits{
			disabledRuleGroups: validation.DisabledRuleGroups{{Name: "g1", Namespace: "ns1", User: bundleTestTenant}},
		}
		hDisabled := newBundleTestHarness(t, bundleTestConfig(t), limits)
		_, _, err := hDisabled.host.PrepareReleaseBundle(context.Background(), bundleTestTenant, bundleRuleGroups(bundleTestTenant))
		require.Error(t, err)
		require.Contains(t, err.Error(), "is disabled")
	})

	t.Run("rules per group limit", func(t *testing.T) {
		limits := &ruleLimits{maxRulesPerRuleGroup: 1}
		hLimit := newBundleTestHarness(t, bundleTestConfig(t), limits)
		_, _, err := hLimit.host.PrepareReleaseBundle(context.Background(), bundleTestTenant, bundleRuleGroups(bundleTestTenant))
		require.Error(t, err)
		require.Contains(t, err.Error(), "rules per rule group limit")
	})

	// Every failed prepare left the tenant without candidates and managers.
	tenants, err := h.store().listTenants()
	require.NoError(t, err)
	require.Empty(t, tenants)
}

func TestCoordinator_PrepareRejectsUnauthorizedFederation(t *testing.T) {
	cfg := bundleTestConfig(t)
	cfg.EnableFederatedRules = false
	h := newBundleTestHarness(t, cfg, &ruleLimits{})

	groups := bundleRuleGroups(bundleTestTenant)
	groups[0].SourceTenants = []string{"team-a"}

	_, _, err := h.host.PrepareReleaseBundle(context.Background(), bundleTestTenant, groups)
	require.Error(t, err)
}

func TestCoordinator_CommitSwitchOrderingPreventsDoubleEvaluation(t *testing.T) {
	h := newBundleTestHarness(t, bundleTestConfig(t), &ruleLimits{})

	gen1, report1 := h.prepareAndCommit(t, bundleTestTenant, bundleRuleGroups(bundleTestTenant))
	require.Empty(t, report1.OldGeneration)
	require.False(t, report1.NotifierOwnershipTransferred)

	mgr1 := h.managerAt(0)
	_, _, _, running1, _ := mgr1.snapshot()
	require.True(t, running1)

	// Simulate evaluation ticks of the first generation.
	mgr1.evalTicks.Add(10)

	gen2, report2 := h.prepareAndCommit(t, bundleTestTenant, bundleRuleGroups(bundleTestTenant))
	require.NotEqual(t, gen1, gen2)
	require.Equal(t, gen1, report2.OldGeneration)
	require.True(t, report2.NotifierOwnershipTransferred)

	mgr2 := h.managerAt(1)
	// Wait for the new generation to be running before comparing cut-over
	// timestamps, otherwise its Run goroutine has not recorded the start time.
	test.Poll(t, time.Second, true, func() any {
		_, _, _, running, _ := mgr2.snapshot()
		return running
	})
	_, stopCalledAt1, stopReturnedAt1, running1After, ticks1 := mgr1.snapshot()
	mgr2RunAt, _, _, running2, _ := mgr2.snapshot()

	require.False(t, running1After, "old generation must be stopped")
	require.True(t, running2, "new generation must be running")
	t.Logf("mgr1 stopCalledAt=%v stopReturnedAt=%v; mgr2 runCalledAt=%v", stopCalledAt1, stopReturnedAt1, mgr2RunAt)
	require.False(t, mgr2RunAt.Before(stopReturnedAt1), "new manager must not start before the old one fully stopped")
	require.Equal(t, int64(10), ticks1, "old generation ticks must freeze at cut-over")

	// Exactly one manager owns the tenant and one notifier exists.
	h.host.userManagerMtx.RLock()
	require.Same(t, mgr2, h.host.userManagers[bundleTestTenant])
	h.host.userManagerMtx.RUnlock()
	require.Len(t, h.host.notifiers, 1)

	activeGen, _, ok := h.host.ActiveReleaseBundle(bundleTestTenant)
	require.True(t, ok)
	require.Equal(t, gen2, activeGen)

	// Old generation directory was retired after the old reader ended.
	exists, err := afero.DirExists(h.fs, h.store().releaseDir(bundleTestTenant, gen1))
	require.NoError(t, err)
	require.False(t, exists)

	// Active bundle is still complete and verifiable.
	loadedGen, _, files, err := h.store().loadActiveBundle(bundleTestTenant)
	require.NoError(t, err)
	require.Equal(t, gen2, loadedGen)
	require.NotEmpty(t, files)
}

func TestCoordinator_CommitManagerUpdateFailureKeepsOldGeneration(t *testing.T) {
	h := newBundleTestHarness(t, bundleTestConfig(t), &ruleLimits{})

	gen1, _ := h.prepareAndCommit(t, bundleTestTenant, bundleRuleGroups(bundleTestTenant))
	mgr1 := h.managerAt(0)

	gen2, _, err := h.host.PrepareReleaseBundle(context.Background(), bundleTestTenant, bundleRuleGroups(bundleTestTenant))
	require.NoError(t, err)

	h.failNextManagerUpdate(errBundleManagerUpdateFault)
	_, err = h.host.CommitReleaseBundle(context.Background(), bundleTestTenant, gen2)
	require.Error(t, err)
	require.ErrorIs(t, err, errBundleManagerUpdateFault)
	require.Contains(t, err.Error(), "update rules manager")

	// Old generation remains active and running; the failed generation left no
	// on-disk artifacts.
	activeGen, _, ok := h.host.ActiveReleaseBundle(bundleTestTenant)
	require.True(t, ok)
	require.Equal(t, gen1, activeGen)
	_, _, _, running, _ := mgr1.snapshot()
	require.True(t, running)

	loadedGen, _, _, err := h.store().loadActiveBundle(bundleTestTenant)
	require.NoError(t, err)
	require.Equal(t, gen1, loadedGen)

	candidateExists, err := afero.DirExists(h.fs, h.store().candidateDir(bundleTestTenant, gen2))
	require.NoError(t, err)
	require.False(t, candidateExists)
	releaseExists, err := afero.DirExists(h.fs, h.store().releaseDir(bundleTestTenant, gen2))
	require.NoError(t, err)
	require.False(t, releaseExists)
}

func TestCoordinator_CommitRejectsFederationRevocation(t *testing.T) {
	cfg := bundleTestConfig(t)
	cfg.EnableFederatedRules = true
	cfg.AllowedFederatedTenants = []string{bundleTestTenant}
	h := newBundleTestHarness(t, cfg, &ruleLimits{})

	groups := bundleRuleGroups(bundleTestTenant)
	groups[0].SourceTenants = []string{"team-a"}

	gen1, _ := h.prepareAndCommit(t, bundleTestTenant, groups)
	mgr1 := h.managerAt(0)

	gen2, manifest2, err := h.host.PrepareReleaseBundle(context.Background(), bundleTestTenant, groups)
	require.NoError(t, err)
	require.True(t, manifest2.Federation.OwnerAuthorized)
	require.Len(t, manifest2.Federation.Groups, 1)

	// Revoke the federation permission while the candidate is sealed.
	revokedCfg := cfg
	revokedCfg.AllowedFederatedTenants = []string{"some-other-tenant"}
	h.host.federatedRules = newFederatedRulesChecker(revokedCfg)

	_, err = h.host.CommitReleaseBundle(context.Background(), bundleTestTenant, gen2)
	require.ErrorIs(t, err, errBundleFederationRevoked)

	// The old generation keeps running and stays the only visible bundle.
	activeGen, _, ok := h.host.ActiveReleaseBundle(bundleTestTenant)
	require.True(t, ok)
	require.Equal(t, gen1, activeGen)
	_, _, _, running, _ := mgr1.snapshot()
	require.True(t, running)

	candidateExists, err := afero.DirExists(h.fs, h.store().candidateDir(bundleTestTenant, gen2))
	require.NoError(t, err)
	require.False(t, candidateExists, "revoked candidate must be reclaimed")
}

func TestCoordinator_CancelReclaimsCandidate(t *testing.T) {
	h := newBundleTestHarness(t, bundleTestConfig(t), &ruleLimits{})

	gen, _, err := h.host.PrepareReleaseBundle(context.Background(), bundleTestTenant, bundleRuleGroups(bundleTestTenant))
	require.NoError(t, err)
	require.NoError(t, h.host.CancelReleaseBundle(bundleTestTenant, gen))

	exists, err := afero.DirExists(h.fs, h.store().candidateDir(bundleTestTenant, gen))
	require.NoError(t, err)
	require.False(t, exists)

	require.Error(t, h.host.CancelReleaseBundle(bundleTestTenant, gen))
}

func TestCoordinator_CancelRejectsActiveGeneration(t *testing.T) {
	h := newBundleTestHarness(t, bundleTestConfig(t), &ruleLimits{})
	gen, _ := h.prepareAndCommit(t, bundleTestTenant, bundleRuleGroups(bundleTestTenant))
	require.ErrorIs(t, h.host.CancelReleaseBundle(bundleTestTenant, gen), errBundleGenerationActive)
}

func TestCoordinator_DefaultSyncPathCoexistsWithBundles(t *testing.T) {
	h := newBundleTestHarness(t, bundleTestConfig(t), &ruleLimits{})
	ctx := context.Background()

	gen, _ := h.prepareAndCommit(t, bundleTestTenant, bundleRuleGroups(bundleTestTenant))
	bundleMgr := h.managerAt(0)

	// A periodic sync mentioning the bundle tenant must not touch its manager.
	h.host.SyncRuleGroups(ctx, map[string]rulespb.RuleGroupList{
		bundleTestTenant: bundleRuleGroups(bundleTestTenant),
	})
	require.Equal(t, 1, h.managerCount())
	_, _, _, running, _ := bundleMgr.snapshot()
	require.True(t, running)

	// Other tenants still flow through the default path.
	const otherTenant = "plain-tenant"
	h.host.SyncRuleGroups(ctx, map[string]rulespb.RuleGroupList{
		bundleTestTenant: bundleRuleGroups(bundleTestTenant),
		otherTenant: {
			{Name: "g", Namespace: "ns", User: otherTenant, Interval: time.Minute, Rules: []*rulespb.RuleDesc{{Record: "m", Expr: "up"}}},
		},
	})
	require.Equal(t, 2, h.managerCount())

	// Disappearance of the bundle tenant tears the sealed generation down too.
	h.host.SyncRuleGroups(ctx, map[string]rulespb.RuleGroupList{
		otherTenant: {
			{Name: "g", Namespace: "ns", User: otherTenant, Interval: time.Minute, Rules: []*rulespb.RuleDesc{{Record: "m", Expr: "up"}}},
		},
	})
	_, _, _, running, _ = bundleMgr.snapshot()
	require.False(t, running)
	exists, err := afero.DirExists(h.fs, h.store().tenantRoot(bundleTestTenant))
	require.NoError(t, err)
	require.False(t, exists)
	_, _, ok := h.host.ActiveReleaseBundle(bundleTestTenant)
	require.False(t, ok)
	_ = gen
}

func TestCoordinator_CrashInjectionConvergesToCompleteGeneration(t *testing.T) {
	tests := []struct {
		name       string
		stage      string // "prepare" faults fire while staging/sealing, "commit" faults during the switch
		fault      func(h *bundleTestHarness)
		wantActive string // "old" or "new"
	}{
		{
			name:       "crash while staging rule file",
			stage:      "prepare",
			fault:      func(h *bundleTestHarness) { h.coordinator().faults.AfterRuleFileWrite = func(_ string) error { return errBundleInjectedFault } },
			wantActive: "old",
		},
		{
			name:       "crash after manifest seal",
			stage:      "prepare",
			fault:      func(h *bundleTestHarness) { h.coordinator().faults.AfterManifestSeal = func(_ string) error { return errBundleInjectedFault } },
			wantActive: "old",
		},
		{
			name:       "crash after candidate promotion",
			stage:      "commit",
			fault:      func(h *bundleTestHarness) { h.coordinator().faults.AfterCandidatePromoted = func(_ string) error { return errBundleInjectedFault } },
			wantActive: "old",
		},
		{
			name:       "crash after active pointer swap",
			stage:      "commit",
			fault:      func(h *bundleTestHarness) { h.coordinator().faults.AfterActivePointerSwapped = func(_ string) error { return errBundleInjectedFault } },
			wantActive: "new",
		},
		{
			name:       "crash after old manager stopped",
			stage:      "commit",
			fault:      func(h *bundleTestHarness) { h.coordinator().faults.AfterOldManagerStopped = func(_ string) error { return errBundleInjectedFault } },
			wantActive: "new",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := bundleTestConfig(t)
			limits := &ruleLimits{}
			h1 := newBundleTestHarness(t, cfg, limits)
			ctx := context.Background()

			oldGen, _ := h1.prepareAndCommit(t, bundleTestTenant, bundleRuleGroups(bundleTestTenant))

			var newGen string
			tc.fault(h1)
			if tc.stage == "prepare" {
				// The fault aborts the candidate before it is sealed.
				gen, _, err := h1.host.PrepareReleaseBundle(ctx, bundleTestTenant, bundleRuleGroups(bundleTestTenant))
				require.Error(t, err)
				newGen = gen
			} else {
				var err error
				newGen, _, err = h1.host.PrepareReleaseBundle(ctx, bundleTestTenant, bundleRuleGroups(bundleTestTenant))
				require.NoError(t, err)
				_, err = h1.host.CommitReleaseBundle(ctx, bundleTestTenant, newGen)
				require.Error(t, err)
			}

			// Simulate process restart: a new host over the same persisted FS.
			fs := h1.fs
			h1.host.Stop()

			h2 := newBundleTestHarness(t, cfg, limits)
			h2.host.bundles.store = newBundleStoreWithFs(fs, cfg.RulePath, log.NewNopLogger())
			require.NoError(t, h2.host.RecoverReleaseBundles(ctx))

			loadedGen, manifest, files, err := h2.host.bundles.store.loadActiveBundle(bundleTestTenant)
			require.NoError(t, err, "active pointer must always resolve to a complete verified bundle")
			require.NotEmpty(t, files)
			require.Equal(t, loadedGen, manifest.Generation)

			switch tc.wantActive {
			case "old":
				require.Equal(t, oldGen, loadedGen)
			case "new":
				require.Equal(t, newGen, loadedGen)
				activeGen, _, ok := h2.host.ActiveReleaseBundle(bundleTestTenant)
				require.True(t, ok)
				require.Equal(t, newGen, activeGen)
			}
		})
	}
}

func mustParseTestExpr(t *testing.T, expr string) promqlparser.Expr {
	t.Helper()
	e, err := promqlparser.ParseExpr(expr)
	require.NoError(t, err)
	return e
}

func newTestPromGroup(t *testing.T, file, name string, rules []promRules.Rule) *promRules.Group {
	t.Helper()
	return promRules.NewGroup(promRules.GroupOptions{
		Name:     name,
		File:     file,
		Interval: time.Minute,
		Rules:    rules,
		Opts: &promRules.ManagerOptions{
			Context:    user.InjectOrgID(context.Background(), bundleTestTenant),
			Registerer: prometheus.NewRegistry(),
			QueryFunc:  func(_ context.Context, _ string, _ time.Time) (promql.Vector, error) { return promql.Vector{}, nil },
			Appendable: noopAppendable{},
			NotifyFunc: func(_ context.Context, _ string, _ ...*promRules.Alert) {},
			Logger:     promslog.NewNopLogger(),
		},
	})
}

// noopAppendable is a storage.Appendable that accepts and discards every
// sample. It only exists so hand-built groups can be evaluated in tests.
type noopAppendable struct{}

func (noopAppendable) Appender(_ context.Context) storage.Appender { return noopAppender{} }

type noopAppender struct{}

func (noopAppender) Append(_ storage.SeriesRef, _ labels.Labels, _ int64, _ float64) (storage.SeriesRef, error) {
	return 0, nil
}

func (noopAppender) AppendHistogram(_ storage.SeriesRef, _ labels.Labels, _ int64, _ *histogram.Histogram, _ *histogram.FloatHistogram) (storage.SeriesRef, error) {
	return 0, nil
}

func (noopAppender) SetOptions(_ *storage.AppendOptions) {}

func (noopAppender) AppendHistogramSTZeroSample(_ storage.SeriesRef, _ labels.Labels, _, _ int64, _ *histogram.Histogram, _ *histogram.FloatHistogram) (storage.SeriesRef, error) {
	return 0, nil
}

func (noopAppender) AppendSTZeroSample(_ storage.SeriesRef, _ labels.Labels, _, _ int64) (storage.SeriesRef, error) {
	return 0, nil
}

func (noopAppender) AppendExemplar(_ storage.SeriesRef, _ labels.Labels, _ exemplar.Exemplar) (storage.SeriesRef, error) {
	return 0, nil
}

func (noopAppender) UpdateMetadata(_ storage.SeriesRef, _ labels.Labels, _ metadata.Metadata) (storage.SeriesRef, error) {
	return 0, nil
}

func (noopAppender) Commit() error   { return nil }
func (noopAppender) Rollback() error { return nil }

func newTestAlertRule(t *testing.T, name, expr string, forDur time.Duration, lset, ann labels.Labels) *promRules.AlertingRule {
	t.Helper()
	return promRules.NewAlertingRule(name, mustParseTestExpr(t, expr), forDur, 0, lset, ann, labels.EmptyLabels(), "", true, promslog.NewNopLogger())
}

func TestCompareGroupRules_StrictCompatibilityDecisions(t *testing.T) {
	file := "/rules/release-bundles/t/releases/g/rules/ns"
	baseAlert := func(expr string, lset, ann labels.Labels, forDur time.Duration) *promRules.AlertingRule {
		return newTestAlertRule(t, "AlertOne", expr, forDur, lset, ann)
	}
	baseRecord := func(name, expr string, lset labels.Labels) *promRules.RecordingRule {
		return promRules.NewRecordingRule(name, mustParseTestExpr(t, expr), lset)
	}

	oldGroup := newTestPromGroup(t, file, "g1", []promRules.Rule{
		baseAlert("up == 0", labels.FromStrings("severity", "warn"), labels.FromStrings("runbook", "rb"), time.Minute),
		baseRecord("metric_one", "up", labels.EmptyLabels()),
	})

	t.Run("fully compatible identities migrate", func(t *testing.T) {
		newGroup := newTestPromGroup(t, file, "g1", []promRules.Rule{
			baseAlert("up == 0", labels.FromStrings("severity", "warn"), labels.FromStrings("runbook", "rb"), time.Minute),
			baseRecord("metric_one", "up", labels.EmptyLabels()),
		})
		allCompatible, migrations := compareGroupRules("ns", oldGroup, newGroup)
		require.True(t, allCompatible)
		for _, m := range migrations {
			require.True(t, m.Migrated, "rule %s should migrate: %s", m.RuleName, m.Reason)
			require.Equal(t, migrationCompatible, m.Reason)
		}
	})

	t.Run("different expression text rebuilds even if semantically similar", func(t *testing.T) {
		newGroup := newTestPromGroup(t, file, "g1", []promRules.Rule{
			baseAlert("up == 0 * 1", labels.FromStrings("severity", "warn"), labels.FromStrings("runbook", "rb"), time.Minute),
			baseRecord("metric_one", "up", labels.EmptyLabels()),
		})
		allCompatible, migrations := compareGroupRules("ns", oldGroup, newGroup)
		require.False(t, allCompatible)
		var alertDecision *RuleStateMigration
		for i := range migrations {
			if migrations[i].RuleName == "AlertOne" {
				alertDecision = &migrations[i]
			}
		}
		require.NotNil(t, alertDecision)
		require.False(t, alertDecision.Migrated)
		require.Equal(t, migrationExprChanged, alertDecision.Reason)
	})

	t.Run("changed labels breaks the identity", func(t *testing.T) {
		newGroup := newTestPromGroup(t, file, "g1", []promRules.Rule{
			baseAlert("up == 0", labels.FromStrings("severity", "critical"), labels.FromStrings("runbook", "rb"), time.Minute),
			baseRecord("metric_one", "up", labels.EmptyLabels()),
		})
		allCompatible, migrations := compareGroupRules("ns", oldGroup, newGroup)
		require.False(t, allCompatible)
		require.Equal(t, migrationNewRule, migrations[0].Reason)
	})

	t.Run("changed annotation rebuilds alert state", func(t *testing.T) {
		newGroup := newTestPromGroup(t, file, "g1", []promRules.Rule{
			baseAlert("up == 0", labels.FromStrings("severity", "warn"), labels.FromStrings("runbook", "other"), time.Minute),
			baseRecord("metric_one", "up", labels.EmptyLabels()),
		})
		allCompatible, migrations := compareGroupRules("ns", oldGroup, newGroup)
		require.False(t, allCompatible)
		require.Equal(t, migrationAnnotationsChanged, migrations[0].Reason)
	})

	t.Run("changed for duration rebuilds alert state", func(t *testing.T) {
		newGroup := newTestPromGroup(t, file, "g1", []promRules.Rule{
			baseAlert("up == 0", labels.FromStrings("severity", "warn"), labels.FromStrings("runbook", "rb"), 2*time.Minute),
			baseRecord("metric_one", "up", labels.EmptyLabels()),
		})
		allCompatible, migrations := compareGroupRules("ns", oldGroup, newGroup)
		require.False(t, allCompatible)
		require.Equal(t, migrationForChanged, migrations[0].Reason)
	})

	t.Run("added and removed rules are reported", func(t *testing.T) {
		newGroup := newTestPromGroup(t, file, "g1", []promRules.Rule{
			baseAlert("up == 0", labels.FromStrings("severity", "warn"), labels.FromStrings("runbook", "rb"), time.Minute),
			baseRecord("metric_one", "up", labels.EmptyLabels()),
			baseRecord("metric_two", "up", labels.EmptyLabels()),
		})
		allCompatible, migrations := compareGroupRules("ns", oldGroup, newGroup)
		require.False(t, allCompatible)
		reasons := map[string]string{}
		for _, m := range migrations {
			reasons[m.RuleName] = m.Reason
		}
		require.Equal(t, migrationNewRule, reasons["metric_two"])
	})

	t.Run("removed rule is reported as removed", func(t *testing.T) {
		newGroup := newTestPromGroup(t, file, "g1", []promRules.Rule{
			baseAlert("up == 0", labels.FromStrings("severity", "warn"), labels.FromStrings("runbook", "rb"), time.Minute),
		})
		allCompatible, migrations := compareGroupRules("ns", oldGroup, newGroup)
		require.False(t, allCompatible)
		var removed *RuleStateMigration
		for i := range migrations {
			if migrations[i].Reason == migrationRemovedRule {
				removed = &migrations[i]
			}
		}
		require.NotNil(t, removed)
		require.Equal(t, "metric_one", removed.RuleName)
	})
}

func newTestFiringGroup(t *testing.T, name, expr string) *promRules.Group {
	t.Helper()
	return promRules.NewGroup(promRules.GroupOptions{
		Name:     name,
		File:     "/rules/release-bundles/t/releases/g/rules/ns",
		Interval: time.Minute,
		Rules: []promRules.Rule{
			newTestAlertRule(t, "AlertOne", expr, time.Minute, labels.EmptyLabels(), labels.EmptyLabels()),
		},
		Opts: &promRules.ManagerOptions{
			Context:    user.InjectOrgID(context.Background(), bundleTestTenant),
			Registerer: prometheus.NewRegistry(),
			QueryFunc: func(_ context.Context, _ string, ts time.Time) (promql.Vector, error) {
				return promql.Vector{{
					Metric: labels.FromStrings("__name__", "up", "instance", "localhost"),
					T:      ts.UnixMilli(),
					F:      1,
				}}, nil
			},
			Appendable: noopAppendable{},
			NotifyFunc: func(_ context.Context, _ string, _ ...*promRules.Alert) {},
			Logger:     promslog.NewNopLogger(),
		},
	})
}

func groupAlertingRule(t *testing.T, g *promRules.Group) *promRules.AlertingRule {
	t.Helper()
	rule, ok := g.Rules()[0].(*promRules.AlertingRule)
	require.True(t, ok)
	return rule
}

func TestMigration_CopyStateOnlyAppliedToCompatibleGroups(t *testing.T) {
	// The old groups have evaluated once and hold an active alert.
	oldCompatible := newTestFiringGroup(t, "compatible", "up == 0")
	oldIncompatible := newTestFiringGroup(t, "rebuilt", "up == 0")

	now := time.Now()
	oldCompatible.Eval(context.Background(), now)
	oldIncompatible.Eval(context.Background(), now)
	require.Equal(t, 1, groupAlertingRule(t, oldCompatible).ActiveAlertsCount())
	require.Equal(t, 1, groupAlertingRule(t, oldIncompatible).ActiveAlertsCount())

	newCompatible := newTestFiringGroup(t, "compatible", "up == 0")
	newIncompatible := newTestFiringGroup(t, "rebuilt", "up == 1")

	ok, _ := compareGroupRules("ns", oldCompatible, newCompatible)
	require.True(t, ok)
	newCompatible.CopyState(oldCompatible)
	// Strictly compatible identity: the active alert state is carried over.
	require.Equal(t, 1, groupAlertingRule(t, newCompatible).ActiveAlertsCount())

	ok, _ = compareGroupRules("ns", oldIncompatible, newIncompatible)
	require.False(t, ok)
	// CopyState is deliberately not invoked: the incompatible group starts
	// fresh with no migrated alert state.
	require.Zero(t, groupAlertingRule(t, newIncompatible).ActiveAlertsCount())
}
