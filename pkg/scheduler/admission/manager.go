// SPDX-License-Identifier: AGPL-3.0-only
package admission

import (
	"context"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/cortexproject/cortex/pkg/util/services"
	"github.com/cortexproject/cortex/pkg/util/users"
)

var (
	// ErrStopped is returned once the manager is shutting down. All pending
	// waiters fail with this error and no new admissions are accepted.
	ErrStopped = errors.New("query admission lease manager is stopped")
	// ErrRootCanceled is returned when the root query owning the lease has been
	// canceled. New fragments cannot be admitted after cancellation.
	ErrRootCanceled = errors.New("root query lease has been canceled")
	// ErrLeaseStale is returned when the enqueue references an attempt that has
	// been superseded by a newer retry of the same root query.
	ErrLeaseStale = errors.New("root query lease attempt is stale")
	// ErrAdmissionTimeout is returned when an enqueue cannot reserve enough
	// credits within EnqueueWaitTimeout.
	ErrAdmissionTimeout = errors.New("timed out waiting for query admission lease credits")
	// ErrUnknownLease is returned when no root lease exists for the request.
	ErrUnknownLease = errors.New("root query lease not found")

	errInsufficientCredits = errors.New("insufficient admission credits")

	// epsilon keeps float bookkeeping stable for configured fractional weights.
	epsilon = 1e-9
)

// Admission result labels. They deliberately never contain query identifiers.
const (
	resultAccepted = "accepted"
	resultTimeout  = "timeout"
	resultCanceled = "canceled"
	resultRejected = "rejected"
	resultStopped  = "stopped"

	reapReasonTTL = "ttl"
)

// LeaseKey identifies a root query lease within a single scheduler instance.
// It is the same identity the scheduler uses to track the root query.
type LeaseKey struct {
	FrontendAddress string
	QueryID         uint64
}

// Grant is the proof that one fragment task has been admitted. It holds the
// credits reserved on behalf of the task and returns them exactly once when
// Release is called. A late completion of an old attempt can only release the
// grant of that old attempt; it can never touch the grant of a newer attempt.
type Grant struct {
	Token      uint64
	Lease      LeaseKey
	Attempt    uint64
	tenants    []string
	weights    []float64
	admittedAt time.Time

	// released is guarded by Manager.mtx.
	released bool
}

// rootLease keeps the accounting state of one root query and all of its
// fragments and attempts.
type rootLease struct {
	key     LeaseKey
	tenants []string // sorted and de-duplicated authorized tenants

	// attempt is incremented every time the root query is (re-)enqueued, so
	// retries and reconnects are associated with a fresh attempt while grants
	// of previous attempts stay bound to their own tokens.
	attempt  uint64
	canceled bool

	createdAt    time.Time
	lastActivity time.Time

	// inflight is the number of currently held grants of this lease; tasks is
	// the set of those grants keyed by their unique token.
	inflight int
	tasks    map[uint64]*Grant
}

// waiter is a single blocked Admit call. It waits on its own channel instead
// of on a condition variable held together with the accounting lock, so
// blocked enqueues never keep any global lock occupied.
type waiter struct {
	ch chan struct{}
}

// Manager owns all QueryAdmissionLease accounting of one scheduler instance.
// Everything is in memory and dies with the process; it never pretends to be a
// distributed or persistent global quota.
type Manager struct {
	services.Service

	cfg Config
	log log.Logger

	mtx     sync.Mutex
	stopped bool

	waiters map[*waiter]struct{}

	nextToken      uint64
	globalInflight int
	tenantInflight map[string]float64
	leases         map[LeaseKey]*rootLease

	// Metrics. Labels identify tenants and outcomes, never individual queries.
	inflightGauge       prometheus.Gauge
	tenantInflightGauge *prometheus.GaugeVec
	leasesGauge         prometheus.Gauge
	admitTotal          *prometheus.CounterVec
	waitDuration        *prometheus.HistogramVec
	reclaimedTasks      *prometheus.CounterVec
}

// NewManager creates a new lease manager. The returned service must be started
// and stopped together with the scheduler.
func NewManager(cfg Config, logger log.Logger, registerer prometheus.Registerer) *Manager {
	m := &Manager{
		cfg:            cfg,
		log:            logger,
		waiters:        map[*waiter]struct{}{},
		tenantInflight: map[string]float64{},
		leases:         map[LeaseKey]*rootLease{},

		inflightGauge: promauto.With(registerer).NewGauge(prometheus.GaugeOpts{
			Name: "cortex_query_scheduler_admission_inflight_tasks",
			Help: "Number of fragment tasks currently admitted (in-flight) in this query-scheduler instance.",
		}),
		tenantInflightGauge: promauto.With(registerer).NewGaugeVec(prometheus.GaugeOpts{
			Name: "cortex_query_scheduler_admission_tenant_inflight_tasks",
			Help: "Weighted in-flight quota currently reserved against a tenant by admitted tasks.",
		}, []string{"user"}),
		leasesGauge: promauto.With(registerer).NewGauge(prometheus.GaugeOpts{
			Name: "cortex_query_scheduler_admission_leases",
			Help: "Number of active root query admission leases in this query-scheduler instance.",
		}),
		admitTotal: promauto.With(registerer).NewCounterVec(prometheus.CounterOpts{
			Name: "cortex_query_scheduler_admission_admissions_total",
			Help: "Total number of fragment task admission attempts by result.",
		}, []string{"result"}),
		waitDuration: promauto.With(registerer).NewHistogramVec(prometheus.HistogramOpts{
			Name:                            "cortex_query_scheduler_admission_wait_duration_seconds",
			Help:                            "Time spent waiting for admission credits before an admission result.",
			Buckets:                         []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
			NativeHistogramBucketFactor:     1.1,
			NativeHistogramMaxBucketNumber:  100,
			NativeHistogramMinResetDuration: time.Hour,
		}, []string{"result"}),
		reclaimedTasks: promauto.With(registerer).NewCounterVec(prometheus.CounterOpts{
			Name: "cortex_query_scheduler_admission_reclaimed_tasks_total",
			Help: "Total number of task grants force-reclaimed without an explicit release, by reason.",
		}, []string{"reason"}),
	}

	m.Service = services.NewBasicService(m.starting, m.running, m.stopping).WithName("query-admission-lease")
	return m
}

func (m *Manager) starting(_ context.Context) error {
	return nil
}

// running periodically reaps grants and leases that exceeded their TTL.
func (m *Manager) running(ctx context.Context) error {
	ticker := time.NewTicker(m.cfg.ReapInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			m.reap()
		}
	}
}

// stopping marks the manager stopped and releases every blocked waiter, so a
// scheduler shutdown never leaves enqueues hanging.
func (m *Manager) stopping(_ error) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	m.stopped = true
	m.wakeAllLocked()
	return nil
}

// BeginRoot creates the root lease for a query or, on retry/reconnect, bumps
// the attempt of the existing lease. It returns the attempt number that
// subsequent fragment admissions must present. Tenant IDs are normalized into
// a stable sorted order, which is then used for every reservation.
func (m *Manager) BeginRoot(key LeaseKey, tenantIDs []string) (uint64, error) {
	tenants := users.NormalizeTenantIDs(append([]string(nil), tenantIDs...))
	if len(tenants) == 0 {
		return 0, errors.New("cannot create query admission lease without an authorized tenant")
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	if m.stopped {
		return 0, ErrStopped
	}

	lease, ok := m.leases[key]
	if !ok {
		now := time.Now()
		lease = &rootLease{
			key:          key,
			tenants:      tenants,
			attempt:      1,
			createdAt:    now,
			lastActivity: now,
			tasks:        map[uint64]*Grant{},
		}
		m.leases[key] = lease
	} else {
		// Re-enqueue of the same root query: a new attempt supersedes the old
		// one. Grants of the old attempt remain reserved until their own tasks
		// terminate or the TTL reaps them; they are never transferred.
		lease.attempt++
		lease.lastActivity = time.Now()
		if !sameTenants(lease.tenants, tenants) {
			level.Warn(m.log).Log("msg", "query admission lease retry authorized different tenants; keeping the original tenant set", "frontend", key.FrontendAddress, "query_id", key.QueryID)
		}
	}

	m.leasesGauge.Set(float64(len(m.leases)))
	return lease.attempt, nil
}

// CancelRoot marks a root lease canceled. Already admitted tasks keep their
// credits until they terminate or are conservatively reaped, but no new
// fragment can be admitted afterwards, so credits cannot be over-issued.
func (m *Manager) CancelRoot(key LeaseKey) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if lease, ok := m.leases[key]; ok {
		lease.canceled = true
		lease.lastActivity = time.Now()
		// Nothing is in flight anymore: there is nothing left to wait for.
		if lease.inflight == 0 {
			delete(m.leases, key)
		}
		m.leasesGauge.Set(float64(len(m.leases)))
		m.wakeAllLocked()
	}
}

// Admit reserves credits for one fragment task:
//   - one global in-flight credit,
//   - one per-root-query credit,
//   - the configured weighted quota against every authorized tenant at once.
//
// The tenant reservation is all-or-nothing and tenants are visited in their
// normalized sorted order; on failure nothing is deducted. Admit blocks
// without holding the accounting lock until credits free up, the context is
// canceled, the wait timeout expires or the manager stops.
func (m *Manager) Admit(ctx context.Context, key LeaseKey, attempt uint64) (*Grant, error) {
	startedAt := time.Now()

	m.mtx.Lock()
	if grant, err := m.tryAdmitLocked(key, attempt); err == nil {
		m.mtx.Unlock()
		m.observeWait(resultAccepted, time.Since(startedAt))
		return grant, nil
	} else if !errors.Is(err, errInsufficientCredits) {
		m.mtx.Unlock()
		m.observeWait(resultLabel(err), time.Since(startedAt))
		return nil, err
	}

	waiter := m.addWaiterLocked()
	timer := time.NewTimer(m.cfg.EnqueueWaitTimeout)
	m.mtx.Unlock()

	defer func() {
		timer.Stop()
		m.removeWaiter(waiter)
	}()

	for {
		select {
		case <-ctx.Done():
			m.admitTotal.WithLabelValues(resultCanceled).Inc()
			m.observeWait(resultCanceled, time.Since(startedAt))
			return nil, ctx.Err()
		case <-timer.C:
			m.admitTotal.WithLabelValues(resultTimeout).Inc()
			m.observeWait(resultTimeout, time.Since(startedAt))
			return nil, ErrAdmissionTimeout
		case <-waiter.ch:
			m.mtx.Lock()
			grant, err := m.tryAdmitLocked(key, attempt)
			m.mtx.Unlock()
			if err == nil {
				m.observeWait(resultAccepted, time.Since(startedAt))
				return grant, nil
			}
			if !errors.Is(err, errInsufficientCredits) {
				m.observeWait(resultLabel(err), time.Since(startedAt))
				return nil, err
			}
			// Still out of credits: keep waiting until the same timer expires.
		}
	}
}

// tryAdmitLocked reserves everything atomically or reserves nothing at all.
// Caller must hold m.mtx. errInsufficientCredits signals that waiting may make
// progress; every other error is terminal.
func (m *Manager) tryAdmitLocked(key LeaseKey, attempt uint64) (*Grant, error) {
	if m.stopped {
		m.admitTotal.WithLabelValues(resultStopped).Inc()
		return nil, ErrStopped
	}

	lease, ok := m.leases[key]
	if !ok {
		m.admitTotal.WithLabelValues(resultRejected).Inc()
		return nil, ErrUnknownLease
	}
	if lease.canceled {
		m.admitTotal.WithLabelValues(resultRejected).Inc()
		return nil, ErrRootCanceled
	}
	if lease.attempt != attempt {
		m.admitTotal.WithLabelValues(resultRejected).Inc()
		return nil, ErrLeaseStale
	}

	if m.globalInflight >= m.cfg.MaxInFlightTasks {
		return nil, errInsufficientCredits
	}
	if lease.inflight >= m.cfg.MaxTasksPerRootQuery {
		return nil, errInsufficientCredits
	}

	// Check every tenant first: the weighted reservation is all-or-nothing.
	// Tenants are stored in normalized sorted order, giving a stable traversal.
	weights := make([]float64, len(lease.tenants))
	for i, tenant := range lease.tenants {
		weight := m.cfg.tenantWeight(tenant)
		if m.tenantInflight[tenant]+weight > m.cfg.tenantQuota(tenant)+epsilon {
			return nil, errInsufficientCredits
		}
		weights[i] = weight
	}

	// All checks passed: reserve global, per-root and every tenant quota.
	m.nextToken++
	token := m.nextToken
	now := time.Now()
	grant := &Grant{
		Token:      token,
		Lease:      key,
		Attempt:    attempt,
		tenants:    append([]string(nil), lease.tenants...),
		weights:    weights,
		admittedAt: now,
	}

	m.globalInflight++
	lease.inflight++
	lease.lastActivity = now
	lease.tasks[token] = grant
	for i, tenant := range grant.tenants {
		m.tenantInflight[tenant] += grant.weights[i]
	}

	m.admitTotal.WithLabelValues(resultAccepted).Inc()
	m.refreshGaugesLocked()
	return grant, nil
}

// Release returns every credit held by the grant. It is idempotent: the same
// task is accounted back exactly once even if cancellation and completion
// paths both run, and a grant belonging to an old attempt can never release
// credits reserved by another grant.
func (m *Manager) Release(grant *Grant) {
	if grant == nil {
		return
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.releaseLocked(grant, "")
}

// releaseLocked performs the actual accounting. reason is empty for explicit
// releases and set (and counted) when the TTL reaper force-reclaims a grant.
// Caller must hold m.mtx.
func (m *Manager) releaseLocked(grant *Grant, reason string) {
	if grant.released {
		return
	}
	grant.released = true

	if reason != "" {
		m.reclaimedTasks.WithLabelValues(reason).Inc()
	}

	m.globalInflight--
	if m.globalInflight < 0 {
		level.Error(m.log).Log("msg", "query admission lease global inflight counter went negative", "frontend", grant.Lease.FrontendAddress, "query_id", grant.Lease.QueryID)
		m.globalInflight = 0
	}

	for i, tenant := range grant.tenants {
		remaining := m.tenantInflight[tenant] - grant.weights[i]
		if remaining <= epsilon {
			delete(m.tenantInflight, tenant)
			m.tenantInflightGauge.DeletePartialMatch(prometheus.Labels{"user": tenant})
		} else {
			m.tenantInflight[tenant] = remaining
		}
	}

	lease, ok := m.leases[grant.Lease]
	if ok {
		lease.inflight--
		if lease.inflight < 0 {
			level.Error(m.log).Log("msg", "query admission lease per-root inflight counter went negative", "frontend", grant.Lease.FrontendAddress, "query_id", grant.Lease.QueryID)
			lease.inflight = 0
		}
		delete(lease.tasks, grant.Token)
		lease.lastActivity = time.Now()

		// A canceled lease with no in-flight work has nothing left to wait for.
		if lease.canceled && lease.inflight == 0 {
			delete(m.leases, grant.Lease)
		}
	}

	m.refreshGaugesLocked()
	m.wakeAllLocked()
}

// reap force-reclaims grants whose task outlived the conservative TTL, and
// garbage collects empty leases. It is the safety net that prevents a lost
// querier or a missed cancellation from leaking credits forever.
func (m *Manager) reap() {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	now := time.Now()
	for key, lease := range m.leases {
		for _, grant := range lease.tasks {
			if now.Sub(grant.admittedAt) > m.cfg.LeaseTTL {
				level.Warn(m.log).Log("msg", "query admission lease task grant exceeded TTL, force-reclaiming credits", "frontend", key.FrontendAddress, "query_id", key.QueryID, "attempt", grant.Attempt, "age", now.Sub(grant.admittedAt))
				m.releaseLocked(grant, reapReasonTTL)
			}
		}

		// Empty leases are kept for LeaseTTL to absorb late retries with the
		// same identity, then removed.
		if lease.inflight == 0 && now.Sub(lease.lastActivity) > m.cfg.LeaseTTL {
			delete(m.leases, key)
		}
	}

	m.refreshGaugesLocked()
}

func (m *Manager) addWaiterLocked() *waiter {
	w := &waiter{ch: make(chan struct{}, 1)}
	m.waiters[w] = struct{}{}
	return w
}

func (m *Manager) removeWaiter(w *waiter) {
	m.mtx.Lock()
	delete(m.waiters, w)
	m.mtx.Unlock()
}

// wakeAllLocked notifies every blocked Admit. Channel sends are non-blocking
// (each waiter channel has capacity one and pending signals coalesce).
func (m *Manager) wakeAllLocked() {
	for w := range m.waiters {
		select {
		case w.ch <- struct{}{}:
		default:
		}
	}
}

func (m *Manager) refreshGaugesLocked() {
	m.inflightGauge.Set(float64(m.globalInflight))
	m.leasesGauge.Set(float64(len(m.leases)))
	for tenant, used := range m.tenantInflight {
		m.tenantInflightGauge.WithLabelValues(tenant).Set(used)
	}
}

func (m *Manager) observeWait(result string, waited time.Duration) {
	m.waitDuration.WithLabelValues(result).Observe(waited.Seconds())
}

func resultLabel(err error) string {
	if errors.Is(err, ErrStopped) {
		return resultStopped
	}
	return resultRejected
}

func sameTenants(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// GlobalInflight returns the number of currently admitted tasks.
func (m *Manager) GlobalInflight() int {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return m.globalInflight
}

// TenantInflight returns the weighted quota currently reserved against tenant.
func (m *Manager) TenantInflight(tenant string) float64 {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return m.tenantInflight[tenant]
}

// ActiveLeases returns the number of root leases still tracked.
func (m *Manager) ActiveLeases() int {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return len(m.leases)
}

// LeaseState reports the attempt and in-flight count of a root lease. The
// boolean is false when no lease exists.
func (m *Manager) LeaseState(key LeaseKey) (attempt uint64, inflight int, canceled bool, ok bool) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	lease, exists := m.leases[key]
	if !exists {
		return 0, 0, false, false
	}
	return lease.attempt, lease.inflight, lease.canceled, true
}
