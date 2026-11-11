// SPDX-License-Identifier: AGPL-3.0-only
package scheduler

import (
	"context"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"github.com/thanos-io/promql-engine/logicalplan"
	"github.com/weaveworks/common/httpgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cortexproject/cortex/pkg/distributed_execution"
	"github.com/cortexproject/cortex/pkg/distributed_execution/plan_fragments"
	frontendv1 "github.com/cortexproject/cortex/pkg/frontend/v1"
	"github.com/cortexproject/cortex/pkg/scheduler/admission"
	"github.com/cortexproject/cortex/pkg/scheduler/schedulerpb"
	"github.com/cortexproject/cortex/pkg/util/flagext"
	"github.com/cortexproject/cortex/pkg/util/services"
	"github.com/cortexproject/cortex/pkg/util/test"
	"github.com/cortexproject/cortex/pkg/util/users"
)

func testAdmissionConfig() admission.Config {
	return admission.Config{
		Enabled:                       true,
		MaxInFlightTasks:              4,
		MaxTasksPerRootQuery:          4,
		DefaultTenantMaxInFlightTasks: 4,
		DefaultTenantTaskWeight:       1,
		LeaseTTL:                      time.Minute,
		EnqueueWaitTimeout:            5 * time.Second,
		ReapInterval:                  time.Minute,
	}
}

func setupSchedulerWithAdmission(t *testing.T, reg prometheus.Registerer, admissionCfg admission.Config, distributedExecEnabled bool) (*Scheduler, schedulerpb.SchedulerForFrontendClient, schedulerpb.SchedulerForQuerierClient) {
	t.Helper()

	cfg := Config{}
	flagext.DefaultValues(&cfg)
	cfg.Admission = admissionCfg

	s, err := NewScheduler(cfg, frontendv1.MockLimits{Queriers: 2, MaxOutstanding: testMaxOutstandingPerTenant}, users.NewMultiResolver(), log.NewNopLogger(), reg, distributedExecEnabled)
	require.NoError(t, err)

	server := grpc.NewServer()
	schedulerpb.RegisterSchedulerForFrontendServer(server, s)
	schedulerpb.RegisterSchedulerForQuerierServer(server, s)

	require.NoError(t, services.StartAndAwaitRunning(context.Background(), s))
	t.Cleanup(func() {
		_ = services.StopAndAwaitTerminated(context.Background(), s)
	})

	l, err := net.Listen("tcp", "")
	require.NoError(t, err)

	go func() {
		_ = server.Serve(l)
	}()
	t.Cleanup(func() {
		_ = l.Close()
	})

	c, err := grpc.NewClient(l.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = c.Close()
	})

	return s, schedulerpb.NewSchedulerForFrontendClient(c), schedulerpb.NewSchedulerForQuerierClient(c)
}

func enqueueMsg(queryID uint64, user string) *schedulerpb.FrontendToScheduler {
	return &schedulerpb.FrontendToScheduler{
		Type:        schedulerpb.ENQUEUE,
		QueryID:     queryID,
		UserID:      user,
		HttpRequest: &httpgrpc.HTTPRequest{Method: "GET", Url: "/hello"},
	}
}

// asyncEnqueue sends an ENQUEUE on an already initialized loop and reports the
// response (or an ERROR response) on the returned channel.
func asyncEnqueue(t *testing.T, loop schedulerpb.SchedulerForFrontend_FrontendLoopClient, req *schedulerpb.FrontendToScheduler) <-chan *schedulerpb.SchedulerToFrontend {
	t.Helper()
	ch := make(chan *schedulerpb.SchedulerToFrontend, 1)
	go func() {
		if err := loop.Send(req); err != nil {
			ch <- &schedulerpb.SchedulerToFrontend{Status: schedulerpb.ERROR, Error: err.Error()}
			return
		}
		resp, err := loop.Recv()
		if err != nil {
			ch <- &schedulerpb.SchedulerToFrontend{Status: schedulerpb.ERROR, Error: err.Error()}
			return
		}
		ch <- resp
	}()
	return ch
}

func assertNoResponse(t *testing.T, ch <-chan *schedulerpb.SchedulerToFrontend, wait time.Duration) {
	t.Helper()
	select {
	case resp := <-ch:
		t.Fatalf("expected enqueue to stay blocked, got status %v (%s)", resp.Status, resp.Error)
	case <-time.After(wait):
	}
}

// TestSchedulerAdmissionDisabledByDefault proves the zero-config behavior is
// unchanged: no manager is constructed and requests follow the legacy path.
func TestSchedulerAdmissionDisabledByDefault(t *testing.T) {
	scheduler, frontendClient, querierClient := setupScheduler(t, nil, false)
	require.Nil(t, scheduler.admission)

	frontendLoop := initFrontendLoop(t, frontendClient, "frontend-12345")
	frontendToScheduler(t, frontendLoop, &schedulerpb.FrontendToScheduler{
		Type:        schedulerpb.ENQUEUE,
		QueryID:     1,
		UserID:      "test",
		HttpRequest: &httpgrpc.HTTPRequest{Method: "GET", Url: "/hello"},
	})

	querierLoop := initQuerierLoop(t, querierClient, "querier-1")
	msg, err := querierLoop.Recv()
	require.NoError(t, err)
	require.Equal(t, uint64(1), msg.QueryID)
	require.NoError(t, querierLoop.Send(&schedulerpb.QuerierToScheduler{}))

	verifyNoTrackedRequestsLeft(t, scheduler)
}

// TestSchedulerAdmissionMultiTenantContention drives federated ("a|b")
// requests against weighted per-tenant quotas and asserts that actual in-flight
// work never exceeds the limits, that blocked enqueues wait without leaking
// reservations, and that every account finally returns to zero.
func TestSchedulerAdmissionMultiTenantContention(t *testing.T) {
	cfg := testAdmissionConfig()
	// Every federated task reserves a=1 and b=2: tenant-b quota 4 allows at
	// most two concurrent tasks, even though the global pool allows four.
	cfg.TenantTaskWeight = map[string]float64{"tenant-b": 2}

	scheduler, frontendClient, querierClient := setupSchedulerWithAdmission(t, prometheus.NewPedanticRegistry(), cfg, false)

	// Background invariant checker: actual in-flight admission must never
	// exceed the global pool or any tenant quota while the test runs.
	stopChecker := make(chan struct{})
	checkerDone := make(chan struct{})
	go func() {
		defer close(checkerDone)
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopChecker:
				return
			case <-ticker.C:
				if inflight := scheduler.admission.GlobalInflight(); inflight > cfg.MaxInFlightTasks {
					t.Errorf("global inflight %d exceeds cap %d", inflight, cfg.MaxInFlightTasks)
				}
				if used := scheduler.admission.TenantInflight("tenant-b"); used > cfg.DefaultTenantMaxInFlightTasks {
					t.Errorf("tenant-b weighted inflight %v exceeds quota %v", used, cfg.DefaultTenantMaxInFlightTasks)
				}
			}
		}
	}()
	t.Cleanup(func() {
		close(stopChecker)
		<-checkerDone
	})

	const totalRequests = 4
	resultChs := make([]<-chan *schedulerpb.SchedulerToFrontend, totalRequests)
	loops := make([]schedulerpb.SchedulerForFrontend_FrontendLoopClient, totalRequests)
	for i := range totalRequests {
		loops[i] = initFrontendLoop(t, frontendClient, "frontend-"+string(rune('0'+i)))
		resultChs[i] = asyncEnqueue(t, loops[i], enqueueMsg(uint64(i+1), "tenant-a|tenant-b"))
	}

	// Two queriers take the first two tasks and hold them, so the tenant-b
	// quota (2 tasks * weight 2) is fully consumed.
	querier1 := initQuerierLoop(t, querierClient, "querier-1")
	querier2 := initQuerierLoop(t, querierClient, "querier-2")

	held1, err := querier1.Recv()
	require.NoError(t, err)
	held2, err := querier2.Recv()
	require.NoError(t, err)

	test.Poll(t, time.Second, 2, func() any { return scheduler.admission.GlobalInflight() })
	require.Equal(t, 2.0, scheduler.admission.TenantInflight("tenant-a"))
	require.Equal(t, 4.0, scheduler.admission.TenantInflight("tenant-b"))

	// The remaining federated requests cannot be admitted while tenant-b is
	// saturated: no cheap single slot for the joined userID.
	assertNoResponse(t, resultChs[2], 300*time.Millisecond)
	assertNoResponse(t, resultChs[3], 100*time.Millisecond)
	require.Equal(t, 2, scheduler.admission.GlobalInflight())

	// Finish one held task: its credits return and one blocked request is
	// admitted and dispatched, restoring the same saturated accounting.
	require.NoError(t, querier1.Send(&schedulerpb.QuerierToScheduler{}))
	next, err := querier1.Recv()
	require.NoError(t, err)
	require.NotEqual(t, held1.QueryID, next.QueryID)

	test.Poll(t, time.Second, 2, func() any { return scheduler.admission.GlobalInflight() })
	require.Equal(t, 4.0, scheduler.admission.TenantInflight("tenant-b"))
	require.Equal(t, 2.0, scheduler.admission.TenantInflight("tenant-a"))

	// Drain everything: finishing B admits the last blocked request, which is
	// dispatched to the only querier loop waiting for work (querier-2).
	require.NoError(t, querier2.Send(&schedulerpb.QuerierToScheduler{}))
	lastTask, err := querier2.Recv()
	require.NoError(t, err)
	require.NotEqual(t, held2.QueryID, lastTask.QueryID)

	// Finish C (held by querier-1) and the last task D (held by querier-2).
	require.NoError(t, querier1.Send(&schedulerpb.QuerierToScheduler{}))
	require.NoError(t, querier2.Send(&schedulerpb.QuerierToScheduler{}))

	for i := range totalRequests {
		select {
		case resp := <-resultChs[i]:
			require.Equal(t, schedulerpb.OK, resp.Status, "enqueue %d failed: %s", i+1, resp.Error)
		case <-time.After(5 * time.Second):
			t.Fatalf("enqueue %d never completed", i+1)
		}
	}

	// Explicitly cancel every root so leases close once their work ends, then
	// assert the whole ledger settles at zero.
	for i := range totalRequests {
		require.NoError(t, loops[i].Send(&schedulerpb.FrontendToScheduler{
			Type:    schedulerpb.CANCEL,
			QueryID: uint64(i + 1),
		}))
		resp, err := loops[i].Recv()
		require.NoError(t, err)
		require.Equal(t, schedulerpb.OK, resp.Status)
	}

	test.Poll(t, 2*time.Second, 0, func() any { return scheduler.admission.GlobalInflight() })
	require.Equal(t, 0, scheduler.admission.ActiveLeases())
	require.Equal(t, 0.0, scheduler.admission.TenantInflight("tenant-a"))
	require.Equal(t, 0.0, scheduler.admission.TenantInflight("tenant-b"))
}

// TestSchedulerAdmissionFragmentFanoutPerRootCap fragments a logical plan into
// multiple fragments while the per-root cap is one: fragments are admitted one
// at a time as the querier releases each previous task.
func TestSchedulerAdmissionFragmentFanoutPerRootCap(t *testing.T) {
	cfg := testAdmissionConfig()
	cfg.MaxInFlightTasks = 10
	cfg.MaxTasksPerRootQuery = 1
	cfg.DefaultTenantMaxInFlightTasks = 10

	scheduler, frontendClient, querierClient := setupSchedulerWithAdmission(t, prometheus.NewPedanticRegistry(), cfg, true)
	scheduler.distributedExecEnabled = true

	frontendLoop := initFrontendLoop(t, frontendClient, "frontend-fanout")

	lp, err := distributed_execution.CreateTestLogicalPlan("sum(rate(node_cpu_seconds_total{mode!=\"idle\"}[5m])) + sum(rate(node_memory_Active_bytes[5m]))", time.Now(), time.Now(), 0)
	require.NoError(t, err)
	body, err := logicalplan.Marshal((*lp).Root())
	require.NoError(t, err)
	form := url.Values{}
	form.Set("plan", string(body))

	enqueueResp := asyncEnqueue(t, frontendLoop, &schedulerpb.FrontendToScheduler{
		Type:        schedulerpb.ENQUEUE,
		QueryID:     42,
		UserID:      "tenant-a",
		HttpRequest: &httpgrpc.HTTPRequest{Method: "POST", Url: "/hello", Body: []byte(form.Encode())},
	})

	querierLoop := initQuerierLoop(t, querierClient, "querier-1")

	rootSeen := false
	for range 3 {
		// Strict request/response pacing: only acknowledge after the task has
		// been received, so its admission credit stays held while we inspect
		// the in-flight accounting.
		msg, err := querierLoop.Recv()
		require.NoError(t, err)
		require.Equal(t, uint64(42), msg.QueryID)

		// While the task is in-flight the root lease can hold exactly one.
		test.Poll(t, time.Second, 1, func() any { return scheduler.admission.GlobalInflight() })
		if msg.IsRoot {
			rootSeen = true
		}

		// Confirming the end returns the credit, allowing the next fragment of
		// the same root lease to be admitted.
		require.NoError(t, querierLoop.Send(&schedulerpb.QuerierToScheduler{}))
	}
	require.True(t, rootSeen, "root fragment must be dispatched")

	select {
	case resp := <-enqueueResp:
		require.Equal(t, schedulerpb.OK, resp.Status, resp.Error)
	case <-time.After(5 * time.Second):
		t.Fatal("fragmented enqueue never completed")
	}

	require.NoError(t, frontendLoop.Send(&schedulerpb.FrontendToScheduler{Type: schedulerpb.CANCEL, QueryID: 42}))
	cancelResp, err := frontendLoop.Recv()
	require.NoError(t, err)
	require.Equal(t, schedulerpb.OK, cancelResp.Status)

	test.Poll(t, 2*time.Second, 0, func() any { return scheduler.admission.GlobalInflight() })
	require.Equal(t, 0, scheduler.admission.ActiveLeases())
}

// TestSchedulerAdmissionCancelRetainsDispatchedCredits verifies the
// cancellation semantics directly: queued tasks release immediately, while
// already dispatched tasks keep their credits until the confirmed end.
func TestSchedulerAdmissionCancelRetainsDispatchedCredits(t *testing.T) {
	cfg := testAdmissionConfig()
	scheduler, _, _ := setupSchedulerWithAdmission(t, prometheus.NewPedanticRegistry(), cfg, false)

	lk := admission.LeaseKey{FrontendAddress: "frontend-1", QueryID: 100}
	attempt, err := scheduler.admission.BeginRoot(lk, []string{"tenant-a"})
	require.NoError(t, err)

	t.Run("queued task is released immediately on cancel", func(t *testing.T) {
		grant, err := scheduler.admission.Admit(context.Background(), lk, attempt)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		req := &schedulerRequest{
			frontendAddress:  "frontend-1",
			queryID:          100,
			ctx:              ctx,
			ctxCancel:        cancel,
			fragment:         fragmentWithID(7),
			admissionGrant:   grant,
			admissionAttempt: attempt,
		}
		t.Cleanup(cancel)

		scheduler.trackedRequestsMu.Lock()
		qk := queryKey{frontendAddr: "frontend-1", queryID: 100}
		scheduler.queryFragmentRegistry[qk] = []uint64{7}
		scheduler.trackedRequests[requestKey{queryKey: qk, fragmentID: 7}] = req
		scheduler.trackedRequestsMu.Unlock()

		scheduler.cancelRequestAndRemoveFromTracked("frontend-1", 100, 0, true)

		scheduler.trackedRequestsMu.Lock()
		_, present := scheduler.trackedRequests[requestKey{queryKey: qk, fragmentID: 7}]
		scheduler.trackedRequestsMu.Unlock()
		require.False(t, present)
		require.Equal(t, 0, scheduler.admission.GlobalInflight())
	})

	t.Run("dispatched task keeps credits until confirmed end", func(t *testing.T) {
		grant, err := scheduler.admission.Admit(context.Background(), lk, attempt)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		req := &schedulerRequest{
			frontendAddress:     "frontend-1",
			queryID:             100,
			ctx:                 ctx,
			ctxCancel:           cancel,
			fragment:            fragmentWithID(8),
			admissionGrant:      grant,
			admissionAttempt:    attempt,
			admissionDispatched: true,
		}
		t.Cleanup(cancel)

		scheduler.trackedRequestsMu.Lock()
		qk := queryKey{frontendAddr: "frontend-1", queryID: 100}
		scheduler.queryFragmentRegistry[qk] = []uint64{8}
		scheduler.trackedRequests[requestKey{queryKey: qk, fragmentID: 8}] = req
		scheduler.trackedRequestsMu.Unlock()

		// Root cancellation must not return the in-flight credit.
		scheduler.admission.CancelRoot(lk)
		scheduler.cancelRequestAndRemoveFromTracked("frontend-1", 100, 0, true)

		scheduler.trackedRequestsMu.Lock()
		_, present := scheduler.trackedRequests[requestKey{queryKey: qk, fragmentID: 8}]
		scheduler.trackedRequestsMu.Unlock()
		require.True(t, present, "dispatched task stays tracked until confirmed end")
		require.Equal(t, 1, scheduler.admission.GlobalInflight())
		_, inflight, canceled, ok := scheduler.admission.LeaseState(lk)
		require.True(t, ok)
		require.True(t, canceled)
		require.Equal(t, 1, inflight)

		// The confirmed forwarding end returns the credit exactly once.
		scheduler.cancelRequestAndRemoveFromTracked("frontend-1", 100, 8, false)
		scheduler.cancelRequestAndRemoveFromTracked("frontend-1", 100, 8, false)

		require.Equal(t, 0, scheduler.admission.GlobalInflight())
		require.Equal(t, 0, scheduler.admission.ActiveLeases())
	})
}

// TestSchedulerAdmissionRetryAdvancesAttempt drives a reconnect with the same
// frontend address and query ID through the real streams and asserts the
// re-enqueue is associated with a new root lease attempt.
func TestSchedulerAdmissionRetryAdvancesAttempt(t *testing.T) {
	cfg := testAdmissionConfig()
	scheduler, frontendClient, querierClient := setupSchedulerWithAdmission(t, prometheus.NewPedanticRegistry(), cfg, false)

	lk := admission.LeaseKey{FrontendAddress: "frontend-retry", QueryID: 77}

	firstLoop := initFrontendLoop(t, frontendClient, "frontend-retry")
	frontendToScheduler(t, firstLoop, enqueueMsg(77, "tenant-a"))

	querierLoop := initQuerierLoop(t, querierClient, "querier-1")
	msg, err := querierLoop.Recv()
	require.NoError(t, err)
	require.Equal(t, uint64(77), msg.QueryID)

	attempt, inflight, _, ok := scheduler.admission.LeaseState(lk)
	require.True(t, ok)
	require.EqualValues(t, 1, attempt)
	require.Equal(t, 1, inflight)

	// Frontend disconnects: the in-flight task reaches its confirmed end (the
	// server tears the forwarding down) and credits return. The lease itself
	// survives within its TTL.
	require.NoError(t, firstLoop.CloseSend())
	_ = querierLoop.CloseSend()
	test.Poll(t, 2*time.Second, 0, func() any { return scheduler.admission.GlobalInflight() })

	// Reconnect with the same identity and re-enqueue the same query: it must
	// bind to attempt 2 of the same lease, never reusing attempt-1 grants. A
	// fresh querier stream is needed because the old one ended with the
	// frontend disconnect.
	secondLoop := initFrontendLoop(t, frontendClient, "frontend-retry")
	frontendToScheduler(t, secondLoop, enqueueMsg(77, "tenant-a"))

	attempt, _, _, ok = scheduler.admission.LeaseState(lk)
	require.True(t, ok)
	require.EqualValues(t, 2, attempt)

	retriedQuerier := initQuerierLoop(t, querierClient, "querier-2")
	retried, err := retriedQuerier.Recv()
	require.NoError(t, err)
	require.Equal(t, uint64(77), retried.QueryID)
	require.NoError(t, retriedQuerier.Send(&schedulerpb.QuerierToScheduler{}))

	require.NoError(t, secondLoop.Send(&schedulerpb.FrontendToScheduler{Type: schedulerpb.CANCEL, QueryID: 77}))
	resp, err := secondLoop.Recv()
	require.NoError(t, err)
	require.Equal(t, schedulerpb.OK, resp.Status)

	test.Poll(t, 2*time.Second, 0, func() any { return scheduler.admission.ActiveLeases() })
	require.Equal(t, 0, scheduler.admission.GlobalInflight())
}

// TestSchedulerAdmissionShutdownReleasesWaiters ensures an enqueue blocked on
// credits is unblocked when the scheduler stops instead of hanging forever.
func TestSchedulerAdmissionShutdownReleasesWaiters(t *testing.T) {
	cfg := testAdmissionConfig()
	cfg.MaxInFlightTasks = 1
	cfg.MaxTasksPerRootQuery = 1
	scheduler, frontendClient, querierClient := setupSchedulerWithAdmission(t, prometheus.NewPedanticRegistry(), cfg, false)

	firstLoop := initFrontendLoop(t, frontendClient, "frontend-1")
	frontendToScheduler(t, firstLoop, enqueueMsg(1, "tenant-a"))

	querierLoop := initQuerierLoop(t, querierClient, "querier-1")
	_, err := querierLoop.Recv()
	require.NoError(t, err) // holds the single credit

	blockedLoop := initFrontendLoop(t, frontendClient, "frontend-2")
	blocked := asyncEnqueue(t, blockedLoop, enqueueMsg(2, "tenant-a"))
	assertNoResponse(t, blocked, 300*time.Millisecond)

	// Stopping the scheduler wakes every admission waiter.
	require.NoError(t, services.StopAndAwaitTerminated(context.Background(), scheduler))

	select {
	case resp := <-blocked:
		require.NotEqual(t, schedulerpb.OK, resp.Status)
	case <-time.After(3 * time.Second):
		t.Fatal("blocked enqueue was not released on scheduler shutdown")
	}
}

// TestSchedulerAdmissionMetricsLabels uses query-independent labels only.
func TestSchedulerAdmissionMetricsLabels(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	cfg := testAdmissionConfig()
	scheduler, frontendClient, _ := setupSchedulerWithAdmission(t, reg, cfg, false)

	frontendLoop := initFrontendLoop(t, frontendClient, "frontend-metrics")
	frontendToScheduler(t, frontendLoop, enqueueMsg(1, "tenant-a"))
	test.Poll(t, time.Second, 1, func() any { return scheduler.admission.GlobalInflight() })

	families, err := reg.Gather()
	require.NoError(t, err)

	admissionMetrics := 0
	for _, family := range families {
		if family.GetName() == "cortex_query_scheduler_admission_inflight_tasks" {
			admissionMetrics++
			for _, metric := range family.GetMetric() {
				for _, label := range metric.GetLabel() {
					require.NotContains(t, label.GetName(), "query")
				}
			}
		}
	}
	require.Equal(t, 1, admissionMetrics)
}

// Small helper kept local to the cancellation test.
func fragmentWithID(id uint64) plan_fragments.Fragment {
	return plan_fragments.Fragment{FragmentID: id, IsRoot: id == 0}
}
