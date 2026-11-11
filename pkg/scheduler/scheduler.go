package scheduler

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	otgrpc "github.com/opentracing-contrib/go-grpc"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/thanos-io/promql-engine/logicalplan"
	"github.com/weaveworks/common/httpgrpc"
	"github.com/weaveworks/common/middleware"
	"github.com/weaveworks/common/user"
	"google.golang.org/grpc"

	"github.com/cortexproject/cortex/pkg/distributed_execution"
	"github.com/cortexproject/cortex/pkg/distributed_execution/plan_fragments"
	"github.com/cortexproject/cortex/pkg/frontend/v2/frontendv2pb"
	"github.com/cortexproject/cortex/pkg/querier/stats" //lint:ignore faillint scheduler needs to retrieve priority from the context
	"github.com/cortexproject/cortex/pkg/scheduler/admission"
	"github.com/cortexproject/cortex/pkg/scheduler/fragment_table"
	"github.com/cortexproject/cortex/pkg/scheduler/queue"
	"github.com/cortexproject/cortex/pkg/scheduler/schedulerpb"
	"github.com/cortexproject/cortex/pkg/util/grpcclient"
	"github.com/cortexproject/cortex/pkg/util/httpgrpcutil"
	"github.com/cortexproject/cortex/pkg/util/services"
	"github.com/cortexproject/cortex/pkg/util/users"
	"github.com/cortexproject/cortex/pkg/util/validation"
)

var (
	errSchedulerIsNotRunning = errors.New("scheduler is not running")
)

// Scheduler is responsible for queueing and dispatching queries to Queriers.
type Scheduler struct {
	services.Service

	cfg Config
	log log.Logger

	limits         Limits
	tenantResolver users.Resolver

	connectedFrontendsMu sync.Mutex
	connectedFrontends   map[string]*connectedFrontend

	requestQueue *queue.RequestQueue
	activeUsers  *users.ActiveUsersCleanupService

	trackedRequestsMu sync.Mutex

	trackedRequests map[requestKey]*schedulerRequest // Request is kept in this map even after being dispatched to querier. It can still be canceled at that time.

	// admission owns the optional QueryAdmissionLease accounting. It is nil
	// when the feature is disabled, in which case the scheduler behaves exactly
	// as without admission control.
	admission *admission.Manager

	// Subservices manager.
	subservices        *services.Manager
	subservicesWatcher *services.FailureWatcher

	// Metrics.
	queueLength              *prometheus.GaugeVec
	discardedRequests        *prometheus.CounterVec
	connectedQuerierClients  prometheus.GaugeFunc
	connectedFrontendClients prometheus.GaugeFunc
	queueDuration            prometheus.Histogram
	trackedRequestsLength    prometheus.GaugeFunc

	// Enables or disables distributed query execution functionality
	distributedExecEnabled bool
	fragmenter             plan_fragments.Fragmenter     // Splits logical plans into executable fragments
	fragmentTable          *fragment_table.FragmentTable // Tracks fragment execution state and querier assignments

	// Maps queries to their fragment IDs for efficient query cancellation.
	// Using this map avoids the need to scan all tracked requests to find
	// fragments belonging to a specific query.
	queryFragmentRegistry map[queryKey][]uint64
}

type queryKey struct {
	frontendAddr string
	queryID      uint64
}
type requestKey struct {
	queryKey   queryKey
	fragmentID uint64
}

type connectedFrontend struct {
	connections int

	// This context is used for running all queries from the same frontend.
	// When last frontend connection is closed, context is canceled.
	ctx    context.Context
	cancel context.CancelFunc
}

type Config struct {
	QuerierForgetDelay time.Duration     `yaml:"querier_forget_delay"`
	GRPCClientConfig   grpcclient.Config `yaml:"grpc_client_config" doc:"description=This configures the gRPC client used to report errors back to the query-frontend."`

	// Admission configures the optional, instance-local QueryAdmissionLease.
	// Disabled by default; when disabled no admission accounting happens.
	Admission admission.Config `yaml:"query_admission_lease"`
}

func (cfg *Config) RegisterFlags(f *flag.FlagSet) {
	f.DurationVar(&cfg.QuerierForgetDelay, "query-scheduler.querier-forget-delay", 0, "If a querier disconnects without sending notification about graceful shutdown, the query-scheduler will keep the querier in the tenant's shard until the forget delay has passed. This feature is useful to reduce the blast radius when shuffle-sharding is enabled.")
	cfg.GRPCClientConfig.RegisterFlagsWithPrefix("query-scheduler.grpc-client-config", "", f)
	cfg.Admission.RegisterFlagsWithPrefix("query-scheduler.query-admission-lease.", f)
}

// NewScheduler creates a new Scheduler.
func NewScheduler(cfg Config, limits Limits, tenantResolver users.Resolver, log log.Logger, registerer prometheus.Registerer, distributedExecEnabled bool) (*Scheduler, error) {
	if err := cfg.Admission.Validate(); err != nil {
		return nil, err
	}

	s := &Scheduler{
		cfg:            cfg,
		log:            log,
		limits:         limits,
		tenantResolver: tenantResolver,

		trackedRequests:    map[requestKey]*schedulerRequest{},
		connectedFrontends: map[string]*connectedFrontend{},

		fragmentTable:          fragment_table.NewFragmentTable(2 * time.Minute),
		fragmenter:             plan_fragments.NewPlanFragmenter(),
		distributedExecEnabled: distributedExecEnabled,
		queryFragmentRegistry:  map[queryKey][]uint64{},
	}

	if cfg.Admission.Enabled {
		s.admission = admission.NewManager(cfg.Admission, log, registerer)
	}

	s.queueLength = promauto.With(registerer).NewGaugeVec(prometheus.GaugeOpts{
		Name: "cortex_query_scheduler_queue_length",
		Help: "Number of queries in the queue.",
	}, []string{"user", "priority", "type"})

	s.discardedRequests = promauto.With(registerer).NewCounterVec(prometheus.CounterOpts{
		Name: "cortex_query_scheduler_discarded_requests_total",
		Help: "Total number of query requests discarded.",
	}, []string{"user", "priority"})

	s.requestQueue = queue.NewRequestQueue(cfg.QuerierForgetDelay, s.queueLength, s.discardedRequests, s.limits, registerer)

	s.queueDuration = promauto.With(registerer).NewHistogram(prometheus.HistogramOpts{
		Name:                            "cortex_query_scheduler_queue_duration_seconds",
		Help:                            "Time spend by requests in queue before getting picked up by a querier.",
		Buckets:                         []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 20, 30, 60},
		NativeHistogramBucketFactor:     1.1,
		NativeHistogramMaxBucketNumber:  100,
		NativeHistogramMinResetDuration: time.Hour,
	})
	s.connectedQuerierClients = promauto.With(registerer).NewGaugeFunc(prometheus.GaugeOpts{
		Name: "cortex_query_scheduler_connected_querier_clients",
		Help: "Number of querier worker clients currently connected to the query-scheduler.",
	}, s.requestQueue.GetConnectedQuerierWorkersMetric)
	s.connectedFrontendClients = promauto.With(registerer).NewGaugeFunc(prometheus.GaugeOpts{
		Name: "cortex_query_scheduler_connected_frontend_clients",
		Help: "Number of query-frontend worker clients currently connected to the query-scheduler.",
	}, s.getConnectedFrontendClientsMetric)

	s.trackedRequestsLength = promauto.With(registerer).NewGaugeFunc(prometheus.GaugeOpts{
		Name: "cortex_query_scheduler_tracked_requests",
		Help: "Number of requests currently tracked by the scheduler.",
	}, s.getTrackedRequestsMetric)

	s.activeUsers = users.NewActiveUsersCleanupWithDefaultValues(s.cleanupMetricsForInactiveUser)

	subservices := []services.Service{s.requestQueue, s.activeUsers}
	if s.admission != nil {
		subservices = append(subservices, s.admission)
	}

	var err error
	s.subservices, err = services.NewManager(subservices...)
	if err != nil {
		return nil, err
	}

	s.Service = services.NewBasicService(s.starting, s.running, s.stopping)
	return s, nil
}

// Limits needed for the Query Scheduler - interface used for decoupling.
type Limits interface {
	// MaxQueriersPerUser returns max queriers to use per tenant, or 0 if shuffle sharding is disabled.
	MaxQueriersPerUser(user string) float64

	queue.Limits
}

type schedulerRequest struct {
	frontendAddress string
	userID          string
	queryID         uint64
	request         *httpgrpc.HTTPRequest
	statsEnabled    bool

	enqueueTime time.Time

	ctx       context.Context
	ctxCancel context.CancelFunc
	queueSpan opentracing.Span

	// This is only used for testing.
	parentSpanContext opentracing.SpanContext

	// fragment represents a portion of the query plan.
	// In distributed execution mode, contains a specific plan segment.
	// In non-distributed mode, only marks the query as root fragment.
	fragment plan_fragments.Fragment

	// admissionGrant is the QueryAdmissionLease grant held while this task is
	// tracked. It is nil when admission control is disabled.
	admissionGrant *admission.Grant

	// admissionAttempt is the root lease attempt this task belongs to. A late
	// completion of an older attempt can only release its own grant.
	admissionAttempt uint64

	// admissionDispatched is set once the task has been handed to a querier.
	// It is guarded by trackedRequestsMu. A canceled task that is already
	// dispatched keeps its admission credits until the querier confirms the
	// end (or the lease TTL expires), so cancellation cannot immediately
	// over-issue credits to other work.
	admissionDispatched bool
}

func (s schedulerRequest) Priority() int64 {
	priority, ok := stats.FromContext(s.ctx).LoadPriority()
	if !ok {
		return 0
	}

	return priority
}

func getPlanFromHTTPRequest(req *httpgrpc.HTTPRequest) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	values, err := url.ParseQuery(string(req.Body))
	if err != nil {
		return nil, err
	}
	plan := values.Get("plan")
	return []byte(plan), nil
}

// FrontendLoop handles connection from frontend.
func (s *Scheduler) FrontendLoop(frontend schedulerpb.SchedulerForFrontend_FrontendLoopServer) error {
	frontendAddress, frontendCtx, err := s.frontendConnected(frontend)
	if err != nil {
		return err
	}
	defer s.frontendDisconnected(frontendAddress)

	// Response to INIT. If scheduler is not running, we skip for-loop, send SHUTTING_DOWN and exit this method.
	if s.State() == services.Running {
		if err := frontend.Send(&schedulerpb.SchedulerToFrontend{Status: schedulerpb.OK}); err != nil {
			return err
		}
	}

	// We stop accepting new queries in Stopping state. By returning quickly, we disconnect frontends, which in turns
	// cancels all their queries.
	for s.State() == services.Running {
		msg, err := frontend.Recv()
		if err != nil {
			// No need to report this as error, it is expected when query-frontend performs SendClose() (as frontendSchedulerWorker does).
			if err == io.EOF {
				return nil
			}
			return err
		}

		if s.State() != services.Running {
			break // break out of the loop, and send SHUTTING_DOWN message.
		}

		var resp *schedulerpb.SchedulerToFrontend

		switch msg.GetType() {
		case schedulerpb.ENQUEUE:
			resp = s.handleEnqueue(frontendCtx, frontendAddress, msg)

		case schedulerpb.CANCEL:
			// Canceled roots stop admitting new fragments immediately. Tasks
			// already in-flight keep their credits until they terminate or the
			// conservative lease TTL reclaims them.
			if s.admission != nil {
				s.admission.CancelRoot(admission.LeaseKey{FrontendAddress: frontendAddress, QueryID: msg.QueryID})
			}
			s.cancelRequestAndRemoveFromTracked(frontendAddress, msg.QueryID, 0, true)
			resp = &schedulerpb.SchedulerToFrontend{Status: schedulerpb.OK}

		default:
			level.Error(s.log).Log("msg", "unknown request type from frontend", "addr", frontendAddress, "type", msg.GetType())
			return errors.New("unknown request type")
		}

		err = frontend.Send(resp)
		// Failure to send response results in ending this connection.
		if err != nil {
			return err
		}
	}

	// Report shutdown back to frontend, so that it can retry with different scheduler. Also stop the frontend loop.
	return frontend.Send(&schedulerpb.SchedulerToFrontend{Status: schedulerpb.SHUTTING_DOWN})
}

func (s *Scheduler) frontendConnected(frontend schedulerpb.SchedulerForFrontend_FrontendLoopServer) (string, context.Context, error) {
	msg, err := frontend.Recv()
	if err != nil {
		return "", nil, err
	}
	if msg.Type != schedulerpb.INIT || msg.FrontendAddress == "" {
		return "", nil, errors.New("no frontend address")
	}

	s.connectedFrontendsMu.Lock()
	defer s.connectedFrontendsMu.Unlock()

	cf := s.connectedFrontends[msg.FrontendAddress]
	if cf == nil {
		cf = &connectedFrontend{
			connections: 0,
		}
		cf.ctx, cf.cancel = context.WithCancel(context.Background())
		s.connectedFrontends[msg.FrontendAddress] = cf
	}

	cf.connections++
	return msg.FrontendAddress, cf.ctx, nil
}

func (s *Scheduler) frontendDisconnected(frontendAddress string) {
	s.connectedFrontendsMu.Lock()
	defer s.connectedFrontendsMu.Unlock()

	cf := s.connectedFrontends[frontendAddress]
	cf.connections--
	if cf.connections == 0 {
		delete(s.connectedFrontends, frontendAddress)
		cf.cancel()
	}
}

func updatePlanInHTTPRequest(fragment plan_fragments.Fragment) ([]byte, error) {
	byteLP, err := logicalplan.Marshal(fragment.Node)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Add("plan", string(byteLP))
	return []byte(form.Encode()), nil
}

// handleEnqueue resolves the authorized tenants, opens or advances the root
// admission lease and then enqueues the request (possibly fragmented). The
// returned response is sent back to the frontend.
func (s *Scheduler) handleEnqueue(frontendCtx context.Context, frontendAddr string, msg *schedulerpb.FrontendToScheduler) *schedulerpb.SchedulerToFrontend {
	// Resolve the full set of authorized tenants once. Federated requests
	// authenticate with a joined userID, but admission must reserve weighted
	// quota against every tenant instead of occupying a single cheap slot.
	tenantIDs, err := s.resolveAuthorizedTenants(frontendCtx, msg.GetUserID())
	if err != nil {
		return &schedulerpb.SchedulerToFrontend{Status: schedulerpb.ERROR, Error: err.Error()}
	}

	// Every enqueue (including retries and reconnects) is associated with an
	// attempt of the root lease. A fresh attempt never inherits grants of a
	// previous one.
	var attempt uint64 = 1
	if s.admission != nil {
		attempt, err = s.admission.BeginRoot(admission.LeaseKey{FrontendAddress: frontendAddr, QueryID: msg.QueryID}, tenantIDs)
		if err != nil {
			return s.admissionErrorResponse(err)
		}
	}

	// If there is a logical plan in the request body, we will fragment it before enqueueing
	// otherwise, it will be a single request and is the root and can be enqueued directly
	byteLP, err := getPlanFromHTTPRequest(msg.HttpRequest)
	if err != nil {
		return &schedulerpb.SchedulerToFrontend{Status: schedulerpb.ERROR, Error: err.Error()}
	}
	if len(byteLP) != 0 {
		err = s.fragmentAndEnqueueRequest(frontendCtx, frontendAddr, msg, byteLP, tenantIDs, attempt)
	} else {
		err = s.enqueueRequest(frontendCtx, frontendAddr, msg, plan_fragments.Fragment{FragmentID: 0, IsRoot: true}, tenantIDs, attempt)
	}

	switch err {
	case nil:
		return &schedulerpb.SchedulerToFrontend{Status: schedulerpb.OK}
	case queue.ErrTooManyRequests:
		return &schedulerpb.SchedulerToFrontend{Status: schedulerpb.TOO_MANY_REQUESTS_PER_TENANT}
	default:
		if errors.Is(err, admission.ErrAdmissionTimeout) {
			// Admission exhaustion is an overload condition the frontend can retry.
			return &schedulerpb.SchedulerToFrontend{Status: schedulerpb.TOO_MANY_REQUESTS_PER_TENANT}
		}
		return &schedulerpb.SchedulerToFrontend{Status: schedulerpb.ERROR, Error: err.Error()}
	}
}

func (s *Scheduler) admissionErrorResponse(err error) *schedulerpb.SchedulerToFrontend {
	if errors.Is(err, admission.ErrStopped) {
		return &schedulerpb.SchedulerToFrontend{Status: schedulerpb.SHUTTING_DOWN}
	}
	return &schedulerpb.SchedulerToFrontend{Status: schedulerpb.ERROR, Error: err.Error()}
}

func (s *Scheduler) resolveAuthorizedTenants(ctx context.Context, userID string) ([]string, error) {
	return users.TenantIDs(users.InjectResolver(user.InjectOrgID(ctx, userID), s.tenantResolver))
}

func (s *Scheduler) fragmentAndEnqueueRequest(frontendContext context.Context, frontendAddr string, msg *schedulerpb.FrontendToScheduler, byteLogicalPlan []byte, tenantIDs []string, attempt uint64) error {

	// un-serialize logical plan and fragment it
	lpNode, err := distributed_execution.Unmarshal(byteLogicalPlan)
	if err != nil {
		return err
	}

	fragments, err := s.fragmenter.Fragment(msg.QueryID, lpNode)
	if err != nil {
		return err
	}

	// Snapshot the immutable envelope once. Every fragment gets its own message
	// with its own HTTP request and headers copy: the shared incoming message is
	// never mutated, so dequeue-time header injection cannot race with
	// enqueueing the next fragment.
	baseRequest := msg.HttpRequest

	for _, fragment := range fragments {
		frag := fragment

		// update http request body with the new fragmented logical plan
		newBody, err := updatePlanInHTTPRequest(frag)
		if err != nil {
			return err
		}

		headers := make([]*httpgrpc.Header, len(baseRequest.Headers))
		copy(headers, baseRequest.Headers)

		fragmentMsg := &schedulerpb.FrontendToScheduler{
			Type:            msg.Type,
			FrontendAddress: msg.FrontendAddress,
			QueryID:         msg.QueryID,
			UserID:          msg.UserID,
			StatsEnabled:    msg.StatsEnabled,
			HttpRequest: &httpgrpc.HTTPRequest{
				Method:  baseRequest.Method,
				Url:     baseRequest.Url,
				Headers: headers,
				Body:    newBody,
			},
		}

		// if there is an error in any of the process enqueueing the fragments
		// immediately propagate the error back
		if err := s.enqueueRequest(frontendContext, frontendAddr, fragmentMsg, frag, tenantIDs, attempt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Scheduler) enqueueRequest(frontendContext context.Context, frontendAddr string, msg *schedulerpb.FrontendToScheduler, fragment plan_fragments.Fragment, tenantIDs []string, attempt uint64) error {
	// Create new context for this request, to support cancellation.
	ctx, cancel := context.WithCancel(frontendContext)
	shouldCancel := true
	defer func() {
		if shouldCancel {
			cancel()
		}
	}()

	// Extract tracing information from headers in HTTP request. FrontendContext doesn't have the correct tracing
	// information, since that is a long-running request.
	tracer := opentracing.GlobalTracer()
	parentSpanContext, err := httpgrpcutil.GetParentSpanForRequest(tracer, msg.HttpRequest)
	if err != nil {
		return err
	}

	userID := msg.GetUserID()

	req := &schedulerRequest{
		frontendAddress:  frontendAddr,
		userID:           msg.UserID,
		queryID:          msg.QueryID,
		request:          msg.HttpRequest,
		statsEnabled:     msg.StatsEnabled,
		fragment:         fragment,
		admissionAttempt: attempt,
	}

	now := time.Now()

	req.parentSpanContext = parentSpanContext
	req.queueSpan, req.ctx = opentracing.StartSpanFromContextWithTracer(ctx, tracer, "queued", opentracing.ChildOf(parentSpanContext))
	req.enqueueTime = now
	req.ctxCancel = cancel

	// aggregate the max queriers limit in the case of a multi tenant query
	maxQueriers := validation.SmallestPositiveNonZeroFloat64PerTenant(tenantIDs, s.limits.MaxQueriersPerUser)

	// Admission happens before queueing, while no scheduler-wide lock is held:
	// Admit waits on the lease manager's own waiters, never on
	// trackedRequestsMu. The reservation is atomic across the global pool, the
	// per-root cap and every authorized tenant; on failure nothing is deducted.
	if s.admission != nil {
		grant, admitErr := s.admission.Admit(req.ctx, admission.LeaseKey{FrontendAddress: frontendAddr, QueryID: msg.QueryID}, attempt)
		if admitErr != nil {
			return admitErr
		}
		req.admissionGrant = grant
	}

	s.activeUsers.UpdateUserTimestamp(userID, now)
	err = s.requestQueue.EnqueueRequest(userID, req, maxQueriers, func() {
		shouldCancel = false

		s.trackedRequestsMu.Lock()
		defer s.trackedRequestsMu.Unlock()

		queryKey := queryKey{frontendAddr: frontendAddr, queryID: msg.QueryID}
		s.queryFragmentRegistry[queryKey] = append(s.queryFragmentRegistry[queryKey], req.fragment.FragmentID)
		s.trackedRequests[requestKey{queryKey: queryKey, fragmentID: req.fragment.FragmentID}] = req
	})
	if err != nil && req.admissionGrant != nil {
		// The request never made it into the queue, so nothing will ever release
		// this grant: return all reserved credits immediately.
		s.admission.Release(req.admissionGrant)
		req.admissionGrant = nil
	}
	return err
}

// releaseGrant returns the admission credits of a terminating task. Release is
// idempotent, so cancellation and completion funnels can both invoke it for
// the same task without ever returning it twice.
func (s *Scheduler) releaseGrant(req *schedulerRequest) {
	if s.admission != nil && req.admissionGrant != nil {
		s.admission.Release(req.admissionGrant)
	}
}

// This method doesn't do removal from the queue.
func (s *Scheduler) cancelRequestAndRemoveFromTracked(frontendAddr string, queryID uint64, fragmentID uint64, cancelAll bool) {
	s.trackedRequestsMu.Lock()
	defer s.trackedRequestsMu.Unlock()

	querykey := queryKey{frontendAddr: frontendAddr, queryID: queryID}

	if cancelAll {
		// cancel all requests under the queryID
		for _, fragID := range s.queryFragmentRegistry[querykey] {
			key := requestKey{queryKey: querykey, fragmentID: fragID}
			if req := s.trackedRequests[key]; req != nil {
				req.ctxCancel()
				if req.admissionDispatched {
					// The task is already in-flight on a querier. Keep both the
					// tracking entry and the admission credits until forwarding
					// confirms the end (single-fragment call below) or the lease
					// TTL reaps the grant. Releasing now would over-issue credits.
					continue
				}
				s.releaseGrant(req)
			}
			delete(s.trackedRequests, key)
		}
		delete(s.queryFragmentRegistry, querykey)
	} else {
		// Terminal funnel (confirmed forwarding end, or an expired request
		// skipped before dispatch): whatever the previous cancellation did, the
		// grant is returned here exactly once.
		key := requestKey{queryKey: querykey, fragmentID: fragmentID}
		if req := s.trackedRequests[key]; req != nil {
			req.ctxCancel()
			s.releaseGrant(req)
		}
		delete(s.trackedRequests, key)

		// Clean up queryFragmentRegistry for this specific fragment
		if fragmentIDs, ok := s.queryFragmentRegistry[querykey]; ok {
			// Fast path: if there's only one fragment and it's the one we're deleting,
			// just delete the entire entry without allocating a new slice
			if len(fragmentIDs) == 1 && fragmentIDs[0] == fragmentID {
				delete(s.queryFragmentRegistry, querykey)
			} else {
				// Slow path: remove this fragmentID from the slice
				newFragmentIDs := make([]uint64, 0, len(fragmentIDs)-1)
				for _, fid := range fragmentIDs {
					if fid != fragmentID {
						newFragmentIDs = append(newFragmentIDs, fid)
					}
				}

				// If no more fragments remain, delete the entire entry
				if len(newFragmentIDs) == 0 {
					delete(s.queryFragmentRegistry, querykey)
				} else {
					s.queryFragmentRegistry[querykey] = newFragmentIDs
				}
			}
		}
	}
}

// QuerierLoop is started by querier to receive queries from scheduler.
func (s *Scheduler) QuerierLoop(querier schedulerpb.SchedulerForQuerier_QuerierLoopServer) error {
	resp, err := querier.Recv()
	if err != nil {
		return err
	}

	querierID := resp.GetQuerierID()

	s.requestQueue.RegisterQuerierConnection(querierID)
	defer s.requestQueue.UnregisterQuerierConnection(querierID)

	// If the downstream connection to querier is cancelled,
	// we need to ping the condition variable to unblock getNextRequestForQuerier.
	// Ideally we'd have ctx aware condition variables...
	go func() {
		<-querier.Context().Done()
		s.requestQueue.QuerierDisconnecting()
	}()

	lastUserIndex := queue.FirstUser()

	// In stopping state scheduler is not accepting new queries, but still dispatching queries in the queues.
	for s.isRunningOrStopping() {
		req, idx, err := s.requestQueue.GetNextRequestForQuerier(querier.Context(), lastUserIndex, querierID)
		if err != nil {
			return err
		}
		lastUserIndex = idx

		r := req.(*schedulerRequest)

		// The task is now in-flight on a querier: if it gets canceled afterwards
		// its admission credits must be retained until this forwarding ends.
		s.trackedRequestsMu.Lock()
		r.admissionDispatched = true
		s.trackedRequestsMu.Unlock()

		// Propagate the enqueue timestamp to the querier via an HTTP header.
		// The querier will use its own wall-clock as the dequeue time.
		stats.InjectQueueTimeHeader(r.request, r.enqueueTime)

		s.queueDuration.Observe(time.Since(r.enqueueTime).Seconds())
		r.queueSpan.Finish()

		/*
		  We want to dequeue the next unexpired request from the chosen tenant queue.
		  The chance of choosing a particular tenant for dequeueing is (1/active_tenants).
		  This is problematic under load, especially with other middleware enabled such as
		  querier.split-by-interval, where one request may fan out into many.
		  If expired requests aren't exhausted before checking another tenant, it would take
		  n_active_tenants * n_expired_requests_at_front_of_queue requests being processed
		  before an active request was handled for the tenant in question.
		  If this tenant meanwhile continued to queue requests,
		  it's possible that it's own queue would perpetually contain only expired requests.
		*/

		if r.ctx.Err() != nil {
			s.cancelRequestAndRemoveFromTracked(r.frontendAddress, r.queryID, r.fragment.FragmentID, false)

			lastUserIndex = lastUserIndex.ReuseLastUser()
			continue
		}

		if err := s.forwardRequestToQuerier(querier, r, resp.GetQuerierAddress()); err != nil {
			return err
		}
	}

	return errSchedulerIsNotRunning
}

func (s *Scheduler) NotifyQuerierShutdown(_ context.Context, req *schedulerpb.NotifyQuerierShutdownRequest) (*schedulerpb.NotifyQuerierShutdownResponse, error) {
	level.Info(s.log).Log("msg", "received shutdown notification from querier", "querier", req.GetQuerierID())
	s.requestQueue.NotifyQuerierShutdown(req.GetQuerierID())

	return &schedulerpb.NotifyQuerierShutdownResponse{}, nil
}

func (s *Scheduler) forwardRequestToQuerier(querier schedulerpb.SchedulerForQuerier_QuerierLoopServer, req *schedulerRequest, QuerierAddress string) error {
	// Make sure to cancel request at the end to cleanup resources.
	defer s.cancelRequestAndRemoveFromTracked(req.frontendAddress, req.queryID, req.fragment.FragmentID, false)

	// Handle the stream sending & receiving on a goroutine so we can
	// monitoring the contexts in a select and cancel things appropriately.
	errCh := make(chan error, 1)
	go func() {
		childIDtoAddrs := make(map[uint64]string)
		if len(req.fragment.ChildIDs) != 0 {
			for _, childID := range req.fragment.ChildIDs {
				addr, ok := s.fragmentTable.GetAddrByID(req.queryID, childID)
				if !ok {
					errCh <- fmt.Errorf("cannot find child addr for parent fragment %d", req.fragment.FragmentID)
					return
				}
				childIDtoAddrs[childID] = addr
			}
		}

		err := querier.Send(&schedulerpb.SchedulerToQuerier{
			UserID:          req.userID,
			QueryID:         req.queryID,
			FrontendAddress: req.frontendAddress,
			HttpRequest:     req.request,
			StatsEnabled:    req.statsEnabled,
			FragmentID:      req.fragment.FragmentID,
			ChildIDtoAddrs:  childIDtoAddrs,
			IsRoot:          req.fragment.IsRoot,
		})

		if s.distributedExecEnabled {
			s.fragmentTable.AddAddressByID(req.queryID, req.fragment.FragmentID, QuerierAddress)
		}

		if err != nil {
			errCh <- err
			return
		}

		_, err = querier.Recv()
		errCh <- err
	}()

	select {
	case <-req.ctx.Done():
		// If the upstream request is cancelled (eg. frontend issued CANCEL or closed connection),
		// we need to cancel the downstream req. Only way we can do that is to close the stream (by returning error here).
		// Querier is expecting this semantics.
		return req.ctx.Err()

	case err := <-errCh:
		// Is there was an error handling this request due to network IO,
		// then error out this upstream request _and_ stream.

		if err != nil {
			s.forwardErrorToFrontend(req.ctx, req, err)
		}
		return err
	}
}

func (s *Scheduler) forwardErrorToFrontend(ctx context.Context, req *schedulerRequest, requestErr error) {
	opts, err := s.cfg.GRPCClientConfig.DialOption([]grpc.UnaryClientInterceptor{
		otgrpc.OpenTracingClientInterceptor(opentracing.GlobalTracer()),
		middleware.ClientUserHeaderInterceptor},
		nil)
	if err != nil {
		level.Warn(s.log).Log("msg", "failed to create gRPC options for the connection to frontend to report error", "frontend", req.frontendAddress, "err", err, "requestErr", requestErr)
		return
	}

	conn, err := grpc.NewClient(req.frontendAddress, opts...)
	if err != nil {
		level.Warn(s.log).Log("msg", "failed to create gRPC connection to frontend to report error", "frontend", req.frontendAddress, "err", err, "requestErr", requestErr)
		return
	}

	defer func() {
		_ = conn.Close()
	}()

	client := frontendv2pb.NewFrontendForQuerierClient(conn)

	userCtx := user.InjectOrgID(ctx, req.userID)
	_, err = client.QueryResult(userCtx, &frontendv2pb.QueryResultRequest{
		QueryID: req.queryID,
		HttpResponse: &httpgrpc.HTTPResponse{
			Code: http.StatusInternalServerError,
			Body: []byte(requestErr.Error()),
		},
	})

	if err != nil {
		level.Warn(s.log).Log("msg", "failed to forward error to frontend", "frontend", req.frontendAddress, "err", err, "requestErr", requestErr)
		return
	}
}

func (s *Scheduler) isRunningOrStopping() bool {
	st := s.State()
	return st == services.Running || st == services.Stopping
}

func (s *Scheduler) starting(ctx context.Context) error {
	s.subservicesWatcher.WatchManager(s.subservices)

	if err := services.StartManagerAndAwaitHealthy(ctx, s.subservices); err != nil {
		return errors.Wrap(err, "unable to start scheduler subservices")
	}

	return nil
}

func (s *Scheduler) running(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-s.subservicesWatcher.Chan():
			return errors.Wrap(err, "scheduler subservice failed")
		}
	}
}

// Close the Scheduler.
func (s *Scheduler) stopping(_ error) error {
	// This will also stop the requests queue, which stop accepting new requests and errors out any tracked requests.
	return services.StopManagerAndAwaitStopped(context.Background(), s.subservices)
}

func (s *Scheduler) cleanupMetricsForInactiveUser(user string) {
	s.queueLength.DeletePartialMatch(prometheus.Labels{
		"user": user,
	})
	s.discardedRequests.DeletePartialMatch(prometheus.Labels{
		"user": user,
	})
	s.requestQueue.CleanupInactiveUserMetrics(user)
}

func (s *Scheduler) getConnectedFrontendClientsMetric() float64 {
	s.connectedFrontendsMu.Lock()
	defer s.connectedFrontendsMu.Unlock()

	count := 0
	for _, workers := range s.connectedFrontends {
		count += workers.connections
	}

	return float64(count)
}

func (s *Scheduler) getTrackedRequestsMetric() float64 {
	s.trackedRequestsMu.Lock()
	defer s.trackedRequestsMu.Unlock()

	return float64(len(s.trackedRequests))
}
