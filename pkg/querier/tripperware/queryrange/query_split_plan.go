package queryrange

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/google/uuid"
	thanosquerysharding "github.com/thanos-io/thanos/pkg/querysharding"
	"github.com/thanos-io/thanos/pkg/store/storepb"
	"github.com/weaveworks/common/httpgrpc"

	"github.com/cortexproject/cortex/pkg/querier/tripperware"
	cquerysharding "github.com/cortexproject/cortex/pkg/querysharding"
	"github.com/cortexproject/cortex/pkg/util/users"
	"github.com/cortexproject/cortex/pkg/util/validation"
)

// Protocol versions recorded in every QuerySplitPlan. They pin the analysis and
// execution contracts a plan was built against; bumping either one changes the
// plan digest and therefore invalidates older recovery cursors.
const (
	PlanSchemaVersion = 1

	AnalyzerProtocolVersion = "thanos-querysharding-analyzer/v1"
	EngineProtocolVersion   = "cortex-queryrange-tripperware/v1"

	// DefaultMaxPlanTasks bounds the total number of enumerated tasks
	// (horizontal splits * vertical shards) for a single plan.
	DefaultMaxPlanTasks = 10000
	// DefaultMaxVerticalShards is a hard safety cap on vertical shard size
	// regardless of the per-tenant limit.
	DefaultMaxVerticalShards = 128
	// DefaultMaxTotalRange bounds the original request end-start span.
	DefaultMaxTotalRange = 100 * 365 * 24 * time.Hour

	// ReexecutionSemanticsDeclaration is carried verbatim by every plan and
	// states what a retry/Resume can and cannot promise about live data.
	ReexecutionSemanticsDeclaration = "in-process retries reuse confirmed task results and re-run only incomplete tasks against current live data (at-least-once); no identical live-data snapshot is guaranteed across processes, cross-process recovery requires an explicit whole-plan re-execution"
)

// Sentinel errors shared by the Planner, Executor and recovery cursor logic.
var (
	ErrPlanTooLarge                    = errors.New("query split plan exceeds the maximum number of tasks")
	ErrShardCountTooLarge              = errors.New("query split plan exceeds the maximum vertical shard count")
	ErrTotalRangeTooLarge              = errors.New("query split plan exceeds the maximum total time range")
	ErrInvalidTimeRange                = errors.New("invalid query time range")
	ErrPlanDigestMismatch              = errors.New("recovery cursor does not belong to the presented query split plan")
	ErrTaskIdentityMismatch            = errors.New("recovery cursor contains an unknown or altered task identity")
	ErrIncompleteTasks                 = errors.New("cannot merge query split plan results: some tasks are not succeeded")
	ErrCrossProcessSnapshotUnavailable = errors.New("confirmed task results cannot be reused across processes: live-data snapshot is not guaranteed; request an explicit whole-plan re-execution instead")
	ErrPlanVerificationFailed          = errors.New("query split plan digest verification failed: the plan was altered after planning")
)

// TaskStatus is the runtime state of a single plan task. It is intentionally
// not part of the immutable QuerySplitPlan artifact; the Executor owns it.
type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusSucceeded TaskStatus = "succeeded"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusPartial   TaskStatus = "partial"
)

// GridSegment describes a contiguous, step-aligned sub-grid covered by a task.
// All covered timestamps are FirstTs + k*Step for k in [0, Count).
type GridSegment struct {
	FirstTs int64 `json:"first_ts"`
	LastTs  int64 `json:"last_ts"`
	Count   int64 `json:"count"`
}

// Covers reports whether ts belongs to the segment. Segments are built
// step-aligned, so bound containment implies grid membership.
func (g GridSegment) Covers(ts int64) bool {
	return ts >= g.FirstTs && ts <= g.LastTs
}

// PlanTask is one immutable, finitely enumerated unit of work. Runtime state
// lives in the Executor and never mutates this structure.
type PlanTask struct {
	ID              string      `json:"id"`
	HorizontalIndex int         `json:"horizontal_index"`
	Query           string      `json:"query"`
	Start           int64       `json:"start"`
	End             int64       `json:"end"`
	Step            int64       `json:"step"`
	ShardIndex      int         `json:"shard_index"`
	TotalShards     int         `json:"total_shards"`
	Coverage        GridSegment `json:"coverage"`
	IdentityDigest  string      `json:"identity_digest"`
}

// TenantLimitsSnapshot captures the per-tenant limit values that can influence
// split/shard planning. Cortex limits carry no monotonic generation number, so
// the generation is defined as a digest over these snapshots.
type TenantLimitsSnapshot struct {
	TenantID               string `json:"tenant_id"`
	QueryVerticalShardSize int    `json:"query_vertical_shard_size"`
	MaxQueryParallelism    int    `json:"max_query_parallelism"`
	MaxQueryLookbackMs     int64  `json:"max_query_lookback_ms"`
	MaxQueryLengthMs       int64  `json:"max_query_length_ms"`
	MaxCacheFreshnessMs    int64  `json:"max_cache_freshness_ms"`
	MaxQueryResponseSize   int64  `json:"max_query_response_size"`
}

// LimitsGeneration is the frozen limits snapshot a plan was built with.
type LimitsGeneration struct {
	Digest  string                 `json:"digest"`
	Tenants []TenantLimitsSnapshot `json:"tenants"`
}

// QuerySplitPlan is the frozen artifact produced by the Planner. It is fully
// JSON-serializable so it can be inspected before execution and carried by
// recovery cursors. It contains no runtime state and must not be mutated after
// creation.
type QuerySplitPlan struct {
	SchemaVersion int    `json:"schema_version"`
	PlanID        string `json:"plan_id"`
	Digest        string `json:"digest"`
	// CreatedAtUnixMs is excluded from the digest.
	CreatedAtUnixMs int64 `json:"created_at_unix_ms"`

	// Original request grid, preserved verbatim.
	OriginalQuery string `json:"original_query"`
	OriginalStart int64  `json:"original_start"`
	OriginalEnd   int64  `json:"original_end"`
	OriginalStep  int64  `json:"original_step"`
	Path          string `json:"path"`

	// Execution context snapshot.
	TenantIDs       []string `json:"tenant_ids"`
	LookbackDeltaMs int64    `json:"lookback_delta_ms"`

	LimitsGeneration LimitsGeneration `json:"limits_generation"`

	AnalyzerProtocolVersion string `json:"analyzer_protocol_version"`
	EngineProtocolVersion   string `json:"engine_protocol_version"`

	// Analysis inputs and outputs.
	DynamicSplitConfig        DynamicQuerySplitsConfig `json:"dynamic_split_config"`
	BaseSplitIntervalMs       int64                    `json:"base_split_interval_ms"`
	HorizontalSplitIntervalMs int64                    `json:"horizontal_split_interval_ms"`
	VerticalShardSize         int                      `json:"vertical_shard_size"`
	Shardable                 bool                     `json:"shardable"`
	ShardingLabels            []string                 `json:"sharding_labels"`

	// The finite, fully enumerated task list.
	Tasks []PlanTask `json:"tasks"`

	// Effective bounds and declared semantics.
	MaxTasks             int    `json:"max_tasks"`
	ReexecutionSemantics string `json:"reexecution_semantics"`
}

// PlannerOptions holds the hard safety bounds for plan enumeration. Zero fields
// fall back to the package defaults.
type PlannerOptions struct {
	MaxPlanTasks      int
	MaxVerticalShards int
	MaxTotalRange     time.Duration
}

// Planner builds QuerySplitPlans. It reuses the existing static/dynamic
// interval functions, splitQuery and sharding injection unchanged; it does not
// re-implement or rename any of the existing split/shard algorithms.
type Planner struct {
	cfg           Config
	limits        tripperware.Limits
	analyzer      thanosquerysharding.Analyzer
	lookbackDelta time.Duration
	opts          PlannerOptions
}

// NewPlanner constructs a Planner. cfg and limits are the same values passed to
// Middlewares(), so the interval function selection stays identical.
func NewPlanner(cfg Config, limits tripperware.Limits, analyzer thanosquerysharding.Analyzer, lookbackDelta time.Duration, opts PlannerOptions) *Planner {
	if opts.MaxPlanTasks <= 0 {
		opts.MaxPlanTasks = DefaultMaxPlanTasks
	}
	if opts.MaxVerticalShards <= 0 {
		opts.MaxVerticalShards = DefaultMaxVerticalShards
	}
	if opts.MaxTotalRange <= 0 {
		opts.MaxTotalRange = DefaultMaxTotalRange
	}
	return &Planner{
		cfg:           cfg,
		limits:        limits,
		analyzer:      analyzer,
		lookbackDelta: lookbackDelta,
		opts:          opts,
	}
}

// Plan builds the immutable QuerySplitPlan without executing anything.
func (p *Planner) Plan(ctx context.Context, r tripperware.Request) (*QuerySplitPlan, error) {
	if p.cfg.SplitQueriesByInterval <= 0 {
		return nil, errors.New("query split planner requires a positive split_queries_by_interval")
	}
	if err := p.validateRequest(r); err != nil {
		return nil, err
	}

	tenantIDs, err := users.TenantIDs(ctx)
	if err != nil {
		return nil, httpgrpcError(http.StatusBadRequest, err.Error())
	}
	tenantIDs = users.NormalizeTenantIDs(tenantIDs)

	generation, err := p.snapshotLimits(tenantIDs)
	if err != nil {
		return nil, err
	}

	// Pick the interval function exactly like Middlewares() does, so a plan
	// describes precisely the requests the current middleware chain would send.
	intervalFn := staticIntervalFn(p.cfg)
	if p.cfg.DynamicQuerySplitsConfig.MaxShardsPerQuery > 0 || p.cfg.DynamicQuerySplitsConfig.MaxFetchedDataDurationPerQuery > 0 {
		intervalFn = dynamicIntervalFn(p.cfg, p.limits, p.analyzer, p.lookbackDelta)
	}

	planCtx, interval, err := intervalFn(ctx, r)
	if err != nil {
		return nil, httpgrpcError(http.StatusBadRequest, err.Error())
	}

	verticalShardSize := validation.SmallestPositiveIntPerTenant(tenantIDs, p.limits.QueryVerticalShardSize)
	if dynamicSize, ok := tripperware.VerticalShardSizeFromContext(planCtx); ok {
		verticalShardSize = dynamicSize
	}
	if verticalShardSize > p.opts.MaxVerticalShards {
		return nil, fmt.Errorf("%w: requested=%d max=%d", ErrShardCountTooLarge, verticalShardSize, p.opts.MaxVerticalShards)
	}

	// splitQuery enumerates horizontal splits against the original grid and
	// evaluates @ start()/@ end() exactly once on the original request.
	horizontalReqs, err := splitQuery(r, interval)
	if err != nil {
		return nil, httpgrpcError(http.StatusBadRequest, err.Error())
	}

	// Re-run the same analysis shardBy performs on the rewritten query.
	analysis, err := p.analyzer.Analyze(horizontalReqs[0].GetQuery())
	if err != nil {
		return nil, httpgrpcError(http.StatusBadRequest, err.Error())
	}
	shardable := verticalShardSize > 1 && analysis.IsShardable()

	effectiveShards := 1
	if shardable {
		effectiveShards = verticalShardSize
	}
	expectedTasks := len(horizontalReqs) * effectiveShards
	if expectedTasks > p.opts.MaxPlanTasks {
		return nil, fmt.Errorf("%w: requested=%d max=%d", ErrPlanTooLarge, expectedTasks, p.opts.MaxPlanTasks)
	}

	tasks, err := p.enumerateTasks(horizontalReqs, shardable, verticalShardSize, analysis)
	if err != nil {
		return nil, err
	}

	shardingLabels := analysis.ShardingLabels()
	sort.Strings(shardingLabels)

	plan := &QuerySplitPlan{
		SchemaVersion:             PlanSchemaVersion,
		PlanID:                    uuid.NewString(),
		CreatedAtUnixMs:           time.Now().UnixMilli(),
		OriginalQuery:             r.GetQuery(),
		OriginalStart:             r.GetStart(),
		OriginalEnd:               r.GetEnd(),
		OriginalStep:              r.GetStep(),
		Path:                      requestPath(r),
		TenantIDs:                 tenantIDs,
		LookbackDeltaMs:           p.lookbackDelta.Milliseconds(),
		LimitsGeneration:          generation,
		AnalyzerProtocolVersion:   AnalyzerProtocolVersion,
		EngineProtocolVersion:     EngineProtocolVersion,
		DynamicSplitConfig:        p.cfg.DynamicQuerySplitsConfig,
		BaseSplitIntervalMs:       p.cfg.SplitQueriesByInterval.Milliseconds(),
		HorizontalSplitIntervalMs: interval.Milliseconds(),
		VerticalShardSize:         verticalShardSize,
		Shardable:                 shardable,
		ShardingLabels:            shardingLabels,
		Tasks:                     tasks,
		MaxTasks:                  p.opts.MaxPlanTasks,
		ReexecutionSemantics:      ReexecutionSemanticsDeclaration,
	}

	plan.Digest = digestJSON(planDigestContent(plan))
	for i := range plan.Tasks {
		plan.Tasks[i].IdentityDigest = taskIdentityDigest(plan.Digest, plan.Tasks[i])
	}
	return plan, nil
}

// DryRun is the plan-only entry point: it returns the plan for inspection and
// never sends a downstream request.
func (p *Planner) DryRun(ctx context.Context, r tripperware.Request) (*QuerySplitPlan, error) {
	return p.Plan(ctx, r)
}

func (p *Planner) validateRequest(r tripperware.Request) error {
	if r.GetStep() <= 0 {
		return fmt.Errorf("%w: step must be positive, got %d", ErrInvalidTimeRange, r.GetStep())
	}
	if r.GetEnd() < r.GetStart() {
		return fmt.Errorf("%w: end %d is before start %d", ErrInvalidTimeRange, r.GetEnd(), r.GetStart())
	}
	span, ok := checkedSub(r.GetEnd(), r.GetStart())
	if !ok {
		return fmt.Errorf("%w: end-start overflow (start=%d end=%d)", ErrInvalidTimeRange, r.GetStart(), r.GetEnd())
	}
	if span > p.opts.MaxTotalRange.Milliseconds() {
		return fmt.Errorf("%w: span_ms=%d max_ms=%d", ErrTotalRangeTooLarge, span, p.opts.MaxTotalRange.Milliseconds())
	}
	// Guard the grid point count against overflow as well.
	if _, ok := checkedAdd(span/r.GetStep(), 1); !ok {
		return fmt.Errorf("%w: grid point count overflow", ErrInvalidTimeRange)
	}
	return nil
}

func (p *Planner) snapshotLimits(tenantIDs []string) (LimitsGeneration, error) {
	snapshots := make([]TenantLimitsSnapshot, 0, len(tenantIDs))
	for _, id := range tenantIDs {
		snapshots = append(snapshots, TenantLimitsSnapshot{
			TenantID:               id,
			QueryVerticalShardSize: p.limits.QueryVerticalShardSize(id),
			MaxQueryParallelism:    p.limits.MaxQueryParallelism(id),
			MaxQueryLookbackMs:     p.limits.MaxQueryLookback(id).Milliseconds(),
			MaxQueryLengthMs:       p.limits.MaxQueryLength(id).Milliseconds(),
			MaxCacheFreshnessMs:    p.limits.MaxCacheFreshness(id).Milliseconds(),
			MaxQueryResponseSize:   p.limits.MaxQueryResponseSize(id),
		})
	}
	gen := LimitsGeneration{Tenants: snapshots}
	gen.Digest = digestJSON(snapshots)
	return gen, nil
}

func (p *Planner) enumerateTasks(horizontalReqs []tripperware.Request, shardable bool, verticalShardSize int, analysis thanosquerysharding.QueryAnalysis) ([]PlanTask, error) {
	tasks := make([]PlanTask, 0, len(horizontalReqs)*max(1, verticalShardSize))
	for h, hr := range horizontalReqs {
		segment := GridSegment{
			FirstTs: hr.GetStart(),
			LastTs:  hr.GetEnd(),
			Count:   (hr.GetEnd()-hr.GetStart())/hr.GetStep() + 1,
		}
		unsharded := PlanTask{
			ID:              taskID(h, 0),
			HorizontalIndex: h,
			Query:           hr.GetQuery(),
			Start:           hr.GetStart(),
			End:             hr.GetEnd(),
			Step:            hr.GetStep(),
			ShardIndex:      0,
			TotalShards:     1,
			Coverage:        segment,
		}
		if !shardable {
			tasks = append(tasks, unsharded)
			continue
		}

		shards := make([]PlanTask, 0, verticalShardSize)
		injectionFailed := false
		for i := range verticalShardSize {
			q, err := cquerysharding.InjectShardingInfo(hr.GetQuery(), &storepb.ShardInfo{
				TotalShards: int64(verticalShardSize),
				ShardIndex:  int64(i),
				By:          analysis.ShardBy(),
				Labels:      analysis.ShardingLabels(),
			})
			if err != nil {
				// Mirror shardBy.shardQuery: on injection failure replace the
				// whole shard group with the single unsharded request.
				injectionFailed = true
				break
			}
			shards = append(shards, PlanTask{
				ID:              taskID(h, i),
				HorizontalIndex: h,
				Query:           q,
				Start:           hr.GetStart(),
				End:             hr.GetEnd(),
				Step:            hr.GetStep(),
				ShardIndex:      i,
				TotalShards:     verticalShardSize,
				Coverage:        segment,
			})
		}
		if injectionFailed {
			tasks = append(tasks, unsharded)
		} else {
			tasks = append(tasks, shards...)
		}
	}
	return tasks, nil
}

// Verify recomputes the plan and task identity digests and reports whether the
// immutable artifact is intact.
func (p *QuerySplitPlan) Verify() error {
	if p.Digest != digestJSON(planDigestContent(p)) {
		return ErrPlanVerificationFailed
	}
	for _, t := range p.Tasks {
		if t.IdentityDigest != taskIdentityDigest(p.Digest, t) {
			return fmt.Errorf("%w: task %s", ErrPlanVerificationFailed, t.ID)
		}
	}
	return nil
}

// TaskByID returns the task and its slice index for the given stable ID.
func (p *QuerySplitPlan) TaskByID(id string) (PlanTask, int, bool) {
	for i, t := range p.Tasks {
		if t.ID == id {
			return t, i, true
		}
	}
	return PlanTask{}, -1, false
}

// planDigestContent is the canonical set of fields covered by the plan digest.
// It deliberately excludes PlanID, CreatedAtUnixMs and Digest itself, and it
// contains no maps, so JSON marshaling is deterministic.
func planDigestContent(p *QuerySplitPlan) any {
	return struct {
		SchemaVersion             int                      `json:"schema_version"`
		OriginalQuery             string                   `json:"original_query"`
		OriginalStart             int64                    `json:"original_start"`
		OriginalEnd               int64                    `json:"original_end"`
		OriginalStep              int64                    `json:"original_step"`
		Path                      string                   `json:"path"`
		TenantIDs                 []string                 `json:"tenant_ids"`
		LookbackDeltaMs           int64                    `json:"lookback_delta_ms"`
		LimitsGeneration          LimitsGeneration         `json:"limits_generation"`
		AnalyzerProtocolVersion   string                   `json:"analyzer_protocol_version"`
		EngineProtocolVersion     string                   `json:"engine_protocol_version"`
		DynamicSplitConfig        DynamicQuerySplitsConfig `json:"dynamic_split_config"`
		BaseSplitIntervalMs       int64                    `json:"base_split_interval_ms"`
		HorizontalSplitIntervalMs int64                    `json:"horizontal_split_interval_ms"`
		VerticalShardSize         int                      `json:"vertical_shard_size"`
		Shardable                 bool                     `json:"shardable"`
		ShardingLabels            []string                 `json:"sharding_labels"`
		Tasks                     []taskDigestContent      `json:"tasks"`
		ReexecutionSemantics      string                   `json:"reexecution_semantics"`
	}{
		SchemaVersion:             p.SchemaVersion,
		OriginalQuery:             p.OriginalQuery,
		OriginalStart:             p.OriginalStart,
		OriginalEnd:               p.OriginalEnd,
		OriginalStep:              p.OriginalStep,
		Path:                      p.Path,
		TenantIDs:                 p.TenantIDs,
		LookbackDeltaMs:           p.LookbackDeltaMs,
		LimitsGeneration:          p.LimitsGeneration,
		AnalyzerProtocolVersion:   p.AnalyzerProtocolVersion,
		EngineProtocolVersion:     p.EngineProtocolVersion,
		DynamicSplitConfig:        p.DynamicSplitConfig,
		BaseSplitIntervalMs:       p.BaseSplitIntervalMs,
		HorizontalSplitIntervalMs: p.HorizontalSplitIntervalMs,
		VerticalShardSize:         p.VerticalShardSize,
		Shardable:                 p.Shardable,
		ShardingLabels:            p.ShardingLabels,
		Tasks:                     taskDigestContents(p.Tasks),
		ReexecutionSemantics:      p.ReexecutionSemantics,
	}
}

type taskDigestContent struct {
	HorizontalIndex int         `json:"horizontal_index"`
	Query           string      `json:"query"`
	Start           int64       `json:"start"`
	End             int64       `json:"end"`
	Step            int64       `json:"step"`
	ShardIndex      int         `json:"shard_index"`
	TotalShards     int         `json:"total_shards"`
	Coverage        GridSegment `json:"coverage"`
}

func taskDigestContents(tasks []PlanTask) []taskDigestContent {
	out := make([]taskDigestContent, 0, len(tasks))
	for _, t := range tasks {
		out = append(out, taskDigestContent{
			HorizontalIndex: t.HorizontalIndex,
			Query:           t.Query,
			Start:           t.Start,
			End:             t.End,
			Step:            t.Step,
			ShardIndex:      t.ShardIndex,
			TotalShards:     t.TotalShards,
			Coverage:        t.Coverage,
		})
	}
	return out
}

func taskIdentityDigest(planDigest string, t PlanTask) string {
	content := struct {
		PlanDigest string `json:"plan_digest"`
		taskDigestContent
	}{
		PlanDigest:        planDigest,
		taskDigestContent: taskDigestContents([]PlanTask{t})[0],
	}
	return digestJSON(content)
}

func digestJSON(v any) string {
	b, err := stdjson.Marshal(v)
	if err != nil {
		// All digest content types are plain structs/slices of JSON-safe types.
		panic(fmt.Sprintf("query split plan: failed to marshal digest content: %v", err))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func taskID(horizontalIndex, shardIndex int) string {
	return fmt.Sprintf("task-%04d-%04d", horizontalIndex, shardIndex)
}

func requestPath(r tripperware.Request) string {
	if pr, ok := r.(*tripperware.PrometheusRequest); ok {
		return pr.GetPath()
	}
	return ""
}

// checkedSub returns a-b and ok=false when the subtraction overflows int64.
func checkedSub(a, b int64) (int64, bool) {
	if b < 0 && a > math.MaxInt64+b {
		return 0, false
	}
	if b > 0 && a < math.MinInt64+b {
		return 0, false
	}
	return a - b, true
}

// checkedAdd returns a+b and ok=false when the addition overflows int64.
func checkedAdd(a, b int64) (int64, bool) {
	if b > 0 && a > math.MaxInt64-b {
		return 0, false
	}
	if b < 0 && a < math.MinInt64-b {
		return 0, false
	}
	return a + b, true
}

func httpgrpcError(status int, msg string) error {
	return httpgrpc.Errorf(status, "%s", msg)
}

// dryRunErrorResponse is the JSON body returned by the dry-run handler on error.
type dryRunErrorResponse struct {
	Status string `json:"status"`
	Error  string `json:"error"`
}

// NewPlanDryRunHandler returns an http.Handler that decodes a query_range
// request, builds the QuerySplitPlan and writes it as JSON. It never invokes a
// downstream query Handler, so it is safe to expose purely for inspection.
func NewPlanDryRunHandler(planner *Planner, codec tripperware.Codec) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := codec.DecodeRequest(r.Context(), r, nil)
		if err != nil {
			writeDryRunError(w, http.StatusBadRequest, err)
			return
		}
		plan, err := planner.DryRun(r.Context(), req)
		if err != nil {
			writeDryRunError(w, dryRunErrorStatus(err), err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := stdjson.NewEncoder(w).Encode(plan); err != nil {
			writeDryRunError(w, http.StatusInternalServerError, err)
		}
	})
}

func dryRunErrorStatus(err error) int {
	switch {
	case errors.Is(err, ErrPlanTooLarge), errors.Is(err, ErrShardCountTooLarge), errors.Is(err, ErrTotalRangeTooLarge):
		return http.StatusUnprocessableEntity
	default:
		return http.StatusBadRequest
	}
}

func writeDryRunError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = stdjson.NewEncoder(w).Encode(dryRunErrorResponse{
		Status: "error",
		Error:  err.Error(),
	})
}
