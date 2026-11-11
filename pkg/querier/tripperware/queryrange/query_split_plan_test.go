package queryrange

import (
	"context"
	stdjson "encoding/json"
	"fmt"
	"math"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/stretchr/testify/require"
	"github.com/thanos-io/thanos/pkg/querysharding"
	"github.com/thanos-io/thanos/pkg/store/storepb"
	"github.com/weaveworks/common/user"

	"github.com/cortexproject/cortex/pkg/cortexpb"
	cortexparser "github.com/cortexproject/cortex/pkg/parser"
	"github.com/cortexproject/cortex/pkg/querier/partialdata"
	"github.com/cortexproject/cortex/pkg/querier/tripperware"
	cquerysharding "github.com/cortexproject/cortex/pkg/querysharding"
)

const (
	planTestLookback = 5 * time.Minute
	planTestStep     = int64(60 * 1000)
)

// testUniverse is the deterministic series universe served by fakeDownstream.
var testUniverse = []labels.Labels{
	labels.FromStrings("__name__", "metric", "pod", "pod-0"),
	labels.FromStrings("__name__", "metric", "pod", "pod-1"),
	labels.FromStrings("__name__", "metric", "pod", "pod-2"),
	labels.FromStrings("__name__", "metric", "pod", "pod-3"),
	labels.FromStrings("__name__", "metric", "pod", "pod-5"),
}

// capturedRequest is the normalized identity of a request observed on the wire.
type capturedRequest struct {
	Query       string
	Start       int64
	End         int64
	Step        int64
	ShardIndex  int
	TotalShards int
}

// fakeDownstream is a deterministic tripperware.Handler that emulates a
// shard-aware querier: it filters the fixed series universe through the
// injected ShardInfo matcher and returns step-aligned matrix points.
type fakeDownstream struct {
	mu sync.Mutex

	// calls counts downstream invocations per normalized request key.
	calls map[string]int
	// seen keeps the ordered list of observed requests.
	seen []capturedRequest

	// failNTimes makes the first N calls for a key return err (or partial).
	failNTimes map[string]int
	partial    map[string]bool
	// delayFn optionally stalls a call, used for out-of-order tests.
	delayFn func(key string) time.Duration
}

func newFakeDownstream() *fakeDownstream {
	return &fakeDownstream{
		calls:      map[string]int{},
		failNTimes: map[string]int{},
		partial:    map[string]bool{},
	}
}

func (f *fakeDownstream) Do(ctx context.Context, r tripperware.Request) (tripperware.Response, error) {
	key := requestKey(r)
	captured := capturedRequest{
		Query:       r.GetQuery(),
		Start:       r.GetStart(),
		End:         r.GetEnd(),
		Step:        r.GetStep(),
		ShardIndex:  -1,
		TotalShards: 0,
	}
	if info := extractShardInfo(r.GetQuery()); info != nil {
		captured.ShardIndex = int(info.ShardIndex)
		captured.TotalShards = int(info.TotalShards)
	}

	if f.delayFn != nil {
		if d := f.delayFn(key); d > 0 {
			select {
			case <-time.After(d):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	f.mu.Lock()
	f.calls[key]++
	f.seen = append(f.seen, captured)
	remaining := f.failNTimes[key]
	if remaining > 0 {
		f.failNTimes[key] = remaining - 1
		isPartial := f.partial[key]
		f.mu.Unlock()
		if isPartial {
			return nil, fmt.Errorf("wrapped failure: %w", partialdata.ErrPartialData)
		}
		return nil, fmt.Errorf("simulated downstream failure for %s", key)
	}
	f.mu.Unlock()

	return f.buildResponse(r, captured), nil
}

func (f *fakeDownstream) buildResponse(r tripperware.Request, captured capturedRequest) *tripperware.PrometheusResponse {
	streams := make([]tripperware.SampleStream, 0, len(testUniverse))
	for seriesIdx, lbls := range testUniverse {
		if captured.TotalShards > 0 && !seriesMatchesShard(lbls, r.GetQuery()) {
			continue
		}
		samples := make([]cortexpb.Sample, 0)
		for ts := r.GetStart(); ts <= r.GetEnd(); ts += r.GetStep() {
			samples = append(samples, cortexpb.Sample{
				TimestampMs: ts,
				Value:       float64(seriesIdx*1000 + int((ts/r.GetStep())%97)),
			})
		}
		streams = append(streams, tripperware.SampleStream{
			Labels:  cortexpb.FromLabelsToLabelAdapters(lbls),
			Samples: samples,
		})
	}
	warnings := []string{"shared-warning"}
	if captured.TotalShards > 0 {
		warnings = append(warnings, fmt.Sprintf("shard-warning-%d", captured.ShardIndex))
	}
	return &tripperware.PrometheusResponse{
		Status: tripperware.StatusSuccess,
		Data: tripperware.PrometheusData{
			ResultType: model.ValMatrix.String(),
			Result: tripperware.PrometheusQueryResult{
				Result: &tripperware.PrometheusQueryResult_Matrix{
					Matrix: &tripperware.Matrix{SampleStreams: streams},
				},
			},
		},
		Warnings: warnings,
	}
}

func (f *fakeDownstream) callCount(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[key]
}

func (f *fakeDownstream) totalCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	total := 0
	for _, n := range f.calls {
		total += n
	}
	return total
}

func requestKey(r tripperware.Request) string {
	return fmt.Sprintf("%d|%d|%d|%s", r.GetStart(), r.GetEnd(), r.GetStep(), r.GetQuery())
}

// extractShardInfo extracts the first injected ShardInfo from a query.
func extractShardInfo(query string) *storepb.ShardInfo {
	expr, err := cortexparser.ParseExpr(query)
	if err != nil {
		return nil
	}
	var info *storepb.ShardInfo
	parser.Inspect(expr, func(n parser.Node, _ []parser.Node) error {
		vs, ok := n.(*parser.VectorSelector)
		if !ok {
			return nil
		}
		_, si, err := cquerysharding.ExtractShardingInfo(vs.LabelMatchers)
		if err == nil && si != nil && si.TotalShards > 0 && info == nil {
			info = si
		}
		return nil
	})
	return info
}

// seriesMatchesShard reports whether the labels belong to the request's shard.
func seriesMatchesShard(lbls labels.Labels, query string) bool {
	expr, err := cortexparser.ParseExpr(query)
	if err != nil {
		return false
	}
	matchers := firstVectorSelectorMatchers(expr)
	if matchers == nil {
		return true
	}
	_, matcher, err := cquerysharding.ExtractShardingMatchers(matchers)
	if err != nil || matcher == nil {
		return true
	}
	defer matcher.Close()
	return matcher.MatchesLabels(lbls)
}

func firstVectorSelectorMatchers(expr parser.Expr) []*labels.Matcher {
	var found []*labels.Matcher
	parser.Inspect(expr, func(n parser.Node, _ []parser.Node) error {
		if vs, ok := n.(*parser.VectorSelector); ok && found == nil {
			found = vs.LabelMatchers
		}
		return nil
	})
	return found
}

func encodeDecodePlan(t *testing.T, p *QuerySplitPlan) *QuerySplitPlan {
	t.Helper()
	b, err := stdjson.Marshal(p)
	require.NoError(t, err)
	var out QuerySplitPlan
	require.NoError(t, stdjson.Unmarshal(b, &out))
	return &out
}

func planTestRequest(start, end, step int64, query string) *tripperware.PrometheusRequest {
	return &tripperware.PrometheusRequest{
		Path:  "/api/v1/query_range",
		Start: start,
		End:   end,
		Step:  step,
		Query: query,
	}
}

func planTestContext() context.Context {
	return user.InjectOrgID(context.Background(), "tenant-a")
}

func newTestPlanner(t *testing.T, cfg Config, limits tripperware.Limits, opts PlannerOptions) *Planner {
	t.Helper()
	return NewPlanner(cfg, limits, querysharding.NewQueryAnalyzer(), planTestLookback, opts)
}

func testCodecs() (tripperware.Codec, tripperware.Codec) {
	return NewPrometheusCodec(false, "", string(tripperware.JsonCodecType)),
		NewPrometheusCodec(true, "", string(tripperware.JsonCodecType))
}

// normalizePlanRequests converts plan tasks into the capturedRequest shape.
func normalizePlanTasks(t *testing.T, plan *QuerySplitPlan) []capturedRequest {
	t.Helper()
	out := make([]capturedRequest, 0, len(plan.Tasks))
	for _, task := range plan.Tasks {
		c := capturedRequest{
			Query:       task.Query,
			Start:       task.Start,
			End:         task.End,
			Step:        task.Step,
			ShardIndex:  task.ShardIndex,
			TotalShards: task.TotalShards,
		}
		if task.TotalShards <= 1 {
			c.ShardIndex = -1
			c.TotalShards = 0
		}
		out = append(out, c)
	}
	sortCaptured(out)
	return out
}

func sortCaptured(reqs []capturedRequest) {
	sort.Slice(reqs, func(i, j int) bool {
		if reqs[i].Start != reqs[j].Start {
			return reqs[i].Start < reqs[j].Start
		}
		if reqs[i].ShardIndex != reqs[j].ShardIndex {
			return reqs[i].ShardIndex < reqs[j].ShardIndex
		}
		return reqs[i].Query < reqs[j].Query
	})
}

func TestPlannerEquivalentToMiddlewareChain(t *testing.T) {
	t.Parallel()

	const shardSize = 3
	limits := mockLimits{queryVerticalShardSize: shardSize}
	query := "sum by (pod) (metric)"
	start := time.Unix(0, 0).UnixMilli()
	end := 4 * 24 * int64(time.Hour/time.Millisecond)
	step := planTestStep

	cfg := Config{SplitQueriesByInterval: 24 * time.Hour}

	planner := newTestPlanner(t, cfg, limits, PlannerOptions{})
	plan, err := planner.DryRun(planTestContext(), planTestRequest(start, end, step, query))
	require.NoError(t, err)
	require.NoError(t, plan.Verify())

	// Drive the real middleware chain with the same inputs and capture the
	// exact downstream requests it produces.
	capture := &captureHandler{}
	promCodec, shardedCodec := testCodecs()
	chain := tripperware.MergeMiddlewares(
		SplitByIntervalMiddleware(staticIntervalFn(cfg), limits, promCodec, prometheus.NewRegistry(), planTestLookback),
		tripperware.ShardByMiddleware(log.NewNopLogger(), limits, shardedCodec, querysharding.NewQueryAnalyzer()),
	).Wrap(capture)

	_, err = chain.Do(planTestContext(), planTestRequest(start, end, step, query))
	require.NoError(t, err)

	planned := normalizePlanTasks(t, plan)
	expected := capture.snapshot()
	sortCaptured(expected)
	require.Equal(t, expected, planned)

	// Every planned task must cover the original grid endpoints exactly once at
	// the extremes.
	require.Equal(t, start, plan.Tasks[0].Start)
	require.Equal(t, end, plan.Tasks[len(plan.Tasks)-1].End)
	require.Equal(t, 4, expectedHorizontalSplits(plan))
	require.Equal(t, shardSize, plan.VerticalShardSize)
	require.True(t, plan.Shardable)
}

func TestPlannerEquivalentToMiddlewareChainDynamic(t *testing.T) {
	t.Parallel()

	limits := mockLimits{queryVerticalShardSize: 4}
	query := "sum by (pod) (metric)"
	start := time.Unix(0, 0).UnixMilli()
	end := 4 * 24 * int64(time.Hour/time.Millisecond)
	step := planTestStep

	cfg := Config{
		SplitQueriesByInterval: 24 * time.Hour,
		DynamicQuerySplitsConfig: DynamicQuerySplitsConfig{
			MaxShardsPerQuery:             8,
			EnableDynamicVerticalSharding: true,
		},
	}

	planner := newTestPlanner(t, cfg, limits, PlannerOptions{})
	plan, err := planner.DryRun(planTestContext(), planTestRequest(start, end, step, query))
	require.NoError(t, err)
	require.NoError(t, plan.Verify())

	capture := &captureHandler{}
	_, shardedCodec := testCodecs()
	chain := tripperware.MergeMiddlewares(
		SplitByIntervalMiddleware(dynamicIntervalFn(cfg, limits, querysharding.NewQueryAnalyzer(), planTestLookback), limits, NewPrometheusCodec(false, "", "json"), prometheus.NewRegistry(), planTestLookback),
		tripperware.ShardByMiddleware(log.NewNopLogger(), limits, shardedCodec, querysharding.NewQueryAnalyzer()),
	).Wrap(capture)

	_, err = chain.Do(planTestContext(), planTestRequest(start, end, step, query))
	require.NoError(t, err)

	require.Equal(t, capture.snapshotSorted(), normalizePlanTasks(t, plan))
}

func TestPlannerPreservesRequestContext(t *testing.T) {
	t.Parallel()

	limits := mockLimits{queryVerticalShardSize: 2}
	cfg := Config{SplitQueriesByInterval: 24 * time.Hour}
	planner := newTestPlanner(t, cfg, limits, PlannerOptions{})

	start := int64(3600 * 1000)
	end := start + 3*3600*1000
	req := planTestRequest(start, end, planTestStep, "sum by (pod) (metric)")
	plan, err := planner.DryRun(planTestContext(), req)
	require.NoError(t, err)

	require.Equal(t, "sum by (pod) (metric)", plan.OriginalQuery)
	require.Equal(t, start, plan.OriginalStart)
	require.Equal(t, end, plan.OriginalEnd)
	require.Equal(t, planTestStep, plan.OriginalStep)
	require.Equal(t, "/api/v1/query_range", plan.Path)
	require.Equal(t, []string{"tenant-a"}, plan.TenantIDs)
	require.Equal(t, planTestLookback.Milliseconds(), plan.LookbackDeltaMs)
	require.Equal(t, AnalyzerProtocolVersion, plan.AnalyzerProtocolVersion)
	require.Equal(t, EngineProtocolVersion, plan.EngineProtocolVersion)
	require.Equal(t, PlanSchemaVersion, plan.SchemaVersion)
	require.NotEmpty(t, plan.Digest)
	require.NotEmpty(t, plan.PlanID)
	require.Equal(t, ReexecutionSemanticsDeclaration, plan.ReexecutionSemantics)

	require.NotEmpty(t, plan.LimitsGeneration.Digest)
	require.Len(t, plan.LimitsGeneration.Tenants, 1)
	require.Equal(t, "tenant-a", plan.LimitsGeneration.Tenants[0].TenantID)
	require.Equal(t, 2, plan.LimitsGeneration.Tenants[0].QueryVerticalShardSize)

	// JSON round trip must preserve the whole plan.
	roundTrip := encodeDecodePlan(t, plan)
	require.Equal(t, plan, roundTrip)
}

func TestPlannerDigestSensitivity(t *testing.T) {
	t.Parallel()

	baseReq := planTestRequest(0, 4*3600*1000, planTestStep, "sum by (pod) (metric)")
	baseCfg := Config{SplitQueriesByInterval: time.Hour}

	planA := mustPlan(t, baseCfg, mockLimits{queryVerticalShardSize: 2}, baseReq)
	planACopy := mustPlan(t, baseCfg, mockLimits{queryVerticalShardSize: 2}, baseReq)
	require.Equal(t, planA.Digest, planACopy.Digest)
	require.Len(t, planA.Tasks, len(planACopy.Tasks))
	for i := range planA.Tasks {
		require.Equal(t, planA.Tasks[i].IdentityDigest, planACopy.Tasks[i].IdentityDigest)
	}

	// Any planning-input change must move the digest.
	changedLimits := mustPlan(t, baseCfg, mockLimits{queryVerticalShardSize: 3}, baseReq)
	require.NotEqual(t, planA.Digest, changedLimits.Digest)

	changedQuery := mustPlan(t, baseCfg, mockLimits{queryVerticalShardSize: 2}, planTestRequest(0, 4*3600*1000, planTestStep, "sum by (pod) (metric offset 1m)"))
	require.NotEqual(t, planA.Digest, changedQuery.Digest)

	changedStart := mustPlan(t, baseCfg, mockLimits{queryVerticalShardSize: 2}, planTestRequest(60_000, 4*3600*1000, planTestStep, "sum by (pod) (metric)"))
	require.NotEqual(t, planA.Digest, changedStart.Digest)

	dynCfg := Config{
		SplitQueriesByInterval:   time.Hour,
		DynamicQuerySplitsConfig: DynamicQuerySplitsConfig{MaxShardsPerQuery: 4},
	}
	changedCfg := mustPlan(t, dynCfg, mockLimits{queryVerticalShardSize: 2}, baseReq)
	require.NotEqual(t, planA.Digest, changedCfg.Digest)

	// Tampering with a frozen plan is detected by Verify.
	tampered := encodeDecodePlan(t, planA)
	tampered.Tasks[0].Start += 1
	require.ErrorIs(t, tampered.Verify(), ErrPlanVerificationFailed)
}

func TestPlannerAtModifierResolvedOnce(t *testing.T) {
	t.Parallel()

	start := int64(2 * 3600 * 1000)
	end := start + 4*3600*1000
	for _, query := range []string{
		`metric @ start()`,
		`sum by (pod) (rate(metric[1m] @ end()))`,
		`sum_over_time(metric[1h:1m] @ start())`,
		`rate(metric[5m] @ 1234000)`,
		// Nested subquery carrying @ modifiers at both levels.
		`sum_over_time((sum by (pod) (rate(metric[1m] @ start())))[2h:1m] @ end())`,
	} {
		t.Run(query, func(t *testing.T) {
			t.Parallel()
			cfg := Config{SplitQueriesByInterval: time.Hour}
			plan := mustPlan(t, cfg, mockLimits{queryVerticalShardSize: 2}, planTestRequest(start, end, planTestStep, query))
			require.NotEmpty(t, plan.Tasks)

			for _, task := range plan.Tasks {
				require.NotContains(t, task.Query, "start()", "task query: %s", task.Query)
				require.NotContains(t, task.Query, "end()", "task query: %s", task.Query)

				expr, err := cortexparser.ParseExpr(task.Query)
				require.NoError(t, err)
				assertAtModifiersResolved(t, query, expr, start, end)
			}
			// The constant @ modifier must be preserved verbatim.
			if strings.Contains(query, "@ 1234000") {
				for _, task := range plan.Tasks {
					require.Contains(t, task.Query, "@ 1234000")
				}
			}
		})
	}
}

func assertAtModifiersResolved(t *testing.T, originalQuery string, expr parser.Expr, start, end int64) {
	t.Helper()
	var sawStart, sawEnd bool
	parser.Inspect(expr, func(n parser.Node, _ []parser.Node) error {
		switch sel := n.(type) {
		case *parser.VectorSelector:
			// The StartOrEnd marker must be gone: @start()/@end() are resolved
			// once on the original request into constant timestamps.
			require.Zero(t, sel.StartOrEnd)
			if sel.Timestamp != nil {
				switch *sel.Timestamp {
				case start:
					sawStart = true
				case end:
					sawEnd = true
				}
			}
		case *parser.SubqueryExpr:
			require.Zero(t, sel.StartOrEnd)
			if sel.Timestamp != nil {
				switch *sel.Timestamp {
				case start:
					sawStart = true
				case end:
					sawEnd = true
				}
			}
		}
		return nil
	})
	if strings.Contains(originalQuery, "@ start()") {
		require.True(t, sawStart, "expected a resolved @start() constant at %d in %s", start, expr.String())
	}
	if strings.Contains(originalQuery, "@ end()") {
		require.True(t, sawEnd, "expected a resolved @end() constant at %d in %s", end, expr.String())
	}
}

func TestPlannerBoundsAndOverflow(t *testing.T) {
	t.Parallel()

	cfg := Config{SplitQueriesByInterval: time.Hour}
	shardableQuery := "sum by (pod) (metric)"

	t.Run("step must be positive", func(t *testing.T) {
		t.Parallel()
		planner := newTestPlanner(t, cfg, mockLimits{queryVerticalShardSize: 2}, PlannerOptions{})
		_, err := planner.DryRun(planTestContext(), planTestRequest(0, 1000, 0, shardableQuery))
		require.ErrorIs(t, err, ErrInvalidTimeRange)
	})

	t.Run("zero split interval rejected", func(t *testing.T) {
		t.Parallel()
		planner := newTestPlanner(t, Config{}, mockLimits{queryVerticalShardSize: 2}, PlannerOptions{})
		_, err := planner.DryRun(planTestContext(), planTestRequest(0, 1000, planTestStep, shardableQuery))
		require.Error(t, err)
		require.Contains(t, err.Error(), "split_queries_by_interval")
	})

	t.Run("end before start", func(t *testing.T) {
		t.Parallel()
		planner := newTestPlanner(t, cfg, mockLimits{queryVerticalShardSize: 2}, PlannerOptions{})
		_, err := planner.DryRun(planTestContext(), planTestRequest(1000, 0, planTestStep, shardableQuery))
		require.ErrorIs(t, err, ErrInvalidTimeRange)
	})

	t.Run("int64 span overflow rejected", func(t *testing.T) {
		t.Parallel()
		planner := newTestPlanner(t, cfg, mockLimits{queryVerticalShardSize: 2}, PlannerOptions{})
		_, err := planner.DryRun(planTestContext(), planTestRequest(math.MinInt64, math.MaxInt64, 1, shardableQuery))
		require.ErrorIs(t, err, ErrInvalidTimeRange)
	})

	t.Run("total range cap", func(t *testing.T) {
		t.Parallel()
		planner := newTestPlanner(t, cfg, mockLimits{queryVerticalShardSize: 2}, PlannerOptions{MaxTotalRange: time.Hour})
		_, err := planner.DryRun(planTestContext(), planTestRequest(0, 2*3600*1000, planTestStep, shardableQuery))
		require.ErrorIs(t, err, ErrTotalRangeTooLarge)
	})

	t.Run("task count cap", func(t *testing.T) {
		t.Parallel()
		planner := newTestPlanner(t, cfg, mockLimits{queryVerticalShardSize: 1}, PlannerOptions{MaxPlanTasks: 2})
		_, err := planner.DryRun(planTestContext(), planTestRequest(0, 4*3600*1000, planTestStep, shardableQuery))
		require.ErrorIs(t, err, ErrPlanTooLarge)
	})

	t.Run("vertical shard cap", func(t *testing.T) {
		t.Parallel()
		planner := newTestPlanner(t, cfg, mockLimits{queryVerticalShardSize: 8}, PlannerOptions{MaxVerticalShards: 4})
		_, err := planner.DryRun(planTestContext(), planTestRequest(0, 3600*1000, planTestStep, shardableQuery))
		require.ErrorIs(t, err, ErrShardCountTooLarge)
	})

	t.Run("negative timestamps supported", func(t *testing.T) {
		t.Parallel()
		planner := newTestPlanner(t, Config{SplitQueriesByInterval: 24 * time.Hour}, mockLimits{queryVerticalShardSize: 1}, PlannerOptions{})
		negStart := -48 * 3600 * 1000
		negEnd := -1 * 3600 * 1000
		plan, err := planner.DryRun(planTestContext(), planTestRequest(int64(negStart), int64(negEnd), planTestStep, shardableQuery))
		require.NoError(t, err)
		require.NoError(t, plan.Verify())
		require.Equal(t, int64(negStart), plan.OriginalStart)
		require.Equal(t, int64(negEnd), plan.OriginalEnd)
		for _, task := range plan.Tasks {
			require.Negative(t, task.Start)
			require.Negative(t, task.End)
			require.Equal(t, (task.End-task.Start)/planTestStep+1, task.Coverage.Count)
		}
		require.Equal(t, int64(47*60+1), planCoverageCount(plan))
	})
}

func TestDryRunHandlerNeverExecutes(t *testing.T) {
	t.Parallel()

	cfg := Config{SplitQueriesByInterval: time.Hour}
	planner := newTestPlanner(t, cfg, mockLimits{queryVerticalShardSize: 2}, PlannerOptions{})
	codec, _ := testCodecs()
	handler := NewPlanDryRunHandler(planner, codec)

	server := httptest.NewServer(handler)
	defer server.Close()

	req := httptest.NewRequest("GET", "/api/v1/query_range?start=0&end=3600000&step=60000&query="+strings.ReplaceAll("sum by (pod) (metric)", " ", "+"), nil)
	req = req.WithContext(planTestContext())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, 200, rec.Code)
	var plan QuerySplitPlan
	require.NoError(t, stdjson.Unmarshal(rec.Body.Bytes(), &plan))
	require.NotEmpty(t, plan.Digest)
	require.NotEmpty(t, plan.Tasks)

	// Invalid query is rejected as a 4xx without downstream interaction.
	badReq := httptest.NewRequest("GET", "/api/v1/query_range?start=0&end=1000&step=60000&query=invalid(", nil)
	badReq = badReq.WithContext(planTestContext())
	badRec := httptest.NewRecorder()
	handler.ServeHTTP(badRec, badReq)
	require.GreaterOrEqual(t, badRec.Code, 400)
	require.Less(t, badRec.Code, 500)
}

func expectedHorizontalSplits(plan *QuerySplitPlan) int {
	seen := map[int]struct{}{}
	for _, t := range plan.Tasks {
		seen[t.HorizontalIndex] = struct{}{}
	}
	return len(seen)
}

func planCoverageCount(plan *QuerySplitPlan) int64 {
	return (plan.OriginalEnd-plan.OriginalStart)/plan.OriginalStep + 1
}

func mustPlan(t *testing.T, cfg Config, limits tripperware.Limits, req tripperware.Request) *QuerySplitPlan {
	t.Helper()
	plan, err := newTestPlanner(t, cfg, limits, PlannerOptions{}).DryRun(planTestContext(), req)
	require.NoError(t, err)
	return plan
}

// captureHandler records requests inside the real middleware chain.
type captureHandler struct {
	mu   sync.Mutex
	reqs []capturedRequest
}

func (c *captureHandler) Do(_ context.Context, r tripperware.Request) (tripperware.Response, error) {
	captured := capturedRequest{
		Query:       r.GetQuery(),
		Start:       r.GetStart(),
		End:         r.GetEnd(),
		Step:        r.GetStep(),
		ShardIndex:  -1,
		TotalShards: 0,
	}
	if info := extractShardInfo(r.GetQuery()); info != nil && info.TotalShards > 0 {
		captured.ShardIndex = int(info.ShardIndex)
		captured.TotalShards = int(info.TotalShards)
	}
	c.mu.Lock()
	c.reqs = append(c.reqs, captured)
	c.mu.Unlock()
	return tripperware.NewEmptyPrometheusResponse(false), nil
}

func (c *captureHandler) snapshot() []capturedRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := append([]capturedRequest(nil), c.reqs...)
	return out
}

func (c *captureHandler) snapshotSorted() []capturedRequest {
	out := c.snapshot()
	sortCaptured(out)
	return out
}
