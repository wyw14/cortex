package queryrange

import (
	"context"
	stdjson "encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cortexproject/cortex/pkg/cortexpb"
	"github.com/cortexproject/cortex/pkg/querier/partialdata"
	"github.com/cortexproject/cortex/pkg/querier/tripperware"
)

type matrixPoint struct {
	ts    int64
	value float64
}

func matrixAsMap(t *testing.T, resp tripperware.Response) map[string][]matrixPoint {
	t.Helper()
	promResp, ok := resp.(*tripperware.PrometheusResponse)
	require.True(t, ok)
	matrix := promResp.Data.Result.GetMatrix()
	require.NotNil(t, matrix)

	out := make(map[string][]matrixPoint, len(matrix.GetSampleStreams()))
	for _, stream := range matrix.GetSampleStreams() {
		key := cortexpb.FromLabelAdaptersToLabels(stream.Labels).String()
		points := make([]matrixPoint, 0, len(stream.Samples))
		for _, s := range stream.Samples {
			points = append(points, matrixPoint{ts: s.TimestampMs, value: s.Value})
		}
		out[key] = points
	}
	return out
}

func requirePointwiseEqual(t *testing.T, expected, actual tripperware.Response) {
	t.Helper()
	want := matrixAsMap(t, expected)
	got := matrixAsMap(t, actual)
	require.Equal(t, want, got)
}

func newTestExecutor(t *testing.T, downstream tripperware.Handler, limits tripperware.Limits, mode ReexecutionMode, processID int) *Executor {
	t.Helper()
	promCodec, shardedCodec := testCodecs()
	opts := ExecutorOptions{Mode: mode}
	if processID != 0 {
		opts.ProcessID = processID
	}
	return NewExecutor(downstream, limits, promCodec, shardedCodec, opts)
}

func referenceResponse(t *testing.T, fake *fakeDownstream, plan *QuerySplitPlan) tripperware.Response {
	t.Helper()
	resp, err := fake.Do(context.Background(), planTestRequest(plan.OriginalStart, plan.OriginalEnd, plan.OriginalStep, plan.OriginalQuery))
	require.NoError(t, err)
	return resp
}

func TestExecutorPointwiseEquivalence(t *testing.T) {
	t.Parallel()

	start := time.Unix(0, 0).UnixMilli()
	end := start + 4*3600*1000
	cases := []struct {
		name      string
		query     string
		shardSize int
	}{
		{name: "plain aggregation with vertical shards", query: "sum by (pod) (metric)", shardSize: 3},
		{name: "offset selector with vertical shards", query: "sum by (pod) (metric offset 1h)", shardSize: 2},
		{name: "at start modifier", query: "metric @ start()", shardSize: 2},
		{name: "binary expression with vector matching", query: `metric{pod="pod-1"} / on(pod) metric{pod="pod-2"}`, shardSize: 2},
		{name: "nested subquery horizontal only", query: "sum_over_time((sum by (pod) (rate(metric[1m] @ start())))[2h:1m] @ end())", shardSize: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := Config{SplitQueriesByInterval: time.Hour}
			limits := mockLimits{queryVerticalShardSize: tc.shardSize}
			plan := mustPlan(t, cfg, limits, planTestRequest(start, end, planTestStep, tc.query))
			require.NotEmpty(t, plan.Tasks)

			fake := newFakeDownstream()
			executor := newTestExecutor(t, fake, limits, ReexecutionModeDefault, 100)
			result, err := executor.Execute(planTestContext(), plan)
			require.NoError(t, err)

			requirePointwiseEqual(t, referenceResponse(t, newFakeDownstream(), plan), result.Response)

			// Warnings from every shard must be preserved and de-duplicated.
			promResp := result.Response.(*tripperware.PrometheusResponse)
			require.Contains(t, promResp.Warnings, "shared-warning")
			if tc.shardSize > 1 && plan.Shardable {
				for i := range tc.shardSize {
					require.Contains(t, promResp.Warnings, fmt.Sprintf("shard-warning-%d", i))
				}
			}
			// Coverage spans the whole original grid.
			require.Equal(t, (end-start)/planTestStep+1, result.Coverage.ExpectedPoints)
			require.Equal(t, result.Coverage.ExpectedPoints, result.Coverage.CoveredPoints)
			require.Empty(t, result.Coverage.MissingSegments)
		})
	}
}

func TestExecutorShardUnionReconstructsUniverse(t *testing.T) {
	t.Parallel()

	start := time.Unix(0, 0).UnixMilli()
	end := start + 2*3600*1000
	cfg := Config{SplitQueriesByInterval: time.Hour}
	limits := mockLimits{queryVerticalShardSize: 4}
	plan := mustPlan(t, cfg, limits, planTestRequest(start, end, planTestStep, "sum by (pod) (metric)"))
	require.True(t, plan.Shardable)

	fake := newFakeDownstream()
	executor := newTestExecutor(t, fake, limits, ReexecutionModeDefault, 100)
	result, err := executor.Execute(planTestContext(), plan)
	require.NoError(t, err)

	gotLabels := map[string]struct{}{}
	for key := range matrixAsMap(t, result.Response) {
		gotLabels[key] = struct{}{}
	}
	for _, lbls := range testUniverse {
		_, ok := gotLabels[lbls.String()]
		require.True(t, ok, "series %s missing from shard union", lbls.String())
	}
	require.Len(t, gotLabels, len(testUniverse))
}

func TestExecutorFailedAndPartialAreNeverComplete(t *testing.T) {
	t.Parallel()

	start := time.Unix(0, 0).UnixMilli()
	end := start + 3*3600*1000
	cfg := Config{SplitQueriesByInterval: time.Hour}
	limits := mockLimits{queryVerticalShardSize: 2}
	plan := mustPlan(t, cfg, limits, planTestRequest(start, end, planTestStep, "sum by (pod) (metric)"))

	t.Run("hard failure", func(t *testing.T) {
		t.Parallel()
		fake := newFakeDownstream()
		// Fail every task of the first horizontal split: sibling vertical
		// shards cover the same time segment, so taking the whole split down
		// is what produces an observable missing grid segment.
		failed := 0
		for _, task := range plan.Tasks {
			if task.HorizontalIndex != 0 {
				continue
			}
			fake.failNTimes[requestKey(taskRequest(task))] = 1
			failed++
		}
		require.Greater(t, failed, 0)

		executor := newTestExecutor(t, fake, limits, ReexecutionModeDefault, 100)
		result, err := executor.Execute(planTestContext(), plan)
		require.ErrorIs(t, err, ErrIncompleteTasks)
		require.Nil(t, result.Response)
		require.Equal(t, failed, result.Coverage.Failed)
		require.NotEmpty(t, result.Coverage.MissingSegments)

		views := executor.StateViews()
		for _, v := range views {
			if v.Task.HorizontalIndex == 0 {
				require.Equal(t, TaskStatusFailed, v.Status)
				require.Contains(t, v.Error, "simulated downstream failure")
			} else {
				require.Equal(t, TaskStatusSucceeded, v.Status)
			}
		}
	})

	t.Run("partial data failure", func(t *testing.T) {
		t.Parallel()
		fake := newFakeDownstream()
		failKey := requestKey(taskRequest(plan.Tasks[0]))
		fake.failNTimes[failKey] = 1
		fake.partial[failKey] = true

		executor := newTestExecutor(t, fake, limits, ReexecutionModeDefault, 100)
		result, err := executor.Execute(planTestContext(), plan)
		require.ErrorIs(t, err, ErrIncompleteTasks)
		require.Equal(t, 1, result.Coverage.Partial)

		for _, v := range executor.StateViews() {
			if v.Task.ID == plan.Tasks[0].ID {
				require.Equal(t, TaskStatusPartial, v.Status)
				require.Contains(t, v.Error, partialdata.ErrPartialData.Error())
			} else {
				require.Equal(t, TaskStatusSucceeded, v.Status)
			}
		}
	})
}

func TestExecutorResumeRetriesOnlyIncompleteTasks(t *testing.T) {
	t.Parallel()

	start := time.Unix(0, 0).UnixMilli()
	end := start + 3*3600*1000
	cfg := Config{SplitQueriesByInterval: time.Hour}
	limits := mockLimits{queryVerticalShardSize: 2}
	plan := mustPlan(t, cfg, limits, planTestRequest(start, end, planTestStep, "sum by (pod) (metric)"))

	fake := newFakeDownstream()
	failKey := requestKey(taskRequest(plan.Tasks[0]))
	fake.failNTimes[failKey] = 1

	executor := newTestExecutor(t, fake, limits, ReexecutionModeDefault, 100)
	first, err := executor.Execute(planTestContext(), plan)
	require.ErrorIs(t, err, ErrIncompleteTasks)
	require.Nil(t, first.Response)

	cursor := executor.Snapshot()
	require.Equal(t, plan.Digest, cursor.PlanDigest)
	// Only succeeded tasks are confirmed; the failed one is absent.
	require.Len(t, cursor.ConfirmedTasks, len(plan.Tasks)-1)

	// Second attempt reuses confirmed results and only re-runs the failed task.
	second, err := executor.Resume(planTestContext(), plan, cursor)
	require.NoError(t, err)
	requirePointwiseEqual(t, referenceResponse(t, newFakeDownstream(), plan), second.Response)

	require.Equal(t, 2, fake.callCount(failKey))
	for _, task := range plan.Tasks[1:] {
		require.Equal(t, 1, fake.callCount(requestKey(taskRequest(task))), "task %s must not be re-run", task.ID)
	}

	// The final state reports a fully covered grid.
	require.Empty(t, second.Coverage.MissingSegments)
	require.Equal(t, second.Coverage.ExpectedPoints, second.Coverage.CoveredPoints)
}

func TestExecutorCursorDigestAndIdentityBinding(t *testing.T) {
	t.Parallel()

	start := time.Unix(0, 0).UnixMilli()
	end := start + 2*3600*1000
	cfg := Config{SplitQueriesByInterval: time.Hour}

	plan1 := mustPlan(t, cfg, mockLimits{queryVerticalShardSize: 2}, planTestRequest(start, end, planTestStep, "sum by (pod) (metric)"))
	fake := newFakeDownstream()
	executor := newTestExecutor(t, fake, mockLimits{queryVerticalShardSize: 2}, ReexecutionModeDefault, 100)
	result1, err := executor.Execute(planTestContext(), plan1)
	require.NoError(t, err)
	require.NotNil(t, result1.Response)
	cursor1 := executor.Snapshot()

	t.Run("plan digest mismatch rejects limits-driven replan", func(t *testing.T) {
		plan2 := mustPlan(t, cfg, mockLimits{queryVerticalShardSize: 3}, planTestRequest(start, end, planTestStep, "sum by (pod) (metric)"))
		require.NotEqual(t, plan1.Digest, plan2.Digest)

		_, err := executor.Resume(planTestContext(), plan2, cursor1)
		require.ErrorIs(t, err, ErrPlanDigestMismatch)
	})

	t.Run("tampered task identity rejected", func(t *testing.T) {
		tampered := *cursor1
		tampered.ConfirmedTasks = append([]ConfirmedTask(nil), cursor1.ConfirmedTasks...)
		tampered.ConfirmedTasks[0].IdentityDigest = "tampered-digest"
		_, err := executor.Resume(planTestContext(), plan1, &tampered)
		require.ErrorIs(t, err, ErrTaskIdentityMismatch)
	})

	t.Run("unknown task id rejected", func(t *testing.T) {
		tampered := *cursor1
		tampered.ConfirmedTasks = append([]ConfirmedTask(nil), cursor1.ConfirmedTasks...)
		tampered.ConfirmedTasks[0].TaskID = "task-9999-9999"
		_, err := executor.Resume(planTestContext(), plan1, &tampered)
		require.ErrorIs(t, err, ErrTaskIdentityMismatch)
	})

	t.Run("nil cursor rejected", func(t *testing.T) {
		_, err := executor.Resume(planTestContext(), plan1, nil)
		require.ErrorIs(t, err, ErrPlanDigestMismatch)
	})
}

func TestExecutorOutOfOrderCompletionIsStable(t *testing.T) {
	t.Parallel()

	start := time.Unix(0, 0).UnixMilli()
	end := start + 3*3600*1000
	cfg := Config{SplitQueriesByInterval: time.Hour}
	limits := mockLimits{queryVerticalShardSize: 3}
	plan := mustPlan(t, cfg, limits, planTestRequest(start, end, planTestStep, "sum by (pod) (metric)"))
	require.Greater(t, len(plan.Tasks), 4)

	var baseline tripperware.Response
	for seed := range 3 {
		fake := newFakeDownstream()
		fake.delayFn = func(key string) time.Duration {
			// Deterministic per-seed jitter so completion order is shuffled.
			sum := 0
			for _, c := range key {
				sum += int(c)
			}
			return time.Duration(1+(sum+seed)%7) * time.Millisecond
		}
		executor := newTestExecutor(t, fake, limits, ReexecutionModeDefault, 100)
		result, err := executor.Execute(planTestContext(), plan)
		require.NoError(t, err)

		if baseline == nil {
			baseline = result.Response
		} else {
			requirePointwiseEqual(t, baseline, result.Response)
		}

		views := executor.StateViews()
		require.Len(t, views, len(plan.Tasks))
		// Views are always presented in plan-task index order, regardless of
		// the order workers finished.
		for i, v := range views {
			require.Equal(t, plan.Tasks[i].ID, v.Task.ID)
			require.Equal(t, TaskStatusSucceeded, v.Status)
		}
		// Every task got a distinct finish sequence (completion really was out
		// of order for at least one seed).
		seqs := make([]int, 0, len(views))
		for _, v := range views {
			seqs = append(seqs, v.FinishSeq)
		}
		sort.Ints(seqs)
		for i := range seqs {
			require.Equal(t, i+1, seqs[i])
		}
	}
}

func TestExecutorCrossProcessRecoverySemantics(t *testing.T) {
	t.Parallel()

	start := time.Unix(0, 0).UnixMilli()
	end := start + 2*3600*1000
	cfg := Config{SplitQueriesByInterval: time.Hour}
	limits := mockLimits{queryVerticalShardSize: 2}
	plan := mustPlan(t, cfg, limits, planTestRequest(start, end, planTestStep, "sum by (pod) (metric)"))

	fake := newFakeDownstream()
	first := newTestExecutor(t, fake, limits, ReexecutionModeDefault, 100)
	result, err := first.Execute(planTestContext(), plan)
	require.NoError(t, err)
	expected := result.Response
	cursor := first.Snapshot()
	initialCalls := fake.totalCalls()
	require.Equal(t, len(plan.Tasks), initialCalls)

	t.Run("default mode rejects cross-process mixing", func(t *testing.T) {
		t.Parallel()
		other := newTestExecutor(t, fake, limits, ReexecutionModeDefault, 200)
		_, err := other.Resume(planTestContext(), plan, cursor)
		require.ErrorIs(t, err, ErrCrossProcessSnapshotUnavailable)
	})

	t.Run("reexecute-all reruns the whole plan with declaration", func(t *testing.T) {
		t.Parallel()
		other := newTestExecutor(t, fake, limits, ReexecutionModeAll, 200)
		reResult, err := other.Resume(planTestContext(), plan, cursor)
		require.NoError(t, err)
		requirePointwiseEqual(t, expected, reResult.Response)
		require.NotEmpty(t, reResult.Notices)

		// Every task was re-executed exactly once more.
		require.Equal(t, initialCalls*2, fake.totalCalls())
		warnings := reResult.Response.(*tripperware.PrometheusResponse).Warnings
		found := false
		for _, w := range warnings {
			if len(w) > len(ReexecutionNoticePrefix) && w[:len(ReexecutionNoticePrefix)] == ReexecutionNoticePrefix {
				found = true
			}
		}
		require.True(t, found, "re-execution declaration missing from warnings")
	})
}

func TestExecutorBoundaryPointsDeduped(t *testing.T) {
	t.Parallel()

	start := time.Unix(0, 0).UnixMilli()
	end := start + 3*3600*1000
	cfg := Config{SplitQueriesByInterval: time.Hour}
	limits := mockLimits{queryVerticalShardSize: 1}
	plan := mustPlan(t, cfg, limits, planTestRequest(start, end, planTestStep, "metric"))
	require.Greater(t, expectedHorizontalSplits(plan), 1)

	fake := newFakeDownstream()
	executor := newTestExecutor(t, fake, limits, ReexecutionModeDefault, 100)
	result, err := executor.Execute(planTestContext(), plan)
	require.NoError(t, err)

	for _, points := range matrixAsMap(t, result.Response) {
		seen := map[int64]struct{}{}
		for _, p := range points {
			_, dup := seen[p.ts]
			require.False(t, dup, "duplicated grid point %d", p.ts)
			seen[p.ts] = struct{}{}
		}
		// Full grid length preserved.
		require.Len(t, points, int((end-start)/planTestStep+1))
	}
}

func TestExecutorResumeRejectsStaleLocalStateAfterReplan(t *testing.T) {
	t.Parallel()

	start := time.Unix(0, 0).UnixMilli()
	end := start + 2*3600*1000
	cfg := Config{SplitQueriesByInterval: time.Hour}
	req := planTestRequest(start, end, planTestStep, "sum by (pod) (metric)")

	planA := mustPlan(t, cfg, mockLimits{queryVerticalShardSize: 2}, req)
	fake := newFakeDownstream()
	executor := newTestExecutor(t, fake, mockLimits{queryVerticalShardSize: 2}, ReexecutionModeDefault, 100)
	_, err := executor.Execute(planTestContext(), planA)
	require.NoError(t, err)
	cursorA := executor.Snapshot()

	// A limits-driven replan on the same executor replaces the local state.
	planB := mustPlan(t, cfg, mockLimits{queryVerticalShardSize: 3}, req)
	require.NotEqual(t, planA.Digest, planB.Digest)
	_, err = executor.Execute(planTestContext(), planB)
	require.NoError(t, err)

	// Resuming the older plan must not reuse the newer plan's task results:
	// task IDs are index-based and collide across plans.
	_, err = executor.Resume(planTestContext(), planA, cursorA)
	require.ErrorIs(t, err, ErrCrossProcessSnapshotUnavailable)
}

func TestExecutorResumeWithEmptyConfirmedRerunsEverything(t *testing.T) {
	t.Parallel()

	start := time.Unix(0, 0).UnixMilli()
	end := start + 2*3600*1000
	cfg := Config{SplitQueriesByInterval: time.Hour}
	limits := mockLimits{queryVerticalShardSize: 2}
	plan := mustPlan(t, cfg, limits, planTestRequest(start, end, planTestStep, "sum by (pod) (metric)"))

	fake := newFakeDownstream()
	executor := newTestExecutor(t, fake, limits, ReexecutionModeDefault, 100)
	first, err := executor.Execute(planTestContext(), plan)
	require.NoError(t, err)

	emptyCursor := executor.Snapshot()
	emptyCursor.ConfirmedTasks = nil
	second, err := executor.Resume(planTestContext(), plan, emptyCursor)
	require.NoError(t, err)
	requirePointwiseEqual(t, first.Response, second.Response)
	require.Equal(t, len(plan.Tasks)*2, fake.totalCalls())
}

func TestExecutorNegativeTimestampsGrid(t *testing.T) {
	t.Parallel()

	negStart := int64(-6 * 3600 * 1000)
	negEnd := int64(-1 * 3600 * 1000)
	cfg := Config{SplitQueriesByInterval: 2 * time.Hour}
	limits := mockLimits{queryVerticalShardSize: 2}
	plan := mustPlan(t, cfg, limits, planTestRequest(negStart, negEnd, planTestStep, "sum by (pod) (metric)"))
	for _, task := range plan.Tasks {
		require.Negative(t, task.Start)
		require.Negative(t, task.End)
	}

	fake := newFakeDownstream()
	executor := newTestExecutor(t, fake, limits, ReexecutionModeDefault, 100)
	result, err := executor.Execute(planTestContext(), plan)
	require.NoError(t, err)

	requirePointwiseEqual(t, referenceResponse(t, newFakeDownstream(), plan), result.Response)
	require.Equal(t, (negEnd-negStart)/planTestStep+1, result.Coverage.ExpectedPoints)
	require.Equal(t, result.Coverage.ExpectedPoints, result.Coverage.CoveredPoints)
	require.Empty(t, result.Coverage.MissingSegments)
}

func TestRecoveryCursorJSONRoundTrip(t *testing.T) {
	t.Parallel()

	cursor := &RecoveryCursor{
		PlanDigest:      "abc",
		OriginProcessID: 42,
		PlannedAtUnixMs: 123456,
		ConfirmedTasks: []ConfirmedTask{
			{TaskID: "task-0001-0000", IdentityDigest: "def", CompletedAtUnixMs: 999},
		},
	}
	b, err := stdjson.Marshal(cursor)
	require.NoError(t, err)

	var decoded RecoveryCursor
	require.NoError(t, stdjson.Unmarshal(b, &decoded))
	require.Equal(t, cursor, &decoded)
}
