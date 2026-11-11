package queryrange

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/cortexproject/cortex/pkg/querier/partialdata"
	"github.com/cortexproject/cortex/pkg/querier/tripperware"
	"github.com/cortexproject/cortex/pkg/util/validation"
)

// ReexecutionMode controls how Resume treats confirmed task results that
// cannot be replayed in the current execution context.
type ReexecutionMode string

const (
	// ReexecutionModeDefault rejects mixing confirmed results across processes.
	ReexecutionModeDefault ReexecutionMode = "default"
	// ReexecutionModeAll discards every confirmed result and re-runs the whole
	// plan against current live data, attaching an explicit declaration.
	ReexecutionModeAll ReexecutionMode = "reexecute_all"

	// ReexecutionNoticePrefix is used when a declaration is surfaced as a
	// warning on the merged response.
	ReexecutionNoticePrefix = "cortex query split plan re-execution: "
)

// ConfirmedTask binds a succeeded task ID to the identity digest it had in the
// plan that originally produced it.
type ConfirmedTask struct {
	TaskID            string `json:"task_id"`
	IdentityDigest    string `json:"identity_digest"`
	CompletedAtUnixMs int64  `json:"completed_at_unix_ms"`
}

// RecoveryCursor is the serialized, digest-bound resume handle.
type RecoveryCursor struct {
	PlanDigest      string          `json:"plan_digest"`
	OriginProcessID int             `json:"origin_process_id"`
	PlannedAtUnixMs int64           `json:"planned_at_unix_ms"`
	ConfirmedTasks  []ConfirmedTask `json:"confirmed_tasks"`
}

// TaskState is the runtime state of one task inside an Executor.
type TaskState struct {
	Task              PlanTask
	Status            TaskStatus
	Attempts          int
	FinishSeq         int
	Err               error
	Response          tripperware.Response
	CompletedAtUnixMs int64
}

// TaskStateView is a lock-free snapshot of a TaskState used for inspection.
type TaskStateView struct {
	Task      PlanTask   `json:"task"`
	Status    TaskStatus `json:"status"`
	Attempts  int        `json:"attempts"`
	FinishSeq int        `json:"finish_seq"`
	Error     string     `json:"error,omitempty"`
}

// CoverageReport explains which part of the original request grid the
// succeeded tasks currently cover.
type CoverageReport struct {
	ExpectedPoints  int64         `json:"expected_points"`
	CoveredPoints   int64         `json:"covered_points"`
	MissingSegments []GridSegment `json:"missing_segments"`
	TotalTasks      int           `json:"total_tasks"`
	Succeeded       int           `json:"succeeded"`
	Failed          int           `json:"failed"`
	Partial         int           `json:"partial"`
	Pending         int           `json:"pending"`
	Running         int           `json:"running"`
}

// ExecutionResult is the output of a successful or incomplete execution.
type ExecutionResult struct {
	PlanDigest string
	Response   tripperware.Response
	Coverage   CoverageReport
	Notices    []string
}

// Executor consumes an immutable QuerySplitPlan: it schedules the enumerated
// tasks against a downstream tripperware Handler, tracks per-task status and
// coverage, and merges successful outputs on the original grid.
//
// An Executor is not safe for concurrent Execute/Resume calls; in-flight task
// workers themselves are synchronized through its internal mutex.
type Executor struct {
	downstream       tripperware.Handler
	limits           tripperware.Limits
	horizontalMerger tripperware.Merger
	shardMerger      tripperware.Merger
	processID        int
	mode             ReexecutionMode
	now              func() time.Time

	mu            sync.Mutex
	states        map[string]*TaskState
	activeTasks   []PlanTask
	activeDigest  string
	planCreatedAt int64
	nextFinishSeq int
}

// ExecutorOptions configures an Executor. The two mergers correspond to the
// existing prometheusCodec (horizontal interval merge) and sharded
// prometheusCodec (vertical shard merge) contracts.
type ExecutorOptions struct {
	Mode      ReexecutionMode
	ProcessID int
	Now       func() time.Time
}

// NewExecutor builds an Executor. When opts.ProcessID is zero the OS pid is
// used, which makes a freshly constructed Executor simulate a new process in
// cross-process recovery tests.
func NewExecutor(downstream tripperware.Handler, limits tripperware.Limits, horizontalMerger, shardMerger tripperware.Merger, opts ExecutorOptions) *Executor {
	mode := opts.Mode
	if mode == "" {
		mode = ReexecutionModeDefault
	}
	processID := opts.ProcessID
	if processID == 0 {
		processID = os.Getpid()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Executor{
		downstream:       downstream,
		limits:           limits,
		horizontalMerger: horizontalMerger,
		shardMerger:      shardMerger,
		processID:        processID,
		mode:             mode,
		now:              now,
	}
}

// Execute runs every task of a verified plan.
func (e *Executor) Execute(ctx context.Context, plan *QuerySplitPlan) (*ExecutionResult, error) {
	if err := plan.Verify(); err != nil {
		return nil, err
	}
	states := newTaskStates(plan)

	e.mu.Lock()
	e.states = states
	e.activeTasks = append([]PlanTask(nil), plan.Tasks...)
	e.activeDigest = plan.Digest
	e.planCreatedAt = plan.CreatedAtUnixMs
	e.nextFinishSeq = 0
	e.mu.Unlock()

	if err := e.runPending(ctx, plan, states); err != nil {
		return nil, err
	}
	return e.buildResult(ctx, plan, states, nil)
}

// Resume continues a plan using a digest-bound cursor. Only tasks absent from
// the confirmed set are re-run.
func (e *Executor) Resume(ctx context.Context, plan *QuerySplitPlan, cursor *RecoveryCursor) (*ExecutionResult, error) {
	if err := plan.Verify(); err != nil {
		return nil, err
	}
	if cursor == nil || cursor.PlanDigest != plan.Digest {
		return nil, ErrPlanDigestMismatch
	}

	confirmed := make(map[string]string, len(cursor.ConfirmedTasks))
	for _, c := range cursor.ConfirmedTasks {
		task, _, ok := plan.TaskByID(c.TaskID)
		if !ok || task.IdentityDigest != c.IdentityDigest {
			return nil, fmt.Errorf("%w: task_id=%q", ErrTaskIdentityMismatch, c.TaskID)
		}
		confirmed[c.TaskID] = c.IdentityDigest
	}

	states := newTaskStates(plan)
	var notices []string

	if cursor.OriginProcessID != e.processID {
		if e.mode != ReexecutionModeAll {
			return nil, ErrCrossProcessSnapshotUnavailable
		}
		// Explicit whole-plan re-execution: discard all confirmations and
		// re-run every task against current live data.
		notices = append(notices, ReexecutionNoticePrefix+"whole-plan re-execution requested; all tasks were re-run against current live data and previously confirmed results were discarded")
	} else {
		e.mu.Lock()
		prior := e.states
		activeDigest := e.activeDigest
		e.mu.Unlock()
		// Task IDs are index-based and therefore collide across different
		// plans. Reusing local state is only safe when the executor's current
		// run is exactly the plan being resumed; otherwise results computed for
		// a newer plan would be mixed into the older plan's output.
		if activeDigest != plan.Digest {
			return nil, fmt.Errorf("%w: local results belong to a different plan", ErrCrossProcessSnapshotUnavailable)
		}
		for id := range confirmed {
			prev, ok := prior[id]
			if !ok || prev.Status != TaskStatusSucceeded || prev.Response == nil {
				return nil, fmt.Errorf("%w: confirmed task %q has no locally retained result", ErrCrossProcessSnapshotUnavailable, id)
			}
			states[id].Status = TaskStatusSucceeded
			states[id].Response = prev.Response
			states[id].Attempts = prev.Attempts
			states[id].FinishSeq = prev.FinishSeq
			states[id].CompletedAtUnixMs = prev.CompletedAtUnixMs
		}
	}

	e.mu.Lock()
	e.states = states
	e.activeTasks = append([]PlanTask(nil), plan.Tasks...)
	e.activeDigest = plan.Digest
	e.planCreatedAt = plan.CreatedAtUnixMs
	e.mu.Unlock()

	if err := e.runPending(ctx, plan, states); err != nil {
		return nil, err
	}
	return e.buildResult(ctx, plan, states, notices)
}

// Snapshot returns the digest-bound recovery cursor for the current run.
func (e *Executor) Snapshot() *RecoveryCursor {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.states == nil {
		return nil
	}
	cursor := &RecoveryCursor{
		PlanDigest:      e.activeDigest,
		OriginProcessID: e.processID,
		PlannedAtUnixMs: e.planCreatedAt,
	}
	for _, t := range e.activeTasks {
		st := e.states[t.ID]
		if st != nil && st.Status == TaskStatusSucceeded {
			cursor.ConfirmedTasks = append(cursor.ConfirmedTasks, ConfirmedTask{
				TaskID:            t.ID,
				IdentityDigest:    t.IdentityDigest,
				CompletedAtUnixMs: st.CompletedAtUnixMs,
			})
		}
	}
	return cursor
}

// StateViews returns ordered, lock-free snapshots of every task state.
func (e *Executor) StateViews() []TaskStateView {
	e.mu.Lock()
	defer e.mu.Unlock()
	views := make([]TaskStateView, 0, len(e.activeTasks))
	for _, t := range e.activeTasks {
		st := e.states[t.ID]
		if st == nil {
			continue
		}
		view := TaskStateView{
			Task:      st.Task,
			Status:    st.Status,
			Attempts:  st.Attempts,
			FinishSeq: st.FinishSeq,
		}
		if st.Err != nil {
			view.Error = st.Err.Error()
		}
		views = append(views, view)
	}
	return views
}

// Coverage computes the current coverage report without attempting a merge.
func (e *Executor) Coverage(plan *QuerySplitPlan) CoverageReport {
	e.mu.Lock()
	defer e.mu.Unlock()
	return coverageReport(plan, e.states)
}

func newTaskStates(plan *QuerySplitPlan) map[string]*TaskState {
	states := make(map[string]*TaskState, len(plan.Tasks))
	for _, t := range plan.Tasks {
		states[t.ID] = &TaskState{Task: t, Status: TaskStatusPending}
	}
	return states
}

// runPending schedules all pending tasks with bounded parallelism. Task
// failures never cancel sibling tasks: the caller decides via coverage whether
// the partial outcome is acceptable.
func (e *Executor) runPending(ctx context.Context, plan *QuerySplitPlan, states map[string]*TaskState) error {
	pending := make([]*TaskState, 0, len(plan.Tasks))
	for _, t := range plan.Tasks {
		if states[t.ID].Status == TaskStatusPending {
			pending = append(pending, states[t.ID])
		}
	}
	if len(pending) == 0 {
		return nil
	}

	parallelism := validation.SmallestPositiveIntPerTenant(plan.TenantIDs, e.limits.MaxQueryParallelism)
	if parallelism <= 0 {
		parallelism = 1
	}
	if parallelism > len(pending) {
		parallelism = len(pending)
	}

	jobs := make(chan *TaskState)
	var wg sync.WaitGroup
	for range parallelism {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for st := range jobs {
				e.executeTask(ctx, st)
			}
		}()
	}

	for _, st := range pending {
		select {
		case jobs <- st:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	return nil
}

func (e *Executor) executeTask(ctx context.Context, st *TaskState) {
	e.mu.Lock()
	st.Status = TaskStatusRunning
	st.Attempts++
	e.mu.Unlock()

	resp, err := e.downstream.Do(ctx, taskRequest(st.Task))

	e.mu.Lock()
	defer e.mu.Unlock()
	e.nextFinishSeq++
	st.FinishSeq = e.nextFinishSeq
	st.CompletedAtUnixMs = e.now().UnixMilli()
	if err != nil {
		st.Err = err
		if partialdata.IsPartialDataError(err) {
			st.Status = TaskStatusPartial
		} else {
			st.Status = TaskStatusFailed
		}
		return
	}
	st.Response = resp
	st.Status = TaskStatusSucceeded
}

func taskRequest(t PlanTask) tripperware.Request {
	return &tripperware.PrometheusRequest{
		Start: t.Start,
		End:   t.End,
		Step:  t.Step,
		Query: t.Query,
	}
}

func (e *Executor) buildResult(ctx context.Context, plan *QuerySplitPlan, states map[string]*TaskState, notices []string) (*ExecutionResult, error) {
	report := coverageReport(plan, states)
	result := &ExecutionResult{
		PlanDigest: plan.Digest,
		Coverage:   report,
		Notices:    append([]string(nil), notices...),
	}

	if report.Succeeded != report.TotalTasks {
		return result, fmt.Errorf("%w: succeeded=%d failed=%d partial=%d pending=%d running=%d",
			ErrIncompleteTasks, report.Succeeded, report.Failed, report.Partial, report.Pending, report.Running)
	}
	// Defensive: full success must also mean full grid coverage.
	if report.CoveredPoints != report.ExpectedPoints || len(report.MissingSegments) != 0 {
		return result, fmt.Errorf("%w: covered_points=%d expected_points=%d missing_segments=%d",
			ErrIncompleteTasks, report.CoveredPoints, report.ExpectedPoints, len(report.MissingSegments))
	}

	// Stage 1: merge vertical shards within each horizontal split, in shard
	// index order, using the sharded codec merger contract.
	maxHorizontal := 0
	for _, t := range plan.Tasks {
		if t.HorizontalIndex > maxHorizontal {
			maxHorizontal = t.HorizontalIndex
		}
	}
	horizontalResponses := make([]tripperware.Response, 0, maxHorizontal+1)
	for h := range maxHorizontal + 1 {
		group := make([]tripperware.Response, 0)
		for _, t := range plan.Tasks {
			if t.HorizontalIndex != h {
				continue
			}
			group = append(group, states[t.ID].Response)
		}
		merged, err := e.shardMerger.MergeResponse(ctx, nil, group...)
		if err != nil {
			return result, err
		}
		horizontalResponses = append(horizontalResponses, merged)
	}

	// Stage 2: merge horizontal splits in time order using the standard
	// prometheus codec merger, which de-duplicates shared boundary grid points.
	final, err := e.horizontalMerger.MergeResponse(ctx, nil, horizontalResponses...)
	if err != nil {
		return result, err
	}

	if len(notices) > 0 {
		if promResp, ok := final.(*tripperware.PrometheusResponse); ok {
			for _, n := range notices {
				promResp.Warnings = append(promResp.Warnings, n)
			}
		}
	}
	result.Response = final
	return result, nil
}

func coverageReport(plan *QuerySplitPlan, states map[string]*TaskState) CoverageReport {
	report := CoverageReport{
		ExpectedPoints: (plan.OriginalEnd-plan.OriginalStart)/plan.OriginalStep + 1,
		TotalTasks:     len(plan.Tasks),
	}

	segments := make([]GridSegment, 0)
	for _, t := range plan.Tasks {
		st := states[t.ID]
		if st == nil {
			report.Pending++
			continue
		}
		switch st.Status {
		case TaskStatusSucceeded:
			report.Succeeded++
			segments = append(segments, t.Coverage)
		case TaskStatusFailed:
			report.Failed++
		case TaskStatusPartial:
			report.Partial++
		case TaskStatusRunning:
			report.Running++
		default:
			report.Pending++
		}
	}

	sort.Slice(segments, func(i, j int) bool { return segments[i].FirstTs < segments[j].FirstTs })
	merged := mergeGridSegments(segments, plan.OriginalStep)

	cursor := plan.OriginalStart
	for _, seg := range merged {
		if seg.FirstTs > cursor {
			report.MissingSegments = append(report.MissingSegments, GridSegment{
				FirstTs: cursor,
				LastTs:  seg.FirstTs - plan.OriginalStep,
				Count:   (seg.FirstTs-plan.OriginalStep-cursor)/plan.OriginalStep + 1,
			})
		}
		report.CoveredPoints += (seg.LastTs-seg.FirstTs)/plan.OriginalStep + 1
		cursor = seg.LastTs + plan.OriginalStep
	}
	if cursor <= plan.OriginalEnd {
		report.MissingSegments = append(report.MissingSegments, GridSegment{
			FirstTs: cursor,
			LastTs:  plan.OriginalEnd,
			Count:   (plan.OriginalEnd-cursor)/plan.OriginalStep + 1,
		})
	}
	return report
}

// mergeGridSegments unions step-aligned segments that overlap or touch at a
// shared boundary point.
func mergeGridSegments(segments []GridSegment, step int64) []GridSegment {
	if len(segments) == 0 {
		return nil
	}
	merged := make([]GridSegment, 0, len(segments))
	current := segments[0]
	for _, seg := range segments[1:] {
		if seg.FirstTs <= current.LastTs+step {
			if seg.LastTs > current.LastTs {
				current.LastTs = seg.LastTs
			}
			continue
		}
		merged = append(merged, current)
		current = seg
	}
	merged = append(merged, current)
	return merged
}
