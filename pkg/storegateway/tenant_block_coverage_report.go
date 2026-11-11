package storegateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/oklog/ulid/v2"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/thanos-io/objstore"
	"github.com/thanos-io/thanos/pkg/block"
	"github.com/thanos-io/thanos/pkg/block/metadata"
	thanos_model "github.com/thanos-io/thanos/pkg/model"

	"github.com/cortexproject/cortex/pkg/storage/bucket"
	"github.com/cortexproject/cortex/pkg/storage/tsdb"
	"github.com/cortexproject/cortex/pkg/storage/tsdb/bucketindex"
	"github.com/cortexproject/cortex/pkg/util"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
)

const (
	// Report statuses. The report never claims to be a complete/atomic snapshot: it is either
	// Unknown (the fixed bucket-index artifact could not be read) or Incomplete (the artifact
	// was read but weakly consistent storage cannot prove a complete listing).
	coverageStatusUnknown    = "Unknown"
	coverageStatusIncomplete = "Incomplete"

	// Segment states. Zero-depth segments are explicitly named "uncovered-metadata": they only
	// describe what the bucket index does not cover and must never be interpreted as sample loss
	// or as evidence that ingesters hold no data for the interval.
	coverageStateCovered           = "covered"
	coverageStateUncoveredMetadata = "uncovered-metadata"
	coverageStateUnknownTruncated  = "unknown-truncated"

	// Filter stage names, in the same order in which the store-gateway applies them.
	filterStageSharding      = "sharding"
	filterStageTimePartition = "time_partition"
	filterStageConsistency   = "consistency_delay"
	filterStageDeletionMark  = "deletion_mark"
	filterStageReplicaLabel  = "replica_label"
	filterStageNonQueryable  = "non_queryable"

	// Per-stage outcomes.
	reasonPassed           = "accepted"
	reasonNotReached       = "not-reached"
	reasonTooFresh         = "too-fresh"
	reasonNonQueryable     = "non-queryable"
	reasonTimeExcluded     = "time-excluded"
	reasonInvalidULID      = "invalid-ulid"
	reasonInvalidTimeRange = "invalid-time-range"

	// Unknown kinds/reasons.
	unknownKindBucketIndex  = "bucket-index"
	unknownKindInvalidBlock = "invalid-block"
	unknownKindTruncated    = "truncated"

	unknownReasonIndexMissing   = "bucket-index-missing"
	unknownReasonIndexCorrupted = "bucket-index-corrupted"
	unknownReasonBlockLimit     = "block-limit-reached"
	unknownReasonEventLimit     = "event-point-limit-reached"

	// Default hard limits bounding the report size. They can be overridden through
	// CoverageReportConfig.Limits.
	defaultMaxBlocks      = 2000
	defaultMaxEventPoints = 10000
	defaultMaxOutputBytes = 1 << 20 // 1 MiB
)

var (
	ErrInvalidCoverageWindow = errors.New("invalid coverage window: minTime must not be negative, maxTime must be a positive millisecond timestamp and maxTime must be greater than minTime")
	ErrReportTooLarge        = errors.New("tenant block coverage report exceeds the configured max output bytes even after truncation")
)

// CoverageReportLimits bounds the size of a report. The zero value is replaced by
// DefaultCoverageReportLimits() when the reporter is built.
type CoverageReportLimits struct {
	MaxBlocks      int `json:"max_blocks"`
	MaxEventPoints int `json:"max_event_points"`
	MaxOutputBytes int `json:"max_output_bytes"`
}

func DefaultCoverageReportLimits() CoverageReportLimits {
	return CoverageReportLimits{
		MaxBlocks:      defaultMaxBlocks,
		MaxEventPoints: defaultMaxEventPoints,
		MaxOutputBytes: defaultMaxOutputBytes,
	}
}

func (l CoverageReportLimits) withDefaults() CoverageReportLimits {
	def := DefaultCoverageReportLimits()
	if l.MaxBlocks <= 0 {
		l.MaxBlocks = def.MaxBlocks
	}
	if l.MaxEventPoints <= 0 {
		l.MaxEventPoints = def.MaxEventPoints
	}
	if l.MaxOutputBytes <= 0 {
		l.MaxOutputBytes = def.MaxOutputBytes
	}
	return l
}

// CoverageReportConfig is the immutable filter configuration used to build the report.
// It mirrors the store-gateway metadata filter wiring so that the report reuses the exact
// same filtering logic without sharing any live filter state.
type CoverageReportConfig struct {
	// ConsistencyDelay maps to -store-gateway.consistency-delay.
	ConsistencyDelay time.Duration
	// IgnoreDeletionMarksDelay maps to -store-gateway.ignore-deletion-marks-delay.
	IgnoreDeletionMarksDelay time.Duration
	// IgnoreBlocksWithin maps to -store-gateway.ignore-blocks-within. Zero disables the filter.
	IgnoreBlocksWithin time.Duration
	// IgnoreBlocksBefore maps to -store-gateway.ignore-blocks-before. Zero disables the filter.
	IgnoreBlocksBefore time.Duration
	// ReplicaLabels are removed from block metadata by the replica label remover. The identity
	// of each block is recorded both before and after removal.
	ReplicaLabels []string
	// Limits bounds the report size.
	Limits CoverageReportLimits
}

// FilterConfigSnapshot is the canonical, hashable representation of the filtering configuration
// that was in effect when the report was observed.
type FilterConfigSnapshot struct {
	ConsistencyDelayMillis         int64    `json:"consistency_delay_millis"`
	IgnoreDeletionMarksDelayMillis int64    `json:"ignore_deletion_marks_delay_millis"`
	IgnoreBlocksWithinMillis       int64    `json:"ignore_blocks_within_millis"`
	IgnoreBlocksBeforeMillis       int64    `json:"ignore_blocks_before_millis"`
	ReplicaLabels                  []string `json:"replica_labels"`
	ShardingStrategy               string   `json:"sharding_strategy"`
}

// CoverageWindow is the explicit half-open [MinTime, MaxTime) time window the report is about.
// Timestamps are in milliseconds.
type CoverageWindow struct {
	MinTime int64 `json:"min_time"`
	MaxTime int64 `json:"max_time"`
}

// FilterStageResult records what a single metadata filter did to one block.
type FilterStageResult struct {
	Stage    string `json:"stage"`
	Excluded bool   `json:"excluded"`
	Reason   string `json:"reason"`
	Detail   string `json:"detail,omitempty"`
}

// BlockCoverageEntry explains why a block present in the bucket index is finally accepted by
// the store-gateway or excluded by one of its metadata filters.
type BlockCoverageEntry struct {
	ULID       string `json:"ulid"`
	MinTime    int64  `json:"min_time"`
	MaxTime    int64  `json:"max_time"`
	UploadedAt string `json:"uploaded_at,omitempty"`

	// LabelsBeforeReplicaLabelRemoval and LabelsAfterReplicaLabelRemoval record the block
	// identity on both sides of the replica label remover. Both are nil for blocks excluded
	// before the replica label stage is reached.
	LabelsBeforeReplicaLabelRemoval map[string]string `json:"labels_before_replica_label_removal,omitempty"`
	LabelsAfterReplicaLabelRemoval  map[string]string `json:"labels_after_replica_label_removal,omitempty"`
	RemovedReplicaLabels            []string          `json:"removed_replica_labels,omitempty"`

	FilterTrace     []FilterStageResult `json:"filter_trace"`
	Accepted        bool                `json:"accepted"`
	ExclusionStage  string              `json:"exclusion_stage,omitempty"`
	ExclusionReason string              `json:"exclusion_reason,omitempty"`
}

// CoverageSegment is a constant-depth interval produced by the sweep-line. Intervals are
// half-open [MinTime, MaxTime).
type CoverageSegment struct {
	MinTime    int64    `json:"min_time"`
	MaxTime    int64    `json:"max_time"`
	Depth      int      `json:"depth"`
	State      string   `json:"state"`
	BlockULIDs []string `json:"block_ulids,omitempty"`
}

// OverlapGroup describes a maximal interval where at least two accepted blocks overlap.
type OverlapGroup struct {
	MinTime    int64    `json:"min_time"`
	MaxTime    int64    `json:"max_time"`
	BlockULIDs []string `json:"block_ulids"`
}

// CoverageUnknown records something that could not be characterized, such as a missing or
// corrupted bucket index, an invalid block entry, or a truncation due to configured limits.
type CoverageUnknown struct {
	Kind      string `json:"kind"`
	Reference string `json:"reference,omitempty"`
	Reason    string `json:"reason"`
	Detail    string `json:"detail,omitempty"`
}

// TenantBlockCoverageReport is the fixed artifact describing block interval coverage and
// overlaps for one authorized tenant and one explicit half-open time window, based on one
// fixed bucket-index object.
type TenantBlockCoverageReport struct {
	TenantID string         `json:"tenant_id"`
	Window   CoverageWindow `json:"window"`

	// ObservedAt is the single observation time bound to the artifact. All time-based filter
	// explanations (consistency delay, non-queryable, deletion mark age) refer to this instant.
	ObservedAt string `json:"observed_at"`

	// Status is Unknown or Incomplete. It is never "complete": weakly consistent object stores
	// cannot provide a consistent, cross-object listing, and the report must never claim one.
	Status string `json:"status"`

	// IndexDigest is the SHA-256 of the raw bucket-index object bytes the report was built from.
	IndexDigest string `json:"index_digest"`
	// IndexUpdatedAt is the UpdatedAt field recorded inside the bucket index.
	IndexUpdatedAt         string               `json:"index_updated_at,omitempty"`
	IndexBlockCount        int                  `json:"index_block_count"`
	IndexDeletionMarks     int                  `json:"index_deletion_marks"`
	FilterConfig           FilterConfigSnapshot `json:"filter_config"`
	FilterConfigGeneration string               `json:"filter_config_generation"`

	Blocks   []BlockCoverageEntry `json:"blocks"`
	Segments []CoverageSegment    `json:"segments"`
	Overlaps []OverlapGroup       `json:"overlaps"`
	Unknowns []CoverageUnknown    `json:"unknowns"`

	// Truncated lists the truncations applied to honor the configured limits.
	Truncated []string `json:"truncated,omitempty"`
	// Limits records the limits the report was built against.
	Limits CoverageReportLimits `json:"limits"`
	// Notices carries the mandatory semantic disclaimers. They are never truncated.
	Notices []string `json:"notices"`
}

// TenantBlockCoverageReporter builds TenantBlockCoverageReport values for a single authorized
// tenant. It never mutates live store-gateway metadata: it reads the bucket index once, builds
// its own copy of the metas, runs fresh filter instances and never downloads or deletes blocks.
type TenantBlockCoverageReporter struct {
	userID      string
	bkt         objstore.Bucket
	strategy    ShardingStrategy
	cfgProvider bucket.TenantConfigProvider
	cfg         CoverageReportConfig
	logger      log.Logger

	// now is injectable for testing. Production code uses time.Now.
	now func() time.Time
}

// NewTenantBlockCoverageReporter creates a reporter bound to one authorized tenant.
func NewTenantBlockCoverageReporter(userID string, bkt objstore.Bucket, strategy ShardingStrategy, cfgProvider bucket.TenantConfigProvider, cfg CoverageReportConfig, logger log.Logger) *TenantBlockCoverageReporter {
	if logger == nil {
		logger = log.NewNopLogger()
	}
	if len(cfg.ReplicaLabels) == 0 {
		// Default to the same replica labels the store-gateway removes in production.
		cfg.ReplicaLabels = []string{tsdb.TenantIDExternalLabel, tsdb.IngesterIDExternalLabel}
	}
	cfg.Limits = cfg.Limits.withDefaults()

	return &TenantBlockCoverageReporter{
		userID:      userID,
		bkt:         bkt,
		strategy:    strategy,
		cfgProvider: cfgProvider,
		cfg:         cfg,
		logger:      util_log.WithUserID(userID, logger),
		now:         func() time.Time { return time.Now().UTC() },
	}
}

// coverageNopGaugeVec is a no-op block.GaugeVec used by the fresh, report-private filter
// instances. The report does not contribute to production metrics: the wrapped gauge is
// unregistered and created per report build.
type coverageNopGaugeVec struct {
	gauge prometheus.Gauge
}

func (g coverageNopGaugeVec) WithLabelValues(_ ...string) prometheus.Gauge { return g.gauge }

// Build generates the report for the explicit half-open window [minTime, maxTime).
func (r *TenantBlockCoverageReporter) Build(ctx context.Context, minTime, maxTime int64) (*TenantBlockCoverageReport, error) {
	if minTime < 0 || maxTime <= 0 || maxTime <= minTime {
		return nil, ErrInvalidCoverageWindow
	}

	observedAt := r.now()
	filterConfig := r.filterConfigSnapshot()
	report := &TenantBlockCoverageReport{
		TenantID:               r.userID,
		Window:                 CoverageWindow{MinTime: minTime, MaxTime: maxTime},
		ObservedAt:             observedAt.Format(time.RFC3339Nano),
		Status:                 coverageStatusIncomplete,
		FilterConfig:           filterConfig,
		FilterConfigGeneration: hashFilterConfig(filterConfig),
		Limits:                 r.cfg.Limits,
		Notices: []string{
			"this report is built from a single bucket-index object and is not a cross-object atomic snapshot of the bucket",
			"object storage is weakly consistent: the bucket index may lag blocks and deletion marks actually present in the bucket",
			"zero-coverage segments describe uncovered bucket-index metadata only; they do not imply sample loss and do not include data held by ingesters",
			"the report does not modify live store-gateway metadata and does not download or delete any block",
		},
	}

	// Read the fixed bucket-index artifact in a single Get. No other bucket object is ever
	// accessed: no Iter, no block download and no deletion.
	idx, digest, err := bucketindex.ReadIndexArtifact(ctx, r.bkt, r.userID, r.cfgProvider, r.logger)
	if err != nil {
		switch {
		case errors.Is(err, bucketindex.ErrIndexNotFound):
			level.Warn(r.logger).Log("msg", "coverage report: bucket index not found", "err", err)
			report.Status = coverageStatusUnknown
			report.Unknowns = append(report.Unknowns, CoverageUnknown{
				Kind:   unknownKindBucketIndex,
				Reason: unknownReasonIndexMissing,
				Detail: "no bucket-index object exists for the tenant; block coverage cannot be characterized",
			})
			return report, nil
		case errors.Is(err, bucketindex.ErrIndexCorrupted):
			level.Warn(r.logger).Log("msg", "coverage report: bucket index corrupted", "err", err)
			report.Status = coverageStatusUnknown
			report.IndexDigest = digest
			report.Unknowns = append(report.Unknowns, CoverageUnknown{
				Kind:   unknownKindBucketIndex,
				Reason: unknownReasonIndexCorrupted,
				Detail: "the bucket-index object cannot be decompressed or decoded; block coverage cannot be characterized",
			})
			return report, nil
		default:
			// Access denied, context cancellation or transient storage errors are hard failures:
			// do not pretend to have an Unknown artifact.
			level.Warn(r.logger).Log("msg", "coverage report: failed to read bucket index", "err", err)
			return nil, errors.Wrap(err, "read bucket index artifact")
		}
	}

	report.IndexDigest = digest
	report.IndexUpdatedAt = idx.GetUpdatedAt().UTC().Format(time.RFC3339Nano)
	report.IndexBlockCount = len(idx.Blocks)
	report.IndexDeletionMarks = len(idx.BlockDeletionMarks)

	// Validate every block before any sorting happens. Invalid entries are surfaced as Unknown
	// and excluded from both filtering and the sweep.
	validBlocks, invalidBlocks := r.validateBlocks(idx.Blocks)
	for _, ub := range invalidBlocks {
		report.Unknowns = append(report.Unknowns, ub)
	}

	// Deterministic ordering, then the block-count limit.
	sortBlocksByIntervalThenULID(validBlocks)
	if len(validBlocks) > r.cfg.Limits.MaxBlocks {
		omitted := len(validBlocks) - r.cfg.Limits.MaxBlocks
		report.Truncated = append(report.Truncated, "blocks")
		report.Unknowns = append(report.Unknowns, CoverageUnknown{
			Kind:   unknownKindTruncated,
			Reason: unknownReasonBlockLimit,
			Detail: fmt.Sprintf("%d bucket-index blocks omitted beyond the limit of %d", omitted, r.cfg.Limits.MaxBlocks),
		})
		validBlocks = validBlocks[:r.cfg.Limits.MaxBlocks]
	}

	// Build the working metas map. These are fresh meta objects owned by the report: the live
	// store-gateway metas map is never touched.
	working := make(map[ulid.ULID]*metadata.Meta, len(validBlocks))
	originals := make(map[ulid.ULID]*metadata.Meta, len(validBlocks))
	entries := make(map[ulid.ULID]*BlockCoverageEntry, len(validBlocks))
	orderedIDs := make([]ulid.ULID, 0, len(validBlocks))

	for _, b := range validBlocks {
		meta := b.ThanosMeta(r.userID)
		working[b.ID] = meta
		originals[b.ID] = meta
		entries[b.ID] = &BlockCoverageEntry{
			ULID:        b.ID.String(),
			MinTime:     b.MinTime,
			MaxTime:     b.MaxTime,
			UploadedAt:  b.GetUploadedAt().UTC().Format(time.RFC3339Nano),
			FilterTrace: []FilterStageResult{},
			Accepted:    true,
		}
		orderedIDs = append(orderedIDs, b.ID)
	}

	if err := r.runFilterChain(ctx, idx, working, originals, orderedIDs, entries, observedAt); err != nil {
		return nil, err
	}

	// Finalize the per-block entries in deterministic order.
	report.Blocks = make([]BlockCoverageEntry, 0, len(orderedIDs))
	accepted := make(map[ulid.ULID]*metadata.Meta, len(orderedIDs))
	for _, id := range orderedIDs {
		entry := entries[id]
		report.Blocks = append(report.Blocks, *entry)
		if entry.Accepted {
			accepted[id] = working[id]
		}
	}

	// Sweep-line over the accepted blocks only: excluded blocks are not served by this
	// store-gateway and therefore do not contribute to its coverage.
	segments, overlaps := r.sweepCoverage(CoverageWindow{MinTime: minTime, MaxTime: maxTime}, accepted, report)
	report.Segments = segments
	report.Overlaps = overlaps

	if err := report.enforceOutputByteLimit(r.cfg.Limits.MaxOutputBytes); err != nil {
		return nil, err
	}

	return report, nil
}

func (r *TenantBlockCoverageReporter) filterConfigSnapshot() FilterConfigSnapshot {
	return FilterConfigSnapshot{
		ConsistencyDelayMillis:         r.cfg.ConsistencyDelay.Milliseconds(),
		IgnoreDeletionMarksDelayMillis: r.cfg.IgnoreDeletionMarksDelay.Milliseconds(),
		IgnoreBlocksWithinMillis:       r.cfg.IgnoreBlocksWithin.Milliseconds(),
		IgnoreBlocksBeforeMillis:       r.cfg.IgnoreBlocksBefore.Milliseconds(),
		ReplicaLabels:                  append([]string(nil), r.cfg.ReplicaLabels...),
		ShardingStrategy:               fmt.Sprintf("%T", r.strategy),
	}
}

func hashFilterConfig(snapshot FilterConfigSnapshot) string {
	b, err := json.Marshal(snapshot)
	if err != nil {
		// The snapshot only contains basic types so this cannot realistically fail.
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// validateBlocks separates valid index blocks from invalid ones. It runs before any sorting,
// as required: malformed identities must not enter the sweep or the filter chain.
func (r *TenantBlockCoverageReporter) validateBlocks(blocks bucketindex.Blocks) (valid bucketindex.Blocks, unknowns []CoverageUnknown) {
	for _, b := range blocks {
		if b == nil {
			unknowns = append(unknowns, CoverageUnknown{
				Kind:   unknownKindInvalidBlock,
				Reason: reasonInvalidULID,
				Detail: "bucket index contains a nil block entry",
			})
			continue
		}

		if b.ID == (ulid.ULID{}) {
			unknowns = append(unknowns, CoverageUnknown{
				Kind:      unknownKindInvalidBlock,
				Reference: b.ID.String(),
				Reason:    reasonInvalidULID,
				Detail:    "block has a zero ULID",
			})
			continue
		}

		if b.MinTime < 0 || b.MaxTime <= b.MinTime {
			unknowns = append(unknowns, CoverageUnknown{
				Kind:      unknownKindInvalidBlock,
				Reference: b.ID.String(),
				Reason:    reasonInvalidTimeRange,
				Detail:    fmt.Sprintf("block has an invalid half-open interval [%d,%d)", b.MinTime, b.MaxTime),
			})
			continue
		}

		valid = append(valid, b)
	}
	return valid, unknowns
}

// runFilterChain runs fresh instances of the real store-gateway metadata filters against the
// report-private metas map, in the exact production order, recording the per-block outcome of
// every stage. The live filter instances (and therefore the live metas) are never touched.
func (r *TenantBlockCoverageReporter) runFilterChain(
	ctx context.Context,
	idx *bucketindex.Index,
	working map[ulid.ULID]*metadata.Meta,
	originals map[ulid.ULID]*metadata.Meta,
	orderedIDs []ulid.ULID,
	entries map[ulid.ULID]*BlockCoverageEntry,
	observedAt time.Time,
) error {
	// Unregistered, report-private metric sink: production metrics are untouched.
	gauge := coverageNopGaugeVec{gauge: prometheus.NewGauge(prometheus.GaugeOpts{})}

	// 1. Sharding. The real fetcher first gates the tenant, then filters blocks through the
	// ring-backed strategy. A brand-new adapter is used so the production adapter's
	// lastBlocks state is never mutated.
	tenantInShard := len(r.strategy.FilterUsers(ctx, []string{r.userID})) == 1
	shardingAdapter := NewShardingMetadataFilterAdapter(r.userID, r.strategy)
	if err := r.traceStage(filterStageSharding, working, orderedIDs, entries, func() error {
		if !tenantInShard {
			for id := range working {
				delete(working, id)
			}
			return nil
		}
		return shardingAdapter.Filter(ctx, working, gauge, gauge)
	}, func(id ulid.ULID) (string, string) {
		if !tenantInShard {
			return shardExcludedMeta, "tenant is not assigned to this store-gateway shard"
		}
		owned, err := r.strategy.OwnBlock(r.userID, *originals[id])
		switch {
		case err != nil:
			return shardExcludedMeta, "ring ownership check failed: " + err.Error()
		case !owned:
			return shardExcludedMeta, "block is not owned by this store-gateway shard"
		default:
			return shardExcludedMeta, "block filtered out by the sharding strategy"
		}
	}); err != nil {
		return err
	}

	// 2. Optional time partition filter (ignore-blocks-before).
	if r.cfg.IgnoreBlocksBefore > 0 {
		filterMaxTimeDuration := model.Duration(time.Second)
		ignoreBlocksBefore := -model.Duration(r.cfg.IgnoreBlocksBefore)
		timeFilter := block.NewTimePartitionMetaFilter(
			thanos_model.TimeOrDurationValue{Dur: &ignoreBlocksBefore},
			thanos_model.TimeOrDurationValue{Dur: &filterMaxTimeDuration},
		)
		if err := r.traceStage(filterStageTimePartition, working, orderedIDs, entries, func() error {
			return timeFilter.Filter(ctx, working, gauge, gauge)
		}, func(id ulid.ULID) (string, string) {
			m := originals[id]
			return reasonTimeExcluded, fmt.Sprintf(
				"block interval [%s,%s) is outside the range kept by ignore-blocks-before (%s)",
				util.TimeFromMillis(m.MinTime).UTC().Format(time.RFC3339),
				util.TimeFromMillis(m.MaxTime).UTC().Format(time.RFC3339),
				r.cfg.IgnoreBlocksBefore.String(),
			)
		}); err != nil {
			return err
		}
	}

	// 3. Consistency delay. Fresh instance of the real Thanos filter; no registry and no
	// shared state. Index-derived metas have no UploadTime, so the filter (correctly) falls
	// back to the ULID timestamp, exactly as it does in the store-gateway.
	consistencyFilter := block.NewConsistencyDelayMetaFilterWithoutMetrics(r.logger, r.cfg.ConsistencyDelay)
	if err := r.traceStage(filterStageConsistency, working, orderedIDs, entries, func() error {
		return consistencyFilter.Filter(ctx, working, gauge, gauge)
	}, func(id ulid.ULID) (string, string) {
		cutoff := observedAt.Add(-r.cfg.ConsistencyDelay)
		ulidTime := time.UnixMilli(int64(id.Time())).UTC()
		return reasonTooFresh, fmt.Sprintf(
			"block ULID timestamp %s is newer than the consistency-delay cutoff %s (delay %s)",
			ulidTime.Format(time.RFC3339), cutoff.Format(time.RFC3339), r.cfg.ConsistencyDelay.String(),
		)
	}); err != nil {
		return err
	}

	// 4. Deletion marks. FilterWithBucketIndex only reads the fixed index: it performs no
	// bucket I/O, so no block is downloaded or deleted.
	userBkt := bucket.NewUserBucketClient(r.userID, r.bkt, r.cfgProvider)
	deletionFilter := NewIgnoreDeletionMarkFilter(r.logger, userBkt, r.cfg.IgnoreDeletionMarksDelay, 1)
	if err := r.traceStage(filterStageDeletionMark, working, orderedIDs, entries, func() error {
		return deletionFilter.FilterWithBucketIndex(ctx, working, idx, gauge)
	}, func(id ulid.ULID) (string, string) {
		for _, mark := range idx.BlockDeletionMarks {
			if mark.ID != id {
				continue
			}
			return block.MarkedForDeletionMeta, fmt.Sprintf(
				"deletion mark recorded at %s is older than the ignore-deletion-marks delay %s",
				mark.GetDeletionTime().UTC().Format(time.RFC3339), r.cfg.IgnoreDeletionMarksDelay.String(),
			)
		}
		return block.MarkedForDeletionMeta, "block is marked for deletion in the bucket index"
	}); err != nil {
		return err
	}

	// 5. Replica label remover. It never excludes blocks, but it changes their identity: both
	// the pre- and post-removal label sets are recorded on the entry.
	replicaRemover := NewReplicaLabelRemover(r.logger, r.cfg.ReplicaLabels)
	if err := r.traceReplicaLabelStage(working, orderedIDs, entries, func() error {
		return replicaRemover.Filter(ctx, working, gauge, gauge)
	}); err != nil {
		return err
	}

	// 6. Optional non-queryable blocks filter (ignore-blocks-within).
	if r.cfg.IgnoreBlocksWithin > 0 {
		nonQueryableFilter := NewIgnoreNonQueryableBlocksFilter(r.logger, r.cfg.IgnoreBlocksWithin)
		if err := r.traceStage(filterStageNonQueryable, working, orderedIDs, entries, func() error {
			return nonQueryableFilter.Filter(ctx, working, gauge, gauge)
		}, func(id ulid.ULID) (string, string) {
			cutoff := observedAt.Add(-r.cfg.IgnoreBlocksWithin)
			m := originals[id]
			return reasonNonQueryable, fmt.Sprintf(
				"block min time %s is newer than the non-queryable cutoff %s (ignore-within %s)",
				util.TimeFromMillis(m.MinTime).UTC().Format(time.RFC3339),
				cutoff.Format(time.RFC3339),
				r.cfg.IgnoreBlocksWithin.String(),
			)
		}); err != nil {
			return err
		}
	}

	return nil
}

// traceStage runs one real filter and records its decision for every known block.
func (r *TenantBlockCoverageReporter) traceStage(
	stage string,
	working map[ulid.ULID]*metadata.Meta,
	orderedIDs []ulid.ULID,
	entries map[ulid.ULID]*BlockCoverageEntry,
	runFilter func() error,
	detail func(id ulid.ULID) (reason string, detail string),
) error {
	if err := runFilter(); err != nil {
		return errors.Wrapf(err, "run %q metadata filter", stage)
	}

	for _, id := range orderedIDs {
		entry := entries[id]

		// Already excluded by an earlier stage: this stage is never reached.
		if !entry.Accepted {
			entry.FilterTrace = append(entry.FilterTrace, FilterStageResult{Stage: stage, Reason: reasonNotReached})
			continue
		}

		if _, ok := working[id]; ok {
			entry.FilterTrace = append(entry.FilterTrace, FilterStageResult{Stage: stage, Reason: reasonPassed})
			continue
		}

		reason, detailText := detail(id)
		entry.Accepted = false
		entry.ExclusionStage = stage
		entry.ExclusionReason = reason
		entry.FilterTrace = append(entry.FilterTrace, FilterStageResult{
			Stage:    stage,
			Excluded: true,
			Reason:   reason,
			Detail:   detailText,
		})
	}
	return nil
}

// traceReplicaLabelStage snapshots labels on both sides of the replica label remover.
func (r *TenantBlockCoverageReporter) traceReplicaLabelStage(
	working map[ulid.ULID]*metadata.Meta,
	orderedIDs []ulid.ULID,
	entries map[ulid.ULID]*BlockCoverageEntry,
	runFilter func() error,
) error {
	before := make(map[ulid.ULID]map[string]string, len(working))
	for id, meta := range working {
		before[id] = cloneLabels(meta.Thanos.Labels)
	}

	if err := runFilter(); err != nil {
		return errors.Wrapf(err, "run %q metadata filter", filterStageReplicaLabel)
	}

	for _, id := range orderedIDs {
		entry := entries[id]
		if !entry.Accepted {
			entry.FilterTrace = append(entry.FilterTrace, FilterStageResult{Stage: filterStageReplicaLabel, Reason: reasonNotReached})
			continue
		}

		meta := working[id]
		entry.LabelsBeforeReplicaLabelRemoval = before[id]
		entry.LabelsAfterReplicaLabelRemoval = cloneLabels(meta.Thanos.Labels)
		entry.RemovedReplicaLabels = removedKeys(before[id], meta.Thanos.Labels)
		entry.FilterTrace = append(entry.FilterTrace, FilterStageResult{Stage: filterStageReplicaLabel, Reason: reasonPassed})
	}
	return nil
}

// sweepCoverage runs the half-open [minTime, maxTime) sweep-line over the accepted blocks and
// returns constant-depth segments and maximal overlap groups.
func (r *TenantBlockCoverageReporter) sweepCoverage(window CoverageWindow, accepted map[ulid.ULID]*metadata.Meta, report *TenantBlockCoverageReport) ([]CoverageSegment, []OverlapGroup) {
	type point struct {
		t      int64
		starts []ulid.ULID
		ends   []ulid.ULID
	}

	pointsByTime := map[int64]*point{}
	for id, meta := range accepted {
		lo := maxInt64(meta.MinTime, window.MinTime)
		hi := minInt64(meta.MaxTime, window.MaxTime)
		if lo >= hi {
			// The block does not intersect the explicit window.
			continue
		}

		start, ok := pointsByTime[lo]
		if !ok {
			start = &point{t: lo}
			pointsByTime[lo] = start
		}
		start.starts = append(start.starts, id)

		end, ok := pointsByTime[hi]
		if !ok {
			end = &point{t: hi}
			pointsByTime[hi] = end
		}
		end.ends = append(end.ends, id)
	}

	pointTimes := make([]int64, 0, len(pointsByTime))
	for t := range pointsByTime {
		pointTimes = append(pointTimes, t)
	}
	sort.Slice(pointTimes, func(i, j int) bool { return pointTimes[i] < pointTimes[j] })

	eventTruncated := false
	if len(pointTimes) > r.cfg.Limits.MaxEventPoints {
		eventTruncated = true
		report.Truncated = append(report.Truncated, "event-points")
		report.Unknowns = append(report.Unknowns, CoverageUnknown{
			Kind:   unknownKindTruncated,
			Reason: unknownReasonEventLimit,
			Detail: fmt.Sprintf("%d sweep event points found beyond the limit of %d; the trailing window cannot be characterized",
				len(pointTimes), r.cfg.Limits.MaxEventPoints),
		})
		pointTimes = pointTimes[:r.cfg.Limits.MaxEventPoints]
	}

	for _, p := range pointsByTime {
		sortULIDs(p.starts)
		sortULIDs(p.ends)
	}

	active := map[ulid.ULID]struct{}{}
	segments := make([]CoverageSegment, 0, len(pointTimes)+1)
	prev := window.MinTime

	emit := func(t int64) {
		if prev >= t {
			return
		}
		ids := sortedActiveIDs(active)
		state := coverageStateUncoveredMetadata
		depth := 0
		if len(active) > 0 {
			state = coverageStateCovered
			depth = len(active)
		}
		segments = append(segments, CoverageSegment{
			MinTime:    prev,
			MaxTime:    t,
			Depth:      depth,
			State:      state,
			BlockULIDs: ids,
		})
	}

	for _, t := range pointTimes {
		if t > window.MaxTime {
			break
		}
		if t >= window.MinTime {
			emit(t)
		}

		// Half-open intervals: at a shared timestamp, endings take effect before beginnings so
		// adjacent blocks [a,b) and [b,c) never count as overlapping.
		p := pointsByTime[t]
		for _, id := range p.ends {
			delete(active, id)
		}
		for _, id := range p.starts {
			active[id] = struct{}{}
		}
		if t > prev {
			prev = t
		}
	}

	if eventTruncated {
		// The remainder of the window contains unprocessed event points: its depth is unknown.
		if prev < window.MaxTime {
			segments = append(segments, CoverageSegment{
				MinTime: prev,
				MaxTime: window.MaxTime,
				State:   coverageStateUnknownTruncated,
			})
		}
	} else {
		emit(window.MaxTime)
	}

	return segments, buildOverlapGroups(segments)
}

// buildOverlapGroups merges adjacent depth>=2 segments sharing the same active block set.
func buildOverlapGroups(segments []CoverageSegment) []OverlapGroup {
	var overlaps []OverlapGroup
	for _, seg := range segments {
		if seg.Depth < 2 {
			continue
		}

		ids := append([]string(nil), seg.BlockULIDs...)
		if last := len(overlaps) - 1; last >= 0 &&
			overlaps[last].MaxTime == seg.MinTime &&
			equalStringSets(overlaps[last].BlockULIDs, ids) {
			overlaps[last].MaxTime = seg.MaxTime
			continue
		}

		overlaps = append(overlaps, OverlapGroup{
			MinTime:    seg.MinTime,
			MaxTime:    seg.MaxTime,
			BlockULIDs: ids,
		})
	}
	return overlaps
}

// enforceOutputByteLimit progressively trims non-essential payload while keeping the safety
// notices and all Unknown entries. It returns ErrReportTooLarge only if no further trimming is
// possible.
func (rep *TenantBlockCoverageReport) enforceOutputByteLimit(limit int) error {
	if l := rep.jsonSize(); l <= limit {
		return nil
	}

	rep.Truncated = append(rep.Truncated, "output-bytes:block-identifiers")
	for i := range rep.Segments {
		rep.Segments[i].BlockULIDs = nil
	}
	for i := range rep.Overlaps {
		rep.Overlaps[i].BlockULIDs = nil
	}
	if rep.jsonSize() <= limit {
		return nil
	}

	rep.Truncated = append(rep.Truncated, "output-bytes:filter-details")
	for i := range rep.Blocks {
		for j := range rep.Blocks[i].FilterTrace {
			rep.Blocks[i].FilterTrace[j].Detail = ""
		}
	}
	if rep.jsonSize() <= limit {
		return nil
	}

	rep.Truncated = append(rep.Truncated, "output-bytes:segments")
	for rep.jsonSize() > limit && len(rep.Segments) > 1 {
		rep.Segments = rep.Segments[:(len(rep.Segments)+1)/2]
	}
	if rep.jsonSize() <= limit {
		return nil
	}

	return ErrReportTooLarge
}

func (rep *TenantBlockCoverageReport) jsonSize() int {
	b, err := json.Marshal(rep)
	if err != nil {
		return 0
	}
	return len(b)
}

func sortBlocksByIntervalThenULID(blocks bucketindex.Blocks) {
	sort.Slice(blocks, func(i, j int) bool {
		if blocks[i].MinTime != blocks[j].MinTime {
			return blocks[i].MinTime < blocks[j].MinTime
		}
		return blocks[i].ID.String() < blocks[j].ID.String()
	})
}

func sortULIDs(ids []ulid.ULID) {
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
}

func sortedActiveIDs(active map[ulid.ULID]struct{}) []string {
	if len(active) == 0 {
		return nil
	}
	ids := make([]string, 0, len(active))
	for id := range active {
		ids = append(ids, id.String())
	}
	sort.Strings(ids)
	return ids
}

func cloneLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func removedKeys(before, after map[string]string) []string {
	var removed []string
	for k := range before {
		if _, ok := after[k]; !ok {
			removed = append(removed, k)
		}
	}
	sort.Strings(removed)
	return removed
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]struct{}, len(a))
	for _, v := range a {
		seen[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := seen[v]; !ok {
			return false
		}
	}
	return true
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
