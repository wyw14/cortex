package storegateway

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"path"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/oklog/ulid/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/thanos-io/objstore"
	"github.com/thanos-io/thanos/pkg/block"
	"github.com/thanos-io/thanos/pkg/block/metadata"

	"github.com/cortexproject/cortex/pkg/storage/bucket"
	"github.com/cortexproject/cortex/pkg/storage/tsdb"
	"github.com/cortexproject/cortex/pkg/storage/tsdb/bucketindex"
	"github.com/cortexproject/cortex/pkg/util/concurrency"
	cortex_testutil "github.com/cortexproject/cortex/pkg/util/testutil"
)

var coverageTestNow = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

func testULID(t *testing.T, idTime time.Time, entropy byte) ulid.ULID {
	t.Helper()
	entropyBytes := make([]byte, 10)
	entropyBytes[0] = entropy
	id, err := ulid.New(ulid.Timestamp(idTime), bytes.NewReader(entropyBytes))
	require.NoError(t, err)
	return id
}

func coverageBlock(id ulid.ULID, minT, maxT int64) *bucketindex.Block {
	return &bucketindex.Block{
		ID:         id,
		MinTime:    minT,
		MaxTime:    maxT,
		UploadedAt: coverageTestNow.Add(-time.Hour).Unix(),
	}
}

func writeCoverageIndex(t *testing.T, ctx context.Context, bkt objstore.Bucket, userID string, idx *bucketindex.Index) {
	t.Helper()
	require.NoError(t, bucketindex.WriteIndex(ctx, bkt, userID, nil, idx))
}

func newCoverageReporter(t *testing.T, userID string, bkt objstore.Bucket, strategy ShardingStrategy, cfg CoverageReportConfig, logger log.Logger) *TenantBlockCoverageReporter {
	t.Helper()
	if strategy == nil {
		strategy = NewNoShardingStrategy(logger, nil)
	}
	r := NewTenantBlockCoverageReporter(userID, bkt, strategy, nil, cfg, logger)
	r.now = func() time.Time { return coverageTestNow }
	return r
}

func findBlockEntry(t *testing.T, rep *TenantBlockCoverageReport, id ulid.ULID) BlockCoverageEntry {
	t.Helper()
	for _, entry := range rep.Blocks {
		if entry.ULID == id.String() {
			return entry
		}
	}
	require.Failf(t, "block entry not found", "ulid: %s", id.String())
	return BlockCoverageEntry{}
}

func acceptedULIDs(rep *TenantBlockCoverageReport) []string {
	var ids []string
	for _, entry := range rep.Blocks {
		if entry.Accepted {
			ids = append(ids, entry.ULID)
		}
	}
	sort.Strings(ids)
	return ids
}

// naiveSegment is an independent brute-force interval scan reference, deliberately not using
// a sweep line, so it can cross-check the reporter implementation.
type naiveSegment struct {
	MinTime int64
	MaxTime int64
	Depth   int
	ULIDs   []string
}

func naiveCoverageReference(t *testing.T, windowMin, windowMax int64, blocks []*bucketindex.Block) []naiveSegment {
	t.Helper()
	type clippedBlock struct {
		id     ulid.ULID
		lo, hi int64
	}

	boundaries := map[int64]struct{}{windowMin: {}, windowMax: {}}
	var clipped []clippedBlock
	for _, b := range blocks {
		lo := maxInt64(b.MinTime, windowMin)
		hi := minInt64(b.MaxTime, windowMax)
		if lo >= hi {
			continue
		}
		clipped = append(clipped, clippedBlock{b.ID, lo, hi})
		boundaries[lo] = struct{}{}
		boundaries[hi] = struct{}{}
	}

	var times []int64
	for ts := range boundaries {
		times = append(times, ts)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })

	var out []naiveSegment
	for i := 0; i+1 < len(times); i++ {
		lo, hi := times[i], times[i+1]
		if lo >= hi {
			continue
		}
		mid := lo + (hi-lo)/2
		var ids []string
		for _, c := range clipped {
			if c.lo <= mid && mid < c.hi {
				ids = append(ids, c.id.String())
			}
		}
		sort.Strings(ids)
		out = append(out, naiveSegment{MinTime: lo, MaxTime: hi, Depth: len(ids), ULIDs: ids})
	}
	return out
}

func TestTenantBlockCoverageReport_SweepLineNestedAndHandoverIntervals(t *testing.T) {
	t.Parallel()
	const userID = "user-1"

	ctx := context.Background()
	bkt, _ := cortex_testutil.PrepareFilesystemBucket(t)
	logger := log.NewNopLogger()

	oldTime := coverageTestNow.Add(-24 * time.Hour)
	blockA := coverageBlock(testULID(t, oldTime, 1), 0, 100)
	blockB := coverageBlock(testULID(t, oldTime, 2), 20, 80)   // nested in A
	blockC := coverageBlock(testULID(t, oldTime, 3), 100, 200) // handover after A
	blockD := coverageBlock(testULID(t, oldTime, 4), 150, 250) // overlaps C
	blockE := coverageBlock(testULID(t, oldTime, 5), 260, 300)
	blockF := coverageBlock(testULID(t, oldTime, 6), 290, 400) // extends beyond the window, must be clipped
	blockG := coverageBlock(testULID(t, oldTime, 7), 300, 400) // starts at window end, no intersection

	writeCoverageIndex(t, ctx, bkt, userID, &bucketindex.Index{
		Version:   bucketindex.IndexVersion1,
		Blocks:    bucketindex.Blocks{blockA, blockB, blockC, blockD, blockE, blockF, blockG},
		UpdatedAt: coverageTestNow.Unix(),
	})

	reporter := newCoverageReporter(t, userID, bkt, nil, CoverageReportConfig{}, logger)
	rep, err := reporter.Build(ctx, 0, 300)
	require.NoError(t, err)
	require.Equal(t, coverageStatusIncomplete, rep.Status)
	require.NotEmpty(t, rep.IndexDigest)
	require.Len(t, rep.Blocks, 7)
	require.ElementsMatch(t,
		[]string{blockA.ID.String(), blockB.ID.String(), blockC.ID.String(), blockD.ID.String(), blockE.ID.String(), blockF.ID.String(), blockG.ID.String()},
		acceptedULIDs(rep))

	expectedSegments := []CoverageSegment{
		{MinTime: 0, MaxTime: 20, Depth: 1, State: coverageStateCovered, BlockULIDs: []string{blockA.ID.String()}},
		{MinTime: 20, MaxTime: 80, Depth: 2, State: coverageStateCovered, BlockULIDs: []string{blockA.ID.String(), blockB.ID.String()}},
		{MinTime: 80, MaxTime: 100, Depth: 1, State: coverageStateCovered, BlockULIDs: []string{blockA.ID.String()}},
		{MinTime: 100, MaxTime: 150, Depth: 1, State: coverageStateCovered, BlockULIDs: []string{blockC.ID.String()}},
		{MinTime: 150, MaxTime: 200, Depth: 2, State: coverageStateCovered, BlockULIDs: []string{blockC.ID.String(), blockD.ID.String()}},
		{MinTime: 200, MaxTime: 250, Depth: 1, State: coverageStateCovered, BlockULIDs: []string{blockD.ID.String()}},
		{MinTime: 250, MaxTime: 260, Depth: 0, State: coverageStateUncoveredMetadata},
		{MinTime: 260, MaxTime: 290, Depth: 1, State: coverageStateCovered, BlockULIDs: []string{blockE.ID.String()}},
		{MinTime: 290, MaxTime: 300, Depth: 2, State: coverageStateCovered, BlockULIDs: []string{blockE.ID.String(), blockF.ID.String()}},
	}
	require.Equal(t, expectedSegments, rep.Segments)

	require.Equal(t, []OverlapGroup{
		{MinTime: 20, MaxTime: 80, BlockULIDs: []string{blockA.ID.String(), blockB.ID.String()}},
		{MinTime: 150, MaxTime: 200, BlockULIDs: []string{blockC.ID.String(), blockD.ID.String()}},
		{MinTime: 290, MaxTime: 300, BlockULIDs: []string{blockE.ID.String(), blockF.ID.String()}},
	}, rep.Overlaps)

	// Cross-check every segment against the independent brute-force interval scan.
	naive := naiveCoverageReference(t, 0, 300, bucketindex.Blocks{blockA, blockB, blockC, blockD, blockE, blockF, blockG})
	require.Len(t, naive, len(rep.Segments))
	for i, seg := range rep.Segments {
		require.Equal(t, naive[i].MinTime, seg.MinTime, "segment %d min time", i)
		require.Equal(t, naive[i].MaxTime, seg.MaxTime, "segment %d max time", i)
		require.Equal(t, naive[i].Depth, seg.Depth, "segment %d depth", i)
		require.Equal(t, naive[i].ULIDs, seg.BlockULIDs, "segment %d blocks", i)
	}

	// Uncovered segments must carry the explicit semantic wording, never a data-loss claim.
	for _, seg := range rep.Segments {
		if seg.Depth == 0 {
			require.Equal(t, coverageStateUncoveredMetadata, seg.State)
		}
	}
	require.Contains(t, rep.Notices[2], "uncovered bucket-index metadata only")
}

func TestTenantBlockCoverageReport_DeletedAndNotYetVisibleBlocks(t *testing.T) {
	t.Parallel()
	const userID = "user-1"

	ctx := context.Background()
	bkt, _ := cortex_testutil.PrepareFilesystemBucket(t)
	logger := log.NewNopLogger()

	// Anchor time-based fixtures to the wall clock: the real filters decide against time.Now().
	now := time.Now().UTC()

	oldBlock := coverageBlock(testULID(t, now.Add(-3*time.Hour), 1), 100, 200)
	freshBlock := coverageBlock(testULID(t, now, 2), 200, 300)
	delOldBlock := coverageBlock(testULID(t, now.Add(-3*time.Hour), 3), 300, 400)
	delRecentBlock := coverageBlock(testULID(t, now.Add(-3*time.Hour), 4), 400, 500)

	index := &bucketindex.Index{
		Version: bucketindex.IndexVersion1,
		Blocks:  bucketindex.Blocks{oldBlock, freshBlock, delOldBlock, delRecentBlock},
		BlockDeletionMarks: bucketindex.BlockDeletionMarks{
			{ID: delOldBlock.ID, DeletionTime: now.Add(-3 * time.Hour).Unix()},
			{ID: delRecentBlock.ID, DeletionTime: now.Add(-30 * time.Minute).Unix()},
		},
		UpdatedAt: now.Unix(),
	}
	writeCoverageIndex(t, ctx, bkt, userID, index)

	cfg := CoverageReportConfig{
		ConsistencyDelay:         time.Hour,
		IgnoreDeletionMarksDelay: 2 * time.Hour,
	}
	reporter := newCoverageReporter(t, userID, bkt, nil, cfg, logger)
	reporter.now = func() time.Time { return now }
	rep, err := reporter.Build(ctx, 0, 1000)
	require.NoError(t, err)

	// Old block: visible and accepted.
	oldEntry := findBlockEntry(t, rep, oldBlock.ID)
	require.True(t, oldEntry.Accepted)

	// Fresh block: excluded by the consistency delay (not yet visible).
	freshEntry := findBlockEntry(t, rep, freshBlock.ID)
	require.False(t, freshEntry.Accepted)
	require.Equal(t, filterStageConsistency, freshEntry.ExclusionStage)
	require.Equal(t, reasonTooFresh, freshEntry.ExclusionReason)
	// Every later stage must be marked as not reached.
	for _, stage := range freshEntry.FilterTrace {
		if stage.Stage == filterStageConsistency {
			require.True(t, stage.Excluded)
		}
		if stage.Stage == filterStageDeletionMark || stage.Stage == filterStageReplicaLabel {
			require.False(t, stage.Excluded)
			require.Equal(t, reasonNotReached, stage.Reason)
		}
	}

	// Block with an old deletion mark: excluded by the deletion mark filter.
	delOldEntry := findBlockEntry(t, rep, delOldBlock.ID)
	require.False(t, delOldEntry.Accepted)
	require.Equal(t, filterStageDeletionMark, delOldEntry.ExclusionStage)
	require.Equal(t, block.MarkedForDeletionMeta, delOldEntry.ExclusionReason)

	// Block with a recent deletion mark: still kept because the ignore delay has not elapsed.
	delRecentEntry := findBlockEntry(t, rep, delRecentBlock.ID)
	require.True(t, delRecentEntry.Accepted)

	require.ElementsMatch(t, []string{oldBlock.ID.String(), delRecentBlock.ID.String()}, acceptedULIDs(rep))

	// Only accepted blocks contribute to the sweep.
	for _, seg := range rep.Segments {
		for _, id := range seg.BlockULIDs {
			require.NotEqual(t, freshBlock.ID.String(), id)
			require.NotEqual(t, delOldBlock.ID.String(), id)
		}
	}
}

func TestTenantBlockCoverageReport_ShardExclusion(t *testing.T) {
	t.Parallel()
	const userID = "user-1"

	ctx := context.Background()
	bkt, _ := cortex_testutil.PrepareFilesystemBucket(t)

	oldTime := coverageTestNow.Add(-24 * time.Hour)
	keptBlock := coverageBlock(testULID(t, oldTime, 1), 0, 100)
	excludedBlock := coverageBlock(testULID(t, oldTime, 2), 100, 200)

	writeCoverageIndex(t, ctx, bkt, userID, &bucketindex.Index{
		Version:   bucketindex.IndexVersion1,
		Blocks:    bucketindex.Blocks{keptBlock, excludedBlock},
		UpdatedAt: coverageTestNow.Unix(),
	})

	t.Run("block owned by another shard", func(t *testing.T) {
		strategy := &mockShardingStrategy{}
		strategy.On("FilterUsers", mock.Anything, []string{userID}).Return([]string{userID})
		strategy.On("FilterBlocks", mock.Anything, userID, mock.Anything, mock.Anything, mock.Anything).
			Return(nil).
			Run(func(args mock.Arguments) {
				metas := args.Get(2).(map[ulid.ULID]*metadata.Meta)
				delete(metas, excludedBlock.ID)
			})
		strategy.On("OwnBlock", userID, mock.MatchedBy(func(m metadata.Meta) bool { return m.ULID == excludedBlock.ID })).
			Return(false, nil)

		reporter := newCoverageReporter(t, userID, bkt, strategy, CoverageReportConfig{}, log.NewNopLogger())
		rep, err := reporter.Build(ctx, 0, 300)
		require.NoError(t, err)

		entry := findBlockEntry(t, rep, excludedBlock.ID)
		require.False(t, entry.Accepted)
		require.Equal(t, filterStageSharding, entry.ExclusionStage)
		require.Equal(t, shardExcludedMeta, entry.ExclusionReason)
		require.Contains(t, entry.FilterTrace[0].Detail, "not owned by this store-gateway shard")

		require.Equal(t, []string{keptBlock.ID.String()}, acceptedULIDs(rep))
		for _, seg := range rep.Segments {
			require.NotContains(t, seg.BlockULIDs, excludedBlock.ID.String())
		}
	})

	t.Run("tenant not assigned to the shard", func(t *testing.T) {
		strategy := &mockShardingStrategy{}
		strategy.On("FilterUsers", mock.Anything, []string{userID}).Return([]string{})

		reporter := newCoverageReporter(t, userID, bkt, strategy, CoverageReportConfig{}, log.NewNopLogger())
		rep, err := reporter.Build(ctx, 0, 300)
		require.NoError(t, err)

		require.Empty(t, acceptedULIDs(rep))
		for _, entry := range rep.Blocks {
			require.False(t, entry.Accepted)
			require.Equal(t, filterStageSharding, entry.ExclusionStage)
			require.Contains(t, entry.FilterTrace[0].Detail, "tenant is not assigned")
		}
		// No block is served by this shard: the whole window is reported as uncovered
		// metadata, never as sample loss.
		require.Equal(t, []CoverageSegment{{
			MinTime: 0,
			MaxTime: 300,
			Depth:   0,
			State:   coverageStateUncoveredMetadata,
		}}, rep.Segments)
	})
}

func TestTenantBlockCoverageReport_ReplicaLabelIdentity(t *testing.T) {
	t.Parallel()
	const userID = "user-1"

	ctx := context.Background()
	bkt, _ := cortex_testutil.PrepareFilesystemBucket(t)

	block1 := coverageBlock(testULID(t, coverageTestNow.Add(-24*time.Hour), 1), 0, 100)
	writeCoverageIndex(t, ctx, bkt, userID, &bucketindex.Index{
		Version:   bucketindex.IndexVersion1,
		Blocks:    bucketindex.Blocks{block1},
		UpdatedAt: coverageTestNow.Unix(),
	})

	reporter := newCoverageReporter(t, userID, bkt, nil, CoverageReportConfig{
		ReplicaLabels: []string{tsdb.TenantIDExternalLabel, tsdb.IngesterIDExternalLabel},
	}, log.NewNopLogger())
	rep, err := reporter.Build(ctx, 0, 200)
	require.NoError(t, err)

	entry := findBlockEntry(t, rep, block1.ID)
	require.True(t, entry.Accepted)
	// Identity before replica label removal still carries the tenant external label.
	require.Equal(t, map[string]string{tsdb.TenantIDExternalLabel: userID}, entry.LabelsBeforeReplicaLabelRemoval)
	// Identity after removal has no labels left.
	require.Empty(t, entry.LabelsAfterReplicaLabelRemoval)
	require.Equal(t, []string{tsdb.TenantIDExternalLabel}, entry.RemovedReplicaLabels)

	// The same identity recording must work for arbitrary replica labels present on metas.
	t.Run("synthetic labels via direct stage", func(t *testing.T) {
		syntheticID := testULID(t, coverageTestNow.Add(-24*time.Hour), 9)
		working := map[ulid.ULID]*metadata.Meta{
			syntheticID: {
				ULID:    syntheticID,
				MinTime: 0,
				MaxTime: 100,
				Thanos: metadata.Thanos{Labels: map[string]string{
					tsdb.TenantIDExternalLabel:   userID,
					tsdb.IngesterIDExternalLabel: "ingester-0",
					"keep":                       "value",
				}},
			},
		}
		entries := map[ulid.ULID]*BlockCoverageEntry{syntheticID: {Accepted: true, FilterTrace: []FilterStageResult{}}}
		r := newCoverageReporter(t, userID, bkt, nil, CoverageReportConfig{}, log.NewNopLogger())
		nopGauge := coverageNopGaugeVec{gauge: prometheus.NewGauge(prometheus.GaugeOpts{})}
		require.NoError(t, r.traceReplicaLabelStage(working, []ulid.ULID{syntheticID}, entries, func() error {
			return NewReplicaLabelRemover(log.NewNopLogger(),
				[]string{tsdb.TenantIDExternalLabel, tsdb.IngesterIDExternalLabel}).
				Filter(ctx, working, nopGauge, nopGauge)
		}))

		require.Equal(t, map[string]string{"keep": "value"}, entries[syntheticID].LabelsAfterReplicaLabelRemoval)
		require.ElementsMatch(t,
			[]string{tsdb.TenantIDExternalLabel, tsdb.IngesterIDExternalLabel},
			entries[syntheticID].RemovedReplicaLabels)
	})
}

func TestTenantBlockCoverageReport_MatchesRealFetcherAndPreservesLiveState(t *testing.T) {
	t.Parallel()
	const userID = "user-1"

	ctx := context.Background()
	bkt, _ := cortex_testutil.PrepareFilesystemBucket(t)
	logger := log.NewNopLogger()

	// Anchor time-based fixtures to the wall clock: the real filters decide against time.Now().
	now := time.Now().UTC()

	oldBlock := coverageBlock(testULID(t, now.Add(-3*time.Hour), 1), 100, 200)
	freshBlock := coverageBlock(testULID(t, now, 2), 200, 300)
	delOldBlock := coverageBlock(testULID(t, now.Add(-3*time.Hour), 3), 300, 400)
	delRecentBlock := coverageBlock(testULID(t, now.Add(-3*time.Hour), 4), 400, 500)

	writeCoverageIndex(t, ctx, bkt, userID, &bucketindex.Index{
		Version: bucketindex.IndexVersion1,
		Blocks:  bucketindex.Blocks{oldBlock, freshBlock, delOldBlock, delRecentBlock},
		BlockDeletionMarks: bucketindex.BlockDeletionMarks{
			{ID: delOldBlock.ID, DeletionTime: now.Add(-3 * time.Hour).Unix()},
			{ID: delRecentBlock.ID, DeletionTime: now.Add(-30 * time.Minute).Unix()},
		},
		UpdatedAt: now.Unix(),
	})

	const (
		consistencyDelay = time.Hour
		deletionDelay    = 2 * time.Hour
	)
	replicaLabels := []string{tsdb.TenantIDExternalLabel, tsdb.IngesterIDExternalLabel}

	// Wire the real store-gateway fetcher exactly like bucket_stores.go does.
	userBkt := bucket.NewUserBucketClient(userID, bkt, nil)
	realFilters := []block.MetadataFilter{
		NewShardingMetadataFilterAdapter(userID, NewNoShardingStrategy(logger, nil)),
		block.NewConsistencyDelayMetaFilter(logger, consistencyDelay, prometheus.NewPedanticRegistry()),
		NewIgnoreDeletionMarkFilter(logger, userBkt, deletionDelay, 1),
		NewReplicaLabelRemover(logger, replicaLabels),
	}
	fetcher := NewBucketIndexMetadataFetcher(userID, bkt, NewNoShardingStrategy(logger, nil), nil, logger,
		prometheus.NewPedanticRegistry(), realFilters)

	metasBefore, _, err := fetcher.Fetch(ctx)
	require.NoError(t, err)

	reporter := newCoverageReporter(t, userID, bkt, nil, CoverageReportConfig{
		ConsistencyDelay:         consistencyDelay,
		IgnoreDeletionMarksDelay: deletionDelay,
		ReplicaLabels:            replicaLabels,
	}, logger)
	reporter.now = func() time.Time { return now }
	rep, err := reporter.Build(ctx, 0, 1000)
	require.NoError(t, err)

	// The reporter's accepted set must exactly match the real fetcher's final metas.
	require.Equal(t, len(metasBefore), len(acceptedULIDs(rep)))
	for id, meta := range metasBefore {
		entry := findBlockEntry(t, rep, id)
		require.True(t, entry.Accepted)
		// Post replica-removal identity must match the fetcher meta identity.
		if len(meta.Thanos.Labels) == 0 {
			require.Empty(t, entry.LabelsAfterReplicaLabelRemoval)
		} else {
			require.Equal(t, meta.Thanos.Labels, entry.LabelsAfterReplicaLabelRemoval)
		}
	}

	// Live fetcher state is unchanged after running the reporter.
	metasAfter, _, err := fetcher.Fetch(ctx)
	require.NoError(t, err)
	require.Equal(t, metasBefore, metasAfter)

	// Running the reporter again with a fixed observation clock produces the exact same artifact.
	rep2, err := reporter.Build(ctx, 0, 1000)
	require.NoError(t, err)
	repJSON, err := json.Marshal(rep)
	require.NoError(t, err)
	rep2JSON, err := json.Marshal(rep2)
	require.NoError(t, err)
	require.Equal(t, string(repJSON), string(rep2JSON))
}

func TestTenantBlockCoverageReport_DoesNotMutateBucket(t *testing.T) {
	t.Parallel()
	const userID = "user-1"

	ctx := context.Background()

	block1 := coverageBlock(testULID(t, coverageTestNow.Add(-24*time.Hour), 1), 0, 100)
	idx := &bucketindex.Index{
		Version:   bucketindex.IndexVersion1,
		Blocks:    bucketindex.Blocks{block1},
		UpdatedAt: coverageTestNow.Unix(),
	}

	// Manually gzip the index so the strict mock can serve it through Get only.
	rawIndex, err := json.Marshal(idx)
	require.NoError(t, err)
	var gzipped bytes.Buffer
	gw := gzip.NewWriter(&gzipped)
	_, err = gw.Write(rawIndex)
	require.NoError(t, err)
	require.NoError(t, gw.Close())

	bkt := &bucket.ClientMock{}
	indexPath := path.Join(userID, bucketindex.IndexCompressedFilename)
	bkt.MockGet(indexPath, gzipped.String(), nil)

	reporter := newCoverageReporter(t, userID, bkt, nil, CoverageReportConfig{
		IgnoreDeletionMarksDelay: time.Hour,
	}, log.NewNopLogger())
	rep, err := reporter.Build(ctx, 0, 200)
	require.NoError(t, err)
	require.True(t, findBlockEntry(t, rep, block1.ID).Accepted)

	// Exactly one Get (the index object), and no mutation/listing operation whatsoever.
	bkt.AssertNumberOfCalls(t, "Get", 1)
	bkt.AssertNotCalled(t, "Upload", mock.Anything, mock.Anything, mock.Anything)
	bkt.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	bkt.AssertNotCalled(t, "Iter", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	bkt.AssertNotCalled(t, "IterWithAttributes", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestTenantBlockCoverageReport_UnknownWhenIndexMissingOrCorrupted(t *testing.T) {
	t.Parallel()
	const userID = "user-1"

	ctx := context.Background()
	logger := log.NewNopLogger()

	t.Run("missing index", func(t *testing.T) {
		bkt, _ := cortex_testutil.PrepareFilesystemBucket(t)
		reporter := newCoverageReporter(t, userID, bkt, nil, CoverageReportConfig{}, logger)
		rep, err := reporter.Build(ctx, 0, 100)
		require.NoError(t, err)
		require.Equal(t, coverageStatusUnknown, rep.Status)
		require.Len(t, rep.Unknowns, 1)
		require.Equal(t, unknownKindBucketIndex, rep.Unknowns[0].Kind)
		require.Equal(t, unknownReasonIndexMissing, rep.Unknowns[0].Reason)
		require.Empty(t, rep.Blocks)
		require.Empty(t, rep.Segments)
	})

	t.Run("corrupted index", func(t *testing.T) {
		bkt, _ := cortex_testutil.PrepareFilesystemBucket(t)
		require.NoError(t, bkt.Upload(ctx, path.Join(userID, bucketindex.IndexCompressedFilename), strings.NewReader("not-gzip")))

		reporter := newCoverageReporter(t, userID, bkt, nil, CoverageReportConfig{}, logger)
		rep, err := reporter.Build(ctx, 0, 100)
		require.NoError(t, err)
		require.Equal(t, coverageStatusUnknown, rep.Status)
		require.Len(t, rep.Unknowns, 1)
		require.Equal(t, unknownReasonIndexCorrupted, rep.Unknowns[0].Reason)
		// The digest still binds the report to the exact (unparseable) artifact bytes.
		require.Len(t, rep.IndexDigest, 64)
	})

	t.Run("access denied is a hard error", func(t *testing.T) {
		bkt := &bucket.ClientMock{}
		bkt.MockGet(path.Join(userID, bucketindex.IndexCompressedFilename), "c", bucket.ErrCustomerManagedKeyAccessDenied)

		reporter := newCoverageReporter(t, userID, bkt, nil, CoverageReportConfig{}, logger)
		_, err := reporter.Build(ctx, 0, 100)
		require.Error(t, err)
		require.True(t, errors.Is(err, bucket.ErrCustomerManagedKeyAccessDenied))
	})
}

func TestTenantBlockCoverageReport_InvalidBlocksAndLimits(t *testing.T) {
	t.Parallel()
	const userID = "user-1"

	ctx := context.Background()
	bkt, _ := cortex_testutil.PrepareFilesystemBucket(t)
	logger := log.NewNopLogger()

	zeroULIDBlock := &bucketindex.Block{ID: ulid.ULID{}, MinTime: 0, MaxTime: 100}
	badRangeBlock := coverageBlock(testULID(t, coverageTestNow.Add(-24*time.Hour), 1), 100, 100)
	goodBlock1 := coverageBlock(testULID(t, coverageTestNow.Add(-24*time.Hour), 2), 0, 100)
	goodBlock2 := coverageBlock(testULID(t, coverageTestNow.Add(-24*time.Hour), 3), 100, 200)
	goodBlock3 := coverageBlock(testULID(t, coverageTestNow.Add(-24*time.Hour), 4), 200, 300)
	goodBlock4 := coverageBlock(testULID(t, coverageTestNow.Add(-24*time.Hour), 5), 300, 400)

	writeCoverageIndex(t, ctx, bkt, userID, &bucketindex.Index{
		Version:   bucketindex.IndexVersion1,
		Blocks:    bucketindex.Blocks{zeroULIDBlock, badRangeBlock, goodBlock1, goodBlock2, goodBlock3, goodBlock4},
		UpdatedAt: coverageTestNow.Unix(),
	})

	t.Run("invalid blocks are reported before sorting", func(t *testing.T) {
		reporter := newCoverageReporter(t, userID, bkt, nil, CoverageReportConfig{}, logger)
		rep, err := reporter.Build(ctx, 0, 500)
		require.NoError(t, err)

		var reasons []string
		for _, u := range rep.Unknowns {
			if u.Kind == unknownKindInvalidBlock {
				reasons = append(reasons, u.Reason)
			}
		}
		require.ElementsMatch(t, []string{reasonInvalidULID, reasonInvalidTimeRange}, reasons)
		require.Len(t, rep.Blocks, 4)
	})

	t.Run("block count limit", func(t *testing.T) {
		cfg := CoverageReportConfig{Limits: CoverageReportLimits{MaxBlocks: 2, MaxEventPoints: 100, MaxOutputBytes: defaultMaxOutputBytes}}
		reporter := newCoverageReporter(t, userID, bkt, nil, cfg, logger)
		rep, err := reporter.Build(ctx, 0, 500)
		require.NoError(t, err)
		require.Contains(t, rep.Truncated, "blocks")
		require.Len(t, rep.Blocks, 2)
		require.True(t, hasUnknownReason(rep, unknownReasonBlockLimit))
	})

	t.Run("event point limit", func(t *testing.T) {
		cfg := CoverageReportConfig{Limits: CoverageReportLimits{MaxBlocks: 100, MaxEventPoints: 1, MaxOutputBytes: defaultMaxOutputBytes}}
		reporter := newCoverageReporter(t, userID, bkt, nil, cfg, logger)
		rep, err := reporter.Build(ctx, 0, 500)
		require.NoError(t, err)
		require.Contains(t, rep.Truncated, "event-points")
		require.True(t, hasUnknownReason(rep, unknownReasonEventLimit))
		require.Equal(t, coverageStateUnknownTruncated, rep.Segments[len(rep.Segments)-1].State)
	})

	t.Run("output byte limit", func(t *testing.T) {
		cfg := CoverageReportConfig{Limits: CoverageReportLimits{MaxBlocks: 100, MaxEventPoints: 100, MaxOutputBytes: 10}}
		reporter := newCoverageReporter(t, userID, bkt, nil, cfg, logger)
		_, err := reporter.Build(ctx, 0, 500)
		require.ErrorIs(t, err, ErrReportTooLarge)
	})

	t.Run("invalid window", func(t *testing.T) {
		reporter := newCoverageReporter(t, userID, bkt, nil, CoverageReportConfig{}, logger)
		_, err := reporter.Build(ctx, 100, 100)
		require.ErrorIs(t, err, ErrInvalidCoverageWindow)
		_, err = reporter.Build(ctx, -1, 100)
		require.ErrorIs(t, err, ErrInvalidCoverageWindow)
	})
}

func TestTenantBlockCoverageReport_IndexDigestBinding(t *testing.T) {
	t.Parallel()
	const userID = "user-1"

	ctx := context.Background()
	bkt, _ := cortex_testutil.PrepareFilesystemBucket(t)
	logger := log.NewNopLogger()

	block1 := coverageBlock(testULID(t, coverageTestNow.Add(-24*time.Hour), 1), 0, 100)
	writeCoverageIndex(t, ctx, bkt, userID, &bucketindex.Index{
		Version:   bucketindex.IndexVersion1,
		Blocks:    bucketindex.Blocks{block1},
		UpdatedAt: coverageTestNow.Unix(),
	})

	reporter := newCoverageReporter(t, userID, bkt, nil, CoverageReportConfig{}, logger)
	rep1, err := reporter.Build(ctx, 0, 200)
	require.NoError(t, err)

	// Same artifact: stable digest and generation.
	rep1Again, err := reporter.Build(ctx, 0, 200)
	require.NoError(t, err)
	require.Equal(t, rep1.IndexDigest, rep1Again.IndexDigest)
	require.Equal(t, rep1.FilterConfigGeneration, rep1Again.FilterConfigGeneration)

	// A new index object changes the digest.
	block2 := coverageBlock(testULID(t, coverageTestNow.Add(-24*time.Hour), 2), 100, 200)
	writeCoverageIndex(t, ctx, bkt, userID, &bucketindex.Index{
		Version:   bucketindex.IndexVersion1,
		Blocks:    bucketindex.Blocks{block1, block2},
		UpdatedAt: coverageTestNow.Unix(),
	})
	rep2, err := reporter.Build(ctx, 0, 200)
	require.NoError(t, err)
	require.NotEqual(t, rep1.IndexDigest, rep2.IndexDigest)
}

func TestTenantBlockCoverageReport_LogsDoNotLeakOtherTenants(t *testing.T) {
	t.Parallel()
	const (
		authorizedTenant = "tenant-a"
		otherTenant      = "tenant-b"
	)

	ctx := context.Background()
	bkt, _ := cortex_testutil.PrepareFilesystemBucket(t)

	// Populate another tenant's prefix: the reporter must never read or log it.
	writeCoverageIndex(t, ctx, bkt, otherTenant, &bucketindex.Index{
		Version:   bucketindex.IndexVersion1,
		Blocks:    bucketindex.Blocks{coverageBlock(testULID(t, coverageTestNow.Add(-24*time.Hour), 1), 0, 100)},
		UpdatedAt: coverageTestNow.Unix(),
	})

	logs := &concurrency.SyncBuffer{}
	logger := log.NewLogfmtLogger(logs)
	reporter := newCoverageReporter(t, authorizedTenant, bkt, nil, CoverageReportConfig{}, logger)

	// Missing index for the authorized tenant triggers a warning log line.
	rep, err := reporter.Build(ctx, 0, 100)
	require.NoError(t, err)
	require.Equal(t, coverageStatusUnknown, rep.Status)
	require.Contains(t, logs.String(), authorizedTenant)
	require.NotContains(t, logs.String(), otherTenant)
}

func hasUnknownReason(rep *TenantBlockCoverageReport, reason string) bool {
	for _, u := range rep.Unknowns {
		if u.Reason == reason {
			return true
		}
	}
	return false
}

func TestDefaultCoverageReportLimits(t *testing.T) {
	t.Parallel()
	limits := CoverageReportLimits{}.withDefaults()
	require.Equal(t, defaultMaxBlocks, limits.MaxBlocks)
	require.Equal(t, defaultMaxEventPoints, limits.MaxEventPoints)
	require.Equal(t, defaultMaxOutputBytes, limits.MaxOutputBytes)

	// Explicit values are preserved.
	custom := CoverageReportLimits{MaxBlocks: 1, MaxEventPoints: 2, MaxOutputBytes: 3}.withDefaults()
	require.Equal(t, 1, custom.MaxBlocks)
	require.Equal(t, 2, custom.MaxEventPoints)
	require.Equal(t, 3, custom.MaxOutputBytes)
}

func TestHashFilterConfigChangesWithConfig(t *testing.T) {
	t.Parallel()
	r := newCoverageReporter(t, "user-1", nil, nil, CoverageReportConfig{ConsistencyDelay: time.Hour}, log.NewNopLogger())
	gen1 := hashFilterConfig(r.filterConfigSnapshot())

	r2 := newCoverageReporter(t, "user-1", nil, nil, CoverageReportConfig{ConsistencyDelay: 2 * time.Hour}, log.NewNopLogger())
	gen2 := hashFilterConfig(r2.filterConfigSnapshot())
	require.NotEqual(t, gen1, gen2)
	require.NotEmpty(t, gen1)

	// Same config, same strategy type: identical generation.
	r3 := newCoverageReporter(t, "user-1", nil, nil, CoverageReportConfig{ConsistencyDelay: time.Hour}, log.NewNopLogger())
	require.Equal(t, gen1, hashFilterConfig(r3.filterConfigSnapshot()))

	// The reporter stores a full, comparable snapshot.
	require.True(t, reflect.DeepEqual(r.filterConfigSnapshot(), r3.filterConfigSnapshot()))
}
