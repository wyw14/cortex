package bucketindex

import (
	"context"
	"errors"
	"path"
	"strings"
	"testing"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thanos-io/objstore"

	"github.com/cortexproject/cortex/pkg/storage/bucket"
	"github.com/cortexproject/cortex/pkg/storage/bucket/s3"
	"github.com/cortexproject/cortex/pkg/util/testutil"
)

func TestReadIndex_ShouldReturnErrorIfIndexDoesNotExist(t *testing.T) {
	bkt, _ := testutil.PrepareFilesystemBucket(t)

	idx, err := ReadIndex(context.Background(), bkt, "user-1", nil, log.NewNopLogger())
	require.Equal(t, ErrIndexNotFound, err)
	require.Nil(t, idx)
}

func TestReadIndex_ShouldReturnErrorIfIndexIsCorrupted(t *testing.T) {
	const userID = "user-1"

	ctx := context.Background()
	bkt, _ := testutil.PrepareFilesystemBucket(t)

	// Write a corrupted index.
	require.NoError(t, bkt.Upload(ctx, path.Join(userID, IndexCompressedFilename), strings.NewReader("invalid!}")))

	idx, err := ReadIndex(ctx, bkt, userID, nil, log.NewNopLogger())
	require.Equal(t, ErrIndexCorrupted, err)
	require.Nil(t, idx)
}

func TestReadIndex_ShouldReturnErrorIfKeyAccessDeniedErr(t *testing.T) {
	bkt, _ := testutil.PrepareFilesystemBucket(t)
	bkt = &testutil.MockBucketFailure{
		Bucket: bkt,
		GetFailures: map[string]error{
			path.Join("user-1", "bucket-index.json.gz"): testutil.ErrKeyAccessDeniedError,
		},
	}
	idx, err := ReadIndex(context.Background(), bkt, "user-1", nil, log.NewNopLogger())
	require.True(t, errors.Is(err, bucket.ErrCustomerManagedKeyAccessDenied))
	require.Nil(t, idx)
}

func TestReadIndex_ShouldReturnTheParsedIndexOnSuccess(t *testing.T) {
	const userID = "user-1"

	ctx := context.Background()
	logger := log.NewNopLogger()

	bkt, _ := testutil.PrepareFilesystemBucket(t)

	// Mock some blocks in the storage.
	bkt = BucketWithGlobalMarkers(bkt)
	testutil.MockStorageBlock(t, bkt, userID, 10, 20)
	testutil.MockStorageBlock(t, bkt, userID, 20, 30)
	testutil.MockStorageDeletionMark(t, bkt, userID, testutil.MockStorageBlock(t, bkt, userID, 30, 40))

	// Write the index.
	u := NewUpdater(bkt, userID, nil, logger)
	expectedIdx, _, _, err := u.UpdateIndex(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, WriteIndex(ctx, bkt, userID, nil, expectedIdx))

	// Read it back and compare.
	actualIdx, err := ReadIndex(ctx, bkt, userID, nil, logger)
	require.NoError(t, err)
	assert.Equal(t, expectedIdx, actualIdx)
}

func TestReadIndex_ShouldRetryUpload(t *testing.T) {
	const userID = "user-1"

	ctx := context.Background()
	logger := log.NewNopLogger()

	bkt, _ := testutil.PrepareFilesystemBucket(t)

	mBucket := &testutil.MockBucketFailure{
		Bucket:         bkt,
		UploadFailures: map[string]error{userID: errors.New("test")},
	}
	s3Bkt, _ := s3.NewBucketWithRetries(mBucket, 5, 0, 0, log.NewNopLogger())
	bkt = BucketWithGlobalMarkers(objstore.WithNoopInstr(s3Bkt))

	u := NewUpdater(bkt, userID, nil, logger)
	expectedIdx, _, _, err := u.UpdateIndex(ctx, nil)
	require.NoError(t, err)
	require.Error(t, WriteIndex(ctx, bkt, userID, nil, expectedIdx))
	require.Equal(t, mBucket.UploadCalls.Load(), int32(5))
}

func BenchmarkReadIndex(b *testing.B) {
	const (
		numBlocks             = 1000
		numBlockDeletionMarks = 100
		userID                = "user-1"
	)

	ctx := context.Background()
	logger := log.NewNopLogger()

	bkt, _ := testutil.PrepareFilesystemBucket(b)

	// Mock some blocks and deletion marks in the storage.
	bkt = BucketWithGlobalMarkers(bkt)
	for i := range numBlocks {
		minT := int64(i * 10)
		maxT := int64((i + 1) * 10)

		block := testutil.MockStorageBlock(b, bkt, userID, minT, maxT)

		if i < numBlockDeletionMarks {
			testutil.MockStorageDeletionMark(b, bkt, userID, block)
		}
	}

	// Write the index.
	u := NewUpdater(bkt, userID, nil, logger)
	idx, _, _, err := u.UpdateIndex(ctx, nil)
	require.NoError(b, err)
	require.NoError(b, WriteIndex(ctx, bkt, userID, nil, idx))

	// Read it back once just to make sure the index contains the expected data.
	idx, err = ReadIndex(ctx, bkt, userID, nil, logger)
	require.NoError(b, err)
	require.Len(b, idx.Blocks, numBlocks)
	require.Len(b, idx.BlockDeletionMarks, numBlockDeletionMarks)

	for b.Loop() {
		_, err := ReadIndex(ctx, bkt, userID, nil, logger)
		require.NoError(b, err)
	}
}

func TestReadIndexArtifact_ShouldReturnDigestAndParsedIndexFromSingleObject(t *testing.T) {
	const userID = "user-1"

	ctx := context.Background()
	logger := log.NewNopLogger()

	bkt, _ := testutil.PrepareFilesystemBucket(t)
	bkt = BucketWithGlobalMarkers(bkt)
	testutil.MockStorageBlock(t, bkt, userID, 10, 20)
	testutil.MockStorageBlock(t, bkt, userID, 20, 30)

	u := NewUpdater(bkt, userID, nil, logger)
	expectedIdx, _, _, err := u.UpdateIndex(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, WriteIndex(ctx, bkt, userID, nil, expectedIdx))

	actualIdx, digest, err := ReadIndexArtifact(ctx, bkt, userID, nil, logger)
	require.NoError(t, err)
	require.Len(t, digest, 64) // SHA-256 hex encoded.
	assert.Equal(t, expectedIdx, actualIdx)

	// Reading the same immutable object must produce a stable digest.
	_, digestAgain, err := ReadIndexArtifact(ctx, bkt, userID, nil, logger)
	require.NoError(t, err)
	assert.Equal(t, digest, digestAgain)

	// Rewriting the index with another block must change the digest.
	testutil.MockStorageBlock(t, bkt, userID, 30, 40)
	updatedIdx, _, _, err := u.UpdateIndex(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, WriteIndex(ctx, bkt, userID, nil, updatedIdx))
	_, newDigest, err := ReadIndexArtifact(ctx, bkt, userID, nil, logger)
	require.NoError(t, err)
	assert.NotEqual(t, digest, newDigest)
}

func TestReadIndexArtifact_ShouldMapMissingAndCorruptedLikeReadIndex(t *testing.T) {
	const userID = "user-1"

	ctx := context.Background()
	logger := log.NewNopLogger()

	t.Run("missing", func(t *testing.T) {
		bkt, _ := testutil.PrepareFilesystemBucket(t)
		idx, digest, err := ReadIndexArtifact(ctx, bkt, userID, nil, logger)
		require.Equal(t, ErrIndexNotFound, err)
		require.Nil(t, idx)
		require.Empty(t, digest)
	})

	t.Run("corrupted", func(t *testing.T) {
		bkt, _ := testutil.PrepareFilesystemBucket(t)
		require.NoError(t, bkt.Upload(ctx, path.Join(userID, IndexCompressedFilename), strings.NewReader("invalid!}")))

		idx, digest, err := ReadIndexArtifact(ctx, bkt, userID, nil, logger)
		require.Equal(t, ErrIndexCorrupted, err)
		require.Nil(t, idx)
		// The corrupted object is still bound to its exact bytes via the digest.
		require.Len(t, digest, 64)
	})

	t.Run("access denied", func(t *testing.T) {
		bkt, _ := testutil.PrepareFilesystemBucket(t)
		bkt = &testutil.MockBucketFailure{
			Bucket: bkt,
			GetFailures: map[string]error{
				path.Join(userID, IndexCompressedFilename): testutil.ErrKeyAccessDeniedError,
			},
		}
		idx, _, err := ReadIndexArtifact(ctx, bkt, userID, nil, logger)
		require.True(t, errors.Is(err, bucket.ErrCustomerManagedKeyAccessDenied))
		require.Nil(t, idx)
	})
}

func TestDeleteIndex_ShouldNotReturnErrorIfIndexDoesNotExist(t *testing.T) {
	ctx := context.Background()
	bkt, _ := testutil.PrepareFilesystemBucket(t)

	assert.NoError(t, DeleteIndex(ctx, bkt, "user-1", nil))
}
