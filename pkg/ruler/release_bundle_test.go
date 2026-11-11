package ruler

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMemBundleStore(t *testing.T) *bundleStore {
	t.Helper()
	return newBundleStoreWithFs(afero.NewMemMapFs(), "/rules", log.NewNopLogger())
}

func testBundleMeta() bundleManifestMeta {
	return bundleManifestMeta{
		createdAt:      time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		ruleGroupCount: 1,
		ruleCount:      2,
		externalLabels: labels.FromStrings("zone", "eu"),
		externalURL:    "http://alerts.example.com",
		federation: BundleFederationSnapshot{
			OwnerAuthorized: true,
			Groups: []BundleGroupFederation{{
				Namespace:     "ns",
				GroupName:     "g",
				SourceTenants: []string{"team-a"},
			}},
		},
	}
}

func stageAndSeal(t *testing.T, s *bundleStore, tenant, generation string, files map[string][]byte) *BundleManifest {
	t.Helper()
	for rel, content := range files {
		require.NoError(t, s.stageRuleFile(tenant, generation, rel, content, nil))
	}
	manifest, err := s.sealCandidate(tenant, generation, testBundleMeta(), nil)
	require.NoError(t, err)
	return manifest
}

func TestBundleStore_StagedCandidateIsNotVisible(t *testing.T) {
	s := newMemBundleStore(t)
	const tenant, gen = "team-1", "gen-staged"

	require.NoError(t, s.stageRuleFile(tenant, gen, ruleFileRelPath("ns"), []byte("groups: []"), nil))

	// No active pointer and no sealed manifest: the live manager has nothing
	// it is allowed to load.
	_, _, _, err := s.loadActiveBundle(tenant)
	require.ErrorIs(t, err, errBundleNotFound)

	sealed, err := s.manifestExists(s.candidateDir(tenant, gen))
	require.NoError(t, err)
	require.False(t, sealed)
}

func TestBundleStore_StageRuleFileWriteFaultLeavesNoFinalFile(t *testing.T) {
	s := newMemBundleStore(t)
	const tenant, gen, rel = "team-1", "gen-fault", "rules/ns"

	fault := func(_ string) error { return assert.AnError }
	err := s.stageRuleFile(tenant, gen, rel, []byte("data"), fault)
	require.Error(t, err)

	exists, err := afero.Exists(s.fs, filepath.Join(s.candidateDir(tenant, gen), filepath.FromSlash(rel)))
	require.NoError(t, err)
	require.False(t, exists, "a failed write must not leave a file under its final name")
}

func TestBundleStore_SealVerifiesHashesAndDigests(t *testing.T) {
	s := newMemBundleStore(t)
	const tenant, gen = "team-1", "gen-seal"
	manifest := stageAndSeal(t, s, tenant, gen, map[string][]byte{
		ruleFileRelPath("ns"): []byte("groups:\n- name: g\n  rules:\n  - record: m\n    expr: up\n"),
	})

	require.Equal(t, tenant, manifest.Tenant)
	require.Equal(t, gen, manifest.Generation)
	require.Len(t, manifest.Files, 1)
	require.NotEmpty(t, manifest.ContentSHA256)

	verified, files, err := s.verifySealed(s.candidateDir(tenant, gen))
	require.NoError(t, err)
	require.Equal(t, manifest.ContentSHA256, verified.ContentSHA256)
	require.Len(t, files, 1)
}

func TestBundleStore_TamperedSealedFileFailsVerification(t *testing.T) {
	s := newMemBundleStore(t)
	const tenant, gen = "team-1", "gen-tamper"
	rel := ruleFileRelPath("ns")
	stageAndSeal(t, s, tenant, gen, map[string][]byte{rel: []byte("original")})

	target := filepath.Join(s.candidateDir(tenant, gen), filepath.FromSlash(rel))
	require.NoError(t, afero.WriteFile(s.fs, target, []byte("tampered"), 0o666))

	_, _, err := s.verifySealed(s.candidateDir(tenant, gen))
	require.ErrorIs(t, err, errBundleVerification)
}

func TestBundleStore_ExtraFileInSealedBundleFailsVerification(t *testing.T) {
	s := newMemBundleStore(t)
	const tenant, gen = "team-1", "gen-extra"
	stageAndSeal(t, s, tenant, gen, map[string][]byte{ruleFileRelPath("ns"): []byte("original")})

	extra := filepath.Join(s.rulesDir(s.candidateDir(tenant, gen)), "rogue")
	require.NoError(t, afero.WriteFile(s.fs, extra, []byte("nope"), 0o666))

	_, _, err := s.verifySealed(s.candidateDir(tenant, gen))
	require.ErrorIs(t, err, errBundleVerification)
}

func TestBundleStore_PublishProtocolAndActiveVisibility(t *testing.T) {
	s := newMemBundleStore(t)
	const tenant, gen = "team-1", "gen-published"
	stageAndSeal(t, s, tenant, gen, map[string][]byte{ruleFileRelPath("ns"): []byte("content")})

	releaseDir, err := s.promoteCandidate(tenant, gen)
	require.NoError(t, err)
	require.Equal(t, s.releaseDir(tenant, gen), releaseDir)

	// Before the pointer swap nothing is active even though the release exists.
	active, err := s.readActivePointer(tenant)
	require.NoError(t, err)
	require.Empty(t, active)
	_, _, _, err = s.loadActiveBundle(tenant)
	require.ErrorIs(t, err, errBundleNotFound)

	require.NoError(t, s.swapActivePointer(tenant, gen))

	loadedGen, manifest, files, err := s.loadActiveBundle(tenant)
	require.NoError(t, err)
	require.Equal(t, gen, loadedGen)
	require.Equal(t, gen, manifest.Generation)
	require.Len(t, files, 1)

	// Promotion is idempotent for retry after crash.
	_, err = s.promoteCandidate(tenant, gen)
	require.NoError(t, err)
}

func TestBundleStore_RecoverRemovesUnsealedCandidate(t *testing.T) {
	s := newMemBundleStore(t)
	const tenant, gen = "team-1", "gen-unsealed"
	require.NoError(t, s.stageRuleFile(tenant, gen, ruleFileRelPath("ns"), []byte("partial"), nil))

	report, err := s.recoverTenant(tenant)
	require.NoError(t, err)
	require.Empty(t, report.ActiveGeneration)
	require.Equal(t, []string{gen}, report.RemovedUnsealedCandidates)

	exists, err := afero.DirExists(s.fs, s.candidateDir(tenant, gen))
	require.NoError(t, err)
	require.False(t, exists)
}

func TestBundleStore_RecoverReclaimsSealedCandidateNeverPublished(t *testing.T) {
	s := newMemBundleStore(t)
	const tenant, gen = "team-1", "gen-sealed-orphan"
	stageAndSeal(t, s, tenant, gen, map[string][]byte{ruleFileRelPath("ns"): []byte("content")})

	report, err := s.recoverTenant(tenant)
	require.NoError(t, err)
	require.Equal(t, []string{gen}, report.ReclaimedSealedCandidates)
	require.Empty(t, report.ActiveGeneration)
}

func TestBundleStore_RecoverCrashAfterPromotionKeepsOldGeneration(t *testing.T) {
	s := newMemBundleStore(t)
	const tenant, oldGen, newGen = "team-1", "gen-old", "gen-new"

	stageAndSeal(t, s, tenant, oldGen, map[string][]byte{ruleFileRelPath("ns"): []byte("old")})
	_, err := s.promoteCandidate(tenant, oldGen)
	require.NoError(t, err)
	require.NoError(t, s.swapActivePointer(tenant, oldGen))

	// Crash after the new generation was promoted but before the pointer swap.
	stageAndSeal(t, s, tenant, newGen, map[string][]byte{ruleFileRelPath("ns"): []byte("new")})
	_, err = s.promoteCandidate(tenant, newGen)
	require.NoError(t, err)

	report, err := s.recoverTenant(tenant)
	require.NoError(t, err)
	require.Equal(t, oldGen, report.ActiveGeneration)
	require.Equal(t, []string{newGen}, report.ReclaimedOrphanReleases)

	// Only the complete old bundle is visible.
	loadedGen, _, _, err := s.loadActiveBundle(tenant)
	require.NoError(t, err)
	require.Equal(t, oldGen, loadedGen)
}

func TestBundleStore_RecoverCrashAfterPointerSwapResolvesNewGeneration(t *testing.T) {
	s := newMemBundleStore(t)
	const tenant, oldGen, newGen = "team-1", "gen-old", "gen-new"

	stageAndSeal(t, s, tenant, oldGen, map[string][]byte{ruleFileRelPath("ns"): []byte("old")})
	_, err := s.promoteCandidate(tenant, oldGen)
	require.NoError(t, err)
	require.NoError(t, s.swapActivePointer(tenant, oldGen))

	stageAndSeal(t, s, tenant, newGen, map[string][]byte{ruleFileRelPath("ns"): []byte("new")})
	_, err = s.promoteCandidate(tenant, newGen)
	require.NoError(t, err)
	require.NoError(t, s.swapActivePointer(tenant, newGen))
	// Simulate the process dying before the old generation was retired.
	report, err := s.recoverTenant(tenant)
	require.NoError(t, err)
	require.Equal(t, newGen, report.ActiveGeneration)
	require.Equal(t, []string{oldGen}, report.ReclaimedOrphanReleases)

	loadedGen, _, _, err := s.loadActiveBundle(tenant)
	require.NoError(t, err)
	require.Equal(t, newGen, loadedGen)
}

func TestBundleStore_RecoverQuarantinesPointerToMissingGeneration(t *testing.T) {
	s := newMemBundleStore(t)
	const tenant, gen = "team-1", "gen-ghost"
	// Write a pointer to a generation that was never published, e.g. left by a
	// crash that lost the release directory. swapActivePointer would refuse
	// this state, which is exactly why recovery must quarantine it.
	pointerDir := s.tenantRoot(tenant)
	require.NoError(t, s.fs.MkdirAll(pointerDir, 0o777))
	require.NoError(t, afero.WriteFile(s.fs, s.activePointerPath(tenant), []byte(`{"generation":"`+gen+`","updated_at":"2026-01-02T03:04:05Z"}`), 0o666))

	report, err := s.recoverTenant(tenant)
	require.NoError(t, err)
	require.True(t, report.CorruptPointer)
	require.Empty(t, report.ActiveGeneration)

	_, _, _, err = s.loadActiveBundle(tenant)
	require.ErrorIs(t, err, errBundleNotFound)
}

func TestBundleStore_RecoverQuarantinesUnverifiableActiveGeneration(t *testing.T) {
	s := newMemBundleStore(t)
	const tenant, gen = "team-1", "gen-corrupt"
	stageAndSeal(t, s, tenant, gen, map[string][]byte{ruleFileRelPath("ns"): []byte("content")})
	_, err := s.promoteCandidate(tenant, gen)
	require.NoError(t, err)
	require.NoError(t, s.swapActivePointer(tenant, gen))

	// Corrupt the published content after the pointer was committed.
	target := filepath.Join(s.releaseDir(tenant, gen), bundleRulesDir, "ns")
	require.NoError(t, afero.WriteFile(s.fs, target, []byte("corrupted"), 0o666))

	report, err := s.recoverTenant(tenant)
	require.NoError(t, err)
	require.True(t, report.CorruptPointer)
	require.Empty(t, report.ActiveGeneration)
	require.Contains(t, report.ReclaimedOrphanReleases, gen)
}

func TestBundleStore_RetireReleaseRefusesActiveGeneration(t *testing.T) {
	s := newMemBundleStore(t)
	const tenant, gen = "team-1", "gen-retire"
	stageAndSeal(t, s, tenant, gen, map[string][]byte{ruleFileRelPath("ns"): []byte("content")})
	_, err := s.promoteCandidate(tenant, gen)
	require.NoError(t, err)
	require.NoError(t, s.swapActivePointer(tenant, gen))

	require.ErrorIs(t, s.retireRelease(tenant, gen), errBundleGenerationActive)
}

func TestBundleStore_RetireReleaseDeletesOldGeneration(t *testing.T) {
	s := newMemBundleStore(t)
	const tenant, oldGen, newGen = "team-1", "gen-old", "gen-new"
	stageAndSeal(t, s, tenant, oldGen, map[string][]byte{ruleFileRelPath("ns"): []byte("old")})
	_, err := s.promoteCandidate(tenant, oldGen)
	require.NoError(t, err)
	stageAndSeal(t, s, tenant, newGen, map[string][]byte{ruleFileRelPath("ns"): []byte("new")})
	_, err = s.promoteCandidate(tenant, newGen)
	require.NoError(t, err)
	require.NoError(t, s.swapActivePointer(tenant, newGen))

	require.NoError(t, s.retireRelease(tenant, oldGen))
	exists, err := afero.DirExists(s.fs, s.releaseDir(tenant, oldGen))
	require.NoError(t, err)
	assert.False(t, exists)

	// The active generation stays intact and visible.
	loadedGen, _, _, err := s.loadActiveBundle(tenant)
	require.NoError(t, err)
	require.Equal(t, newGen, loadedGen)
}

func TestBundleStore_RemoveCandidateRejectsActiveGeneration(t *testing.T) {
	s := newMemBundleStore(t)
	const tenant, gen = "team-1", "gen-active"
	stageAndSeal(t, s, tenant, gen, map[string][]byte{ruleFileRelPath("ns"): []byte("content")})
	_, err := s.promoteCandidate(tenant, gen)
	require.NoError(t, err)
	require.NoError(t, s.swapActivePointer(tenant, gen))

	require.ErrorIs(t, s.removeCandidate(tenant, gen), errBundleGenerationActive)
}

func TestReleaseBundleConfigValidation(t *testing.T) {
	require.NoError(t, (&ReleaseBundleConfig{Enabled: false}).Validate())
	require.Error(t, (&ReleaseBundleConfig{Enabled: true, MaxRuleGroupsPerBundle: 0, MaxRulesPerBundle: 1}).Validate())
	require.Error(t, (&ReleaseBundleConfig{Enabled: true, MaxRuleGroupsPerBundle: 1, MaxRulesPerBundle: 0}).Validate())
	require.NoError(t, (&ReleaseBundleConfig{Enabled: true, MaxRuleGroupsPerBundle: 1, MaxRulesPerBundle: 1}).Validate())
}
