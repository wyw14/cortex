package ruler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/pkg/errors"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/spf13/afero"
)

const (
	releaseBundleSchemaVersion = 1

	releaseBundleRootName = "release-bundles"
	bundleCandidatesDir   = "candidates"
	bundleReleasesDir     = "releases"
	bundleRetiringDir     = "retiring"
	bundleRulesDir        = "rules"
	bundleManifestFile    = "manifest.json"
	bundleManifestTmpFile = "manifest.json.tmp"
	bundleActivePointer   = "active.json"
	bundleCorruptPrefix   = "active.json.corrupt-"
	bundleTempSuffix      = ".tmp"

	defaultMaxRuleGroupsPerBundle = 100
	defaultMaxRulesPerBundle      = 1000
)

var (
	errReleaseBundlesDisabled   = errors.New("ruler release bundles are disabled")
	errBundleNotFound           = errors.New("release bundle not found")
	errBundleUnsealed           = errors.New("release bundle candidate is not sealed")
	errBundleVerification       = errors.New("release bundle verification failed")
	errBundleActiveCorrupt      = errors.New("active release bundle pointer is corrupt")
	errBundleSingleTenantScope  = errors.New("a release bundle is scoped to a single tenant")
	errBundleGenerationUnknown  = errors.New("release bundle generation is unknown")
	errBundleGenerationActive   = errors.New("the active release bundle generation cannot be cancelled or replaced")
	errBundleFederationRevoked  = errors.New("federation authorization changed after the release bundle was sealed")
	errBundleInjectedFault      = errors.New("injected release bundle fault")
	errBundleManagerUpdateFault = errors.New("injected rules manager update fault")
)

// ReleaseBundleConfig configures the optional RulerReleaseBundle mechanism.
//
// A release bundle turns the complete rule set of a single tenant (namespace
// rule files, the resolved external labels/URL and the federated source
// tenants) into an immutable candidate that is fully validated and sealed
// before an explicit generation switch makes it active.
type ReleaseBundleConfig struct {
	// Enabled turns on the release bundle mechanism. When false, the ruler
	// keeps synchronizing rules through the default SyncRuleGroups entry point
	// exactly as before.
	Enabled bool `yaml:"enabled"`
	// MaxRuleGroupsPerBundle bounds the number of rule groups accepted in a
	// single bundle. The mechanism is intentionally scoped to one tenant and a
	// finite rule set, it is not a cluster-wide transaction.
	MaxRuleGroupsPerBundle int `yaml:"max_rule_groups_per_bundle"`
	// MaxRulesPerBundle bounds the total number of rules accepted in a bundle.
	MaxRulesPerBundle int `yaml:"max_rules_per_bundle"`
}

// RegisterFlags registers the release bundle flags.
func (c *ReleaseBundleConfig) RegisterFlags(f *flag.FlagSet) {
	f.BoolVar(&c.Enabled, "ruler.release-bundles.enabled", false, "Enable the experimental ruler release bundle mechanism, which stages and seals the complete rule set of a tenant as an immutable generation and switches the live manager to it only after the sealed generation is explicitly committed.")
	f.IntVar(&c.MaxRuleGroupsPerBundle, "ruler.release-bundles.max-rule-groups", defaultMaxRuleGroupsPerBundle, "Maximum number of rule groups accepted in a single tenant release bundle.")
	f.IntVar(&c.MaxRulesPerBundle, "ruler.release-bundles.max-rules", defaultMaxRulesPerBundle, "Maximum total number of rules accepted in a single tenant release bundle.")
}

// Validate the release bundle configuration.
func (c *ReleaseBundleConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.MaxRuleGroupsPerBundle <= 0 {
		return errors.New("ruler release bundles max rule groups per bundle must be greater than 0")
	}
	if c.MaxRulesPerBundle <= 0 {
		return errors.New("ruler release bundles max rules per bundle must be greater than 0")
	}
	return nil
}

// BundleFile is the sealed record of a single rule file in a bundle.
type BundleFile struct {
	// Relative path of the rule file inside the bundle directory.
	Path string `json:"path"`
	// SHA256 hex digest of the file contents.
	SHA256 string `json:"sha256"`
	// Size of the file contents in bytes.
	Bytes int64 `json:"bytes"`
}

// BundleGroupFederation pins the federated source tenants of one rule group
// at the time the bundle was sealed.
type BundleGroupFederation struct {
	Namespace     string   `json:"namespace"`
	GroupName     string   `json:"group"`
	SourceTenants []string `json:"source_tenants"`
}

// BundleFederationSnapshot freezes the federation authorization decision of
// a bundle. It is re-checked at commit time: revoking the federation
// authorization after sealing forbids publishing the candidate.
type BundleFederationSnapshot struct {
	OwnerAuthorized bool                    `json:"owner_authorized"`
	Groups          []BundleGroupFederation `json:"groups"`
}

// BundleManifest is the sealed, immutable description of a release bundle.
// It is written last in the candidate directory and is the only thing that
// turns a staging directory into a visible, verifiable generation.
type BundleManifest struct {
	SchemaVersion int `json:"schema_version"`

	Tenant     string `json:"tenant"`
	Generation string `json:"generation"`

	CreatedAt time.Time `json:"created_at"`
	SealedAt  time.Time `json:"sealed_at"`

	RuleGroupCount int `json:"rule_group_count"`
	RuleCount      int `json:"rule_count"`

	// Resolved external labels/URL pinned into the generation. They are stored
	// sorted so the manifest serialization is stable.
	ExternalLabels labels.Labels `json:"external_labels"`
	ExternalURL    string        `json:"external_url"`

	Federation BundleFederationSnapshot `json:"federation"`

	// Sealed rule files, sorted by relative path.
	Files []BundleFile `json:"files"`

	// ContentSHA256 covers the rule files and the frozen metadata, excluding
	// this field itself. Any tampering makes verification fail.
	ContentSHA256 string `json:"content_sha256"`
}

// RecoveryReport summarizes the crash recovery work performed for one tenant.
type RecoveryReport struct {
	Tenant string
	// ActiveGeneration is the generation the active pointer resolves to after
	// recovery. Empty when no valid generation is active.
	ActiveGeneration string
	// CorruptPointer is true when the active pointer named a missing or
	// unverifiable generation and was moved aside instead of trusted.
	CorruptPointer bool
	// Unsealed candidates (no manifest) left by a crash while staging.
	RemovedUnsealedCandidates []string
	// Sealed candidates that never reached the active pointer.
	ReclaimedSealedCandidates []string
	// Published generations superseded by the active pointer or abandoned by a
	// crash during the switch.
	ReclaimedOrphanReleases []string
	// Leftover retiring directories.
	ReclaimedRetiring []string
}

// bundleStore owns the on-disk layout of release bundles and the recoverable
// publish protocol.
//
// Layout for a tenant, under <rulePath>/release-bundles/<tenant>/:
//
//	candidates/<generation>/rules/<escaped namespace>   staging files, never read by a live manager
//	candidates/<generation>/manifest.json               written atomically last, seals the candidate
//	releases/<generation>/...                            sealed, immutable, published generations
//	retiring/<generation>/...                            old generations drained and removed
//	active.json                                          single active pointer, swapped atomically
//
// The active pointer is the only commit marker: a live manager only ever
// loads the generation named there, and only from releases/ after a full
// manifest/hash verification. Per-file renames inside an unpublished
// candidate therefore never make a partial batch visible.
type bundleStore struct {
	fs       afero.Fs
	basePath string
	logger   log.Logger
}

func newBundleStore(basePath string, logger log.Logger) *bundleStore {
	return newBundleStoreWithFs(afero.NewOsFs(), basePath, logger)
}

func newBundleStoreWithFs(fs afero.Fs, basePath string, logger log.Logger) *bundleStore {
	return &bundleStore{fs: fs, basePath: basePath, logger: logger}
}

func (s *bundleStore) root() string {
	return filepath.Join(s.basePath, releaseBundleRootName)
}

func (s *bundleStore) tenantRoot(tenant string) string {
	return filepath.Join(s.root(), tenant)
}

func (s *bundleStore) candidateDir(tenant, generation string) string {
	return filepath.Join(s.tenantRoot(tenant), bundleCandidatesDir, generation)
}

func (s *bundleStore) releaseDir(tenant, generation string) string {
	return filepath.Join(s.tenantRoot(tenant), bundleReleasesDir, generation)
}

func (s *bundleStore) retiringDir(tenant, generation string) string {
	return filepath.Join(s.tenantRoot(tenant), bundleRetiringDir, generation)
}

func (s *bundleStore) activePointerPath(tenant string) string {
	return filepath.Join(s.tenantRoot(tenant), bundleActivePointer)
}

func (s *bundleStore) rulesDir(base string) string {
	return filepath.Join(base, bundleRulesDir)
}

// newGenerationID returns an explicit, unique generation identifier.
func newGenerationID() (string, error) {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "", errors.Wrap(err, "generate release bundle generation id")
	}
	return fmt.Sprintf("gen-%d-%s", time.Now().UnixNano(), hex.EncodeToString(buf)), nil
}

// stageRuleFile writes one rule file into the candidate directory. The file
// is materialized under a temporary name and renamed into place, so a crash
// or write fault never leaves a partial file under its final name. The
// candidate directory itself is not referenced by the active pointer, so the
// live manager cannot observe it.
func (s *bundleStore) stageRuleFile(tenant, generation, relPath string, content []byte, afterWrite func(relPath string) error) error {
	target := filepath.Join(s.candidateDir(tenant, generation), filepath.FromSlash(relPath))
	if err := s.fs.MkdirAll(filepath.Dir(target), 0o777); err != nil {
		return errors.Wrapf(err, "create release bundle candidate directory for %s", relPath)
	}

	tmp := target + bundleTempSuffix
	if err := afero.WriteFile(s.fs, tmp, content, 0o666); err != nil {
		return errors.Wrapf(err, "write release bundle rule file %s", relPath)
	}
	if afterWrite != nil {
		if err := afterWrite(relPath); err != nil {
			_ = s.fSRemove(tmp)
			return err
		}
	}
	if err := s.fs.Rename(tmp, target); err != nil {
		return errors.Wrapf(err, "publish release bundle rule file %s", relPath)
	}
	return nil
}

// fSRemove removes a path without returning an error when it does not exist.
func (s *bundleStore) fSRemove(path string) error {
	if err := s.fs.Remove(path); err != nil && !errors.Is(err, afero.ErrFileNotFound) {
		return err
	}
	return nil
}

// sealCandidate hashes every staged file, builds and atomically writes the
// manifest and returns it. The candidate becomes immutable and verifiable
// only once the manifest is in place.
func (s *bundleStore) sealCandidate(tenant, generation string, meta bundleManifestMeta, afterSeal func(generation string) error) (*BundleManifest, error) {
	dir := s.candidateDir(tenant, generation)
	if sealed, err := s.manifestExists(dir); err != nil {
		return nil, err
	} else if sealed {
		return nil, errors.Errorf("release bundle candidate %s is already sealed", generation)
	}

	files, err := s.hashRuleFiles(dir)
	if err != nil {
		return nil, err
	}

	manifest := &BundleManifest{
		SchemaVersion:  releaseBundleSchemaVersion,
		Tenant:         tenant,
		Generation:     generation,
		CreatedAt:      meta.createdAt,
		SealedAt:       time.Now().UTC(),
		RuleGroupCount: meta.ruleGroupCount,
		RuleCount:      meta.ruleCount,
		ExternalLabels: meta.externalLabels,
		ExternalURL:    meta.externalURL,
		Federation:     meta.federation,
		Files:          files,
	}
	manifest.ContentSHA256 = computeContentSHA256(manifest)

	if err := s.writeManifest(dir, manifest); err != nil {
		return nil, err
	}
	if afterSeal != nil {
		if err := afterSeal(generation); err != nil {
			return nil, err
		}
	}
	return manifest, nil
}

// bundleManifestMeta carries the metadata frozen at seal time.
type bundleManifestMeta struct {
	createdAt      time.Time
	ruleGroupCount int
	ruleCount      int
	externalLabels labels.Labels
	externalURL    string
	federation     BundleFederationSnapshot
}

// hashRuleFiles walks the rules directory of a bundle directory and returns
// the sealed file records sorted by relative path.
func (s *bundleStore) hashRuleFiles(bundleDir string) ([]BundleFile, error) {
	rulesRoot := s.rulesDir(bundleDir)
	entries, err := afero.ReadDir(s.fs, rulesRoot)
	if err != nil {
		return nil, errors.Wrapf(err, "read release bundle rules directory %s", rulesRoot)
	}

	files := make([]BundleFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, errors.Errorf("unexpected subdirectory %s in release bundle rules directory", entry.Name())
		}
		abs := filepath.Join(rulesRoot, entry.Name())
		content, err := afero.ReadFile(s.fs, abs)
		if err != nil {
			return nil, errors.Wrapf(err, "read release bundle rule file %s", entry.Name())
		}
		sum := sha256.Sum256(content)
		relPath := filepath.ToSlash(filepath.Join(bundleRulesDir, entry.Name()))
		files = append(files, BundleFile{
			Path:   relPath,
			SHA256: hex.EncodeToString(sum[:]),
			Bytes:  int64(len(content)),
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

// computeContentSHA256 hashes the sealed rule files together with the frozen
// metadata. The digest field itself is excluded.
func computeContentSHA256(m *BundleManifest) string {
	h := sha256.New()
	write := func(s string) { _, _ = h.Write([]byte(s)) }

	write(fmt.Sprintf("schema=%d\n", m.SchemaVersion))
	write(fmt.Sprintf("tenant=%s\n", m.Tenant))
	write(fmt.Sprintf("generation=%s\n", m.Generation))
	write(fmt.Sprintf("created_at=%d\n", m.CreatedAt.UnixNano()))
	write(fmt.Sprintf("rule_groups=%d\n", m.RuleGroupCount))
	write(fmt.Sprintf("rules=%d\n", m.RuleCount))
	write("external_labels=")
	m.ExternalLabels.Range(func(l labels.Label) {
		write(fmt.Sprintf("%s=%s,", l.Name, l.Value))
	})
	write("\n")
	write(fmt.Sprintf("external_url=%s\n", m.ExternalURL))
	write(fmt.Sprintf("federation_owner_authorized=%t\n", m.Federation.OwnerAuthorized))
	for _, g := range m.Federation.Groups {
		write(fmt.Sprintf("federation=%s/%s=%s\n", g.Namespace, g.GroupName, strings.Join(g.SourceTenants, ",")))
	}
	for _, f := range m.Files {
		write(fmt.Sprintf("file=%s:%s:%d\n", f.Path, f.SHA256, f.Bytes))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (s *bundleStore) writeManifest(bundleDir string, manifest *BundleManifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return errors.Wrap(err, "marshal release bundle manifest")
	}
	final := filepath.Join(bundleDir, bundleManifestFile)
	tmp := filepath.Join(bundleDir, bundleManifestTmpFile)
	if err := afero.WriteFile(s.fs, tmp, data, 0o666); err != nil {
		return errors.Wrap(err, "write release bundle manifest")
	}
	if err := s.fs.Rename(tmp, final); err != nil {
		return errors.Wrap(err, "seal release bundle manifest")
	}
	return nil
}

func (s *bundleStore) manifestExists(bundleDir string) (bool, error) {
	exists, err := afero.Exists(s.fs, filepath.Join(bundleDir, bundleManifestFile))
	if err != nil {
		return false, errors.Wrap(err, "check release bundle manifest")
	}
	return exists, nil
}

// readManifest reads and parses the manifest of a bundle directory.
func (s *bundleStore) readManifest(bundleDir string) (*BundleManifest, error) {
	data, err := afero.ReadFile(s.fs, filepath.Join(bundleDir, bundleManifestFile))
	if err != nil {
		if errors.Is(err, afero.ErrFileNotFound) {
			return nil, errBundleUnsealed
		}
		return nil, errors.Wrap(err, "read release bundle manifest")
	}
	manifest := &BundleManifest{}
	if err := json.Unmarshal(data, manifest); err != nil {
		return nil, errors.Wrap(errBundleVerification, err.Error())
	}
	return manifest, nil
}

// verifySealed re-reads every sealed file from disk and checks it against the
// manifest, then recomputes the content digest. It returns the manifest and
// the absolute paths of the verified rule files in manifest order. A bundle
// that fails verification is never exposed to a manager.
func (s *bundleStore) verifySealed(bundleDir string) (*BundleManifest, []string, error) {
	manifest, err := s.readManifest(bundleDir)
	if err != nil {
		return nil, nil, err
	}
	if manifest.SchemaVersion != releaseBundleSchemaVersion {
		return nil, nil, errors.Wrapf(errBundleVerification, "unsupported schema version %d", manifest.SchemaVersion)
	}

	rulesRoot := s.rulesDir(bundleDir)
	entries, err := afero.ReadDir(s.fs, rulesRoot)
	if err != nil {
		return nil, nil, errors.Wrap(err, "read sealed release bundle rules directory")
	}
	onDisk := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		onDisk[filepath.ToSlash(filepath.Join(bundleRulesDir, entry.Name()))] = struct{}{}
	}

	files := make([]string, 0, len(manifest.Files))
	for _, sealed := range manifest.Files {
		if _, ok := onDisk[sealed.Path]; !ok {
			return nil, nil, errors.Wrapf(errBundleVerification, "sealed rule file %s is missing", sealed.Path)
		}
		delete(onDisk, sealed.Path)

		abs := filepath.Join(bundleDir, filepath.FromSlash(sealed.Path))
		content, err := afero.ReadFile(s.fs, abs)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "read sealed rule file %s", sealed.Path)
		}
		sum := sha256.Sum256(content)
		if got := hex.EncodeToString(sum[:]); got != sealed.SHA256 {
			return nil, nil, errors.Wrapf(errBundleVerification, "hash mismatch for sealed rule file %s", sealed.Path)
		}
		if int64(len(content)) != sealed.Bytes {
			return nil, nil, errors.Wrapf(errBundleVerification, "size mismatch for sealed rule file %s", sealed.Path)
		}
		files = append(files, abs)
	}
	for extra := range onDisk {
		return nil, nil, errors.Wrapf(errBundleVerification, "unsealed file %s present in sealed bundle", extra)
	}

	if got := computeContentSHA256(manifest); got != manifest.ContentSHA256 {
		return nil, nil, errors.Wrap(errBundleVerification, "manifest content digest mismatch")
	}
	return manifest, files, nil
}

// promoteCandidate moves a sealed candidate into the releases directory. The
// directory rename is the only mutation, so the published generation appears
// as a whole or not at all; retries after a crash are idempotent.
func (s *bundleStore) promoteCandidate(tenant, generation string) (string, error) {
	src := s.candidateDir(tenant, generation)
	dst := s.releaseDir(tenant, generation)

	if exists, err := afero.DirExists(s.fs, dst); err != nil {
		return "", errors.Wrap(err, "check published release bundle")
	} else if exists {
		// Retry after a crash between the rename and the next step: the
		// candidate must already be gone and the release must verify.
		if candidateExists, err := afero.DirExists(s.fs, src); err != nil {
			return "", errors.Wrap(err, "check release bundle candidate after retry")
		} else if candidateExists {
			return "", errors.Wrapf(errBundleVerification, "candidate and published release both exist for generation %s", generation)
		}
		if _, _, err := s.verifySealed(dst); err != nil {
			return "", errors.Wrapf(err, "published generation %s is not verifiable", generation)
		}
		return dst, nil
	}

	if exists, err := afero.DirExists(s.fs, src); err != nil {
		return "", errors.Wrap(err, "check release bundle candidate")
	} else if !exists {
		return "", errors.Wrapf(errBundleGenerationUnknown, "candidate generation %s", generation)
	}
	if _, _, err := s.verifySealed(src); err != nil {
		return "", err
	}
	if err := s.fs.MkdirAll(filepath.Dir(dst), 0o777); err != nil {
		return "", errors.Wrap(err, "create releases directory")
	}
	if err := s.fs.Rename(src, dst); err != nil {
		return "", errors.Wrap(err, "promote release bundle candidate")
	}
	return dst, nil
}

// activePointer is the on-disk content of the single active generation marker.
type activePointer struct {
	Generation string    `json:"generation"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// swapActivePointer atomically points the tenant at the given published
// generation. The temp-file rename makes the pointer change the single commit
// point of the protocol: readers always observe the old or the new pointer,
// never a half-written one.
func (s *bundleStore) swapActivePointer(tenant, generation string) error {
	if exists, err := afero.DirExists(s.fs, s.releaseDir(tenant, generation)); err != nil {
		return errors.Wrap(err, "check published generation before activating")
	} else if !exists {
		return errors.Wrapf(errBundleGenerationUnknown, "published generation %s", generation)
	}

	pointer := activePointer{Generation: generation, UpdatedAt: time.Now().UTC()}
	data, err := json.MarshalIndent(pointer, "", "  ")
	if err != nil {
		return errors.Wrap(err, "marshal active release pointer")
	}
	final := s.activePointerPath(tenant)
	tmp := final + bundleTempSuffix
	if err := s.fs.MkdirAll(filepath.Dir(final), 0o777); err != nil {
		return errors.Wrap(err, "create tenant bundle directory")
	}
	if err := afero.WriteFile(s.fs, tmp, data, 0o666); err != nil {
		return errors.Wrap(err, "write active release pointer")
	}
	if err := s.fs.Rename(tmp, final); err != nil {
		return errors.Wrap(err, "swap active release pointer")
	}
	return nil
}

// readActivePointer returns the generation named by the active pointer, or an
// empty string when no pointer exists. A malformed pointer is reported as
// corrupt rather than guessed at.
func (s *bundleStore) readActivePointer(tenant string) (string, error) {
	data, err := afero.ReadFile(s.fs, s.activePointerPath(tenant))
	if err != nil {
		if errors.Is(err, afero.ErrFileNotFound) {
			return "", nil
		}
		return "", errors.Wrap(err, "read active release pointer")
	}
	pointer := activePointer{}
	if err := json.Unmarshal(data, &pointer); err != nil || pointer.Generation == "" {
		return "", errors.Wrap(errBundleActiveCorrupt, "active pointer cannot be parsed")
	}
	return pointer.Generation, nil
}

// movePointerAside preserves an untrusted active pointer for forensics
// instead of deleting it.
func (s *bundleStore) movePointerAside(tenant string) error {
	final := s.activePointerPath(tenant)
	quarantine := fmt.Sprintf("%s%d", filepath.Join(s.tenantRoot(tenant), bundleCorruptPrefix), time.Now().UnixNano())
	if err := s.fs.Rename(final, quarantine); err != nil {
		return errors.Wrap(err, "quarantine corrupt active release pointer")
	}
	level.Warn(s.logger).Log("msg", "quarantined corrupt active release bundle pointer", "user", tenant, "quarantine", quarantine)
	return nil
}

// loadActiveBundle resolves and verifies the generation named by the active
// pointer. This is the only path used by a live manager to load rule files,
// so candidates and unverifiable generations are never exposed.
func (s *bundleStore) loadActiveBundle(tenant string) (string, *BundleManifest, []string, error) {
	generation, err := s.readActivePointer(tenant)
	if err != nil {
		return "", nil, nil, err
	}
	if generation == "" {
		return "", nil, nil, errBundleNotFound
	}
	dir := s.releaseDir(tenant, generation)
	manifest, files, err := s.verifySealed(dir)
	if err != nil {
		return generation, nil, nil, err
	}
	return generation, manifest, files, nil
}

// removeCandidate deletes a staging generation. It refuses to touch a
// published generation.
func (s *bundleStore) removeCandidate(tenant, generation string) error {
	active, err := s.readActivePointer(tenant)
	if err != nil {
		return err
	}
	if active == generation {
		return errBundleGenerationActive
	}
	dir := s.candidateDir(tenant, generation)
	if exists, err := afero.DirExists(s.fs, dir); err != nil {
		return errors.Wrap(err, "check release bundle candidate")
	} else if !exists {
		return errors.Wrapf(errBundleGenerationUnknown, "candidate generation %s", generation)
	}
	if err := s.fs.RemoveAll(dir); err != nil {
		return errors.Wrap(err, "remove release bundle candidate")
	}
	return nil
}

// retireRelease moves a published generation out of releases/ and removes it.
// It is called only once the old manager reader has fully stopped.
func (s *bundleStore) retireRelease(tenant, generation string) error {
	if active, err := s.readActivePointer(tenant); err != nil {
		return err
	} else if active == generation {
		return errBundleGenerationActive
	}

	src := s.releaseDir(tenant, generation)
	if exists, err := afero.DirExists(s.fs, src); err != nil {
		return errors.Wrap(err, "check retiring release bundle")
	} else if !exists {
		// Already retired, possibly by a recovered earlier attempt.
		dst := s.retiringDir(tenant, generation)
		if exists, err := afero.DirExists(s.fs, dst); err != nil {
			return errors.Wrap(err, "check retiring release bundle")
		} else if exists {
			return s.fs.RemoveAll(dst)
		}
		return nil
	}

	dst := s.retiringDir(tenant, generation)
	if err := s.fs.MkdirAll(filepath.Dir(dst), 0o777); err != nil {
		return errors.Wrap(err, "create retiring directory")
	}
	if err := s.fs.Rename(src, dst); err != nil {
		return errors.Wrap(err, "retire release bundle generation")
	}
	if err := s.fs.RemoveAll(dst); err != nil {
		return errors.Wrap(err, "remove retiring release bundle generation")
	}
	return nil
}

// listTenants returns the tenant directories under the bundle root.
func (s *bundleStore) listTenants() ([]string, error) {
	root := s.root()
	entries, err := afero.ReadDir(s.fs, root)
	if err != nil {
		if errors.Is(err, afero.ErrFileNotFound) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "list release bundle tenants")
	}
	tenants := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			tenants = append(tenants, entry.Name())
		}
	}
	return tenants, nil
}

func (s *bundleStore) listSubDirectories(root string) ([]string, error) {
	entries, err := afero.ReadDir(s.fs, root)
	if err != nil {
		if errors.Is(err, afero.ErrFileNotFound) {
			return nil, nil
		}
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	return names, nil
}

// removeTenantDirectory deletes every bundle artifact of a tenant.
func (s *bundleStore) removeTenantDirectory(tenant string) error {
	if err := s.fs.RemoveAll(s.tenantRoot(tenant)); err != nil {
		return errors.Wrap(err, "remove tenant release bundle directory")
	}
	return nil
}

// recoverTenant converges the on-disk state of a tenant after any crash point
// in the protocol. It guarantees that, once it returns, the active pointer
// either resolves to a complete, verifiable generation or does not exist, and
// that no staging or superseded generation is left behind.
func (s *bundleStore) recoverTenant(tenant string) (*RecoveryReport, error) {
	report := &RecoveryReport{Tenant: tenant}

	// 1. Candidates are never visible. Unsealed ones are crash leftovers;
	// sealed ones never reached the active pointer and are reclaimed.
	candidates, err := s.listSubDirectories(filepath.Join(s.tenantRoot(tenant), bundleCandidatesDir))
	if err != nil {
		return nil, errors.Wrap(err, "list release bundle candidates")
	}
	for _, generation := range candidates {
		dir := s.candidateDir(tenant, generation)
		sealed, err := s.manifestExists(dir)
		if err != nil {
			return nil, err
		}
		if sealed {
			report.ReclaimedSealedCandidates = append(report.ReclaimedSealedCandidates, generation)
		} else {
			report.RemovedUnsealedCandidates = append(report.RemovedUnsealedCandidates, generation)
		}
		if err := s.fs.RemoveAll(dir); err != nil {
			return nil, errors.Wrapf(err, "recover candidate generation %s", generation)
		}
	}

	// 2. Resolve the active pointer, quarantining an unreadable one.
	activeGeneration, err := s.readActivePointer(tenant)
	if err != nil {
		report.CorruptPointer = true
		if moveErr := s.movePointerAside(tenant); moveErr != nil {
			return nil, moveErr
		}
		activeGeneration = ""
	}

	// 3. Every release other than the active one is an orphan. The active
	// release itself must verify, otherwise the pointer is quarantined.
	releases, err := s.listSubDirectories(filepath.Join(s.tenantRoot(tenant), bundleReleasesDir))
	if err != nil {
		return nil, errors.Wrap(err, "list published release bundles")
	}
	activeReleaseExists := false
	for _, generation := range releases {
		dir := s.releaseDir(tenant, generation)
		if generation != activeGeneration {
			report.ReclaimedOrphanReleases = append(report.ReclaimedOrphanReleases, generation)
			if err := s.fs.RemoveAll(dir); err != nil {
				return nil, errors.Wrapf(err, "reclaim orphan release %s", generation)
			}
			continue
		}
		if _, _, verifyErr := s.verifySealed(dir); verifyErr != nil {
			level.Error(s.logger).Log("msg", "active release bundle failed verification, quarantining pointer", "user", tenant, "generation", generation, "err", verifyErr)
			report.CorruptPointer = true
			if err := s.movePointerAside(tenant); err != nil {
				return nil, err
			}
			report.ReclaimedOrphanReleases = append(report.ReclaimedOrphanReleases, generation)
			if err := s.fs.RemoveAll(dir); err != nil {
				return nil, errors.Wrapf(err, "reclaim unverifiable release %s", generation)
			}
			activeGeneration = ""
			continue
		}
		activeReleaseExists = true
	}

	// 4. A pointer naming a missing generation (crash before promotion
	// completed) cannot be trusted.
	if activeGeneration != "" && !activeReleaseExists {
		level.Error(s.logger).Log("msg", "active release bundle pointer names a missing generation, quarantining pointer", "user", tenant, "generation", activeGeneration)
		report.CorruptPointer = true
		if err := s.movePointerAside(tenant); err != nil {
			return nil, err
		}
		activeGeneration = ""
	}

	// 5. Clean retiring leftovers from a crash during retirement.
	retiring, err := s.listSubDirectories(filepath.Join(s.tenantRoot(tenant), bundleRetiringDir))
	if err != nil {
		return nil, errors.Wrap(err, "list retiring release bundles")
	}
	for _, generation := range retiring {
		dir := s.retiringDir(tenant, generation)
		report.ReclaimedRetiring = append(report.ReclaimedRetiring, generation)
		if err := s.fs.RemoveAll(dir); err != nil {
			return nil, errors.Wrapf(err, "remove retiring release %s", generation)
		}
	}

	sort.Strings(report.RemovedUnsealedCandidates)
	sort.Strings(report.ReclaimedSealedCandidates)
	sort.Strings(report.ReclaimedOrphanReleases)
	sort.Strings(report.ReclaimedRetiring)
	report.ActiveGeneration = activeGeneration
	return report, nil
}

// ruleFileRelPath returns the relative, slash-separated path of a namespace
// rule file inside a bundle directory.
func ruleFileRelPath(namespace string) string {
	return filepath.ToSlash(filepath.Join(bundleRulesDir, url.PathEscape(namespace)))
}
