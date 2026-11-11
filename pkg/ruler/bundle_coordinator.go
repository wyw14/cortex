package ruler

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/prometheus/model/rulefmt"
	promRules "github.com/prometheus/prometheus/rules"
	"github.com/spf13/afero"
	"gopkg.in/yaml.v3"

	"github.com/cortexproject/cortex/pkg/ruler/rulespb"
	"github.com/cortexproject/cortex/pkg/util/users"
)

// Migration reason codes reported in a SwitchReport. They describe explicitly
// why alert state was kept or rebuilt; the coordinator never guesses PromQL
// equivalence between differently written expressions.
const (
	migrationCompatible         = "identity-compatible"
	migrationNewRule            = "new-rule"
	migrationRemovedRule        = "removed-rule"
	migrationExprChanged        = "expr-changed"
	migrationAnnotationsChanged = "annotations-changed"
	migrationForChanged         = "for-changed"
	migrationGroupMissing       = "group-missing"
)

const (
	bundleOpPrepare   = "prepare"
	bundleOpCommit    = "commit"
	bundleOpCancel    = "cancel"
	bundleOpRecover   = "recover"
	bundleOpRemove    = "remove"
	bundleResultOK    = "success"
	bundleOpResultErr = "error"
)

// RuleStateMigration records the state migration decision for one rule.
type RuleStateMigration struct {
	Namespace string `json:"namespace"`
	GroupName string `json:"group_name"`
	RuleName  string `json:"rule_name"`
	RuleKind  string `json:"rule_kind"`
	// Migrated is true when alerting state was copied from the old generation.
	Migrated bool `json:"migrated"`
	// Reason explains the decision using the migration reason codes.
	Reason string `json:"reason"`
}

// SwitchReport describes the outcome of an explicit generation switch.
type SwitchReport struct {
	Tenant        string    `json:"tenant"`
	OldGeneration string    `json:"old_generation"`
	NewGeneration string    `json:"new_generation"`
	SwitchedAt    time.Time `json:"switched_at"`

	// Groups whose alert state was migrated because every rule kept an
	// explicitly compatible identity.
	MigratedGroups []string `json:"migrated_groups"`
	// Groups rebuilt from scratch because at least one rule identity was not
	// strictly compatible.
	RebuiltGroups []string `json:"rebuilt_groups"`

	// Rules holds the per-rule migration decisions, including removed rules.
	Rules []RuleStateMigration `json:"rules"`

	// NotifierOwnershipTransferred is true when an existing generation handed
	// the per-tenant notifier to the new one. The old manager is fully stopped
	// before the transfer, so only one generation can send alerts.
	NotifierOwnershipTransferred bool `json:"notifier_ownership_transferred"`
}

// BundleFaults are test-only failure injection points. Every hook is placed
// strictly after the durable step it guards, so returning an error simulates a
// process crash at that point without corrupting the protocol.
type BundleFaults struct {
	// AfterRuleFileWrite fires after a staged rule file was renamed into place.
	AfterRuleFileWrite func(relPath string) error
	// AfterManifestSeal fires after the candidate manifest was sealed.
	AfterManifestSeal func(generation string) error
	// AfterCandidatePromoted fires after the candidate was moved into releases/,
	// before the active pointer changed.
	AfterCandidatePromoted func(generation string) error
	// AfterActivePointerSwapped fires after the durable active pointer commit,
	// before the in-memory manager cut-over.
	AfterActivePointerSwapped func(generation string) error
	// AfterOldManagerStopped fires once the old generation stopped draining,
	// before the new manager starts.
	AfterOldManagerStopped func(generation string) error
}

// ReleaseBundleManager is the optional surface implemented by the default
// multi-tenant manager when release bundles are enabled. Callers must treat a
// failed type assertion as "feature disabled" and keep using the default sync
// entry point.
type ReleaseBundleManager interface {
	// PrepareReleaseBundle validates and seals an immutable candidate for one
	// tenant. It never touches the live manager.
	PrepareReleaseBundle(ctx context.Context, tenant string, groups rulespb.RuleGroupList) (generation string, manifest *BundleManifest, err error)
	// CommitReleaseBundle publishes the sealed generation and performs the
	// coordinated manager switch.
	CommitReleaseBundle(ctx context.Context, tenant, generation string) (*SwitchReport, error)
	// CancelReleaseBundle reclaims an unpublished candidate generation.
	CancelReleaseBundle(tenant, generation string) error
	// ActiveReleaseBundle returns the active generation and its manifest.
	ActiveReleaseBundle(tenant string) (generation string, manifest *BundleManifest, ok bool)
	// RecoverReleaseBundles converges on-disk state after crashes and starts
	// managers for the generations the active pointers resolve to.
	RecoverReleaseBundles(ctx context.Context) error
}

type tenantBundleState struct {
	activeGen   string
	manifest    *BundleManifest
	manager     RulesManager
	notifierGen string
	lastReport  *SwitchReport
}

// releaseBundleCoordinator implements the release bundle lifecycle on top of
// the bundleStore and the default multi-tenant manager.
type releaseBundleCoordinator struct {
	cfg    Config
	limits RulesLimits
	host   *DefaultMultiTenantManager
	store  *bundleStore
	logger log.Logger

	faults BundleFaults

	mtx     sync.RWMutex
	tenants map[string]*tenantBundleState

	opsTotal *prometheus.CounterVec
}

func newReleaseBundleCoordinator(cfg Config, limits RulesLimits, host *DefaultMultiTenantManager, reg prometheus.Registerer, logger log.Logger, store *bundleStore) *releaseBundleCoordinator {
	if store == nil {
		store = newBundleStore(cfg.RulePath, logger)
	}
	c := &releaseBundleCoordinator{
		cfg:     cfg,
		limits:  limits,
		host:    host,
		store:   store,
		logger:  logger,
		tenants: map[string]*tenantBundleState{},
		opsTotal: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Namespace: "cortex",
			Name:      "ruler_release_bundle_operations_total",
			Help:      "Total number of ruler release bundle operations, by tenant, operation and result.",
		}, []string{"user", "op", "result"}),
	}
	return c
}

func (c *releaseBundleCoordinator) recordOp(tenant, op string, err error) {
	result := bundleResultOK
	if err != nil {
		result = bundleOpResultErr
	}
	c.opsTotal.WithLabelValues(tenant, op, result).Inc()
}

// managedTenants returns the tenants currently owned by the bundle mechanism.
// The default sync path must leave their managers alone.
func (c *releaseBundleCoordinator) managedTenants() map[string]struct{} {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	out := make(map[string]struct{}, len(c.tenants))
	for tenant := range c.tenants {
		out[tenant] = struct{}{}
	}
	return out
}

// PrepareReleaseBundle stages, validates and seals a candidate generation.
func (c *releaseBundleCoordinator) PrepareReleaseBundle(ctx context.Context, tenant string, groups rulespb.RuleGroupList) (string, *BundleManifest, error) {
	if !c.cfg.ReleaseBundles.Enabled {
		return "", nil, errReleaseBundlesDisabled
	}
	if tenant == "" {
		return "", nil, errors.New("release bundle tenant must not be empty")
	}
	if len(groups) == 0 {
		return "", nil, errors.New("release bundle must contain at least one rule group")
	}

	generation, err := newGenerationID()
	if err != nil {
		return "", nil, err
	}

	// Everything below only mutates the private candidate directory. The live
	// manager is not involved, so any failure leaves the old generation
	// running untouched.
	cleanupOnFailure := true
	defer func() {
		if cleanupOnFailure {
			_ = c.store.fs.RemoveAll(c.store.candidateDir(tenant, generation))
		}
	}()

	federation, totalRules, err := c.validatePreparedGroups(tenant, groups)
	if err != nil {
		c.recordOp(tenant, bundleOpPrepare, err)
		return "", nil, err
	}

	files, err := renderBundleRuleFiles(groups)
	if err != nil {
		c.recordOp(tenant, bundleOpPrepare, err)
		return "", nil, err
	}

	externalLabels, _ := c.host.userExternalLabels.update(tenant)
	externalURL, _ := c.host.userExternalURL.update(tenant)

	for relPath, content := range files {
		if err := c.store.stageRuleFile(tenant, generation, relPath, content, c.faults.AfterRuleFileWrite); err != nil {
			c.recordOp(tenant, bundleOpPrepare, err)
			return "", nil, err
		}
	}

	manifest, err := c.store.sealCandidate(tenant, generation, bundleManifestMeta{
		createdAt:      time.Now().UTC(),
		ruleGroupCount: len(groups),
		ruleCount:      totalRules,
		externalLabels: externalLabels,
		externalURL:    externalURL,
		federation:     federation,
	}, c.faults.AfterManifestSeal)
	if err != nil {
		c.recordOp(tenant, bundleOpPrepare, err)
		return "", nil, err
	}

	cleanupOnFailure = false
	level.Info(c.logger).Log("msg", "sealed ruler release bundle candidate", "user", tenant, "generation", generation, "rule_groups", len(groups), "rules", totalRules)
	c.recordOp(tenant, bundleOpPrepare, nil)
	return generation, manifest, nil
}

// validatePreparedGroups runs the full parse, permission and limits validation
// and builds the federation snapshot pinned into the manifest.
func (c *releaseBundleCoordinator) validatePreparedGroups(tenant string, groups rulespb.RuleGroupList) (BundleFederationSnapshot, int, error) {
	if len(groups) > c.cfg.ReleaseBundles.MaxRuleGroupsPerBundle {
		return BundleFederationSnapshot{}, 0, errors.Errorf("release bundle rule group count %d exceeds limit %d", len(groups), c.cfg.ReleaseBundles.MaxRuleGroupsPerBundle)
	}
	if limit := c.limits.RulerMaxRuleGroupsPerTenant(tenant); limit > 0 && len(groups) > limit {
		return BundleFederationSnapshot{}, 0, errors.Errorf(errMaxRuleGroupsPerUserLimitExceeded, limit, len(groups))
	}

	disabled := c.limits.DisabledRuleGroups(tenant)
	totalRules := 0
	federation := BundleFederationSnapshot{OwnerAuthorized: true}
	hasFederated := false

	for _, g := range groups {
		if g.GetUser() != tenant {
			return BundleFederationSnapshot{}, 0, errors.Wrapf(errBundleSingleTenantScope, "group %s/%s belongs to tenant %s", g.GetNamespace(), g.GetName(), g.GetUser())
		}
		if ruleGroupDisabled(g, disabled) {
			return BundleFederationSnapshot{}, 0, errors.Errorf("rule group %s, namespace %s, user %s is disabled", g.GetName(), g.GetNamespace(), tenant)
		}
		if limit := c.limits.RulerMaxRulesPerRuleGroup(tenant); limit > 0 && len(g.GetRules()) > limit {
			return BundleFederationSnapshot{}, 0, errors.Errorf(errMaxRulesPerRuleGroupPerUserLimitExceeded, limit, len(g.GetRules()))
		}
		totalRules += len(g.GetRules())

		formatted := rulespb.FromProto(g)
		if errs := c.host.ValidateRuleGroup(formatted.RuleGroup); len(errs) > 0 {
			return BundleFederationSnapshot{}, 0, errors.Wrapf(errs[0], "invalid rule group %s/%s", g.GetNamespace(), g.GetName())
		}

		if g.IsFederated() {
			hasFederated = true
			normalized, err := c.host.ValidateFederatedRuleGroup(tenant, g.SourceTenants)
			if err != nil {
				federation.OwnerAuthorized = false
				return BundleFederationSnapshot{}, 0, errors.Wrapf(err, "federated rule group %s/%s is not authorized", g.GetNamespace(), g.GetName())
			}
			federation.Groups = append(federation.Groups, BundleGroupFederation{
				Namespace:     g.GetNamespace(),
				GroupName:     g.GetName(),
				SourceTenants: normalized,
			})
		}
	}

	if totalRules > c.cfg.ReleaseBundles.MaxRulesPerBundle {
		return BundleFederationSnapshot{}, 0, errors.Errorf("release bundle rule count %d exceeds limit %d", totalRules, c.cfg.ReleaseBundles.MaxRulesPerBundle)
	}
	if !hasFederated {
		// No federated content: record the current owner decision for audit but
		// there is nothing to re-check at commit time.
		federation.OwnerAuthorized = c.host.federatedRules.checkOwner(tenant) == nil
	}
	sort.Slice(federation.Groups, func(i, j int) bool {
		if federation.Groups[i].Namespace != federation.Groups[j].Namespace {
			return federation.Groups[i].Namespace < federation.Groups[j].Namespace
		}
		return federation.Groups[i].GroupName < federation.Groups[j].GroupName
	})
	return federation, totalRules, nil
}

// renderBundleRuleFiles renders the namespace rule files exactly like the
// default mapper, so the prometheus manager parses the same YAML content.
func renderBundleRuleFiles(groups rulespb.RuleGroupList) (map[string][]byte, error) {
	formatted := groups.Formatted()
	files := map[string][]byte{}
	for namespace, ruleGroups := range formatted {
		data, err := yaml.Marshal(&rulefmt.RuleGroups{Groups: ruleGroups})
		if err != nil {
			return nil, errors.Wrapf(err, "marshal rule file for namespace %s", namespace)
		}
		files[ruleFileRelPath(namespace)] = data
	}
	return files, nil
}

// CommitReleaseBundle publishes a sealed generation and switches the live
// manager to it under the recoverable protocol.
func (c *releaseBundleCoordinator) CommitReleaseBundle(ctx context.Context, tenant, generation string) (*SwitchReport, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if !c.cfg.ReleaseBundles.Enabled {
		return nil, errReleaseBundlesDisabled
	}
	state := c.tenants[tenant]
	if state != nil && state.activeGen == generation {
		return nil, errors.Wrapf(errBundleGenerationActive, "generation %s is already active", generation)
	}

	// 1. The candidate must be sealed and verify before anything else happens.
	candidateDir := c.store.candidateDir(tenant, generation)
	manifest, _, err := c.store.verifySealed(candidateDir)
	if err != nil {
		c.recordOp(tenant, bundleOpCommit, err)
		return nil, errors.Wrapf(err, "candidate generation %s cannot be committed", generation)
	}

	// 2. Re-validate the sealed content against current permissions and
	// limits. Federation authorization is pinned to the generation: a revoked
	// permission forbids publishing.
	if err := c.revalidateSealedBundle(tenant, manifest); err != nil {
		_ = c.store.removeCandidate(tenant, generation)
		c.recordOp(tenant, bundleOpCommit, err)
		return nil, err
	}

	// 3. Promote the whole candidate directory in one rename. The active
	// pointer still names the old generation, so a crash here only leaves an
	// orphan release that recovery reclaims.
	releaseDir, err := c.store.promoteCandidate(tenant, generation)
	if err != nil {
		c.recordOp(tenant, bundleOpCommit, err)
		return nil, err
	}
	if c.faults.AfterCandidatePromoted != nil {
		if err := c.faults.AfterCandidatePromoted(generation); err != nil {
			c.recordOp(tenant, bundleOpCommit, err)
			return nil, err
		}
	}
	manifest, files, err := c.store.verifySealed(releaseDir)
	if err != nil {
		c.recordOp(tenant, bundleOpCommit, err)
		return nil, err
	}

	// 4. Build the new generation manager but do not run it yet. A failure here
	// cannot affect the old generation, which keeps evaluating.
	newManager, err := c.host.newManager(ctx, tenant)
	if err != nil {
		_ = c.store.retireRelease(tenant, generation)
		c.recordOp(tenant, bundleOpCommit, err)
		return nil, errors.Wrap(err, "create rules manager for release bundle")
	}
	if err := newManager.Update(c.cfg.EvaluationInterval, files, manifest.ExternalLabels, manifest.ExternalURL, c.host.ruleGroupIterationFuncFor(tenant)); err != nil {
		newManager.Stop()
		_ = c.store.retireRelease(tenant, generation)
		c.recordOp(tenant, bundleOpCommit, err)
		return nil, errors.Wrap(err, "update rules manager with sealed release bundle")
	}
	// Federation authorization is part of the sealed generation: wire the
	// source-tenant org IDs to the actual bundle file paths of this generation.
	c.applyFederatedGroups(tenant, manifest, files)

	// 5. Durable commit: swap the active pointer. After this point the new
	// generation is the only complete bundle visible on disk; the in-memory
	// cut-over below is recoverable because a restart loads the active pointer.
	if err := c.store.swapActivePointer(tenant, generation); err != nil {
		newManager.Stop()
		_ = c.store.retireRelease(tenant, generation)
		c.recordOp(tenant, bundleOpCommit, err)
		return nil, err
	}
	if c.faults.AfterActivePointerSwapped != nil {
		if err := c.faults.AfterActivePointerSwapped(generation); err != nil {
			c.recordOp(tenant, bundleOpCommit, err)
			return nil, err
		}
	}

	// 6. Coordinated cut-over. Stop the old manager and wait for every group to
	// finish its in-flight evaluation before the new generation starts, so the
	// same group can never emit alerts or recording samples from two
	// generations at once.
	var (
		oldManager    RulesManager
		oldGeneration string
		oldManifest   *BundleManifest
	)
	if state != nil {
		oldManager = state.manager
		oldGeneration = state.activeGen
		oldManifest = state.manifest
	}
	if oldManager != nil {
		oldManager.Stop()
	}
	if c.faults.AfterOldManagerStopped != nil {
		if err := c.faults.AfterOldManagerStopped(generation); err != nil {
			c.recordOp(tenant, bundleOpCommit, err)
			return nil, err
		}
	}

	// 7. Selective alert state migration. Old groups are stopped, so reading
	// their state is race-free. Only strictly compatible identities migrate.
	report := c.planAndApplyMigration(tenant, oldGeneration, generation, oldManifest, manifest, oldManager, newManager)
	report.NotifierOwnershipTransferred = oldManager != nil

	// 8. Transfer ownership of the per-tenant notifier and start the new
	// generation. The notifier instance is shared, but exactly one manager
	// references it from now on because the old one was fully stopped.
	c.host.userManagerMtx.Lock()
	c.host.userManagers[tenant] = newManager
	c.host.userManagerMtx.Unlock()
	c.host.deleteRuleCache(tenant)
	go newManager.Run()

	c.tenants[tenant] = &tenantBundleState{
		activeGen:   generation,
		manifest:    manifest,
		manager:     newManager,
		notifierGen: generation,
		lastReport:  report,
	}

	// 9. The old reader has ended: retire its on-disk generation.
	if oldGeneration != "" {
		if err := c.store.retireRelease(tenant, oldGeneration); err != nil {
			level.Warn(c.logger).Log("msg", "failed to retire old release bundle generation, it will be reclaimed on recovery", "user", tenant, "generation", oldGeneration, "err", err)
		}
	}

	level.Info(c.logger).Log("msg", "committed ruler release bundle generation", "user", tenant, "generation", generation, "old_generation", oldGeneration, "migrated_groups", len(report.MigratedGroups), "rebuilt_groups", len(report.RebuiltGroups))
	c.recordOp(tenant, bundleOpCommit, nil)
	return report, nil
}

// revalidateSealedBundle re-runs parsing, limits, disabled-group and
// federation authorization checks against the sealed content and the current
// runtime configuration.
func (c *releaseBundleCoordinator) revalidateSealedBundle(tenant string, manifest *BundleManifest) error {
	if manifest.Tenant != tenant {
		return errors.Wrapf(errBundleVerification, "manifest tenant %s does not match %s", manifest.Tenant, tenant)
	}
	if manifest.RuleGroupCount > c.cfg.ReleaseBundles.MaxRuleGroupsPerBundle {
		return errors.Errorf("release bundle rule group count %d exceeds limit %d", manifest.RuleGroupCount, c.cfg.ReleaseBundles.MaxRuleGroupsPerBundle)
	}
	if manifest.RuleCount > c.cfg.ReleaseBundles.MaxRulesPerBundle {
		return errors.Errorf("release bundle rule count %d exceeds limit %d", manifest.RuleCount, c.cfg.ReleaseBundles.MaxRulesPerBundle)
	}
	if limit := c.limits.RulerMaxRuleGroupsPerTenant(tenant); limit > 0 && manifest.RuleGroupCount > limit {
		return errors.Errorf(errMaxRuleGroupsPerUserLimitExceeded, limit, manifest.RuleGroupCount)
	}

	disabled := c.limits.DisabledRuleGroups(tenant)
	disabledKeys := map[string]struct{}{}
	for _, d := range disabled {
		disabledKeys[d.Namespace+"\x00"+d.Name] = struct{}{}
	}

	seenGroups, seenRules := 0, 0
	for _, sealedFile := range manifest.Files {
		content, err := afero.ReadFile(c.store.fs, filepath.Join(c.store.candidateDir(tenant, manifest.Generation), filepath.FromSlash(sealedFile.Path)))
		if err != nil {
			return errors.Wrapf(err, "read sealed bundle file %s", sealedFile.Path)
		}
		var parsed rulefmt.RuleGroups
		if err := yaml.Unmarshal(content, &parsed); err != nil {
			return errors.Wrapf(errBundleVerification, "sealed file %s cannot be parsed", sealedFile.Path)
		}
		namespace, err := namespaceFromRelPath(sealedFile.Path)
		if err != nil {
			return err
		}
		for _, group := range parsed.Groups {
			seenGroups++
			seenRules += len(group.Rules)
			if _, ok := disabledKeys[namespace+"\x00"+group.Name]; ok {
				return errors.Errorf("rule group %s, namespace %s, user %s is disabled", group.Name, namespace, tenant)
			}
			if limit := c.limits.RulerMaxRulesPerRuleGroup(tenant); limit > 0 && len(group.Rules) > limit {
				return errors.Errorf(errMaxRulesPerRuleGroupPerUserLimitExceeded, limit, len(group.Rules))
			}
			if errs := c.host.ValidateRuleGroup(group); len(errs) > 0 {
				return errors.Wrapf(errs[0], "sealed rule group %s/%s is no longer valid", namespace, group.Name)
			}
		}
	}
	if seenGroups != manifest.RuleGroupCount || seenRules != manifest.RuleCount {
		return errors.Wrapf(errBundleVerification, "sealed content counts mismatch: manifest has %d groups/%d rules, files contain %d/%d", manifest.RuleGroupCount, manifest.RuleCount, seenGroups, seenRules)
	}

	// Federation authorization is fixed together with the generation: any
	// change in owner authorization or source tenants forbids publishing.
	if len(manifest.Federation.Groups) > 0 {
		if err := c.host.federatedRules.checkOwner(tenant); err != nil {
			return errors.Wrap(errBundleFederationRevoked, err.Error())
		}
		for _, pinned := range manifest.Federation.Groups {
			current, err := c.host.federatedRules.validateSourceTenants(pinned.SourceTenants)
			if err != nil {
				return errors.Wrapf(errBundleFederationRevoked, "group %s/%s: %s", pinned.Namespace, pinned.GroupName, err.Error())
			}
			if !equalSortedTenants(current, pinned.SourceTenants) {
				return errors.Wrapf(errBundleFederationRevoked, "source tenants of group %s/%s changed after sealing", pinned.Namespace, pinned.GroupName)
			}
		}
	}
	return nil
}

func equalSortedTenants(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// CancelReleaseBundle reclaims an unpublished candidate.
func (c *releaseBundleCoordinator) CancelReleaseBundle(tenant, generation string) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if state := c.tenants[tenant]; state != nil && state.activeGen == generation {
		c.recordOp(tenant, bundleOpCancel, errBundleGenerationActive)
		return errBundleGenerationActive
	}
	if err := c.store.removeCandidate(tenant, generation); err != nil {
		c.recordOp(tenant, bundleOpCancel, err)
		return err
	}
	level.Info(c.logger).Log("msg", "cancelled ruler release bundle candidate", "user", tenant, "generation", generation)
	c.recordOp(tenant, bundleOpCancel, nil)
	return nil
}

// ActiveReleaseBundle returns the active generation and manifest when one exists.
func (c *releaseBundleCoordinator) ActiveReleaseBundle(tenant string) (string, *BundleManifest, bool) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	state, ok := c.tenants[tenant]
	if !ok || state == nil || state.activeGen == "" {
		return "", nil, false
	}
	return state.activeGen, state.manifest, true
}

// RecoverReleaseBundles scans every tenant directory, converges the on-disk
// protocol state and starts a manager for each generation an active pointer
// resolves to.
func (c *releaseBundleCoordinator) RecoverReleaseBundles(ctx context.Context) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	tenants, err := c.store.listTenants()
	if err != nil {
		return errors.Wrap(err, "list tenants during release bundle recovery")
	}
	for _, tenant := range tenants {
		report, err := c.store.recoverTenant(tenant)
		if err != nil {
			c.recordOp(tenant, bundleOpRecover, err)
			level.Error(c.logger).Log("msg", "release bundle recovery failed", "user", tenant, "err", err)
			return err
		}
		c.logRecovery(tenant, report)
		if report.ActiveGeneration == "" {
			delete(c.tenants, tenant)
			c.recordOp(tenant, bundleOpRecover, nil)
			continue
		}
		if err := c.startActiveBundleLocked(ctx, tenant, report.ActiveGeneration); err != nil {
			c.recordOp(tenant, bundleOpRecover, err)
			level.Error(c.logger).Log("msg", "could not start recovered release bundle manager", "user", tenant, "generation", report.ActiveGeneration, "err", err)
			continue
		}
		c.recordOp(tenant, bundleOpRecover, nil)
	}
	return nil
}

func (c *releaseBundleCoordinator) logRecovery(tenant string, report *RecoveryReport) {
	level.Info(c.logger).Log(
		"msg", "recovered ruler release bundle state",
		"user", tenant,
		"active_generation", report.ActiveGeneration,
		"corrupt_pointer", report.CorruptPointer,
		"removed_unsealed_candidates", fmt.Sprint(report.RemovedUnsealedCandidates),
		"reclaimed_sealed_candidates", fmt.Sprint(report.ReclaimedSealedCandidates),
		"reclaimed_orphan_releases", fmt.Sprint(report.ReclaimedOrphanReleases),
		"reclaimed_retiring", fmt.Sprint(report.ReclaimedRetiring),
	)
}

// startActiveBundleLocked loads the generation the active pointer resolves to
// and starts its manager. Used both after crash recovery and when no previous
// in-memory generation exists.
func (c *releaseBundleCoordinator) startActiveBundleLocked(ctx context.Context, tenant, generation string) error {
	activeGen, manifest, files, err := c.store.loadActiveBundle(tenant)
	if err != nil {
		return err
	}
	if activeGen != generation {
		return errors.Wrapf(errBundleActiveCorrupt, "expected generation %s but active pointer resolves to %s", generation, activeGen)
	}

	manager, err := c.host.newManager(ctx, tenant)
	if err != nil {
		return errors.Wrap(err, "create recovered rules manager")
	}
	if err := manager.Update(c.cfg.EvaluationInterval, files, manifest.ExternalLabels, manifest.ExternalURL, c.host.ruleGroupIterationFuncFor(tenant)); err != nil {
		manager.Stop()
		return errors.Wrap(err, "update recovered rules manager")
	}
	c.applyFederatedGroups(tenant, manifest, files)

	c.host.userManagerMtx.Lock()
	c.host.userManagers[tenant] = manager
	c.host.userManagerMtx.Unlock()
	c.host.deleteRuleCache(tenant)
	go manager.Run()

	c.tenants[tenant] = &tenantBundleState{
		activeGen:   generation,
		manifest:    manifest,
		manager:     manager,
		notifierGen: generation,
	}
	level.Info(c.logger).Log("msg", "activated recovered ruler release bundle", "user", tenant, "generation", generation)
	return nil
}

// removeTenant stops the tenant generation and deletes all bundle artifacts.
// It is invoked from the default sync path when the tenant disappears.
func (c *releaseBundleCoordinator) removeTenant(ctx context.Context, tenant string) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	state := c.tenants[tenant]
	if state != nil && state.manager != nil {
		state.manager.Stop()
	}
	delete(c.tenants, tenant)
	if err := c.store.removeTenantDirectory(tenant); err != nil {
		level.Warn(c.logger).Log("msg", "failed to remove tenant release bundle directory", "user", tenant, "err", err)
	}
	c.host.cleanupBundleTenant(tenant)
	c.recordOp(tenant, bundleOpRemove, nil)
	level.Info(c.logger).Log("msg", "removed tenant ruler release bundle", "user", tenant)
}

// ruleDescriptor is the explicitly comparable identity of a rule.
type ruleDescriptor struct {
	kind        string
	name        string
	labelsKey   string
	expr        string
	annotations string
	forDur      time.Duration
	keepFiring  time.Duration
}

func describeRule(rule promRules.Rule) ruleDescriptor {
	d := ruleDescriptor{
		name:      rule.Name(),
		labelsKey: rule.Labels().String(),
		expr:      rule.Query().String(),
	}
	switch r := rule.(type) {
	case *promRules.AlertingRule:
		d.kind = alertingRuleFilter
		d.annotations = r.Annotations().String()
		d.forDur = r.HoldDuration()
		d.keepFiring = r.KeepFiringFor()
	case *promRules.RecordingRule:
		d.kind = recordingRuleFilter
	default:
		d.kind = "unknown"
	}
	return d
}

func (d ruleDescriptor) identityKey() string {
	return d.kind + "\x00" + d.name + "\x00" + d.labelsKey
}

// compatibility is deliberately strict and syntactic: it never assumes two
// different PromQL expressions are equivalent.
func (d ruleDescriptor) compatibleWith(old ruleDescriptor) (bool, string) {
	if d.kind != old.kind || d.name != old.name || d.labelsKey != old.labelsKey {
		return false, migrationNewRule
	}
	if d.expr != old.expr {
		return false, migrationExprChanged
	}
	if d.kind == alertingRuleFilter {
		if d.annotations != old.annotations {
			return false, migrationAnnotationsChanged
		}
		if d.forDur != old.forDur || d.keepFiring != old.keepFiring {
			return false, migrationForChanged
		}
	}
	return true, migrationCompatible
}

// planAndApplyMigration compares the stopped old generation groups with the
// dormant new groups, copies state only for fully compatible groups and
// records every decision in the report.
func (c *releaseBundleCoordinator) planAndApplyMigration(tenant, oldGeneration, newGeneration string, oldManifest, newManifest *BundleManifest, oldManager, newManager RulesManager) *SwitchReport {
	report := &SwitchReport{
		Tenant:        tenant,
		OldGeneration: oldGeneration,
		NewGeneration: newGeneration,
		SwitchedAt:    time.Now().UTC(),
	}

	newGroups := newManager.RuleGroups()
	if len(newGroups) == 0 {
		return report
	}

	oldByKey := map[string]*promRules.Group{}
	if oldManager != nil {
		oldRulesDir := c.bundleRulesDirForManifest(tenant, oldManifest)
		for _, g := range oldManager.RuleGroups() {
			ns, err := namespaceFromBundleFile(g.File(), oldRulesDir)
			if err != nil {
				continue
			}
			oldByKey[ns+"\x00"+g.Name()] = g
		}
	}
	newRulesDir := c.bundleRulesDirForManifest(tenant, newManifest)

	for _, newGroup := range newGroups {
		ns, err := namespaceFromBundleFile(newGroup.File(), newRulesDir)
		if err != nil {
			level.Warn(c.logger).Log("msg", "cannot derive namespace from bundle group file, rebuilding state", "file", newGroup.File(), "err", err)
			report.RebuiltGroups = append(report.RebuiltGroups, newGroup.Name())
			appendGroupRules(report, ns, newGroup, false, migrationGroupMissing)
			continue
		}
		groupKey := ns + "\x00" + newGroup.Name()
		oldGroup, hasOld := oldByKey[groupKey]

		if !hasOld {
			report.RebuiltGroups = append(report.RebuiltGroups, groupKey)
			appendGroupRules(report, ns, newGroup, false, migrationNewRule)
			continue
		}

		allCompatible, migrations := compareGroupRules(ns, oldGroup, newGroup)
		report.Rules = append(report.Rules, migrations...)
		if allCompatible {
			// Prometheus CopyState matches rules by name and labels; it is
			// only invoked when every rule passed the strict compatibility
			// check, so no incompatible identity can inherit state.
			newGroup.CopyState(oldGroup)
			report.MigratedGroups = append(report.MigratedGroups, groupKey)
		} else {
			report.RebuiltGroups = append(report.RebuiltGroups, groupKey)
		}
	}
	return report
}

// bundleRulesDirForManifest returns the absolute rules directory of the
// generation described by the manifest, or empty when the manifest is unknown.
func (c *releaseBundleCoordinator) bundleRulesDirForManifest(tenant string, manifest *BundleManifest) string {
	if manifest == nil {
		return ""
	}
	return c.store.rulesDir(c.store.releaseDir(tenant, manifest.Generation))
}

func namespaceFromBundleFile(file, rulesAbsDir string) (string, error) {
	if rulesAbsDir == "" {
		return "", errors.New("rules directory unknown")
	}
	rel := strings.TrimPrefix(filepath.ToSlash(file), filepath.ToSlash(rulesAbsDir)+"/")
	return url.PathUnescape(rel)
}

// applyFederatedGroups wires the federated source tenants pinned in the
// manifest to the prometheus group keys of the sealed generation. Without
// this the default iteration func could not tell federated groups apart,
// because bundle rule files do not live on the default mapper path.
func (c *releaseBundleCoordinator) applyFederatedGroups(tenant string, manifest *BundleManifest, files []string) {
	if len(manifest.Federation.Groups) == 0 {
		c.host.setFederatedGroups(tenant, nil)
		return
	}

	fileByNamespace := map[string]string{}
	for _, sealed := range manifest.Files {
		namespace, err := namespaceFromRelPath(sealed.Path)
		if err != nil {
			level.Warn(c.logger).Log("msg", "cannot resolve namespace of sealed federated rule file", "user", tenant, "path", sealed.Path, "err", err)
			continue
		}
		fileByNamespace[namespace] = filepath.Join(c.store.releaseDir(tenant, manifest.Generation), filepath.FromSlash(sealed.Path))
	}
	// Prefer the verified absolute paths returned with the manifest.
	for i, sealed := range manifest.Files {
		if i < len(files) {
			namespace, err := namespaceFromRelPath(sealed.Path)
			if err == nil {
				fileByNamespace[namespace] = files[i]
			}
		}
	}

	orgIDs := map[string]string{}
	for _, group := range manifest.Federation.Groups {
		file, ok := fileByNamespace[group.Namespace]
		if !ok {
			level.Warn(c.logger).Log("msg", "sealed federated rule group has no rule file", "user", tenant, "namespace", group.Namespace, "group", group.GroupName)
			continue
		}
		orgIDs[promRules.GroupKey(file, group.GroupName)] = users.JoinTenantIDs(group.SourceTenants)
	}
	c.host.setFederatedGroups(tenant, orgIDs)
}

func namespaceFromRelPath(relPath string) (string, error) {
	rel := strings.TrimPrefix(filepath.ToSlash(relPath), filepath.ToSlash(bundleRulesDir)+"/")
	return url.PathUnescape(rel)
}

// compareGroupRules returns whether every rule in the new group has a strictly
// compatible counterpart in the old one, plus the per-rule decisions.
func compareGroupRules(namespace string, oldGroup, newGroup *promRules.Group) (bool, []RuleStateMigration) {
	oldRules := oldGroup.Rules()
	newRules := newGroup.Rules()

	oldByIdentity := map[string]ruleDescriptor{}
	for _, r := range oldRules {
		d := describeRule(r)
		oldByIdentity[d.identityKey()] = d
	}

	allCompatible := len(oldRules) == len(newRules)
	var migrations []RuleStateMigration
	matchedOld := map[string]struct{}{}

	for _, r := range newRules {
		d := describeRule(r)
		migration := RuleStateMigration{
			Namespace: namespace,
			GroupName: newGroup.Name(),
			RuleName:  d.name,
			RuleKind:  d.kind,
		}
		old, ok := oldByIdentity[d.identityKey()]
		if !ok {
			allCompatible = false
			migration.Migrated = false
			migration.Reason = migrationNewRule
			migrations = append(migrations, migration)
			continue
		}
		matchedOld[d.identityKey()] = struct{}{}
		compatible, reason := d.compatibleWith(old)
		if !compatible {
			allCompatible = false
		}
		migration.Migrated = compatible
		migration.Reason = reason
		migrations = append(migrations, migration)
	}

	for _, r := range oldRules {
		d := describeRule(r)
		if _, ok := matchedOld[d.identityKey()]; ok {
			continue
		}
		allCompatible = false
		migrations = append(migrations, RuleStateMigration{
			Namespace: namespace,
			GroupName: newGroup.Name(),
			RuleName:  d.name,
			RuleKind:  d.kind,
			Migrated:  false,
			Reason:    migrationRemovedRule,
		})
	}
	return allCompatible, migrations
}

func appendGroupRules(report *SwitchReport, namespace string, group *promRules.Group, migrated bool, reason string) {
	for _, r := range group.Rules() {
		d := describeRule(r)
		report.Rules = append(report.Rules, RuleStateMigration{
			Namespace: namespace,
			GroupName: group.Name(),
			RuleName:  d.name,
			RuleKind:  d.kind,
			Migrated:  migrated,
			Reason:    reason,
		})
	}
}
