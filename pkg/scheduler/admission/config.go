// SPDX-License-Identifier: AGPL-3.0-only
package admission

import (
	"flag"
	"time"

	"github.com/pkg/errors"
)

// Config configures the optional QueryAdmissionLease.
//
// QueryAdmissionLease bounds the number of query fragment tasks that a single
// scheduler instance admits to queriers at any moment. Credits are accounted
// for purely in memory and are only meaningful for the lifetime of this
// scheduler process: this is instance-local admission control, not a
// distributed, persistent or global quota system.
type Config struct {
	// Enabled turns on QueryAdmissionLease. When false (the default) the
	// scheduler keeps its historical behavior and no admission accounting is
	// performed.
	Enabled bool `yaml:"enabled"`

	// MaxInFlightTasks is the total number of fragment tasks that may be
	// admitted at the same time by this scheduler instance, across all root
	// queries and all tenants. Each admitted task consumes one global credit.
	MaxInFlightTasks int `yaml:"max_inflight_tasks"`

	// MaxTasksPerRootQuery caps how many fragment tasks of a single root query
	// (including all of its fragments and attempts) may be admitted at once.
	MaxTasksPerRootQuery int `yaml:"max_tasks_per_root_query"`

	// DefaultTenantMaxInFlightTasks is the weighted in-flight quota charged
	// against an authorized tenant when no per-tenant override is configured.
	DefaultTenantMaxInFlightTasks float64 `yaml:"default_tenant_max_inflight_tasks"`

	// TenantMaxInFlightTasks overrides the weighted in-flight quota for
	// individual tenants. This field is YAML-only.
	TenantMaxInFlightTasks map[string]float64 `yaml:"tenant_max_inflight_tasks"`

	// DefaultTenantTaskWeight is the amount of tenant quota charged per
	// admitted task when the tenant has no explicit weight override.
	DefaultTenantTaskWeight float64 `yaml:"default_tenant_task_weight"`

	// TenantTaskWeight overrides the per-task weight of individual tenants.
	// Federated queries reserve quota from every authorized tenant at once, so
	// a request authenticated as "tenant-a|tenant-b" cannot occupy a single
	// cheap slot. This field is YAML-only.
	TenantTaskWeight map[string]float64 `yaml:"tenant_task_weight"`

	// LeaseTTL is the conservative lifetime after which a task grant that was
	// never explicitly released (for example because a querier died without
	// closing its stream) is force-reclaimed, and an empty root lease is
	// garbage collected.
	LeaseTTL time.Duration `yaml:"lease_ttl"`

	// EnqueueWaitTimeout bounds how long an enqueue waits for enough credits
	// before it fails. Waiting never blocks other enqueues or cancellations.
	EnqueueWaitTimeout time.Duration `yaml:"enqueue_wait_timeout"`

	// ReapInterval is how often the background reaper scans for grants and
	// leases that exceeded LeaseTTL.
	ReapInterval time.Duration `yaml:"reap_interval"`
}

// RegisterFlagsWithPrefix registers the CLI flags of QueryAdmissionLease under
// the given flag prefix. Per-tenant maps are intentionally YAML-only.
func (cfg *Config) RegisterFlagsWithPrefix(prefix string, f *flag.FlagSet) {
	f.BoolVar(&cfg.Enabled, prefix+"enabled", false, "Enable the query admission lease in the query-scheduler. This is an instance-local, in-memory admission control: it bounds the number of in-flight query fragment tasks and reserves weighted quota against all authorized tenants of a request. It is not a distributed or persistent global quota. When disabled, the query-scheduler behaves as before.")
	f.IntVar(&cfg.MaxInFlightTasks, prefix+"max-inflight-tasks", 1000, "Maximum number of query fragment tasks that may be admitted (in-flight) at the same time across the whole query-scheduler instance.")
	f.IntVar(&cfg.MaxTasksPerRootQuery, prefix+"max-tasks-per-root-query", 100, "Maximum number of fragment tasks that a single root query (including all of its fragments and retries) may have admitted at the same time.")
	f.Float64Var(&cfg.DefaultTenantMaxInFlightTasks, prefix+"default-tenant-max-inflight-tasks", 100, "Default weighted in-flight quota charged against each authorized tenant. Per-tenant overrides can be set in the YAML configuration.")
	f.Float64Var(&cfg.DefaultTenantTaskWeight, prefix+"default-tenant-task-weight", 1, "Default quota weight charged per admitted task against each authorized tenant. Federated requests reserve the weighted quota against every authorized tenant at once. Per-tenant overrides can be set in the YAML configuration.")
	f.DurationVar(&cfg.LeaseTTL, prefix+"lease-ttl", 5*time.Minute, "Conservative time-to-live for task grants and root leases. Task grants that are not explicitly released before the TTL expires are force-reclaimed, so a lost querier cannot leak credits forever.")
	f.DurationVar(&cfg.EnqueueWaitTimeout, prefix+"enqueue-wait-timeout", 30*time.Second, "Maximum time an enqueue waits for enough admission credits before failing. Waiting does not block other enqueues or cancellations.")
	f.DurationVar(&cfg.ReapInterval, prefix+"reap-interval", 30*time.Second, "How often the query-scheduler scans for task grants and root leases that exceeded their lease TTL.")
}

// Validate checks the configuration. It is a no-op while the feature is
// disabled, so existing configurations keep working unchanged.
func (cfg *Config) Validate() error {
	if !cfg.Enabled {
		return nil
	}

	if cfg.MaxInFlightTasks <= 0 {
		return errors.New("query admission lease max_inflight_tasks must be greater than 0")
	}
	if cfg.MaxTasksPerRootQuery <= 0 {
		return errors.New("query admission lease max_tasks_per_root_query must be greater than 0")
	}
	if cfg.MaxTasksPerRootQuery > cfg.MaxInFlightTasks {
		return errors.New("query admission lease max_tasks_per_root_query must not be greater than max_inflight_tasks")
	}
	if cfg.DefaultTenantMaxInFlightTasks <= 0 {
		return errors.New("query admission lease default_tenant_max_inflight_tasks must be greater than 0")
	}
	if cfg.DefaultTenantTaskWeight <= 0 {
		return errors.New("query admission lease default_tenant_task_weight must be greater than 0")
	}
	for tenant, quota := range cfg.TenantMaxInFlightTasks {
		if quota <= 0 {
			return errors.Errorf("query admission lease tenant_max_inflight_tasks for tenant %q must be greater than 0", tenant)
		}
	}
	for tenant, weight := range cfg.TenantTaskWeight {
		if weight <= 0 {
			return errors.Errorf("query admission lease tenant_task_weight for tenant %q must be greater than 0", tenant)
		}
	}
	if cfg.LeaseTTL <= 0 {
		return errors.New("query admission lease lease_ttl must be greater than 0")
	}
	if cfg.EnqueueWaitTimeout <= 0 {
		return errors.New("query admission lease enqueue_wait_timeout must be greater than 0")
	}
	if cfg.ReapInterval <= 0 {
		return errors.New("query admission lease reap_interval must be greater than 0")
	}
	return nil
}

// tenantQuota returns the configured weighted in-flight quota of a tenant.
func (cfg *Config) tenantQuota(tenant string) float64 {
	if quota, ok := cfg.TenantMaxInFlightTasks[tenant]; ok {
		return quota
	}
	return cfg.DefaultTenantMaxInFlightTasks
}

// tenantWeight returns the per-task weight charged against a tenant.
func (cfg *Config) tenantWeight(tenant string) float64 {
	if weight, ok := cfg.TenantTaskWeight[tenant]; ok {
		return weight
	}
	return cfg.DefaultTenantTaskWeight
}
