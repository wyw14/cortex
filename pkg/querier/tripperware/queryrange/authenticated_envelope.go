package queryrange

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"regexp"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/golang/snappy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/cortexproject/cortex/pkg/util/flagext"
	util_log "github.com/cortexproject/cortex/pkg/util/log"
	"github.com/cortexproject/cortex/pkg/util/users"
)

// Authentication envelope for query-range result cache entries.
//
// The external cache (Memcached/Redis/FIFO) is treated as an untrusted transport
// and storage boundary: cache key strings are retrieval handles only, never
// authenticity credentials. Every value stored while the envelope is enabled is
// a self-describing AuthenticatedResultCacheEnvelope whose HMAC covers both the
// payload bytes and the full semantic identity of the entry (normalized tenant
// set, query semantics/engine protocol version, step/grid identity and the
// trusted invalidation generation). On the read path the entry length is
// bounded before anything is parsed, the HMAC is verified before any
// decompression/decoding, and every failure is handled as a cache miss with a
// bounded reason. An unverified entry is never returned or decompressed, and
// payload bytes are never written to logs.
const (
	// envelopeMagic prefixes every authenticated entry so that legacy plain
	// protobuf/snappy entries are rejected without being trusted.
	envelopeMagic = "CRXCAE01"

	envelopeVersion1          uint8 = 1
	envelopeAlgHMACSHA256     uint8 = 1
	envelopeCompressionNone   uint8 = 0
	envelopeCompressionSnappy uint8 = 1

	// queryRangeCacheProtocolVersion binds the cached CachedResponse/Extent
	// payload schema and the query semantic/engine protocol to the signature.
	// It must be bumped whenever the cached payload semantics change.
	queryRangeCacheProtocolVersion uint16 = 1

	defaultMaxCacheEntryBytes     = 64 * 1024 * 1024
	defaultMaxDecodedPayloadBytes = 128 * 1024 * 1024
	maxVerifyKeys                 = 4
	minSigningKeyBytes            = 32
	maxKeyIDLength                = 64
	envelopeMACSize               = sha256.Size
)

// Bounded set of cache-miss reasons used as metric label values and log fields.
// Never add tenant IDs, cache keys or payload-derived data as a reason.
const (
	reasonEntryTooLarge      = "entry_too_large"
	reasonBadMagic           = "bad_magic"
	reasonMalformed          = "malformed"
	reasonUnknownKey         = "unknown_key"
	reasonBadMAC             = "bad_mac"
	reasonMissingIdentity    = "missing_identity"
	reasonTenantMismatch     = "tenant_mismatch"
	reasonIdentityMismatch   = "identity_mismatch"
	reasonProtocolMismatch   = "protocol_mismatch"
	reasonGenerationMismatch = "generation_mismatch"
	reasonExpired            = "expired"
	reasonPayloadTooLarge    = "payload_too_large"
	reasonDecompressFailed   = "decompress_failed"
)

var envelopeFailureReasons = []string{
	reasonEntryTooLarge,
	reasonBadMagic,
	reasonMalformed,
	reasonUnknownKey,
	reasonBadMAC,
	reasonMissingIdentity,
	reasonTenantMismatch,
	reasonIdentityMismatch,
	reasonProtocolMismatch,
	reasonGenerationMismatch,
	reasonExpired,
	reasonPayloadTooLarge,
	reasonDecompressFailed,
}

var (
	errEnvelopeRejected = errors.New("authenticated results cache entry rejected")
	errMissingIdentity  = errors.New("missing authenticated cache identity")

	keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// AuthenticatedEnvelopeConfig configures the optional HMAC authenticated
// envelope for query-range result cache entries. It is disabled by default, in
// which case cache entries keep their legacy plain (optionally snappy-wrapped)
// protobuf format.
type AuthenticatedEnvelopeConfig struct {
	// Enabled turns on authenticated envelope sealing on writes and verification
	// on reads. Defaults to false.
	Enabled bool `yaml:"enabled"`

	// SigningKeyID is the identifier of the active signing key. It is stored in
	// the envelope header and is only used to select a verification key from the
	// in-memory keyring; key material is never loaded dynamically from paths/URLs.
	SigningKeyID string `yaml:"signing_key_id"`

	// SigningKey is the active HMAC-SHA256 signing secret. Must be at least 32
	// bytes of high-entropy material.
	SigningKey flagext.Secret `yaml:"signing_key"`

	// VerifyKeyIDs/VerifyKeys hold a limited number of retired keys still
	// accepted on the read path during key rotation. Entries are always sealed
	// with SigningKey. The two slices must have the same length and matching
	// positions.
	VerifyKeyIDs flagext.StringSlice          `yaml:"verify_key_ids"`
	VerifyKeys   flagext.SecretStringSliceCSV `yaml:"verify_keys"`

	// MaxCacheEntryBytes bounds the raw on-wire envelope size accepted on the
	// read path. The length is enforced before any parsing or decompression.
	MaxCacheEntryBytes int `yaml:"max_cache_entry_bytes"`

	// MaxDecodedPayloadBytes bounds the decompressed payload size, protecting
	// against compression bombs. The declared snappy length is checked against
	// this cap before the decoder allocates its output buffer.
	MaxDecodedPayloadBytes int `yaml:"max_decoded_payload_bytes"`

	// InvalidationGeneration is the server-trusted cache invalidation
	// generation. An entry carrying a different generation is treated as a
	// cache miss even when its HMAC is valid, so old entries cannot bypass a
	// current invalidation.
	InvalidationGeneration uint64 `yaml:"invalidation_generation"`

	// MaxTTL optionally truncates the TTL applied to sealed entries. Zero means
	// the existing server-side per-tenant TTL policy is used unchanged.
	MaxTTL time.Duration `yaml:"max_ttl"`
}

// RegisterFlags registers the authenticated envelope flags.
func (cfg *AuthenticatedEnvelopeConfig) RegisterFlags(f *flag.FlagSet) {
	const prefix = "frontend.results-cache-authenticated-envelope."

	f.BoolVar(&cfg.Enabled, prefix+"enabled", false, "Enable the HMAC authenticated envelope for query-range results cache entries. When enabled, cache keys remain retrieval handles only and every entry is authenticated before it is decompressed or decoded. Disabled by default and the legacy cache format is preserved.")
	f.StringVar(&cfg.SigningKeyID, prefix+"signing-key-id", "", "Key ID of the active HMAC signing key for the authenticated results cache envelope. Keys are configured inline only and never loaded from paths or URLs.")
	f.Var(&cfg.SigningKey, prefix+"signing-key", "Active HMAC-SHA256 signing secret for the authenticated results cache envelope (minimum 32 bytes).")
	f.Var(&cfg.VerifyKeyIDs, prefix+"verify-key-ids", "Comma-separated key IDs of retired HMAC keys still accepted when verifying old authenticated results cache entries. Positions must match -"+prefix+"verify-keys.")
	f.Var(&cfg.VerifyKeys, prefix+"verify-keys", "Comma-separated retired HMAC signing secrets still accepted when verifying old authenticated results cache entries. Positions must match -"+prefix+"verify-key-ids.")
	f.IntVar(&cfg.MaxCacheEntryBytes, prefix+"max-cache-entry-bytes", defaultMaxCacheEntryBytes, "Maximum size in bytes of a raw authenticated results cache entry accepted on reads. Enforced before parsing or decompression.")
	f.IntVar(&cfg.MaxDecodedPayloadBytes, prefix+"max-decoded-payload-bytes", defaultMaxDecodedPayloadBytes, "Maximum size in bytes of the decompressed authenticated results cache payload. Entries declaring a larger payload are rejected as cache misses before decoding.")
	f.Uint64Var(&cfg.InvalidationGeneration, prefix+"invalidation-generation", 0, "Server-trusted invalidation generation for authenticated results cache entries. Bumping this value invalidates all entries signed under a previous generation, even if their signature is still valid.")
	f.DurationVar(&cfg.MaxTTL, prefix+"max-ttl", 0, "When non-zero, the TTL of authenticated results cache entries is truncated to this value. Zero keeps the existing server-side per-tenant TTL policy.")
}

// Validate checks the envelope configuration.
func (cfg *AuthenticatedEnvelopeConfig) Validate() error {
	if !cfg.Enabled {
		return nil
	}

	if cfg.SigningKeyID == "" {
		return errors.New("authenticated results cache envelope requires a signing key ID")
	}
	if !keyIDPattern.MatchString(cfg.SigningKeyID) {
		return fmt.Errorf("authenticated results cache envelope signing key ID %q is invalid: must match %s and be at most %d characters", cfg.SigningKeyID, keyIDPattern.String(), maxKeyIDLength)
	}
	if len(cfg.SigningKey.Value) < minSigningKeyBytes {
		return fmt.Errorf("authenticated results cache envelope signing key must be at least %d bytes", minSigningKeyBytes)
	}

	verifyIDs := []string(cfg.VerifyKeyIDs)
	verifyKeys := cfg.VerifyKeys.Value()
	if len(verifyIDs) != len(verifyKeys) {
		return errors.New("authenticated results cache envelope verify key IDs and verify keys must have the same number of entries")
	}
	if len(verifyIDs) > maxVerifyKeys {
		return fmt.Errorf("authenticated results cache envelope supports at most %d verify keys", maxVerifyKeys)
	}

	knownIDs := map[string]struct{}{cfg.SigningKeyID: {}}
	for i, id := range verifyIDs {
		if !keyIDPattern.MatchString(id) {
			return fmt.Errorf("authenticated results cache envelope verify key ID %q is invalid: must match %s and be at most %d characters", id, keyIDPattern.String(), maxKeyIDLength)
		}
		if _, ok := knownIDs[id]; ok {
			return fmt.Errorf("authenticated results cache envelope key ID %q is configured more than once", id)
		}
		knownIDs[id] = struct{}{}
		if len(verifyKeys[i]) < minSigningKeyBytes {
			return fmt.Errorf("authenticated results cache envelope verify key %q must be at least %d bytes", id, minSigningKeyBytes)
		}
	}

	if cfg.MaxCacheEntryBytes < 0 {
		return errors.New("authenticated results cache envelope max cache entry bytes must not be negative")
	}
	if cfg.MaxDecodedPayloadBytes < 0 {
		return errors.New("authenticated results cache envelope max decoded payload bytes must not be negative")
	}
	if cfg.MaxTTL < 0 {
		return errors.New("authenticated results cache envelope max TTL must not be negative")
	}
	return nil
}

// cacheAuthIdentity is the in-process, request-scoped semantic identity bound
// into the envelope HMAC. It is derived from the authenticated request context
// and request, never from the cache key string.
type cacheAuthIdentity struct {
	// tenantIDs are already normalized (sorted and de-duplicated), as returned
	// by users.TenantIDs.
	tenantIDs []string
	// query is the PromQL query text.
	query string
	// stepMillis is the requested query step in milliseconds.
	stepMillis int64
	// gridIntervalMillis/gridBucket identify the split interval time grid and
	// the bucket the entry belongs to.
	gridIntervalMillis int64
	gridBucket         int64
	// protocolVersion is the query semantic/engine protocol version.
	protocolVersion uint16
}

func (i *cacheAuthIdentity) canonicalTenants() []string {
	if i == nil {
		return nil
	}
	// Defensive copy and normalization; users.TenantIDs already normalizes but
	// identities may be constructed directly in tests.
	return users.NormalizeTenantIDs(append([]string(nil), i.tenantIDs...))
}

// cacheAuthKeyring is a static, in-memory set of HMAC keys built from
// configuration. Key IDs never trigger path/URL lookups; an unknown ID simply
// rejects the entry.
type cacheAuthKeyring struct {
	signingKeyID string
	signingKey   []byte
	verifyKeys   map[string][]byte
}

func newCacheAuthKeyring(cfg AuthenticatedEnvelopeConfig) (*cacheAuthKeyring, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	keyring := &cacheAuthKeyring{
		signingKeyID: cfg.SigningKeyID,
		signingKey:   []byte(cfg.SigningKey.Value),
		verifyKeys:   make(map[string][]byte, len(cfg.VerifyKeyIDs)),
	}
	verifyKeys := cfg.VerifyKeys.Value()
	for i, id := range []string(cfg.VerifyKeyIDs) {
		// []byte(string) copies the secret into a fresh backing array.
		keyring.verifyKeys[id] = []byte(verifyKeys[i])
	}
	return keyring, nil
}

// keyFor resolves a key ID against the static keyring. It returns false for
// unknown IDs; callers must treat that as a cache miss.
func (k *cacheAuthKeyring) keyFor(id string) ([]byte, bool) {
	if id == k.signingKeyID {
		return k.signingKey, true
	}
	key, ok := k.verifyKeys[id]
	return key, ok
}

// envelopeHeader is the canonical, length-prefixed authenticated header. Its
// exact on-wire bytes are part of the HMAC input, so the framing is part of
// the authenticated data.
type envelopeHeader struct {
	version     uint8
	algorithm   uint8
	compression uint8
	flags       uint8
	keyID       string

	generation         uint64
	issuedAtUnixMillis uint64
	ttlMillis          uint64

	protocolVersion    uint16
	stepMillis         int64
	gridIntervalMillis int64
	gridBucket         int64

	query     string
	tenantIDs []string
}

func encodeEnvelopeHeader(h envelopeHeader) ([]byte, error) {
	if len(h.keyID) > maxKeyIDLength {
		return nil, fmt.Errorf("envelope key ID exceeds %d bytes", maxKeyIDLength)
	}
	if len(h.query) > (1<<32)-1 {
		return nil, errors.New("envelope query too long")
	}
	if len(h.tenantIDs) > (1<<16)-1 {
		return nil, errors.New("envelope tenant set too large")
	}

	size := 4 + // version, algorithm, compression, flags
		2 + len(h.keyID) +
		8 + 8 + 8 + // generation, issued at, ttl
		2 + // protocol version
		8 + 8 + 8 + // step, grid interval, grid bucket
		4 + len(h.query) +
		2 // tenant count
	for _, tenantID := range h.tenantIDs {
		if len(tenantID) > (1<<16)-1 {
			return nil, errors.New("envelope tenant ID too long")
		}
		size += 2 + len(tenantID)
	}

	buf := bytes.NewBuffer(make([]byte, 0, size))
	tmp := make([]byte, 8)

	buf.WriteByte(h.version)
	buf.WriteByte(h.algorithm)
	buf.WriteByte(h.compression)
	buf.WriteByte(h.flags)

	binary.BigEndian.PutUint16(tmp[:2], uint16(len(h.keyID)))
	buf.Write(tmp[:2])
	buf.WriteString(h.keyID)

	binary.BigEndian.PutUint64(tmp, h.generation)
	buf.Write(tmp)
	binary.BigEndian.PutUint64(tmp, h.issuedAtUnixMillis)
	buf.Write(tmp)
	binary.BigEndian.PutUint64(tmp, h.ttlMillis)
	buf.Write(tmp)

	binary.BigEndian.PutUint16(tmp[:2], h.protocolVersion)
	buf.Write(tmp[:2])
	binary.BigEndian.PutUint64(tmp, uint64(h.stepMillis))
	buf.Write(tmp)
	binary.BigEndian.PutUint64(tmp, uint64(h.gridIntervalMillis))
	buf.Write(tmp)
	binary.BigEndian.PutUint64(tmp, uint64(h.gridBucket))
	buf.Write(tmp)

	binary.BigEndian.PutUint32(tmp[:4], uint32(len(h.query)))
	buf.Write(tmp[:4])
	buf.WriteString(h.query)

	binary.BigEndian.PutUint16(tmp[:2], uint16(len(h.tenantIDs)))
	buf.Write(tmp[:2])
	for _, tenantID := range h.tenantIDs {
		binary.BigEndian.PutUint16(tmp[:2], uint16(len(tenantID)))
		buf.Write(tmp[:2])
		buf.WriteString(tenantID)
	}

	return buf.Bytes(), nil
}

// byteCursor is a bounds-checked cursor over untrusted bytes. Any overrun
// leaves a sticky malformed error.
type byteCursor struct {
	b   []byte
	off int
	err error
}

func (c *byteCursor) readU8() uint8 {
	if c.err != nil || c.off+1 > len(c.b) {
		c.err = errEnvelopeRejected
		return 0
	}
	v := c.b[c.off]
	c.off++
	return v
}

func (c *byteCursor) readU16() uint16 {
	if c.err != nil || c.off+2 > len(c.b) {
		c.err = errEnvelopeRejected
		return 0
	}
	v := binary.BigEndian.Uint16(c.b[c.off:])
	c.off += 2
	return v
}

func (c *byteCursor) readU32() uint32 {
	if c.err != nil || c.off+4 > len(c.b) {
		c.err = errEnvelopeRejected
		return 0
	}
	v := binary.BigEndian.Uint32(c.b[c.off:])
	c.off += 4
	return v
}

func (c *byteCursor) readU64() uint64 {
	if c.err != nil || c.off+8 > len(c.b) {
		c.err = errEnvelopeRejected
		return 0
	}
	v := binary.BigEndian.Uint64(c.b[c.off:])
	c.off += 8
	return v
}

func (c *byteCursor) readI64() int64 {
	return int64(c.readU64())
}

func (c *byteCursor) readLenPrefixed16() []byte {
	length := int(c.readU16())
	if c.err != nil || c.off+length > len(c.b) {
		c.err = errEnvelopeRejected
		return nil
	}
	v := c.b[c.off : c.off+length]
	c.off += length
	return v
}

func (c *byteCursor) readLenPrefixed32() []byte {
	length := int(c.readU32())
	if c.err != nil || length < 0 || c.off+length > len(c.b) {
		c.err = errEnvelopeRejected
		return nil
	}
	v := c.b[c.off : c.off+length]
	c.off += length
	return v
}

func decodeEnvelopeHeader(b []byte) (envelopeHeader, error) {
	cursor := &byteCursor{b: b}
	h := envelopeHeader{
		version:     cursor.readU8(),
		algorithm:   cursor.readU8(),
		compression: cursor.readU8(),
		flags:       cursor.readU8(),
	}
	h.keyID = string(cursor.readLenPrefixed16())

	h.generation = cursor.readU64()
	h.issuedAtUnixMillis = cursor.readU64()
	h.ttlMillis = cursor.readU64()

	h.protocolVersion = cursor.readU16()
	h.stepMillis = cursor.readI64()
	h.gridIntervalMillis = cursor.readI64()
	h.gridBucket = cursor.readI64()

	h.query = string(cursor.readLenPrefixed32())

	tenantCount := int(cursor.readU16())
	if cursor.err == nil && tenantCount > 0 {
		h.tenantIDs = make([]string, 0, tenantCount)
		for range tenantCount {
			h.tenantIDs = append(h.tenantIDs, string(cursor.readLenPrefixed16()))
			if cursor.err != nil {
				break
			}
		}
	}

	if cursor.err != nil {
		return envelopeHeader{}, cursor.err
	}
	if cursor.off != len(b) {
		// No trailing bytes are allowed inside the header: strict framing keeps
		// the authenticated byte range unambiguous.
		return envelopeHeader{}, errEnvelopeRejected
	}
	return h, nil
}

// envelopeMetrics records envelope outcomes with a bounded label set.
type envelopeMetrics struct {
	sealedTotal          prometheus.Counter
	sealFailuresTotal    prometheus.Counter
	verifiedTotal        prometheus.Counter
	verificationFailures *prometheus.CounterVec
}

func newEnvelopeMetrics(reg prometheus.Registerer) *envelopeMetrics {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	m := &envelopeMetrics{
		sealedTotal: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "cortex_query_range_results_cache_envelope_sealed_total",
			Help: "Total number of query-range results cache entries sealed with the authenticated envelope.",
		}),
		sealFailuresTotal: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "cortex_query_range_results_cache_envelope_seal_failures_total",
			Help: "Total number of authenticated results cache envelope sealing failures. The source query is unaffected.",
		}),
		verifiedTotal: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "cortex_query_range_results_cache_envelope_verified_total",
			Help: "Total number of authenticated results cache entries that passed full HMAC and semantic identity verification.",
		}),
		verificationFailures: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "cortex_query_range_results_cache_envelope_verification_failures_total",
			Help: "Total number of authenticated results cache entries rejected as cache misses, by bounded reason.",
		}, []string{"reason"}),
	}
	for _, reason := range envelopeFailureReasons {
		m.verificationFailures.WithLabelValues(reason)
	}
	return m
}

// authenticatedEnvelope seals and opens authenticated cache entries at the
// external cache boundary.
type authenticatedEnvelope struct {
	cfg         AuthenticatedEnvelopeConfig
	keyring     *cacheAuthKeyring
	compression string
	logger      log.Logger
	now         func() time.Time
	metrics     *envelopeMetrics
}

func newAuthenticatedEnvelope(cfg AuthenticatedEnvelopeConfig, compression string, logger log.Logger, reg prometheus.Registerer) (*authenticatedEnvelope, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	keyring, err := newCacheAuthKeyring(cfg)
	if err != nil {
		return nil, err
	}

	// Defensive defaults for configurations built without flag registration.
	if cfg.MaxCacheEntryBytes == 0 {
		cfg.MaxCacheEntryBytes = defaultMaxCacheEntryBytes
	}
	if cfg.MaxDecodedPayloadBytes == 0 {
		cfg.MaxDecodedPayloadBytes = defaultMaxDecodedPayloadBytes
	}

	return &authenticatedEnvelope{
		cfg:         cfg,
		keyring:     keyring,
		compression: compression,
		logger:      logger,
		now:         time.Now,
		metrics:     newEnvelopeMetrics(reg),
	}, nil
}

// truncateTTL applies the server-trusted MaxTTL policy to a cache TTL. Zero
// means the existing per-tenant TTL policy is preserved.
func (e *authenticatedEnvelope) truncateTTL(ttl time.Duration) time.Duration {
	if e.cfg.MaxTTL <= 0 {
		return ttl
	}
	if ttl <= 0 || ttl > e.cfg.MaxTTL {
		return e.cfg.MaxTTL
	}
	return ttl
}

// computeMAC returns HMAC-SHA256(key, header || payload). The header carries
// the full semantic identity, so this is an authentication of the complete
// entry rather than a payload-only checksum.
func computeMAC(key, header, payload []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(header)
	h.Write(payload)
	return h.Sum(nil)
}

// seal wraps the marshaled CachedResponse payload into an authenticated
// envelope. Compression, when configured, is applied to the payload before
// signing so that reads can verify the HMAC before any decompression.
func (e *authenticatedEnvelope) seal(ctx context.Context, identity *cacheAuthIdentity, payload []byte, ttl time.Duration) ([]byte, error) {
	if identity == nil {
		e.metrics.sealFailuresTotal.Inc()
		return nil, errMissingIdentity
	}

	body := payload
	compression := envelopeCompressionNone
	if e.compression == "snappy" {
		body = snappy.Encode(nil, payload)
		compression = envelopeCompressionSnappy
	}

	header := envelopeHeader{
		version:     envelopeVersion1,
		algorithm:   envelopeAlgHMACSHA256,
		compression: compression,
		keyID:       e.keyring.signingKeyID,

		generation:         e.cfg.InvalidationGeneration,
		issuedAtUnixMillis: uint64(e.now().UnixMilli()),
		ttlMillis:          uint64(ttl.Milliseconds()),

		protocolVersion:    identity.protocolVersion,
		stepMillis:         identity.stepMillis,
		gridIntervalMillis: identity.gridIntervalMillis,
		gridBucket:         identity.gridBucket,
		query:              identity.query,
		tenantIDs:          identity.canonicalTenants(),
	}

	headerBytes, err := encodeEnvelopeHeader(header)
	if err != nil {
		e.metrics.sealFailuresTotal.Inc()
		level.Error(util_log.WithContext(ctx, e.logger)).Log("msg", "failed to encode authenticated results cache envelope header", "err", err)
		return nil, err
	}

	mac := computeMAC(e.keyring.signingKey, headerBytes, body)

	out := bytes.NewBuffer(make([]byte, 0, len(envelopeMagic)+4+len(headerBytes)+8+len(body)+envelopeMACSize))
	tmp := make([]byte, 8)
	out.WriteString(envelopeMagic)
	binary.BigEndian.PutUint32(tmp[:4], uint32(len(headerBytes)))
	out.Write(tmp[:4])
	out.Write(headerBytes)
	binary.BigEndian.PutUint64(tmp, uint64(len(body)))
	out.Write(tmp)
	out.Write(body)
	out.Write(mac)

	e.metrics.sealedTotal.Inc()
	return out.Bytes(), nil
}

// open verifies an authenticated envelope and returns the plain payload bytes
// (still protobuf-encoded at this layer). It enforces, in order: raw length
// limit, strict framing, static key lookup, constant-time HMAC verification,
// semantic identity, invalidation generation, trusted TTL, and only then
// bounded decompression. Any failure returns a bounded reason and is handled
// by the caller as a cache miss.
func (e *authenticatedEnvelope) open(ctx context.Context, identity *cacheAuthIdentity, raw []byte) ([]byte, string, error) {
	reject := func(reason string) ([]byte, string, error) {
		e.metrics.verificationFailures.WithLabelValues(reason).Inc()
		// Only the bounded reason and the entry length are logged; payload and
		// key material must never reach the logs.
		level.Warn(util_log.WithContext(ctx, e.logger)).Log("msg", "rejected authenticated results cache entry", "reason", reason, "entry_bytes", len(raw))
		return nil, reason, errEnvelopeRejected
	}

	// 1. Bound the raw entry size before parsing anything.
	if len(raw) == 0 {
		return reject(reasonMalformed)
	}
	if len(raw) > e.cfg.MaxCacheEntryBytes {
		return reject(reasonEntryTooLarge)
	}

	// 2. Magic and strict outer framing; this also rejects legacy plain entries.
	if len(raw) < len(envelopeMagic) || string(raw[:len(envelopeMagic)]) != envelopeMagic {
		return reject(reasonBadMagic)
	}
	offset := len(envelopeMagic)
	if len(raw)-offset < 4 {
		return reject(reasonMalformed)
	}
	headerLen := int(binary.BigEndian.Uint32(raw[offset : offset+4]))
	offset += 4
	if headerLen <= 0 || offset+headerLen+8+envelopeMACSize > len(raw) {
		return reject(reasonMalformed)
	}
	headerBytes := raw[offset : offset+headerLen]
	offset += headerLen

	payloadLen := int(binary.BigEndian.Uint64(raw[offset : offset+8]))
	offset += 8
	if payloadLen < 0 || offset+payloadLen+envelopeMACSize != len(raw) {
		return reject(reasonMalformed)
	}
	body := raw[offset : offset+payloadLen]
	receivedMAC := raw[offset+payloadLen:]

	// 3. Parse the header within its authenticated bounds.
	header, err := decodeEnvelopeHeader(headerBytes)
	if err != nil {
		return reject(reasonMalformed)
	}
	if header.version != envelopeVersion1 || header.algorithm != envelopeAlgHMACSHA256 || header.flags != 0 {
		return reject(reasonMalformed)
	}

	// 4. Resolve the key ID against the static, configuration-built keyring.
	key, ok := e.keyring.keyFor(header.keyID)
	if !ok {
		return reject(reasonUnknownKey)
	}

	// 5. Verify the HMAC (constant time) before decompressing or decoding.
	if !hmac.Equal(computeMAC(key, headerBytes, body), receivedMAC) {
		return reject(reasonBadMAC)
	}

	// 6. Bind the authenticated semantic identity to this request. The cache
	//    key string is not consulted for authenticity.
	if identity == nil {
		return reject(reasonMissingIdentity)
	}
	if header.protocolVersion != identity.protocolVersion {
		return reject(reasonProtocolMismatch)
	}
	if !equalStringSlices(header.tenantIDs, identity.canonicalTenants()) {
		return reject(reasonTenantMismatch)
	}
	if header.query != identity.query ||
		header.stepMillis != identity.stepMillis ||
		header.gridIntervalMillis != identity.gridIntervalMillis ||
		header.gridBucket != identity.gridBucket {
		return reject(reasonIdentityMismatch)
	}

	// 7. A valid signature never overrides the current trusted generation.
	if header.generation != e.cfg.InvalidationGeneration {
		return reject(reasonGenerationMismatch)
	}

	// 8. Enforce the authenticated TTL with the server clock even if the
	//    external backend ignores expiry.
	if header.ttlMillis > 0 {
		issuedAt := time.UnixMilli(int64(header.issuedAtUnixMillis))
		if e.now().Sub(issuedAt) >= time.Duration(header.ttlMillis)*time.Millisecond {
			return reject(reasonExpired)
		}
	}

	// 9. Decompress only after authentication, with a hard output cap checked
	//    against the declared length before the decoder allocates memory.
	payload := body
	switch header.compression {
	case envelopeCompressionNone:
	case envelopeCompressionSnappy:
		decodedLen, err := snappy.DecodedLen(body)
		if err != nil {
			return reject(reasonMalformed)
		}
		if decodedLen > e.cfg.MaxDecodedPayloadBytes {
			return reject(reasonPayloadTooLarge)
		}
		decoded, err := snappy.Decode(nil, body)
		if err != nil {
			return reject(reasonDecompressFailed)
		}
		payload = decoded
	default:
		return reject(reasonMalformed)
	}

	e.metrics.verifiedTotal.Inc()
	return payload, "", nil
}

func equalStringSlices(a, b []string) bool {
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
