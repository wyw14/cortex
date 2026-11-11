package queryrange

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-kit/log"
	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"
	"github.com/golang/snappy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/user"

	"github.com/cortexproject/cortex/pkg/chunk/cache"
	"github.com/cortexproject/cortex/pkg/querier/tripperware"
	"github.com/cortexproject/cortex/pkg/util/flagext"
)

const (
	testSigningKeyA = "0123456789abcdef0123456789abcdef" // 32 bytes
	testSigningKeyB = "fedcba9876543210fedcba9876543210" // 32 bytes
	testVerifyKeyC  = "aaaa-bbbb-cccc-dddd-eeee-ffff-0000"
)

func testEnvelopeConfig() AuthenticatedEnvelopeConfig {
	return AuthenticatedEnvelopeConfig{
		Enabled:                true,
		SigningKeyID:           "key-a",
		SigningKey:             flagext.Secret{Value: testSigningKeyA},
		MaxCacheEntryBytes:     1 << 20,
		MaxDecodedPayloadBytes: 1 << 20,
		InvalidationGeneration: 7,
	}
}

func testAuthIdentity(tenants ...string) *cacheAuthIdentity {
	if len(tenants) == 0 {
		tenants = []string{"tenant-a"}
	}
	return &cacheAuthIdentity{
		tenantIDs:          tenants,
		query:              "sum(rate(http_requests_total[5m]))",
		stepMillis:         15_000,
		gridIntervalMillis: day.Milliseconds(),
		gridBucket:         42,
		protocolVersion:    queryRangeCacheProtocolVersion,
	}
}

func newTestEnvelope(t *testing.T, cfg AuthenticatedEnvelopeConfig, compression string) *authenticatedEnvelope {
	t.Helper()
	e, err := newAuthenticatedEnvelope(cfg, compression, log.NewNopLogger(), prometheus.NewRegistry())
	require.NoError(t, err)
	return e
}

// parseEnvelopeFrame splits a raw envelope into its authenticated regions.
func parseEnvelopeFrame(t *testing.T, raw []byte) (header, body, mac []byte) {
	t.Helper()
	require.Equal(t, envelopeMagic, string(raw[:len(envelopeMagic)]))
	headerLen := int(binary.BigEndian.Uint32(raw[8:12]))
	header = raw[12 : 12+headerLen]
	payloadLen := int(binary.BigEndian.Uint64(raw[12+headerLen : 20+headerLen]))
	bodyStart := 20 + headerLen
	body = raw[bodyStart : bodyStart+payloadLen]
	mac = raw[bodyStart+payloadLen:]
	require.Len(t, mac, envelopeMACSize)
	return header, body, mac
}

func TestAuthenticatedEnvelopeConfig_Validate(t *testing.T) {
	t.Parallel()

	valid := testEnvelopeConfig()
	validWithVerify := testEnvelopeConfig()
	validWithVerify.VerifyKeyIDs = flagext.StringSlice{"key-c"}
	validWithVerify.VerifyKeys = flagext.SecretStringSliceCSV{}
	require.NoError(t, validWithVerify.VerifyKeys.Set(testVerifyKeyC))

	for _, tc := range []struct {
		name string
		cfg  AuthenticatedEnvelopeConfig
		err  string
	}{
		{name: "disabled is always valid", cfg: AuthenticatedEnvelopeConfig{Enabled: false}},
		{name: "valid", cfg: valid},
		{name: "valid with verify keys", cfg: validWithVerify},
		{
			name: "missing signing key id",
			cfg: func() AuthenticatedEnvelopeConfig {
				c := testEnvelopeConfig()
				c.SigningKeyID = ""
				return c
			}(),
			err: "signing key ID",
		},
		{
			name: "illegal key id characters",
			cfg: func() AuthenticatedEnvelopeConfig {
				c := testEnvelopeConfig()
				c.SigningKeyID = "../etc/passwd"
				return c
			}(),
			err: "signing key ID",
		},
		{
			name: "short signing key",
			cfg: func() AuthenticatedEnvelopeConfig {
				c := testEnvelopeConfig()
				c.SigningKey = flagext.Secret{Value: "short"}
				return c
			}(),
			err: "at least 32 bytes",
		},
		{
			name: "verify ids and keys length mismatch",
			cfg: func() AuthenticatedEnvelopeConfig {
				c := testEnvelopeConfig()
				c.VerifyKeyIDs = flagext.StringSlice{"key-c", "key-d"}
				require.NoError(t, c.VerifyKeys.Set(testVerifyKeyC))
				return c
			}(),
			err: "same number of entries",
		},
		{
			name: "too many verify keys",
			cfg: func() AuthenticatedEnvelopeConfig {
				c := testEnvelopeConfig()
				secrets := make([]string, 0, maxVerifyKeys+1)
				for i := range maxVerifyKeys + 1 {
					c.VerifyKeyIDs = append(c.VerifyKeyIDs, "key-"+strings.Repeat("x", i+1))
					secrets = append(secrets, strings.Repeat("z", minSigningKeyBytes))
				}
				require.NoError(t, c.VerifyKeys.Set(strings.Join(secrets, ",")))
				return c
			}(),
			err: "at most 4 verify keys",
		},
		{
			name: "duplicate key ids",
			cfg: func() AuthenticatedEnvelopeConfig {
				c := testEnvelopeConfig()
				c.VerifyKeyIDs = flagext.StringSlice{"key-a"}
				require.NoError(t, c.VerifyKeys.Set(testVerifyKeyC))
				return c
			}(),
			err: "more than once",
		},
		{
			name: "negative entry size",
			cfg: func() AuthenticatedEnvelopeConfig {
				c := testEnvelopeConfig()
				c.MaxCacheEntryBytes = -1
				return c
			}(),
			err: "max cache entry bytes",
		},
		{
			name: "negative max ttl",
			cfg: func() AuthenticatedEnvelopeConfig {
				c := testEnvelopeConfig()
				c.MaxTTL = -1
				return c
			}(),
			err: "max TTL",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.cfg.Validate()
			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)
			}
		})
	}
}

func TestAuthenticatedEnvelopeConfig_RegisterFlags(t *testing.T) {
	t.Parallel()

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg := AuthenticatedEnvelopeConfig{}
	cfg.RegisterFlags(fs)

	require.NoError(t, fs.Parse([]string{
		"-frontend.results-cache-authenticated-envelope.enabled",
		"-frontend.results-cache-authenticated-envelope.signing-key-id", "key-a",
		"-frontend.results-cache-authenticated-envelope.signing-key", testSigningKeyA,
		"-frontend.results-cache-authenticated-envelope.invalidation-generation", "9",
	}))
	require.True(t, cfg.Enabled)
	require.Equal(t, "key-a", cfg.SigningKeyID)
	require.Equal(t, testSigningKeyA, cfg.SigningKey.Value)
	require.Equal(t, uint64(9), cfg.InvalidationGeneration)
	require.NoError(t, cfg.Validate())
}

func TestAuthenticatedEnvelope_RoundTrip(t *testing.T) {
	t.Parallel()

	for _, compression := range []string{"", "snappy"} {
		t.Run("compression="+compression, func(t *testing.T) {
			t.Parallel()
			e := newTestEnvelope(t, testEnvelopeConfig(), compression)
			id := testAuthIdentity()
			payload := bytes.Repeat([]byte("cortex-result-payload-"), 256)

			sealed, err := e.seal(context.Background(), id, payload, time.Hour)
			require.NoError(t, err)
			require.Equal(t, envelopeMagic, string(sealed[:len(envelopeMagic)]))

			if compression == "snappy" {
				// The stored body must be the compressed form, not the plaintext.
				_, body, _ := parseEnvelopeFrame(t, sealed)
				require.NotEqual(t, payload, body)
			}

			opened, reason, err := e.open(context.Background(), id, sealed)
			require.NoError(t, err)
			require.Empty(t, reason)
			require.Equal(t, payload, opened)
		})
	}
}

func TestAuthenticatedEnvelope_TamperSingleByte(t *testing.T) {
	t.Parallel()

	e := newTestEnvelope(t, testEnvelopeConfig(), "snappy")
	id := testAuthIdentity()
	payload := bytes.Repeat([]byte("tamper-me-"), 128)

	sealed, err := e.seal(context.Background(), id, payload, time.Hour)
	require.NoError(t, err)

	header, body, macBytes := parseEnvelopeFrame(t, sealed)
	bodyOffset := len(sealed) - len(body) - len(macBytes)

	positions := map[string]int{
		"magic":          0,
		"header-length":  9,
		"header-fields":  13,
		"payload-region": bodyOffset + len(body)/2,
		"mac-region":     len(sealed) - 1,
	}
	for name, pos := range positions {
		t.Run(name, func(t *testing.T) {
			tampered := append([]byte(nil), sealed...)
			tampered[pos] ^= 0xff

			opened, reason, err := e.open(context.Background(), id, tampered)
			require.Error(t, err, "tampering at %s must be rejected", name)
			require.Nil(t, opened, "an unverified entry must never be returned")
			require.NotEmpty(t, reason)
			require.NotContains(t, reason, " ")
		})
	}

	// A tamper inside a semantic header field (the last header byte is part of
	// the authenticated tenant set) must specifically invalidate the MAC.
	lastHeaderByte := 12 + len(header) - 1
	headerTampered := append([]byte(nil), sealed...)
	headerTampered[lastHeaderByte] ^= 0xff
	_, reason, err := e.open(context.Background(), id, headerTampered)
	require.Error(t, err)
	require.Equal(t, reasonBadMAC, reason)
}

func TestAuthenticatedEnvelope_RejectsLegacyAndGarbage(t *testing.T) {
	t.Parallel()

	e := newTestEnvelope(t, testEnvelopeConfig(), "")
	id := testAuthIdentity()

	for _, tc := range []struct {
		name   string
		raw    []byte
		reason string
	}{
		{name: "empty", raw: nil, reason: reasonMalformed},
		{name: "legacy plain protobuf entry", raw: []byte{0x0a, 0x05, 'h', 'e', 'l', 'l', 'o'}, reason: reasonBadMagic},
		{name: "random garbage", raw: bytes.Repeat([]byte{0xff}, 128), reason: reasonBadMagic},
		{name: "truncated magic", raw: []byte(envelopeMagic)[:4], reason: reasonBadMagic},
		{name: "truncated after magic", raw: append([]byte(envelopeMagic), 0x00, 0x01), reason: reasonMalformed},
		{name: "header length beyond entry", raw: append(append([]byte(envelopeMagic), 0xff, 0xff, 0xff, 0xff), bytes.Repeat([]byte{0x01}, 32)...), reason: reasonMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opened, reason, err := e.open(context.Background(), id, tc.raw)
			require.Error(t, err)
			require.Nil(t, opened)
			require.Equal(t, tc.reason, reason)
		})
	}
}

func TestAuthenticatedEnvelope_EntryTooLarge(t *testing.T) {
	t.Parallel()

	cfg := testEnvelopeConfig()
	cfg.MaxCacheEntryBytes = 64
	e := newTestEnvelope(t, cfg, "")
	id := testAuthIdentity()

	sealed, err := e.seal(context.Background(), id, bytes.Repeat([]byte("x"), 128), time.Hour)
	require.NoError(t, err)
	require.Greater(t, len(sealed), 64)

	// The size check happens before parsing or decompression.
	opened, reason, err := e.open(context.Background(), id, sealed)
	require.Error(t, err)
	require.Nil(t, opened)
	require.Equal(t, reasonEntryTooLarge, reason)
}

func TestAuthenticatedEnvelope_UnknownKey(t *testing.T) {
	t.Parallel()

	e := newTestEnvelope(t, testEnvelopeConfig(), "")
	id := testAuthIdentity()
	sealed, err := e.seal(context.Background(), id, []byte("payload"), time.Hour)
	require.NoError(t, err)

	t.Run("unknown key id is rejected", func(t *testing.T) {
		unknown := testEnvelopeConfig()
		unknown.SigningKeyID = "key-zzz"
		unknown.SigningKey = flagext.Secret{Value: strings.Repeat("z", minSigningKeyBytes)}
		eUnknown := newTestEnvelope(t, unknown, "")

		opened, reason, err := eUnknown.open(context.Background(), id, sealed)
		require.Error(t, err)
		require.Nil(t, opened)
		require.Equal(t, reasonUnknownKey, reason)
	})

	t.Run("nil identity is rejected", func(t *testing.T) {
		opened, reason, err := e.open(context.Background(), nil, sealed)
		require.Error(t, err)
		require.Nil(t, opened)
		require.Equal(t, reasonMissingIdentity, reason)

		_, err = e.seal(context.Background(), nil, []byte("payload"), time.Hour)
		require.ErrorIs(t, err, errMissingIdentity)
	})
}

func TestAuthenticatedEnvelope_KeyRotation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	id := testAuthIdentity()

	// Generation 1 of the deployment signs with key-a.
	old := newTestEnvelope(t, testEnvelopeConfig(), "snappy")
	sealedOld, err := old.seal(ctx, id, []byte("rotation-payload"), time.Hour)
	require.NoError(t, err)

	// Generation 2: key-b is active, key-a is retained as a verify-only key.
	rotatedCfg := testEnvelopeConfig()
	rotatedCfg.SigningKeyID = "key-b"
	rotatedCfg.SigningKey = flagext.Secret{Value: testSigningKeyB}
	rotatedCfg.VerifyKeyIDs = flagext.StringSlice{"key-a"}
	require.NoError(t, rotatedCfg.VerifyKeys.Set(testSigningKeyA))
	rotated := newTestEnvelope(t, rotatedCfg, "snappy")

	opened, reason, err := rotated.open(ctx, id, sealedOld)
	require.NoError(t, err, "old entries must verify with a retired verify key")
	require.Empty(t, reason)
	require.Equal(t, []byte("rotation-payload"), opened)

	// New entries are sealed with the active key.
	sealedNew, err := rotated.seal(ctx, id, []byte("new-payload"), time.Hour)
	require.NoError(t, err)
	header, _, _ := parseEnvelopeFrame(t, sealedNew)
	decoded, err := decodeEnvelopeHeader(header)
	require.NoError(t, err)
	require.Equal(t, "key-b", decoded.keyID)

	opened, _, err = rotated.open(ctx, id, sealedNew)
	require.NoError(t, err)
	require.Equal(t, []byte("new-payload"), opened)

	// Once the retired key is removed, old entries can no longer be verified.
	retired := testEnvelopeConfig()
	retired.SigningKeyID = "key-b"
	retired.SigningKey = flagext.Secret{Value: testSigningKeyB}
	withoutOld := newTestEnvelope(t, retired, "snappy")
	opened, reason, err = withoutOld.open(ctx, id, sealedOld)
	require.Error(t, err)
	require.Nil(t, opened)
	require.Equal(t, reasonUnknownKey, reason)
}

func TestAuthenticatedEnvelope_TenantMismatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	e := newTestEnvelope(t, testEnvelopeConfig(), "")

	sealed, err := e.seal(ctx, testAuthIdentity("tenant-a"), []byte("tenant payload"), time.Hour)
	require.NoError(t, err)

	// A cross-tenant copy: same bytes, different expected tenant set.
	opened, reason, err := e.open(ctx, testAuthIdentity("tenant-b"), sealed)
	require.Error(t, err)
	require.Nil(t, opened)
	require.Equal(t, reasonTenantMismatch, reason)

	// Multi-tenant sets are compared in normalized form: ordering does not
	// weaken the binding but the exact set must match.
	sealedMulti, err := e.seal(ctx, testAuthIdentity("tenant-a", "tenant-b"), []byte("federated"), time.Hour)
	require.NoError(t, err)
	opened, _, err = e.open(ctx, testAuthIdentity("tenant-b", "tenant-a"), sealedMulti)
	require.NoError(t, err)
	require.Equal(t, []byte("federated"), opened)

	opened, reason, err = e.open(ctx, testAuthIdentity("tenant-a", "tenant-c"), sealedMulti)
	require.Error(t, err)
	require.Nil(t, opened)
	require.Equal(t, reasonTenantMismatch, reason)
}

func TestAuthenticatedEnvelope_SemanticIdentityMismatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	e := newTestEnvelope(t, testEnvelopeConfig(), "")
	base := testAuthIdentity()

	sealed, err := e.seal(ctx, base, []byte("identity-bound-payload"), time.Hour)
	require.NoError(t, err)

	mutated := func(mut func(*cacheAuthIdentity)) *cacheAuthIdentity {
		id := *base
		id.tenantIDs = append([]string(nil), base.tenantIDs...)
		mut(&id)
		return &id
	}

	for _, tc := range []struct {
		name   string
		id     *cacheAuthIdentity
		reason string
	}{
		{name: "query text", id: mutated(func(i *cacheAuthIdentity) { i.query = "sum(rate(other_metric[5m]))" }), reason: reasonIdentityMismatch},
		{name: "step", id: mutated(func(i *cacheAuthIdentity) { i.stepMillis = 30_000 }), reason: reasonIdentityMismatch},
		{name: "grid interval", id: mutated(func(i *cacheAuthIdentity) { i.gridIntervalMillis = 12 * time.Hour.Milliseconds() }), reason: reasonIdentityMismatch},
		{name: "grid bucket", id: mutated(func(i *cacheAuthIdentity) { i.gridBucket = 43 }), reason: reasonIdentityMismatch},
		{name: "protocol version", id: mutated(func(i *cacheAuthIdentity) { i.protocolVersion = queryRangeCacheProtocolVersion + 1 }), reason: reasonProtocolMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opened, reason, err := e.open(ctx, tc.id, sealed)
			require.Error(t, err)
			require.Nil(t, opened)
			require.Equal(t, tc.reason, reason)
		})
	}
}

func TestAuthenticatedEnvelope_AuthenticationCoversSemanticsNotJustPayload(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	e := newTestEnvelope(t, testEnvelopeConfig(), "")
	payload := []byte("identical-payload-bytes")

	idA := testAuthIdentity("tenant-a")
	idB := testAuthIdentity("tenant-b")

	sealedA, err := e.seal(ctx, idA, payload, time.Hour)
	require.NoError(t, err)
	sealedB, err := e.seal(ctx, idB, payload, time.Hour)
	require.NoError(t, err)

	// The payloads are byte-identical, but the envelopes must differ because
	// the semantic identity is part of the HMAC input.
	require.NotEqual(t, sealedA, sealedB)

	// A payload-only checksum would accept each entry under either identity.
	// The envelope must not.
	opened, reason, err := e.open(ctx, idB, sealedA)
	require.Error(t, err)
	require.Nil(t, opened)
	require.Equal(t, reasonTenantMismatch, reason)

	opened, reason, err = e.open(ctx, idA, sealedB)
	require.Error(t, err)
	require.Nil(t, opened)
	require.Equal(t, reasonTenantMismatch, reason)

	// Same identity, different payload is a MAC failure as well.
	other, err := e.seal(ctx, idA, []byte("different-payload-bytes"), time.Hour)
	require.NoError(t, err)
	headerA, _, macA := parseEnvelopeFrame(t, sealedA)
	_, bodyOther, _ := parseEnvelopeFrame(t, other)

	// Frankenstein entry: header of A, body of the other payload, but the MAC of
	// entry A. The payload region is part of the HMAC input, so recombining
	// regions fails authentication even though every region was once valid.
	frankenstein := bytes.Buffer{}
	frankenstein.WriteString(envelopeMagic)
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint32(tmp[:4], uint32(len(headerA)))
	frankenstein.Write(tmp[:4])
	frankenstein.Write(headerA)
	binary.BigEndian.PutUint64(tmp, uint64(len(bodyOther)))
	frankenstein.Write(tmp)
	frankenstein.Write(bodyOther)
	frankenstein.Write(macA)

	opened, reason, err = e.open(ctx, idA, frankenstein.Bytes())
	require.Error(t, err)
	require.Nil(t, opened)
	require.Equal(t, reasonBadMAC, reason)
}

func TestAuthenticatedEnvelope_ExtentBoundaryTampering(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	e := newTestEnvelope(t, testEnvelopeConfig(), "")
	id := testAuthIdentity()

	cachedResponseWithBoundary := func(start, end int64) []byte {
		extent := mkExtent(start, end)
		buf, err := proto.Marshal(&tripperware.CachedResponse{
			Key:     "cache-key",
			Extents: []tripperware.Extent{extent},
		})
		require.NoError(t, err)
		return buf
	}

	payloadOriginal := cachedResponseWithBoundary(100, 200)
	payloadShifted := cachedResponseWithBoundary(150, 250)
	require.NotEqual(t, payloadOriginal, payloadShifted)

	sealedOriginal, err := e.seal(ctx, id, payloadOriginal, time.Hour)
	require.NoError(t, err)
	sealedShifted, err := e.seal(ctx, id, payloadShifted, time.Hour)
	require.NoError(t, err)

	// Moving an extent boundary changes the payload bytes and breaks the MAC.
	headerA, _, macOrig := parseEnvelopeFrame(t, sealedOriginal)
	_, bodyShifted, _ := parseEnvelopeFrame(t, sealedShifted)

	rewritten := bytes.Buffer{}
	rewritten.WriteString(envelopeMagic)
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint32(tmp[:4], uint32(len(headerA)))
	rewritten.Write(tmp[:4])
	rewritten.Write(headerA)
	binary.BigEndian.PutUint64(tmp, uint64(len(bodyShifted)))
	rewritten.Write(tmp)
	rewritten.Write(bodyShifted)
	rewritten.Write(macOrig)

	opened, reason, err := e.open(ctx, id, rewritten.Bytes())
	require.Error(t, err)
	require.Nil(t, opened)
	require.Equal(t, reasonBadMAC, reason)

	// Single-byte tampering of the payload region (where extent boundaries
	// live) is likewise rejected.
	tampered := append([]byte(nil), sealedOriginal...)
	_, body, macBytes := parseEnvelopeFrame(t, tampered)
	bodyStart := len(tampered) - len(body) - len(macBytes)
	tampered[bodyStart] ^= 0xff
	opened, reason, err = e.open(ctx, id, tampered)
	require.Error(t, err)
	require.Nil(t, opened)
	require.Equal(t, reasonBadMAC, reason)

	// Untampered entries still decode back into the original extent boundary.
	opened, _, err = e.open(ctx, id, sealedOriginal)
	require.NoError(t, err)
	var resp tripperware.CachedResponse
	require.NoError(t, proto.Unmarshal(opened, &resp))
	require.Len(t, resp.Extents, 1)
	require.Equal(t, int64(100), resp.Extents[0].Start)
	require.Equal(t, int64(200), resp.Extents[0].End)
}

func TestAuthenticatedEnvelope_GenerationMismatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	e := newTestEnvelope(t, testEnvelopeConfig(), "")
	id := testAuthIdentity()

	sealed, err := e.seal(ctx, id, []byte("generation-bound"), time.Hour)
	require.NoError(t, err)

	bumped := testEnvelopeConfig()
	bumped.InvalidationGeneration = 8
	eBumped := newTestEnvelope(t, bumped, "")

	// A perfectly valid signature cannot bypass the current generation.
	opened, reason, err := eBumped.open(ctx, id, sealed)
	require.Error(t, err)
	require.Nil(t, opened)
	require.Equal(t, reasonGenerationMismatch, reason)

	// The old generation still accepts its own entries.
	opened, _, err = e.open(ctx, id, sealed)
	require.NoError(t, err)
	require.Equal(t, []byte("generation-bound"), opened)
}

func TestAuthenticatedEnvelope_TTLExpiryAndTruncation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)

	cfg := testEnvelopeConfig()
	cfg.MaxTTL = time.Minute
	e := newTestEnvelope(t, cfg, "")
	e.now = func() time.Time { return now }
	id := testAuthIdentity()

	sealed, err := e.seal(ctx, id, []byte("ttl-bound"), time.Minute)
	require.NoError(t, err)

	e.now = func() time.Time { return now.Add(59 * time.Second) }
	opened, _, err := e.open(ctx, id, sealed)
	require.NoError(t, err)
	require.Equal(t, []byte("ttl-bound"), opened)

	e.now = func() time.Time { return now.Add(time.Minute) }
	opened, reason, err := e.open(ctx, id, sealed)
	require.Error(t, err)
	require.Nil(t, opened)
	require.Equal(t, reasonExpired, reason)

	// Entries without an authenticated TTL rely on the backend expiry.
	noTTL, err := e.seal(ctx, id, []byte("no-ttl"), 0)
	require.NoError(t, err)
	e.now = func() time.Time { return now.Add(10 * 365 * 24 * time.Hour) }
	opened, _, err = e.open(ctx, id, noTTL)
	require.NoError(t, err)
	require.Equal(t, []byte("no-ttl"), opened)

	// The trusted policy can only shorten the TTL.
	require.Equal(t, time.Minute, e.truncateTTL(10*time.Minute))
	require.Equal(t, 30*time.Second, e.truncateTTL(30*time.Second))
	require.Equal(t, time.Minute, e.truncateTTL(0))

	noMax := newTestEnvelope(t, testEnvelopeConfig(), "")
	require.Equal(t, 10*time.Minute, noMax.truncateTTL(10*time.Minute))
	require.Equal(t, time.Duration(0), noMax.truncateTTL(0))
}

func TestAuthenticatedEnvelope_DecompressionBomb(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("declared decoded length is capped before allocation", func(t *testing.T) {
		t.Parallel()
		cfg := testEnvelopeConfig()
		cfg.MaxDecodedPayloadBytes = 1024
		e := newTestEnvelope(t, cfg, "snappy")
		id := testAuthIdentity()

		big := make([]byte, 2*1024*1024) // highly compressible zeros
		sealed, err := e.seal(ctx, id, big, time.Hour)
		require.NoError(t, err)

		// The on-wire entry is far smaller than its decoded form, so the raw
		// entry limit alone cannot protect us; the decoded-length cap must.
		require.Less(t, len(sealed), len(big))
		opened, reason, err := e.open(ctx, id, sealed)
		require.Error(t, err)
		require.Nil(t, opened)
		require.Equal(t, reasonPayloadTooLarge, reason)
	})

	t.Run("corrupt snappy stream with valid mac", func(t *testing.T) {
		t.Parallel()
		e := newTestEnvelope(t, testEnvelopeConfig(), "snappy")
		id := testAuthIdentity()

		body := snappy.Encode(nil, []byte("hello world"))
		// Corrupt the snappy tag byte (after the length varint): framing is
		// broken while the declared decoded length stays readable.
		body[1] ^= 0xff

		header, err := encodeEnvelopeHeader(envelopeHeader{
			version:            envelopeVersion1,
			algorithm:          envelopeAlgHMACSHA256,
			compression:        envelopeCompressionSnappy,
			keyID:              e.keyring.signingKeyID,
			generation:         e.cfg.InvalidationGeneration,
			issuedAtUnixMillis: uint64(e.now().UnixMilli()),
			ttlMillis:          uint64(time.Hour.Milliseconds()),
			protocolVersion:    id.protocolVersion,
			stepMillis:         id.stepMillis,
			gridIntervalMillis: id.gridIntervalMillis,
			gridBucket:         id.gridBucket,
			query:              id.query,
			tenantIDs:          id.canonicalTenants(),
		})
		require.NoError(t, err)
		mac := computeMAC(e.keyring.signingKey, header, body)

		raw := bytes.Buffer{}
		raw.WriteString(envelopeMagic)
		tmp := make([]byte, 8)
		binary.BigEndian.PutUint32(tmp[:4], uint32(len(header)))
		raw.Write(tmp[:4])
		raw.Write(header)
		binary.BigEndian.PutUint64(tmp, uint64(len(body)))
		raw.Write(tmp)
		raw.Write(body)
		raw.Write(mac)

		opened, reason, err := e.open(ctx, id, raw.Bytes())
		require.Error(t, err)
		require.Nil(t, opened)
		require.Equal(t, reasonDecompressFailed, reason)
	})
}

func TestAuthenticatedEnvelope_LogsNeverContainPayload(t *testing.T) {
	t.Parallel()

	var logBuf bytes.Buffer
	logger := log.NewLogfmtLogger(&logBuf)
	e, err := newAuthenticatedEnvelope(testEnvelopeConfig(), "", logger, prometheus.NewRegistry())
	require.NoError(t, err)

	secretMarker := "super-secret-payload-marker-xyz"
	sealed, err := e.seal(context.Background(), testAuthIdentity(), []byte(secretMarker), time.Hour)
	require.NoError(t, err)

	_, reason, err := e.open(context.Background(), testAuthIdentity("intruder"), sealed)
	require.Error(t, err)
	require.Equal(t, reasonTenantMismatch, reason)

	logOutput := logBuf.String()
	assert.NotContains(t, logOutput, secretMarker)
	assert.Contains(t, logOutput, "reason")
	assert.Contains(t, logOutput, reasonTenantMismatch)
}

func TestAuthenticatedEnvelope_FailureMetricsHaveBoundedReasons(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	e, err := newAuthenticatedEnvelope(testEnvelopeConfig(), "", log.NewNopLogger(), reg)
	require.NoError(t, err)
	id := testAuthIdentity()

	sealed, err := e.seal(context.Background(), id, []byte("metrics"), time.Hour)
	require.NoError(t, err)

	_, _, err = e.open(context.Background(), testAuthIdentity("intruder"), sealed)
	require.Error(t, err)
	_, _, err = e.open(context.Background(), id, []byte("not-an-envelope"))
	require.Error(t, err)

	mfs, err := reg.Gather()
	require.NoError(t, err)

	reasons := map[string]float64{}
	var sealedTotal, verifiedTotal float64
	for _, mf := range mfs {
		switch mf.GetName() {
		case "cortex_query_range_results_cache_envelope_verification_failures_total":
			for _, m := range mf.GetMetric() {
				reasons[m.GetLabel()[0].GetValue()] = m.GetCounter().GetValue()
			}
		case "cortex_query_range_results_cache_envelope_sealed_total":
			sealedTotal = mf.GetMetric()[0].GetCounter().GetValue()
		case "cortex_query_range_results_cache_envelope_verified_total":
			verifiedTotal = mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	require.Equal(t, float64(1), sealedTotal)
	require.Equal(t, float64(0), verifiedTotal)
	require.Equal(t, float64(1), reasons[reasonTenantMismatch])
	require.Equal(t, float64(1), reasons[reasonBadMagic])

	// Every possible reason is pre-initialized, keeping the label set bounded.
	for _, reason := range envelopeFailureReasons {
		_, ok := reasons[reason]
		require.True(t, ok, "reason %q must be pre-registered", reason)
	}
}

// ---- middleware-level integration ----

func newEnvelopeResultsCache(t *testing.T, c cache.Cache, cfg ResultsCacheConfig) (*resultsCache, *int32) {
	t.Helper()
	var calls int32
	rcm, _, err := NewResultsCacheMiddleware(
		log.NewNopLogger(),
		cfg,
		splitter(day),
		mockLimits{},
		PrometheusCodec,
		PrometheusResponseExtractor{},
		nil,
		prometheus.NewRegistry(),
		nil,
	)
	require.NoError(t, err)

	rc := rcm.Wrap(tripperware.HandlerFunc(func(_ context.Context, _ tripperware.Request) (tripperware.Response, error) {
		atomic.AddInt32(&calls, 1)
		return parsedResponse, nil
	})).(*resultsCache)
	return rc, &calls
}

func envelopeResultsCacheConfig(c cache.Cache, compression string) ResultsCacheConfig {
	cfg := ResultsCacheConfig{
		CacheConfig: cache.Config{
			Cache: c,
		},
		Compression:           compression,
		AuthenticatedEnvelope: testEnvelopeConfig(),
	}
	return cfg
}

func rawCacheEntry(t *testing.T, c cache.Cache, ctx context.Context, key string) []byte {
	t.Helper()
	hashed := cache.HashKey(key)
	found, bufs, missing := c.Fetch(ctx, []string{hashed}, 0)
	require.Empty(t, missing)
	require.Equal(t, []string{hashed}, found)
	require.Len(t, bufs, 1)
	return bufs[0]
}

func TestResultsCache_AuthenticatedEnvelope_RoundTrip(t *testing.T) {
	t.Parallel()

	c := cache.NewMockCache()
	rc, calls := newEnvelopeResultsCache(t, c, envelopeResultsCacheConfig(c, "snappy"))
	ctx := user.InjectOrgID(context.Background(), "1")

	resp, err := rc.Do(ctx, parsedRequest)
	require.NoError(t, err)
	require.Equal(t, parsedResponse, resp)
	require.Equal(t, int32(1), atomic.LoadInt32(calls))

	// Second request is served from the authenticated cache entry.
	resp, err = rc.Do(ctx, parsedRequest)
	require.NoError(t, err)
	require.Equal(t, parsedResponse, resp)
	require.Equal(t, int32(1), atomic.LoadInt32(calls))

	key := splitter(day).GenerateCacheKey(ctx, "1", parsedRequest)
	raw := rawCacheEntry(t, c, ctx, key)
	require.Equal(t, envelopeMagic, string(raw[:len(envelopeMagic)]))

	// The stored bytes must not be a plain CachedResponse.
	var legacy tripperware.CachedResponse
	require.Error(t, proto.Unmarshal(raw, &legacy))
}

func TestResultsCache_DefaultDisabledKeepsLegacyFormat(t *testing.T) {
	t.Parallel()

	c := cache.NewMockCache()
	cfg := ResultsCacheConfig{CacheConfig: cache.Config{Cache: c}}
	rc, calls := newEnvelopeResultsCache(t, c, cfg)
	ctx := user.InjectOrgID(context.Background(), "1")

	_, err := rc.Do(ctx, parsedRequest)
	require.NoError(t, err)
	_, err = rc.Do(ctx, parsedRequest)
	require.NoError(t, err)
	require.Equal(t, int32(1), atomic.LoadInt32(calls))

	key := splitter(day).GenerateCacheKey(ctx, "1", parsedRequest)
	raw := rawCacheEntry(t, c, ctx, key)
	require.NotEqual(t, envelopeMagic, string(raw[:len(envelopeMagic)]))

	var legacy tripperware.CachedResponse
	require.NoError(t, proto.Unmarshal(raw, &legacy))
	require.Equal(t, key, legacy.Key)
}

func TestResultsCache_AuthenticatedEnvelope_TamperedBackendEntry(t *testing.T) {
	t.Parallel()

	c := cache.NewMockCache()
	rc, calls := newEnvelopeResultsCache(t, c, envelopeResultsCacheConfig(c, ""))
	ctx := user.InjectOrgID(context.Background(), "1")

	_, err := rc.Do(ctx, parsedRequest)
	require.NoError(t, err)

	key := splitter(day).GenerateCacheKey(ctx, "1", parsedRequest)
	raw := rawCacheEntry(t, c, ctx, key)
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 0xff
	c.Store(ctx, []string{cache.HashKey(key)}, [][]byte{tampered}, time.Hour)

	// Tampering forces a cache miss and an origin re-query, never an error.
	resp, err := rc.Do(ctx, parsedRequest)
	require.NoError(t, err)
	require.Equal(t, parsedResponse, resp)
	require.Equal(t, int32(2), atomic.LoadInt32(calls))
}

func TestResultsCache_AuthenticatedEnvelope_LegacyEntrySelfHeals(t *testing.T) {
	t.Parallel()

	c := cache.NewMockCache()
	rc, calls := newEnvelopeResultsCache(t, c, envelopeResultsCacheConfig(c, ""))
	ctx := user.InjectOrgID(context.Background(), "1")

	// Simulate an entry written by a replica that does not have the envelope enabled.
	key := splitter(day).GenerateCacheKey(ctx, "1", parsedRequest)
	legacyBuf, err := proto.Marshal(&tripperware.CachedResponse{Key: key, Extents: []tripperware.Extent{mkExtent(parsedRequest.GetStart(), parsedRequest.GetEnd())}})
	require.NoError(t, err)
	c.Store(ctx, []string{cache.HashKey(key)}, [][]byte{legacyBuf}, time.Hour)

	resp, err := rc.Do(ctx, parsedRequest)
	require.NoError(t, err)
	require.Equal(t, parsedResponse, resp)
	require.Equal(t, int32(1), atomic.LoadInt32(calls))

	// The miss self-heals: the entry is now an authenticated envelope.
	raw := rawCacheEntry(t, c, ctx, key)
	require.Equal(t, envelopeMagic, string(raw[:len(envelopeMagic)]))
}

func TestResultsCache_AuthenticatedEnvelope_CrossTenantCopy(t *testing.T) {
	t.Parallel()

	c := cache.NewMockCache()
	rc, calls := newEnvelopeResultsCache(t, c, envelopeResultsCacheConfig(c, ""))
	ctx1 := user.InjectOrgID(context.Background(), "1")
	ctx2 := user.InjectOrgID(context.Background(), "2")

	_, err := rc.Do(ctx1, parsedRequest)
	require.NoError(t, err)

	key1 := splitter(day).GenerateCacheKey(ctx1, "1", parsedRequest)
	key2 := splitter(day).GenerateCacheKey(ctx2, "2", parsedRequest)
	tenant1Entry := rawCacheEntry(t, c, ctx1, key1)

	// Attack: copy tenant 1's authenticated entry into tenant 2's key slot.
	c.Store(ctx2, []string{cache.HashKey(key2)}, [][]byte{tenant1Entry}, time.Hour)

	resp, err := rc.Do(ctx2, parsedRequest)
	require.NoError(t, err)
	require.Equal(t, parsedResponse, resp)
	require.Equal(t, int32(2), atomic.LoadInt32(calls), "cross-tenant copy must be a cache miss")

	// After the miss, tenant 2 has its own correctly scoped entry.
	_, err = rc.Do(ctx2, parsedRequest)
	require.NoError(t, err)
	require.Equal(t, int32(2), atomic.LoadInt32(calls))
}

func TestResultsCache_AuthenticatedEnvelope_WrongKeyCopy(t *testing.T) {
	t.Parallel()

	c := cache.NewMockCache()
	rc, calls := newEnvelopeResultsCache(t, c, envelopeResultsCacheConfig(c, ""))
	ctx := user.InjectOrgID(context.Background(), "1")

	_, err := rc.Do(ctx, parsedRequest)
	require.NoError(t, err)

	otherRequest := parsedRequest.WithQuery("up")
	keyOriginal := splitter(day).GenerateCacheKey(ctx, "1", parsedRequest)
	keyOther := splitter(day).GenerateCacheKey(ctx, "1", otherRequest)
	entry := rawCacheEntry(t, c, ctx, keyOriginal)

	// Attack: place the envelope under the wrong (colliding) cache key.
	c.Store(ctx, []string{cache.HashKey(keyOther)}, [][]byte{entry}, time.Hour)

	resp, err := rc.Do(ctx, otherRequest)
	require.NoError(t, err)
	require.Equal(t, parsedResponse, resp)
	require.Equal(t, int32(2), atomic.LoadInt32(calls), "wrong-key entries must be rejected as misses")
}

// storeDroppingCache swallows every write, simulating a failing cache backend.
type storeDroppingCache struct {
	cache.Cache
}

func (s *storeDroppingCache) Store(_ context.Context, _ []string, _ [][]byte, _ time.Duration) {
}

func TestResultsCache_AuthenticatedEnvelope_WriteFailureDoesNotFailQuery(t *testing.T) {
	t.Parallel()

	c := &storeDroppingCache{Cache: cache.NewMockCache()}
	rc, calls := newEnvelopeResultsCache(t, c, envelopeResultsCacheConfig(c, ""))
	ctx := user.InjectOrgID(context.Background(), "1")

	for range 3 {
		resp, err := rc.Do(ctx, parsedRequest)
		require.NoError(t, err)
		require.Equal(t, parsedResponse, resp)
	}
	// Nothing was ever cached, so every request reaches the origin handler,
	// but none of them fails.
	require.Equal(t, int32(3), atomic.LoadInt32(calls))
}

func TestResultsCache_AuthenticatedEnvelope_ReplicaKeyMismatch(t *testing.T) {
	t.Parallel()

	shared := cache.NewMockCache()
	ctx := user.InjectOrgID(context.Background(), "1")

	cfgA := envelopeResultsCacheConfig(shared, "")
	rcA, callsA := newEnvelopeResultsCache(t, shared, cfgA)

	cfgB := envelopeResultsCacheConfig(shared, "")
	cfgB.AuthenticatedEnvelope.SigningKeyID = "key-b"
	cfgB.AuthenticatedEnvelope.SigningKey = flagext.Secret{Value: testSigningKeyB}
	rcB, callsB := newEnvelopeResultsCache(t, shared, cfgB)

	// Replica A writes with key-a.
	_, err := rcA.Do(ctx, parsedRequest)
	require.NoError(t, err)

	// Replica B cannot verify A's entry and falls back to the origin.
	resp, err := rcB.Do(ctx, parsedRequest)
	require.NoError(t, err)
	require.Equal(t, parsedResponse, resp)
	require.Equal(t, int32(1), atomic.LoadInt32(callsB))

	// B overwrites the slot with its own entry, which A cannot verify.
	resp, err = rcA.Do(ctx, parsedRequest)
	require.NoError(t, err)
	require.Equal(t, parsedResponse, resp)
	require.Equal(t, int32(2), atomic.LoadInt32(callsA))
}

func TestResultsCache_AuthenticatedEnvelope_FIFOCacheRoundTrip(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	fifo := cache.NewFifoCache("envelope-fifo", cache.FifoCacheConfig{
		MaxSizeItems: 100,
		Validity:     time.Hour,
	}, reg, log.NewNopLogger())
	require.NotNil(t, fifo)

	rc, calls := newEnvelopeResultsCache(t, fifo, envelopeResultsCacheConfig(fifo, "snappy"))
	ctx := user.InjectOrgID(context.Background(), "1")

	resp, err := rc.Do(ctx, parsedRequest)
	require.NoError(t, err)
	require.Equal(t, parsedResponse, resp)

	resp, err = rc.Do(ctx, parsedRequest)
	require.NoError(t, err)
	require.Equal(t, parsedResponse, resp)
	require.Equal(t, int32(1), atomic.LoadInt32(calls), "real FIFO adapter must serve the second request as a hit")

	key := splitter(day).GenerateCacheKey(ctx, "1", parsedRequest)
	raw := rawCacheEntry(t, fifo, ctx, key)
	require.Equal(t, envelopeMagic, string(raw[:len(envelopeMagic)]))

	tampered := append([]byte(nil), raw...)
	tampered[20] ^= 0xff
	fifo.Store(ctx, []string{cache.HashKey(key)}, [][]byte{tampered}, time.Hour)

	resp, err = rc.Do(ctx, parsedRequest)
	require.NoError(t, err)
	require.Equal(t, parsedResponse, resp)
	require.Equal(t, int32(2), atomic.LoadInt32(calls))
}

func TestResultsCache_AuthenticatedEnvelope_RedisCacheRoundTrip(t *testing.T) {
	t.Parallel()

	redisServer, err := miniredis.Run()
	require.NoError(t, err)
	defer redisServer.Close()

	reg := prometheus.NewRegistry()
	redisClient := cache.NewRedisClient(&cache.RedisConfig{
		Endpoint: redisServer.Addr(),
		Timeout:  5 * time.Second,
	})
	redisCache := cache.NewRedisCache("envelope-redis", redisClient, reg, log.NewNopLogger())
	defer redisCache.Stop()

	rc, calls := newEnvelopeResultsCache(t, redisCache, envelopeResultsCacheConfig(redisCache, "snappy"))
	ctx := user.InjectOrgID(context.Background(), "1")

	resp, err := rc.Do(ctx, parsedRequest)
	require.NoError(t, err)
	require.Equal(t, parsedResponse, resp)

	// Real external cache round trip: the entry survives the Redis boundary.
	resp, err = rc.Do(ctx, parsedRequest)
	require.NoError(t, err)
	require.Equal(t, parsedResponse, resp)
	require.Equal(t, int32(1), atomic.LoadInt32(calls))

	key := splitter(day).GenerateCacheKey(ctx, "1", parsedRequest)
	raw := rawCacheEntry(t, redisCache, ctx, key)
	require.Equal(t, envelopeMagic, string(raw[:len(envelopeMagic)]))
	// Snappy compression is encapsulated inside the authenticated payload.
	header, body, _ := parseEnvelopeFrame(t, raw)
	decodedHeader, err := decodeEnvelopeHeader(header)
	require.NoError(t, err)
	require.Equal(t, envelopeCompressionSnappy, decodedHeader.compression)
	decodedLen, err := snappy.DecodedLen(body)
	require.NoError(t, err)
	require.Positive(t, decodedLen)

	// Tamper with the entry directly in Redis and assert a miss + re-query.
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)/2] ^= 0x01
	redisCache.Store(ctx, []string{cache.HashKey(key)}, [][]byte{tampered}, time.Hour)

	resp, err = rc.Do(ctx, parsedRequest)
	require.NoError(t, err)
	require.Equal(t, parsedResponse, resp)
	require.Equal(t, int32(2), atomic.LoadInt32(calls))
}

// Ensure the extent used in envelope tests carries a serializable response in
// the legacy format, exactly like the production write path.
func TestAuthenticatedEnvelope_ExtentFixtureIsMarshalable(t *testing.T) {
	t.Parallel()

	extent := mkExtent(100, 200)
	resp, err := extentToResponse(extent)
	require.NoError(t, err)
	legacy := convertFromTripperwarePrometheusResponse(resp)
	any, err := types.MarshalAny(legacy)
	require.NoError(t, err)
	require.NotNil(t, any)
}
