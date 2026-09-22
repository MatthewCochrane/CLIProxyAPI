package observability

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const (
	SnapshotPath       = "/v1/routing/snapshot"
	DefaultMaxAccounts = 24
	quotaFreshFor      = 15 * time.Minute
	maxWindowMinutes   = int64(10 * 365 * 24 * 60)
	maxResetAfter      = int64(10 * 365 * 24 * 60 * 60)
)

type FailureCategories struct {
	Authentication uint64 `json:"authentication"`
	RateLimit      uint64 `json:"rateLimit"`
	Timeout        uint64 `json:"timeout"`
	Transport      uint64 `json:"transport"`
	Upstream       uint64 `json:"upstream"`
	Request        uint64 `json:"request"`
	Unavailable    uint64 `json:"unavailable"`
	Unknown        uint64 `json:"unknown"`
}

type Counters struct {
	Requests  uint64            `json:"requests"`
	Success   uint64            `json:"success"`
	Failure   uint64            `json:"failure"`
	Failures  FailureCategories `json:"failureCategories"`
	Hit       uint64            `json:"affinityHit"`
	Miss      uint64            `json:"affinityMiss"`
	Rebind    uint64            `json:"affinityRebind"`
	NoSession uint64            `json:"affinityNoSession"`
}

type EligibilityCounts struct {
	Eligible   int `json:"eligible"`
	Ineligible int `json:"ineligible"`
	Unknown    int `json:"unknown"`
}

type HealthSnapshot struct {
	Status        string            `json:"status"`
	ObserverReady bool              `json:"observerReady"`
	ServiceReady  bool              `json:"serviceReady"`
	AccountCount  int               `json:"accountCount"`
	Eligibility   EligibilityCounts `json:"eligibility"`
}

type CooldownSnapshot struct {
	Category  string     `json:"category"`
	ExpiresAt *time.Time `json:"expiresAt"`
}

type QuotaWindow struct {
	Category      string     `json:"category"`
	UsedPercent   *float64   `json:"usedPercent"`
	WindowMinutes *int64     `json:"windowMinutes"`
	ResetsAt      *time.Time `json:"resetsAt"`
}

type QuotaSnapshot struct {
	Status     string        `json:"status"`
	ObservedAt *time.Time    `json:"observedAt"`
	Windows    []QuotaWindow `json:"windows"`
}

type AccountSnapshot struct {
	Account     string           `json:"account"`
	Eligibility string           `json:"eligibility"`
	Cooldown    CooldownSnapshot `json:"cooldown"`
	Quota       QuotaSnapshot    `json:"quota"`
	Counters    Counters         `json:"counters"`
}

type Snapshot struct {
	SchemaVersion int               `json:"schemaVersion"`
	GeneratedAt   time.Time         `json:"generatedAt"`
	Health        HealthSnapshot    `json:"health"`
	Totals        Counters          `json:"totals"`
	Accounts      []AccountSnapshot `json:"accounts"`
}

type eligibilityState struct {
	Disabled         bool
	AccessExpired    bool
	KnownStatus      bool
	Unavailable      bool
	QuotaExceeded    bool
	CredentialQuota  bool
	HasModelStates   bool
	NextRetryAfter   time.Time
	NextQuotaRecover time.Time
}

// Observer aggregates only fixed outcomes under keyed opaque account handles.
type Observer struct {
	sourcesMu             sync.RWMutex
	mu                    sync.Mutex
	hmacKey               []byte
	maxAccounts           int
	totals                Counters
	counters              map[accountCounterKey]Counters
	affinityCounters      map[accountCounterKey]Counters
	selectedMemberships   map[accountCounterKey]struct{}
	membershipGeneration  uint64
	authSource            func() []*coreauth.Auth
	authMembershipSource  func(string) (uint64, uint64, bool)
	authMembershipsSource func() (uint64, []coreauth.AuthMembership)
}

type accountCounterKey struct {
	handle            string
	registrationEpoch uint64
}

func NewObserver(hmacKey []byte, maxAccounts int) *Observer {
	if maxAccounts <= 0 || maxAccounts > DefaultMaxAccounts {
		maxAccounts = DefaultMaxAccounts
	}
	return &Observer{
		hmacKey:             append([]byte(nil), hmacKey...),
		maxAccounts:         maxAccounts,
		counters:            make(map[accountCounterKey]Counters, maxAccounts),
		affinityCounters:    make(map[accountCounterKey]Counters, maxAccounts),
		selectedMemberships: make(map[accountCounterKey]struct{}, maxAccounts),
	}
}

// SetAuthSource installs the authoritative source used for snapshot projection.
// The source must return detached auth snapshots and may be replaced at runtime.
func (o *Observer) SetAuthSource(source func() []*coreauth.Auth) {
	if o == nil {
		return
	}
	o.sourcesMu.Lock()
	o.authSource = source
	o.sourcesMu.Unlock()
}

// SetAuthSources installs authoritative full and credential-free membership sources.
func (o *Observer) SetAuthSources(
	authSource func() []*coreauth.Auth,
	authMembershipSource func(string) (uint64, uint64, bool),
	authMembershipsSource func() (uint64, []coreauth.AuthMembership),
) {
	if o == nil {
		return
	}
	// Source replacement and cache invalidation use the same lock order as
	// event processing: observer state, then source configuration.
	o.mu.Lock()
	o.sourcesMu.Lock()
	o.authSource = authSource
	o.authMembershipSource = authMembershipSource
	o.authMembershipsSource = authMembershipsSource
	o.sourcesMu.Unlock()
	o.membershipGeneration = 0
	o.selectedMemberships = make(map[accountCounterKey]struct{}, o.maxAccounts)
	o.pruneCounterMapsLocked(o.selectedMemberships)
	o.mu.Unlock()
}

func (o *Observer) accountHandle(authID string) string {
	mac := hmac.New(sha256.New, o.hmacKey)
	_, _ = mac.Write([]byte(authID))
	return "acct_" + hex.EncodeToString(mac.Sum(nil))
}

func (o *Observer) sources() (
	func() []*coreauth.Auth,
	func(string) (uint64, uint64, bool),
	func() (uint64, []coreauth.AuthMembership),
) {
	o.sourcesMu.RLock()
	defer o.sourcesMu.RUnlock()
	return o.authSource, o.authMembershipSource, o.authMembershipsSource
}

func (o *Observer) sourceAccounts(source func() []*coreauth.Auth) ([]sourceAccount, bool) {
	if source == nil {
		return nil, false
	}
	return o.selectAccounts(source()), true
}

func (o *Observer) selectAccounts(auths []*coreauth.Auth) []sourceAccount {
	byHandle := make(map[string]*coreauth.Auth, len(auths))
	for _, auth := range auths {
		if auth == nil || auth.ID == "" {
			continue
		}
		handle := o.accountHandle(auth.ID)
		if _, exists := byHandle[handle]; !exists {
			byHandle[handle] = auth
		}
	}
	selected := make([]sourceAccount, 0, len(byHandle))
	for handle, auth := range byHandle {
		selected = append(selected, sourceAccount{handle: handle, auth: auth})
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].handle < selected[j].handle })
	if len(selected) > o.maxAccounts {
		selected = selected[:o.maxAccounts]
	}
	return selected
}

type sourceAccount struct {
	handle string
	auth   *coreauth.Auth
}

func (o *Observer) update(authID string, update func(*Counters)) {
	if o == nil || authID == "" {
		return
	}
	o.recordCurrent(authID, 0, false, o.counters, update)
}

func (o *Observer) OnAuthRegistered(context.Context, *coreauth.Auth) {}

func (o *Observer) OnAuthUpdated(context.Context, *coreauth.Auth) {}

func (o *Observer) OnResult(_ context.Context, result coreauth.Result) {
	category := failureCategory(result)
	o.update(result.AuthID, func(c *Counters) {
		c.Requests++
		if result.Success {
			c.Success++
			return
		}
		c.Failure++
		incrementFailure(&c.Failures, category)
	})
}

func failureCategory(result coreauth.Result) string {
	if result.Success {
		return "none"
	}
	if result.Error == nil {
		return "unknown"
	}
	switch result.Error.Code {
	case coreauth.ErrorCodeRequestScoped:
		return "request"
	case coreauth.ErrorCodeTransientTransport, coreauth.ErrorCodeConnectionLifecycle:
		return "transport"
	}
	switch status := result.Error.HTTPStatus; {
	case status == http.StatusUnauthorized || status == http.StatusPaymentRequired || status == http.StatusForbidden:
		return "authentication"
	case status == http.StatusTooManyRequests:
		return "rate_limit"
	case status == http.StatusRequestTimeout || status == http.StatusGatewayTimeout:
		return "timeout"
	case status == http.StatusNotFound || status == http.StatusServiceUnavailable:
		return "unavailable"
	case status >= 500 && status <= 599:
		return "upstream"
	default:
		return "unknown"
	}
}

func incrementFailure(categories *FailureCategories, category string) {
	switch category {
	case "authentication":
		categories.Authentication++
	case "rate_limit":
		categories.RateLimit++
	case "timeout":
		categories.Timeout++
	case "transport":
		categories.Transport++
	case "upstream":
		categories.Upstream++
	case "request":
		categories.Request++
	case "unavailable":
		categories.Unavailable++
	default:
		categories.Unknown++
	}
}

func (o *Observer) ObserveAffinity(event coreauth.AffinityEvent, authID string) {
	increment := affinityIncrement(event)
	if o == nil || authID == "" || increment == nil {
		return
	}
	o.mu.Lock()
	increment(&o.totals)
	o.mu.Unlock()
}

// ObserveAffinityVersioned attributes an event to one exact auth incarnation.
// The raw auth ID is transformed before acquiring observer state locks.
func (o *Observer) ObserveAffinityVersioned(event coreauth.AffinityEvent, authID string, registrationEpoch uint64) {
	increment := affinityIncrement(event)
	if o == nil || authID == "" || increment == nil {
		return
	}
	o.recordCurrent(authID, registrationEpoch, true, o.affinityCounters, increment)
}

func affinityIncrement(event coreauth.AffinityEvent) func(*Counters) {
	switch event {
	case coreauth.AffinityEventHit:
		return func(c *Counters) { c.Hit++ }
	case coreauth.AffinityEventMiss:
		return func(c *Counters) { c.Miss++ }
	case coreauth.AffinityEventRebind:
		return func(c *Counters) { c.Rebind++ }
	case coreauth.AffinityEventNoSession:
		return func(c *Counters) { c.NoSession++ }
	}
	return nil
}

func (o *Observer) recordCurrent(
	authID string,
	registrationEpoch uint64,
	requireExactEpoch bool,
	counters map[accountCounterKey]Counters,
	update func(*Counters),
) {
	handle := o.accountHandle(authID)
	o.mu.Lock()
	defer o.mu.Unlock()
	update(&o.totals)
	_, membershipSource, membershipsSource := o.sources()
	if membershipSource == nil || membershipsSource == nil {
		return
	}

	// The observer lock is acquired before either Manager RLock source. Manager
	// hooks never run while its auth lock is held, so this is the sole lock order.
	for attempts := 0; attempts < 3; attempts++ {
		generation, currentEpoch, current := membershipSource(authID)
		if o.membershipGeneration != generation {
			snapshotGeneration, memberships := membershipsSource()
			o.rebuildMembershipCacheLocked(snapshotGeneration, memberships)
			if snapshotGeneration != generation {
				continue
			}
		}
		if o.membershipGeneration != generation || !current || requireExactEpoch && currentEpoch != registrationEpoch {
			return
		}
		key := accountCounterKey{handle: handle, registrationEpoch: currentEpoch}
		if _, selected := o.selectedMemberships[key]; !selected {
			return
		}
		account := counters[key]
		update(&account)
		counters[key] = account
		return
	}
}

func (o *Observer) rebuildMembershipCacheLocked(generation uint64, memberships []coreauth.AuthMembership) {
	selected := o.selectMemberships(memberships)
	o.membershipGeneration = generation
	o.selectedMemberships = selected
	o.pruneCounterMapsLocked(selected)
}

func (o *Observer) selectMemberships(memberships []coreauth.AuthMembership) map[accountCounterKey]struct{} {
	keys := make([]accountCounterKey, 0, len(memberships))
	seen := make(map[accountCounterKey]struct{}, len(memberships))
	for _, membership := range memberships {
		if membership.ID == "" {
			continue
		}
		key := accountCounterKey{handle: o.accountHandle(membership.ID), registrationEpoch: membership.RegistrationEpoch}
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].handle != keys[j].handle {
			return keys[i].handle < keys[j].handle
		}
		return keys[i].registrationEpoch < keys[j].registrationEpoch
	})
	if len(keys) > o.maxAccounts {
		keys = keys[:o.maxAccounts]
	}
	selected := make(map[accountCounterKey]struct{}, len(keys))
	for _, key := range keys {
		selected[key] = struct{}{}
	}
	return selected
}

func (o *Observer) selectCachedAccounts(auths []*coreauth.Auth) []sourceAccount {
	selected := make([]sourceAccount, 0, len(o.selectedMemberships))
	seen := make(map[string]struct{}, len(o.selectedMemberships))
	for _, auth := range auths {
		if auth == nil || auth.ID == "" {
			continue
		}
		handle := o.accountHandle(auth.ID)
		key := accountCounterKey{handle: handle, registrationEpoch: auth.RegistrationEpoch}
		if _, current := o.selectedMemberships[key]; !current {
			continue
		}
		if _, exists := seen[handle]; exists {
			continue
		}
		seen[handle] = struct{}{}
		selected = append(selected, sourceAccount{handle: handle, auth: auth})
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].handle < selected[j].handle })
	return selected
}

func (o *Observer) pruneCounterMapsLocked(current map[accountCounterKey]struct{}) {
	for key := range o.counters {
		if _, keep := current[key]; !keep {
			delete(o.counters, key)
		}
	}
	for key := range o.affinityCounters {
		if _, keep := current[key]; !keep {
			delete(o.affinityCounters, key)
		}
	}
}

func (o *Observer) Snapshot(now time.Time) Snapshot {
	snapshot := Snapshot{
		SchemaVersion: 2,
		GeneratedAt:   now.UTC(),
		Health: HealthSnapshot{
			Status:        "unavailable",
			ObserverReady: o != nil,
		},
		Accounts: []AccountSnapshot{},
	}
	if o == nil {
		return snapshot
	}
	authSource, _, membershipsSource := o.sources()
	// Hold o.mu across the authoritative read so a route event that already
	// completed its O(1) manager lookup is applied after, never pruned by, this
	// snapshot. Manager observer callbacks run only after its auth lock is released.
	o.mu.Lock()
	defer o.mu.Unlock()
	var selected []sourceAccount
	available := authSource != nil
	if available && membershipsSource != nil {
		// A stable generation on both sides of the full read proves that its
		// detailed clones correspond to the selected lightweight membership.
		for attempts := 0; attempts < 3; attempts++ {
			generationBefore, _ := membershipsSource()
			auths := authSource()
			generationAfter, memberships := membershipsSource()
			o.rebuildMembershipCacheLocked(generationAfter, memberships)
			if generationBefore == generationAfter {
				selected = o.selectCachedAccounts(auths)
				break
			}
		}
	} else if available {
		selected = o.selectAccounts(authSource())
		current := make(map[accountCounterKey]struct{}, len(selected))
		for _, account := range selected {
			current[accountCounterKey{handle: account.handle, registrationEpoch: account.auth.RegistrationEpoch}] = struct{}{}
		}
		o.pruneCounterMapsLocked(current)
	}
	if !available {
		snapshot.Totals = o.totals
		snapshot.Health.ObserverReady = false
		return snapshot
	}
	snapshot.Totals = o.totals
	joinedCounters := make(map[string]Counters, len(selected))
	for _, account := range selected {
		key := accountCounterKey{handle: account.handle, registrationEpoch: account.auth.RegistrationEpoch}
		counters := o.counters[key]
		affinity := o.affinityCounters[key]
		counters.Hit += affinity.Hit
		counters.Miss += affinity.Miss
		counters.Rebind += affinity.Rebind
		counters.NoSession += affinity.NoSession
		joinedCounters[account.handle] = counters
	}

	for _, account := range selected {
		snapshot.Accounts = append(snapshot.Accounts, AccountSnapshot{
			Account: account.handle, Eligibility: eligibility(sanitizedEligibility(account.auth, now), now),
			Cooldown: cooldown(account.auth, now), Quota: quota(account.auth.Quota, now), Counters: joinedCounters[account.handle],
		})
	}

	snapshot.Health.AccountCount = len(snapshot.Accounts)
	for _, account := range snapshot.Accounts {
		switch account.Eligibility {
		case "eligible":
			snapshot.Health.Eligibility.Eligible++
		case "ineligible":
			snapshot.Health.Eligibility.Ineligible++
		default:
			snapshot.Health.Eligibility.Unknown++
		}
	}
	snapshot.Health.ServiceReady = snapshot.Health.Eligibility.Eligible > 0
	switch {
	case !snapshot.Health.ServiceReady:
		snapshot.Health.Status = "unavailable"
	case snapshot.Health.Eligibility.Ineligible > 0 || snapshot.Health.Eligibility.Unknown > 0:
		snapshot.Health.Status = "degraded"
	default:
		snapshot.Health.Status = "ready"
	}
	return snapshot
}

func sanitizedEligibility(auth *coreauth.Auth, now time.Time) eligibilityState {
	state := eligibilityState{
		Disabled:         auth.Disabled || auth.Status == coreauth.StatusDisabled,
		KnownStatus:      auth.Status != "" && auth.Status != coreauth.StatusUnknown,
		Unavailable:      auth.Unavailable,
		QuotaExceeded:    auth.Quota.Exceeded,
		CredentialQuota:  auth.Quota.Reason == "credential_quota",
		HasModelStates:   len(auth.ModelStates) > 0,
		NextRetryAfter:   auth.NextRetryAfter,
		NextQuotaRecover: auth.Quota.NextRecoverAt,
	}
	if expiry, ok := auth.AccessTokenExpirationTime(); ok && !expiry.IsZero() && !expiry.After(now) {
		state.AccessExpired = true
	}
	return state
}

func eligibility(state eligibilityState, now time.Time) string {
	if state.Disabled || state.AccessExpired {
		return "ineligible"
	}
	quotaExceeded := state.QuotaExceeded
	if state.HasModelStates && !state.CredentialQuota && !state.Unavailable {
		quotaExceeded = false
	}
	if state.Unavailable || quotaExceeded {
		hasRecoveryTime := !state.NextRetryAfter.IsZero() || !state.NextQuotaRecover.IsZero()
		if state.NextRetryAfter.After(now) || state.NextQuotaRecover.After(now) || !hasRecoveryTime {
			return "ineligible"
		}
		return "eligible"
	}
	if state.KnownStatus {
		return "eligible"
	}
	return "unknown"
}

func cooldown(auth *coreauth.Auth, now time.Time) CooldownSnapshot {
	best := CooldownSnapshot{Category: "none"}
	considerCooldown(&best, auth.NextRetryAfter, cooldownCategory(auth.LastError, auth.Quota), now)
	considerCooldown(&best, auth.Quota.NextRecoverAt, quotaCooldownCategory(auth.Quota), now)
	for _, state := range auth.ModelStates {
		if state == nil {
			continue
		}
		considerCooldown(&best, state.NextRetryAfter, cooldownCategory(state.LastError, state.Quota), now)
		considerCooldown(&best, state.Quota.NextRecoverAt, quotaCooldownCategory(state.Quota), now)
	}
	return best
}

func considerCooldown(best *CooldownSnapshot, expiry time.Time, category string, now time.Time) {
	if expiry.IsZero() || !expiry.After(now) {
		return
	}
	if best.ExpiresAt == nil || cooldownPriority(category) > cooldownPriority(best.Category) ||
		(cooldownPriority(category) == cooldownPriority(best.Category) && expiry.After(*best.ExpiresAt)) {
		best.Category = category
		best.ExpiresAt = utcTime(expiry)
	}
}

func cooldownPriority(category string) int {
	switch category {
	case "quota":
		return 5
	case "authentication":
		return 4
	case "model":
		return 3
	case "transient":
		return 2
	case "upstream":
		return 1
	default:
		return 0
	}
}

func cooldownCategory(err *coreauth.Error, quota coreauth.QuotaState) string {
	if quota.Exceeded {
		return "quota"
	}
	if err == nil {
		return "unknown"
	}
	switch err.Code {
	case coreauth.ErrorCodeTransientTransport, coreauth.ErrorCodeConnectionLifecycle, coreauth.ErrorCodeForceCooldown:
		return "transient"
	}
	switch status := err.HTTPStatus; {
	case status == http.StatusUnauthorized || status == http.StatusPaymentRequired || status == http.StatusForbidden:
		return "authentication"
	case status == http.StatusTooManyRequests:
		return "quota"
	case status == http.StatusNotFound:
		return "model"
	case status >= 500 && status <= 599:
		return "upstream"
	default:
		return "unknown"
	}
}

func quotaCooldownCategory(quota coreauth.QuotaState) string {
	if quota.Exceeded {
		return "quota"
	}
	return "unknown"
}

func quota(state coreauth.QuotaState, now time.Time) QuotaSnapshot {
	snapshot := QuotaSnapshot{Status: "unavailable", Windows: []QuotaWindow{}}
	if state.ObservedAt.IsZero() || len(state.Signals) == 0 {
		return snapshot
	}
	for _, spec := range []struct {
		category, used, minutes, resetAt, resetAfter string
		fraction                                     bool
	}{
		{"primary", "X-Codex-Primary-Used-Percent", "X-Codex-Primary-Window-Minutes", "X-Codex-Primary-Reset-At", "X-Codex-Primary-Reset-After-Seconds", false},
		{"secondary", "X-Codex-Secondary-Used-Percent", "X-Codex-Secondary-Window-Minutes", "X-Codex-Secondary-Reset-At", "X-Codex-Secondary-Reset-After-Seconds", false},
		{"five_hour", "Anthropic-Ratelimit-Unified-5h-Utilization", "", "Anthropic-Ratelimit-Unified-5h-Reset", "", true},
		{"seven_day", "Anthropic-Ratelimit-Unified-7d-Utilization", "", "Anthropic-Ratelimit-Unified-7d-Reset", "", true},
	} {
		window, ok := quotaWindow(state, spec.category, spec.used, spec.minutes, spec.resetAt, spec.resetAfter, spec.fraction)
		if ok {
			snapshot.Windows = append(snapshot.Windows, window)
		}
	}
	if len(snapshot.Windows) == 0 {
		return snapshot
	}
	snapshot.ObservedAt = utcTime(state.ObservedAt)
	age := now.Sub(state.ObservedAt)
	if age >= 0 && age <= quotaFreshFor {
		snapshot.Status = "fresh"
	} else {
		snapshot.Status = "stale"
	}
	return snapshot
}

func quotaWindow(state coreauth.QuotaState, category, usedKey, minutesKey, resetAtKey, resetAfterKey string, fraction bool) (QuotaWindow, bool) {
	window := QuotaWindow{Category: category}
	if value, ok := parseFloat(state.Signals[usedKey]); ok {
		if fraction {
			value *= 100
		}
		if value >= 0 && value <= 100 {
			window.UsedPercent = &value
		}
	}
	if minutesKey != "" {
		if value, ok := parseBoundedPositiveInt(state.Signals[minutesKey], maxWindowMinutes); ok {
			window.WindowMinutes = &value
		}
	}
	if value, ok := parseBoundedPositiveInt(state.Signals[resetAtKey], time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC).Unix()); ok {
		reset := time.Unix(value, 0).UTC()
		if reset.Year() >= 2000 {
			window.ResetsAt = &reset
		}
	} else if value, ok = parseBoundedPositiveInt(state.Signals[resetAfterKey], maxResetAfter); ok {
		reset := state.ObservedAt.Add(time.Duration(value) * time.Second).UTC()
		window.ResetsAt = &reset
	}
	return window, window.UsedPercent != nil || window.WindowMinutes != nil || window.ResetsAt != nil
}

func parseFloat(value string) (float64, bool) {
	parsed, err := strconv.ParseFloat(value, 64)
	return parsed, err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0)
}

func parseBoundedPositiveInt(value string, maximum int64) (int64, bool) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	return parsed, err == nil && parsed > 0 && parsed <= maximum
}

func utcTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	utc := value.UTC()
	return &utc
}

func (o *Observer) Handler(token string) http.Handler {
	expected := sha256.Sum256([]byte("Bearer " + token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actual := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeFixedJSON(w, http.StatusUnauthorized, []byte(`{"error":"unauthorized"}`))
			return
		}
		if r.URL.Path != SnapshotPath {
			writeFixedJSON(w, http.StatusNotFound, []byte(`{"error":"not_found"}`))
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeFixedJSON(w, http.StatusMethodNotAllowed, []byte(`{"error":"method_not_allowed"}`))
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			writeFixedJSON(w, http.StatusBadRequest, []byte(`{"error":"query_not_allowed"}`))
			return
		}
		body, err := json.Marshal(o.Snapshot(time.Now()))
		if err != nil {
			writeFixedJSON(w, http.StatusServiceUnavailable, []byte(`{"error":"unavailable"}`))
			return
		}
		writeFixedJSON(w, http.StatusOK, body)
	})
}

func writeFixedJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
