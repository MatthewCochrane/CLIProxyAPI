package observability

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const (
	testToken = "0123456789abcdef0123456789abcdef"
	testKey   = "abcdef0123456789abcdef0123456789"
)

type mutableAuthSource struct {
	mu         sync.RWMutex
	auths      []*coreauth.Auth
	generation uint64
}

func (s *mutableAuthSource) set(auths ...*coreauth.Auth) {
	s.mu.Lock()
	s.auths = cloneAuths(auths)
	s.generation++
	if s.generation == 0 {
		s.generation = 1
	}
	s.mu.Unlock()
}

func (s *mutableAuthSource) list() []*coreauth.Auth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneAuths(s.auths)
}

func (s *mutableAuthSource) membership(id string) (uint64, uint64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, auth := range s.auths {
		if auth != nil && auth.ID == id {
			return s.generation, auth.RegistrationEpoch, true
		}
	}
	return s.generation, 0, false
}

func (s *mutableAuthSource) memberships() (uint64, []coreauth.AuthMembership) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	memberships := make([]coreauth.AuthMembership, 0, len(s.auths))
	for _, auth := range s.auths {
		if auth != nil {
			memberships = append(memberships, coreauth.AuthMembership{ID: auth.ID, RegistrationEpoch: auth.RegistrationEpoch})
		}
	}
	return s.generation, memberships
}

func cloneAuths(auths []*coreauth.Auth) []*coreauth.Auth {
	clones := make([]*coreauth.Auth, 0, len(auths))
	for _, auth := range auths {
		if auth != nil {
			clones = append(clones, auth.Clone())
		}
	}
	return clones
}

func newSourceObserver(maxAccounts int, source *mutableAuthSource) *Observer {
	observer := NewObserver([]byte(testKey), maxAccounts)
	observer.SetAuthSources(source.list, source.membership, source.memberships)
	return observer
}

func TestObserverUnavailableWithoutAuthSource(t *testing.T) {
	observer := NewObserver([]byte(testKey), DefaultMaxAccounts)
	observer.OnResult(context.Background(), coreauth.Result{AuthID: "home-only", Success: true})
	snapshot := observer.Snapshot(time.Now())
	if snapshot.Health.Status != "unavailable" || snapshot.Health.ObserverReady || snapshot.Health.ServiceReady || len(snapshot.Accounts) != 0 {
		t.Fatalf("health without source = %#v", snapshot.Health)
	}
	if snapshot.Totals.Requests != 1 || snapshot.Totals.Success != 1 {
		t.Fatalf("totals without source = %#v", snapshot.Totals)
	}
}

func TestObserverJoinsOpaqueCountersToAuthoritativeAccounts(t *testing.T) {
	source := &mutableAuthSource{}
	rawID := "raw-auth-id-user@example.test"
	source.set(
		&coreauth.Auth{ID: rawID, Status: coreauth.StatusActive, RegistrationEpoch: 7},
		&coreauth.Auth{ID: "second", Status: coreauth.StatusActive},
	)
	observer := newSourceObserver(2, source)
	observer.OnResult(context.Background(), coreauth.Result{
		AuthID: rawID, Error: &coreauth.Error{Code: "provider-secret", Message: "raw upstream failure"},
		Provider: "sensitive-provider", Model: "sensitive-model",
	})
	observer.OnResult(context.Background(), coreauth.Result{AuthID: rawID, Success: true})
	observer.ObserveAffinityVersioned(coreauth.AffinityEventMiss, rawID, 7)
	observer.ObserveAffinityVersioned(coreauth.AffinityEventHit, rawID, 7)
	observer.ObserveAffinityVersioned(coreauth.AffinityEventRebind, rawID, 7)
	observer.ObserveAffinityVersioned(coreauth.AffinityEventNoSession, rawID, 7)
	observer.OnResult(context.Background(), coreauth.Result{AuthID: "home-only", Success: true})

	snapshot := observer.Snapshot(time.Unix(123, 0))
	if snapshot.SchemaVersion != 2 || len(snapshot.Accounts) != 2 {
		t.Fatalf("snapshot schema/accounts = %d/%d, want 2/2", snapshot.SchemaVersion, len(snapshot.Accounts))
	}
	if snapshot.Totals != (Counters{Requests: 3, Success: 2, Failure: 1, Failures: FailureCategories{Unknown: 1}, Hit: 1, Miss: 1, Rebind: 1, NoSession: 1}) {
		t.Fatalf("totals = %#v", snapshot.Totals)
	}
	wantHandle := hmacHandle(testKey, rawID)
	found := false
	for _, account := range snapshot.Accounts {
		if strings.Contains(account.Account, rawID) || !strings.HasPrefix(account.Account, "acct_") {
			t.Fatalf("unsafe account handle %q", account.Account)
		}
		if account.Account == wantHandle {
			found = true
			want := Counters{Requests: 2, Success: 1, Failure: 1, Failures: FailureCategories{Unknown: 1}, Hit: 1, Miss: 1, Rebind: 1, NoSession: 1}
			if account.Counters != want {
				t.Fatalf("account counters = %#v, want %#v", account.Counters, want)
			}
		}
	}
	if !found {
		t.Fatalf("stable HMAC handle %q not found", wantHandle)
	}
}

func TestObserverConcurrentUpdates(t *testing.T) {
	source := &mutableAuthSource{}
	source.set(&coreauth.Auth{ID: "account", Status: coreauth.StatusActive, RegistrationEpoch: 9})
	observer := newSourceObserver(4, source)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			observer.OnResult(context.Background(), coreauth.Result{AuthID: "account", Success: true})
			observer.ObserveAffinityVersioned(coreauth.AffinityEventHit, "account", 9)
			_ = observer.Snapshot(time.Now())
		}()
	}
	wg.Wait()
	got := observer.Snapshot(time.Now())
	if got.Totals.Success != 100 || got.Totals.Hit != 100 || got.Accounts[0].Counters.Success != 100 || got.Accounts[0].Counters.Hit != 100 {
		t.Fatalf("concurrent snapshot = %#v", got)
	}
}

func TestObserverCounterAdmissionUsesAuthoritativeMembership(t *testing.T) {
	source := &mutableAuthSource{}
	source.set(&coreauth.Auth{ID: "active", Status: coreauth.StatusActive})
	observer := newSourceObserver(1, source)

	observer.OnResult(context.Background(), coreauth.Result{AuthID: "home-only", Success: true})
	observer.OnResult(context.Background(), coreauth.Result{AuthID: "removed", Success: true})
	observer.OnResult(context.Background(), coreauth.Result{AuthID: "active", Success: true})

	snapshot := observer.Snapshot(time.Now())
	if snapshot.Totals.Requests != 3 || snapshot.Totals.Success != 3 {
		t.Fatalf("aggregate totals = %#v", snapshot.Totals)
	}
	if len(snapshot.Accounts) != 1 || snapshot.Accounts[0].Account != hmacHandle(testKey, "active") {
		t.Fatalf("authoritative accounts = %#v", snapshot.Accounts)
	}
	if snapshot.Accounts[0].Counters.Requests != 1 || snapshot.Accounts[0].Counters.Success != 1 {
		t.Fatalf("active counters = %#v", snapshot.Accounts[0].Counters)
	}
	if len(observer.counters) != 1 {
		t.Fatalf("counter entries = %d, want 1", len(observer.counters))
	}
}

func TestObserverSnapshotCannotPruneNewActiveResultFromStaleSource(t *testing.T) {
	source := &mutableAuthSource{}
	source.set(&coreauth.Auth{ID: "old", Status: coreauth.StatusActive})
	observer := NewObserver([]byte(testKey), 2)
	captured := make(chan struct{})
	release := make(chan struct{})
	var calls int
	var callsMu sync.Mutex
	observer.SetAuthSources(func() []*coreauth.Auth {
		auths := source.list()
		callsMu.Lock()
		calls++
		call := calls
		callsMu.Unlock()
		if call == 1 {
			close(captured)
			<-release
		}
		return auths
	}, source.membership, source.memberships)

	snapshotDone := make(chan struct{})
	go func() {
		_ = observer.Snapshot(time.Now())
		close(snapshotDone)
	}()
	select {
	case <-captured:
	case <-time.After(2 * time.Second):
		t.Fatal("snapshot did not capture source")
	}
	source.set(&coreauth.Auth{ID: "new", Status: coreauth.StatusActive})
	resultDone := make(chan struct{})
	go func() {
		observer.OnResult(context.Background(), coreauth.Result{AuthID: "new", Success: true})
		close(resultDone)
	}()
	close(release)
	for name, done := range map[string]<-chan struct{}{"snapshot": snapshotDone, "result": resultDone} {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s did not finish", name)
		}
	}

	snapshot := observer.Snapshot(time.Now())
	if len(snapshot.Accounts) != 1 || snapshot.Accounts[0].Account != hmacHandle(testKey, "new") || snapshot.Accounts[0].Counters.Success != 1 {
		t.Fatalf("new active result was pruned: %#v", snapshot.Accounts)
	}
}

func TestObserverSnapshotCannotPruneNewAffinityFromStaleSource(t *testing.T) {
	source := &mutableAuthSource{}
	source.set(&coreauth.Auth{ID: "same-id", Status: coreauth.StatusActive, RegistrationEpoch: 1})
	observer := newSourceObserver(1, source)
	captured := make(chan struct{})
	release := make(chan struct{})
	var calls int
	var callsMu sync.Mutex
	observer.SetAuthSource(func() []*coreauth.Auth {
		auths := source.list()
		callsMu.Lock()
		calls++
		call := calls
		callsMu.Unlock()
		if call == 1 {
			close(captured)
			<-release
		}
		return auths
	})

	snapshotDone := make(chan struct{})
	go func() {
		_ = observer.Snapshot(time.Now())
		close(snapshotDone)
	}()
	select {
	case <-captured:
	case <-time.After(2 * time.Second):
		t.Fatal("snapshot did not capture epoch 1")
	}
	source.set(&coreauth.Auth{ID: "same-id", Status: coreauth.StatusActive, RegistrationEpoch: 2})
	affinityDone := make(chan struct{})
	go func() {
		observer.ObserveAffinityVersioned(coreauth.AffinityEventRebind, "same-id", 2)
		close(affinityDone)
	}()
	select {
	case <-affinityDone:
		t.Fatal("affinity event bypassed serialized source refresh")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	for name, done := range map[string]<-chan struct{}{"snapshot": snapshotDone, "affinity": affinityDone} {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s did not finish", name)
		}
	}

	snapshot := observer.Snapshot(time.Now())
	if len(snapshot.Accounts) != 1 || snapshot.Accounts[0].Counters.Rebind != 1 {
		t.Fatalf("epoch 2 affinity event was pruned: %#v", snapshot.Accounts)
	}
}

func TestObserverOrdinaryAffinityUsesOnlyExactMembershipSource(t *testing.T) {
	observer := NewObserver([]byte(testKey), 1)
	releaseSource := make(chan struct{})
	defer close(releaseSource)
	var callsMu sync.Mutex
	fullCalls := 0
	exactCalls := 0
	membershipCalls := 0
	observer.SetAuthSources(func() []*coreauth.Auth {
		callsMu.Lock()
		fullCalls++
		callsMu.Unlock()
		<-releaseSource
		return []*coreauth.Auth{{ID: "active", Status: coreauth.StatusActive, RegistrationEpoch: 1}}
	}, func(id string) (uint64, uint64, bool) {
		callsMu.Lock()
		exactCalls++
		callsMu.Unlock()
		return 1, 1, id == "active"
	}, func() (uint64, []coreauth.AuthMembership) {
		callsMu.Lock()
		membershipCalls++
		callsMu.Unlock()
		return 1, []coreauth.AuthMembership{{ID: "active", RegistrationEpoch: 1}}
	})

	const events = 32
	var wg sync.WaitGroup
	wg.Add(events)
	for i := 0; i < events; i++ {
		go func() {
			defer wg.Done()
			observer.ObserveAffinityVersioned(coreauth.AffinityEventHit, "active", 1)
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ordinary affinity events waited for the full auth source")
	}
	observer.OnResult(context.Background(), coreauth.Result{AuthID: "active", Success: true})
	callsMu.Lock()
	defer callsMu.Unlock()
	if fullCalls != 0 || membershipCalls != 1 || exactCalls != events+1 {
		t.Fatalf("source calls full/exact/memberships = %d/%d/%d, want 0/%d/1", fullCalls, exactCalls, membershipCalls, events+1)
	}
}

func TestObserverReusesMembershipCacheForRepeatedOverflowEvents(t *testing.T) {
	source := &mutableAuthSource{}
	source.set(
		&coreauth.Auth{ID: "one", Status: coreauth.StatusActive, RegistrationEpoch: 1},
		&coreauth.Auth{ID: "two", Status: coreauth.StatusActive, RegistrationEpoch: 1},
		&coreauth.Auth{ID: "three", Status: coreauth.StatusActive, RegistrationEpoch: 1},
	)
	observer := NewObserver([]byte(testKey), 2)
	var mu sync.Mutex
	membershipCalls := 0
	observer.SetAuthSources(source.list, source.membership, func() (uint64, []coreauth.AuthMembership) {
		mu.Lock()
		membershipCalls++
		mu.Unlock()
		return source.memberships()
	})

	for i := 0; i < 100; i++ {
		observer.ObserveAffinityVersioned(coreauth.AffinityEventHit, "one", 1)
		observer.ObserveAffinityVersioned(coreauth.AffinityEventHit, "two", 1)
		observer.ObserveAffinityVersioned(coreauth.AffinityEventHit, "three", 1)
	}
	mu.Lock()
	steadyCalls := membershipCalls
	mu.Unlock()
	if steadyCalls != 1 {
		t.Fatalf("lightweight snapshot calls for repeated overflow = %d, want 1", steadyCalls)
	}
	if len(observer.affinityCounters) != 2 {
		t.Fatalf("affinity counters = %d, want hard cap 2", len(observer.affinityCounters))
	}
}

func TestSessionAffinityFirstPickCountsExactStartupIncarnation(t *testing.T) {
	source := &mutableAuthSource{}
	auth := &coreauth.Auth{ID: "startup", Status: coreauth.StatusActive, RegistrationEpoch: 11}
	source.set(auth)
	observer := newSourceObserver(1, source)
	selector := coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{
		Fallback: &coreauth.RoundRobinSelector{},
		Observer: observer,
	})
	defer selector.Stop()

	selected, err := selector.Pick(context.Background(), "provider", "model", cliproxyexecutor.Options{
		Headers: http.Header{"X-Session-ID": []string{"startup-session"}},
	}, []*coreauth.Auth{auth})
	if err != nil || selected == nil {
		t.Fatalf("Pick() = (%#v, %v)", selected, err)
	}
	snapshot := observer.Snapshot(time.Now())
	if len(snapshot.Accounts) != 1 || snapshot.Accounts[0].Counters.Miss != 1 {
		t.Fatalf("first affinity miss was not attributed: %#v", snapshot.Accounts)
	}
}

func TestSessionAffinityInterleavedRoutesRetainIndependentCounters(t *testing.T) {
	source := &mutableAuthSource{}
	authA := &coreauth.Auth{ID: "route-a", Status: coreauth.StatusActive, RegistrationEpoch: 21}
	authB := &coreauth.Auth{ID: "route-b", Status: coreauth.StatusActive, RegistrationEpoch: 22}
	source.set(authA, authB)
	observer := newSourceObserver(2, source)
	selector := coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{
		Fallback: &coreauth.RoundRobinSelector{},
		Observer: observer,
	})
	defer selector.Stop()
	optsA := cliproxyexecutor.Options{Headers: http.Header{"X-Session-ID": []string{"route-a-session"}}}
	optsB := cliproxyexecutor.Options{Headers: http.Header{"X-Session-ID": []string{"route-b-session"}}}
	if _, err := selector.Pick(context.Background(), "provider-a", "model-a", optsA, []*coreauth.Auth{authA}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := selector.Pick(context.Background(), "provider-a", "model-a", cliproxyexecutor.Options{}, []*coreauth.Auth{authA}); err != nil {
				t.Errorf("route A Pick: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := selector.Pick(context.Background(), "provider-b", "model-b", cliproxyexecutor.Options{}, []*coreauth.Auth{authB}); err != nil {
				t.Errorf("route B Pick: %v", err)
			}
		}()
	}
	wg.Wait()
	if _, err := selector.Pick(context.Background(), "provider-b", "model-b", optsB, []*coreauth.Auth{authB}); err != nil {
		t.Fatal(err)
	}
	if _, err := selector.Pick(context.Background(), "provider-a", "model-a", optsA, []*coreauth.Auth{authA}); err != nil {
		t.Fatal(err)
	}

	snapshot := observer.Snapshot(time.Now())
	if len(snapshot.Accounts) != 2 {
		t.Fatalf("interleaved accounts = %#v", snapshot.Accounts)
	}
	byHandle := map[string]Counters{}
	for _, account := range snapshot.Accounts {
		byHandle[account.Account] = account.Counters
	}
	if got := byHandle[hmacHandle(testKey, authA.ID)]; got.Miss != 1 || got.Hit != 1 || got.NoSession != 25 {
		t.Fatalf("route A counters = %#v", got)
	}
	if got := byHandle[hmacHandle(testKey, authB.ID)]; got.Miss != 1 || got.Hit != 0 || got.NoSession != 25 {
		t.Fatalf("route B counters = %#v", got)
	}
}

func TestObserverAffinityRequiresCurrentRegistrationEpoch(t *testing.T) {
	source := &mutableAuthSource{}
	source.set(&coreauth.Auth{ID: "same-id", Status: coreauth.StatusActive, RegistrationEpoch: 1})
	observer := newSourceObserver(2, source)
	observer.ObserveAffinityVersioned(coreauth.AffinityEventHit, "same-id", 1)

	source.set(&coreauth.Auth{ID: "same-id", Status: coreauth.StatusActive, RegistrationEpoch: 2})
	observer.ObserveAffinityVersioned(coreauth.AffinityEventMiss, "same-id", 1)
	observer.ObserveAffinityVersioned(coreauth.AffinityEventRebind, "same-id", 2)

	snapshot := observer.Snapshot(time.Now())
	if len(snapshot.Accounts) != 1 {
		t.Fatalf("accounts = %#v", snapshot.Accounts)
	}
	if got := snapshot.Accounts[0].Counters; got.Hit != 0 || got.Miss != 0 || got.Rebind != 1 {
		t.Fatalf("new incarnation counters = %#v", got)
	}
	if snapshot.Totals.Hit != 1 || snapshot.Totals.Miss != 1 || snapshot.Totals.Rebind != 1 {
		t.Fatalf("aggregate affinity totals = %#v", snapshot.Totals)
	}
}

func TestObserverPausedOldEpochCannotOverwriteNewEpoch(t *testing.T) {
	source := &mutableAuthSource{}
	source.set(&coreauth.Auth{ID: "same-id", Status: coreauth.StatusActive, RegistrationEpoch: 1})
	observer := NewObserver([]byte(testKey), 1)
	lookupCaptured := make(chan struct{})
	releaseLookup := make(chan struct{})
	var once sync.Once
	observer.SetAuthSources(source.list, func(id string) (uint64, uint64, bool) {
		generation, epoch, ok := source.membership(id)
		if epoch == 1 {
			once.Do(func() {
				close(lookupCaptured)
				<-releaseLookup
			})
		}
		return generation, epoch, ok
	}, source.memberships)

	oldDone := make(chan struct{})
	go func() {
		observer.ObserveAffinityVersioned(coreauth.AffinityEventHit, "same-id", 1)
		close(oldDone)
	}()
	select {
	case <-lookupCaptured:
	case <-time.After(2 * time.Second):
		t.Fatal("old epoch event did not pause after lookup")
	}
	source.set(&coreauth.Auth{ID: "same-id", Status: coreauth.StatusActive, RegistrationEpoch: 2})
	newDone := make(chan struct{})
	go func() {
		observer.ObserveAffinityVersioned(coreauth.AffinityEventRebind, "same-id", 2)
		close(newDone)
	}()
	select {
	case <-newDone:
		t.Fatal("new epoch event bypassed observer serialization")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseLookup)
	for name, done := range map[string]<-chan struct{}{"old": oldDone, "new": newDone} {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s epoch event did not finish", name)
		}
	}

	snapshot := observer.Snapshot(time.Now())
	if len(snapshot.Accounts) != 1 || snapshot.Accounts[0].Counters.Hit != 0 || snapshot.Accounts[0].Counters.Rebind != 1 {
		t.Fatalf("new epoch counters = %#v", snapshot.Accounts)
	}
	if snapshot.Totals.Hit != 1 || snapshot.Totals.Rebind != 1 {
		t.Fatalf("aggregate counters = %#v", snapshot.Totals)
	}
}

func TestObserverAffinityEpochTransitionReplacesCounterAtCapacity(t *testing.T) {
	source := &mutableAuthSource{}
	source.set(&coreauth.Auth{ID: "same-id", Status: coreauth.StatusActive, RegistrationEpoch: 1})
	observer := newSourceObserver(1, source)
	observer.ObserveAffinityVersioned(coreauth.AffinityEventHit, "same-id", 1)

	source.set(&coreauth.Auth{ID: "same-id", Status: coreauth.StatusActive, RegistrationEpoch: 2})
	observer.ObserveAffinityVersioned(coreauth.AffinityEventRebind, "same-id", 2)
	if len(observer.affinityCounters) != 1 {
		t.Fatalf("affinity counter entries = %d, want 1", len(observer.affinityCounters))
	}
	snapshot := observer.Snapshot(time.Now())
	if got := snapshot.Accounts[0].Counters; got.Hit != 0 || got.Rebind != 1 {
		t.Fatalf("epoch 2 counters = %#v", got)
	}
}

func TestObserverRemovedAffinityChurnCannotConsumeCapacity(t *testing.T) {
	source := &mutableAuthSource{}
	observer := newSourceObserver(1, source)
	for i := 0; i < DefaultMaxAccounts+8; i++ {
		id := fmt.Sprintf("removed-%02d", i)
		source.set(&coreauth.Auth{ID: id, Status: coreauth.StatusActive, RegistrationEpoch: 1})
		observer.ObserveAffinityVersioned(coreauth.AffinityEventHit, id, 1)
		source.set()
		observer.ObserveAffinityVersioned(coreauth.AffinityEventMiss, id, 1)
	}

	source.set(&coreauth.Auth{ID: "current", Status: coreauth.StatusActive, RegistrationEpoch: 9})
	observer.ObserveAffinityVersioned(coreauth.AffinityEventRebind, "current", 9)
	if len(observer.affinityCounters) != 1 {
		t.Fatalf("affinity counter entries = %d, want 1", len(observer.affinityCounters))
	}
	snapshot := observer.Snapshot(time.Now())
	if len(snapshot.Accounts) != 1 || snapshot.Accounts[0].Account != hmacHandle(testKey, "current") || snapshot.Accounts[0].Counters.Rebind != 1 {
		t.Fatalf("current affinity after removed churn = %#v", snapshot.Accounts)
	}
}

func TestObserverVersionedAffinityWithoutSourceIsAggregateOnly(t *testing.T) {
	observer := NewObserver([]byte(testKey), 1)
	observer.ObserveAffinityVersioned(coreauth.AffinityEventHit, "unavailable", 1)
	snapshot := observer.Snapshot(time.Now())
	if snapshot.Totals.Hit != 1 || len(observer.affinityCounters) != 0 || len(snapshot.Accounts) != 0 {
		t.Fatalf("source-less versioned affinity = %#v, counters=%d", snapshot, len(observer.affinityCounters))
	}
}

func TestObserverLegacyAffinityIsAggregateOnly(t *testing.T) {
	source := &mutableAuthSource{}
	source.set(&coreauth.Auth{ID: "legacy", Status: coreauth.StatusActive, RegistrationEpoch: 1})
	observer := newSourceObserver(1, source)
	observer.ObserveAffinity(coreauth.AffinityEventHit, "legacy")

	snapshot := observer.Snapshot(time.Now())
	if snapshot.Totals.Hit != 1 || snapshot.Accounts[0].Counters.Hit != 0 {
		t.Fatalf("legacy affinity attribution = %#v", snapshot)
	}
}

func TestObserverAffinityCounterCapUsesDeterministicHMACOrder(t *testing.T) {
	source := &mutableAuthSource{}
	auths := make([]*coreauth.Auth, 0, 100)
	wantHandles := make([]string, 0, 100)
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("affinity-%03d", i)
		auths = append(auths, &coreauth.Auth{ID: id, Status: coreauth.StatusActive, RegistrationEpoch: 1})
		wantHandles = append(wantHandles, hmacHandle(testKey, id))
	}
	source.set(auths...)
	observer := newSourceObserver(1000, source)
	for i := len(auths) - 1; i >= 0; i-- {
		observer.ObserveAffinityVersioned(coreauth.AffinityEventHit, auths[i].ID, 1)
	}

	snapshot := observer.Snapshot(time.Now())
	sort.Strings(wantHandles)
	if len(observer.affinityCounters) != DefaultMaxAccounts || len(snapshot.Accounts) != DefaultMaxAccounts {
		t.Fatalf("bounded affinity/accounts = %d/%d", len(observer.affinityCounters), len(snapshot.Accounts))
	}
	for i, account := range snapshot.Accounts {
		if account.Account != wantHandles[i] || account.Counters.Hit != 1 {
			t.Fatalf("account %d = %#v, want handle %q with one hit", i, account, wantHandles[i])
		}
	}
}

func TestSnapshotProjectsAuthoritativeSourceMutations(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(10 * time.Minute)
	source := &mutableAuthSource{}
	source.set(&coreauth.Auth{
		ID: "startup-account", Status: coreauth.StatusActive,
		Quota: coreauth.QuotaState{ObservedAt: now.Add(-5 * time.Minute), Signals: map[string]string{
			"X-Codex-Primary-Used-Percent":        "51.5",
			"X-Codex-Primary-Window-Minutes":      "10080",
			"X-Codex-Primary-Reset-After-Seconds": "600",
		}},
		ModelStates: map[string]*coreauth.ModelState{"private-model": {
			Unavailable: true, NextRetryAfter: expires,
			Quota: coreauth.QuotaState{Exceeded: true, NextRecoverAt: expires},
		}},
	})
	observer := newSourceObserver(DefaultMaxAccounts, source)

	startup := observer.Snapshot(now)
	if !startup.Health.ObserverReady || startup.Health.Status != "ready" || len(startup.Accounts) != 1 {
		t.Fatalf("startup projection = %#v", startup)
	}
	account := startup.Accounts[0]
	if account.Eligibility != "eligible" || account.Cooldown.Category != "quota" || account.Cooldown.ExpiresAt == nil || !account.Cooldown.ExpiresAt.Equal(expires) {
		t.Fatalf("startup eligibility/cooldown = %#v", account)
	}
	if account.Quota.Status != "fresh" || account.Quota.ObservedAt == nil || len(account.Quota.Windows) != 1 {
		t.Fatalf("startup quota = %#v", account.Quota)
	}
	window := account.Quota.Windows[0]
	if window.Category != "primary" || window.UsedPercent == nil || *window.UsedPercent != 51.5 || window.WindowMinutes == nil || *window.WindowMinutes != 10080 {
		t.Fatalf("quota window = %#v", window)
	}

	// A config mutation and quota reset are visible solely through the next source snapshot.
	source.set(&coreauth.Auth{ID: "startup-account", Status: coreauth.StatusDisabled, Disabled: true})
	configured := observer.Snapshot(now)
	if configured.Accounts[0].Eligibility != "ineligible" || configured.Accounts[0].Cooldown.Category != "none" || configured.Accounts[0].Quota.Status != "unavailable" {
		t.Fatalf("config/reset projection = %#v", configured.Accounts[0])
	}

	// Recovery is derived at the requested time without an observer event.
	source.set(&coreauth.Auth{ID: "startup-account", Status: coreauth.StatusError, Unavailable: true, NextRetryAfter: now.Add(time.Minute)})
	cooling := observer.Snapshot(now)
	recovered := observer.Snapshot(now.Add(2 * time.Minute))
	if cooling.Accounts[0].Eligibility != "ineligible" || recovered.Accounts[0].Eligibility != "eligible" || recovered.Health.Status != "ready" {
		t.Fatalf("natural expiry cooling/recovered = %#v / %#v", cooling, recovered)
	}

	source.set()
	removed := observer.Snapshot(now.Add(3 * time.Minute))
	if len(removed.Accounts) != 0 || removed.Health.AccountCount != 0 || removed.Health.Status != "unavailable" {
		t.Fatalf("removed account remains = %#v", removed)
	}
}

func TestObserverEligibilityMatchesAggregateSelectorSemantics(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(time.Minute)
	past := now.Add(-time.Minute)
	tests := []struct {
		name string
		auth *coreauth.Auth
		want string
	}{
		{name: "disabled", auth: &coreauth.Auth{Status: coreauth.StatusDisabled}, want: "ineligible"},
		{name: "model scoped aggregate quota", auth: &coreauth.Auth{
			Status: coreauth.StatusError, Quota: coreauth.QuotaState{Exceeded: true, Reason: "quota", NextRecoverAt: future},
			ModelStates: map[string]*coreauth.ModelState{"private-model": {Quota: coreauth.QuotaState{Exceeded: true, NextRecoverAt: future}}},
		}, want: "eligible"},
		{name: "credential quota", auth: &coreauth.Auth{
			Status: coreauth.StatusError, Quota: coreauth.QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: future},
			ModelStates: map[string]*coreauth.ModelState{"private-model": {}},
		}, want: "ineligible"},
		{name: "status error without aggregate block", auth: &coreauth.Auth{Status: coreauth.StatusError}, want: "eligible"},
		{name: "expired unavailable recovery", auth: &coreauth.Auth{Status: coreauth.StatusError, Unavailable: true, NextRetryAfter: past}, want: "eligible"},
		{name: "future unavailable recovery", auth: &coreauth.Auth{Status: coreauth.StatusError, Unavailable: true, NextRetryAfter: future}, want: "ineligible"},
		{name: "unknown status", auth: &coreauth.Auth{Status: coreauth.StatusUnknown}, want: "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := eligibility(sanitizedEligibility(tt.auth, now), now); got != tt.want {
				t.Fatalf("eligibility = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestObserverEligibilityMatchesAccessTokenExpiration(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tests := []struct {
		name     string
		metadata map[string]any
		want     string
	}{
		{name: "valid without expiration", metadata: map[string]any{"access_token": "opaque-token"}, want: "eligible"},
		{name: "future expiration", metadata: map[string]any{"access_token": "opaque-token", "expires_at": now.Add(time.Minute).Format(time.RFC3339)}, want: "eligible"},
		{name: "expired", metadata: map[string]any{"access_token": "opaque-token", "expires_at": now.Add(-time.Minute).Format(time.RFC3339)}, want: "ineligible"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &coreauth.Auth{Status: coreauth.StatusActive, Metadata: tt.metadata}
			if got := eligibility(sanitizedEligibility(auth, now), now); got != tt.want {
				t.Fatalf("eligibility = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestObserverQuotaUnavailableStaleAndBounded(t *testing.T) {
	now := time.Now().UTC()
	source := &mutableAuthSource{}
	source.set(
		&coreauth.Auth{ID: "unsupported", Status: coreauth.StatusActive, Quota: coreauth.QuotaState{ObservedAt: now, Signals: map[string]string{"X-Codex-Plan-Type": "private"}}},
		&coreauth.Auth{ID: "stale", Status: coreauth.StatusActive, Quota: coreauth.QuotaState{ObservedAt: now.Add(-time.Hour), Signals: map[string]string{"X-Codex-Primary-Used-Percent": "25"}}},
		&coreauth.Auth{ID: "invalid", Status: coreauth.StatusActive, Quota: coreauth.QuotaState{ObservedAt: now, Signals: map[string]string{
			"X-Codex-Primary-Used-Percent": "NaN", "X-Codex-Primary-Window-Minutes": "9223372036854775807", "X-Codex-Primary-Reset-At": "9223372036854775807",
		}}},
	)
	observer := newSourceObserver(DefaultMaxAccounts, source)
	snapshot := observer.Snapshot(now)
	statuses := map[string]int{}
	for _, account := range snapshot.Accounts {
		statuses[account.Quota.Status]++
	}
	if statuses["unavailable"] != 2 || statuses["stale"] != 1 {
		t.Fatalf("quota statuses = %#v", statuses)
	}
	if _, err := json.Marshal(snapshot); err != nil {
		t.Fatalf("bounded snapshot did not marshal: %v", err)
	}
}

func TestObserverUsesOnlyFixedFailureCategories(t *testing.T) {
	observer := NewObserver([]byte(testKey), DefaultMaxAccounts)
	cases := []struct {
		err  *coreauth.Error
		want string
	}{
		{&coreauth.Error{HTTPStatus: 401, Message: "authentication secret"}, "authentication"},
		{&coreauth.Error{HTTPStatus: 429, Message: "quota secret"}, "rate_limit"},
		{&coreauth.Error{HTTPStatus: 408, Message: "timeout secret"}, "timeout"},
		{&coreauth.Error{Code: coreauth.ErrorCodeTransientTransport, Message: "transport secret"}, "transport"},
		{&coreauth.Error{HTTPStatus: 502, Message: "upstream secret"}, "upstream"},
		{&coreauth.Error{Code: coreauth.ErrorCodeRequestScoped, Message: "request secret"}, "request"},
		{&coreauth.Error{HTTPStatus: 503, Message: "unavailable secret"}, "unavailable"},
		{&coreauth.Error{Code: "raw-private-code", Message: "unknown secret"}, "unknown"},
	}
	for i, tc := range cases {
		observer.OnResult(context.Background(), coreauth.Result{AuthID: fmt.Sprintf("account-%d", i), Error: tc.err})
		if got := failureCategory(coreauth.Result{Error: tc.err}); got != tc.want {
			t.Fatalf("case %d category = %q, want %q", i, got, tc.want)
		}
	}
	want := FailureCategories{Authentication: 1, RateLimit: 1, Timeout: 1, Transport: 1, Upstream: 1, Request: 1, Unavailable: 1, Unknown: 1}
	if observer.Snapshot(time.Now()).Totals.Failures != want {
		t.Fatalf("failure categories = %#v", observer.Snapshot(time.Now()).Totals)
	}
}

func TestObserverPrunesAndBoundsCounterState(t *testing.T) {
	source := &mutableAuthSource{}
	source.set(&coreauth.Auth{ID: "active-a", Status: coreauth.StatusActive}, &coreauth.Auth{ID: "active-b", Status: coreauth.StatusActive})
	observer := newSourceObserver(2, source)
	observer.OnResult(context.Background(), coreauth.Result{AuthID: "active-a", Success: true})
	observer.OnResult(context.Background(), coreauth.Result{AuthID: "active-b", Success: true})
	for i := 0; i < 100; i++ {
		observer.OnResult(context.Background(), coreauth.Result{AuthID: fmt.Sprintf("home-%03d", i), Success: true})
	}
	first := observer.Snapshot(time.Now())
	if len(first.Accounts) != 2 || len(observer.counters) > 2 {
		t.Fatalf("first bounded state accounts/counters = %d/%d", len(first.Accounts), len(observer.counters))
	}

	source.set(&coreauth.Auth{ID: "active-b", Status: coreauth.StatusActive})
	second := observer.Snapshot(time.Now())
	if len(second.Accounts) != 1 || second.Accounts[0].Account != hmacHandle(testKey, "active-b") {
		t.Fatalf("removed account emitted = %#v", second.Accounts)
	}
	for key := range observer.counters {
		if key.handle == hmacHandle(testKey, "active-a") {
			t.Fatal("removed account counters were not pruned")
		}
	}
	if second.Totals.Requests != 102 {
		t.Fatalf("aggregate totals dropped home/removed results: %#v", second.Totals)
	}
}

func TestObserverCurrentSourceCapIsDeterministicAndBounded(t *testing.T) {
	source := &mutableAuthSource{}
	auths := make([]*coreauth.Auth, 0, 100)
	wantHandles := make([]string, 0, 100)
	for i := 99; i >= 0; i-- {
		id := fmt.Sprintf("private-%03d", i)
		auths = append(auths, &coreauth.Auth{ID: id, Status: coreauth.StatusActive})
		wantHandles = append(wantHandles, hmacHandle(testKey, id))
	}
	source.set(auths...)
	observer := newSourceObserver(1000, source)
	for i := 99; i >= 0; i-- {
		observer.OnResult(context.Background(), coreauth.Result{AuthID: fmt.Sprintf("private-%03d", i), Success: true})
	}
	snapshot := observer.Snapshot(time.Now())
	sort.Strings(wantHandles)
	if len(snapshot.Accounts) != DefaultMaxAccounts {
		t.Fatalf("accounts = %d, want %d", len(snapshot.Accounts), DefaultMaxAccounts)
	}
	for i, account := range snapshot.Accounts {
		if account.Account != wantHandles[i] {
			t.Fatalf("account %d = %q, want %q", i, account.Account, wantHandles[i])
		}
		if account.Counters.Success != 1 {
			t.Fatalf("account %d counters = %#v, want one success", i, account.Counters)
		}
	}
	if len(observer.counters) != DefaultMaxAccounts {
		t.Fatalf("counter entries = %d, want %d", len(observer.counters), DefaultMaxAccounts)
	}
	body, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 32<<10 {
		t.Fatalf("bounded snapshot = %d bytes", len(body))
	}
}

func TestHandlerMarshalFailureReturnsFixedUnavailable(t *testing.T) {
	source := &mutableAuthSource{}
	source.set(&coreauth.Auth{
		ID: "private-id", Status: coreauth.StatusActive,
		Quota: coreauth.QuotaState{
			ObservedAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
			Signals:    map[string]string{"X-Codex-Primary-Used-Percent": "25"},
		},
	})
	observer := newSourceObserver(1, source)
	req := httptest.NewRequest(http.MethodGet, SnapshotPath, nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	recorder := httptest.NewRecorder()

	observer.Handler(testToken).ServeHTTP(recorder, req)

	const wantBody = `{"error":"unavailable"}`
	if recorder.Code != http.StatusServiceUnavailable || recorder.Body.String() != wantBody {
		t.Fatalf("marshal failure response = %d %q, want %d %q", recorder.Code, recorder.Body.String(), http.StatusServiceUnavailable, wantBody)
	}
	if recorder.Header().Get("Content-Type") != "application/json" || recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Content-Length") != fmt.Sprint(len(wantBody)) {
		t.Fatalf("marshal failure headers = %#v", recorder.Header())
	}
	if strings.Contains(recorder.Body.String(), "private-id") || strings.Contains(recorder.Body.String(), "year outside") {
		t.Fatalf("marshal failure leaked details: %q", recorder.Body.String())
	}
}

func TestHandlerContractPrivacyAndStrictSchema(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rawValues := []string{"raw-auth-secret", "session-secret", "model-secret", "provider-secret", "prompt-secret", "response-secret", "tool-secret", "/sensitive/path", "user@example.test"}
	source := &mutableAuthSource{}
	source.set(&coreauth.Auth{
		ID: rawValues[0], Provider: rawValues[3], Status: coreauth.StatusActive,
		Attributes:  map[string]string{"email": rawValues[8]},
		Quota:       coreauth.QuotaState{ObservedAt: now, Signals: map[string]string{"X-Codex-Primary-Used-Percent": "25", "X-Codex-Plan-Type": "private-plan"}},
		ModelStates: map[string]*coreauth.ModelState{rawValues[2]: {LastError: &coreauth.Error{Message: rawValues[5]}}},
	})
	observer := newSourceObserver(1, source)
	observer.OnResult(context.Background(), coreauth.Result{AuthID: rawValues[0], Provider: rawValues[3], Model: rawValues[2], Error: &coreauth.Error{Code: rawValues[1], Message: strings.Join(rawValues[4:], " ")}})
	handler := observer.Handler(testToken)

	tests := []struct {
		name, method, target, auth string
		want                       int
	}{
		{name: "authorized", method: http.MethodGet, target: SnapshotPath, auth: "Bearer " + testToken, want: http.StatusOK},
		{name: "missing auth", method: http.MethodGet, target: SnapshotPath, want: http.StatusUnauthorized},
		{name: "wrong auth", method: http.MethodGet, target: SnapshotPath, auth: "Bearer wrong", want: http.StatusUnauthorized},
		{name: "unauthenticated query", method: http.MethodGet, target: SnapshotPath + "?detail=1", want: http.StatusUnauthorized},
		{name: "query", method: http.MethodGet, target: SnapshotPath + "?detail=1", auth: "Bearer " + testToken, want: http.StatusBadRequest},
		{name: "method", method: http.MethodPost, target: SnapshotPath, auth: "Bearer " + testToken, want: http.StatusMethodNotAllowed},
		{name: "path", method: http.MethodGet, target: "/", auth: "Bearer " + testToken, want: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.target, strings.NewReader("body-must-not-be-read"))
			req.Header.Set("Authorization", tt.auth)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != tt.want {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.want)
			}
			if recorder.Header().Get("Content-Type") != "application/json" || recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Content-Length") != fmt.Sprint(recorder.Body.Len()) {
				t.Fatalf("unsafe headers: %#v", recorder.Header())
			}
			if recorder.Body.Len() > 32<<10 {
				t.Fatalf("response is not bounded: %d bytes", recorder.Body.Len())
			}
			for _, raw := range rawValues {
				if strings.Contains(recorder.Body.String(), raw) {
					t.Fatalf("response leaked %q: %s", raw, recorder.Body.String())
				}
			}
		})
	}

	body, err := json.Marshal(observer.Snapshot(now))
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		t.Fatal(err)
	}
	assertJSONKeys(t, root, "schemaVersion", "generatedAt", "health", "totals", "accounts")
	health := root["health"].(map[string]any)
	assertJSONKeys(t, health, "status", "observerReady", "serviceReady", "accountCount", "eligibility")
	assertJSONKeys(t, health["eligibility"].(map[string]any), "eligible", "ineligible", "unknown")
	assertCounterKeys(t, root["totals"].(map[string]any))
	account := root["accounts"].([]any)[0].(map[string]any)
	assertJSONKeys(t, account, "account", "eligibility", "cooldown", "quota", "counters")
	assertJSONKeys(t, account["cooldown"].(map[string]any), "category", "expiresAt")
	quotaJSON := account["quota"].(map[string]any)
	assertJSONKeys(t, quotaJSON, "status", "observedAt", "windows")
	assertJSONKeys(t, quotaJSON["windows"].([]any)[0].(map[string]any), "category", "usedPercent", "windowMinutes", "resetsAt")
	assertCounterKeys(t, account["counters"].(map[string]any))
}

func hmacHandle(key, id string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(id))
	return "acct_" + hex.EncodeToString(mac.Sum(nil))
}

func assertCounterKeys(t *testing.T, counters map[string]any) {
	t.Helper()
	assertJSONKeys(t, counters, "requests", "success", "failure", "failureCategories", "affinityHit", "affinityMiss", "affinityRebind", "affinityNoSession")
	assertJSONKeys(t, counters["failureCategories"].(map[string]any), "authentication", "rateLimit", "timeout", "transport", "upstream", "request", "unavailable", "unknown")
}

func assertJSONKeys(t *testing.T, object map[string]any, expected ...string) {
	t.Helper()
	if len(object) != len(expected) {
		t.Fatalf("JSON fields = %v, want %v", sortedKeys(object), expected)
	}
	for _, key := range expected {
		if _, ok := object[key]; !ok {
			t.Fatalf("JSON fields = %v, missing %q", sortedKeys(object), key)
		}
	}
}

func sortedKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
