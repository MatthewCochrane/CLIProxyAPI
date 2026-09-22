package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type affinityObservation struct {
	event             AffinityEvent
	authID            string
	registrationEpoch uint64
}

func TestSessionAffinitySelectorUnavailableAliasEmitsRebind(t *testing.T) {
	observer := &recordingAffinityObserver{}
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		Observer: observer,
		TTL:      time.Minute,
	})
	defer selector.Stop()

	combined := cliproxyexecutor.Options{OriginalRequest: []byte(`{"conversation":{"id":"conversation-session"},"prompt_cache_key":"shared-cache-bucket"}`)}
	conversation := cliproxyexecutor.Options{OriginalRequest: []byte(`{"conversation":{"id":"conversation-session"}}`)}
	if _, err := selector.Pick(context.Background(), "openai", "model", conversation, []*Auth{{ID: "unavailable-auth"}}); err != nil {
		t.Fatal(err)
	}
	observer.events = nil

	selected, err := selector.Pick(context.Background(), "openai", "model", combined, []*Auth{{ID: "replacement-auth"}})
	if err != nil {
		t.Fatal(err)
	}
	assertAffinityObservations(t, observer.events, []affinityObservation{{event: AffinityEventRebind, authID: selected.ID}})
}

func TestSessionAffinitySelectorUnavailableForkParentEmitsRebind(t *testing.T) {
	observer := &recordingAffinityObserver{}
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		Observer: observer,
		TTL:      time.Minute,
	})
	defer selector.Stop()

	parent := cliproxyexecutor.Options{Headers: http.Header{"Session-Id": []string{"parent-thread"}}, Metadata: map[string]any{}}
	if _, err := selector.Pick(context.Background(), "openai", "model", parent, []*Auth{{ID: "unavailable-auth"}}); err != nil {
		t.Fatal(err)
	}
	observer.events = nil
	fork := cliproxyexecutor.Options{
		Headers: http.Header{
			"Session-Id":            []string{"fork-thread"},
			"X-Codex-Turn-Metadata": []string{`{"session_id":"fork-thread","forked_from_thread_id":"parent-thread","request_kind":"turn"}`},
		},
		Metadata: map[string]any{},
	}
	selected, err := selector.Pick(context.Background(), "openai", "model", fork, []*Auth{{ID: "replacement-auth"}})
	if err != nil {
		t.Fatal(err)
	}
	assertAffinityObservations(t, observer.events, []affinityObservation{{event: AffinityEventRebind, authID: selected.ID}})
}

func TestSessionAffinitySelectorDisabledParentReuseRemainsMiss(t *testing.T) {
	disabled := false
	observer := &recordingAffinityObserver{}
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:         &RoundRobinSelector{},
		Observer:         observer,
		SubagentAffinity: &disabled,
		TTL:              time.Minute,
	})
	defer selector.Stop()

	parent := cliproxyexecutor.Options{Headers: http.Header{"X-Claude-Code-Session-Id": []string{"parent-session"}}, Metadata: map[string]any{}}
	if _, err := selector.Pick(context.Background(), "claude", "model", parent, []*Auth{{ID: "parent-auth"}}); err != nil {
		t.Fatal(err)
	}
	observer.events = nil
	child := cliproxyexecutor.Options{Headers: http.Header{
		"X-Claude-Code-Session-Id": []string{"parent-session"},
		"X-Claude-Code-Agent-Id":   []string{"child-agent"},
	}, Metadata: map[string]any{}}
	selected, err := selector.Pick(context.Background(), "claude", "model", child, []*Auth{{ID: "replacement-auth"}})
	if err != nil {
		t.Fatal(err)
	}
	assertAffinityObservations(t, observer.events, []affinityObservation{{event: AffinityEventMiss, authID: selected.ID}})
}

func assertAffinityObservations(t *testing.T, got, want []affinityObservation) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("events = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("event %d = %#v, want %#v", index, got[index], want[index])
		}
	}
}

type recordingAffinityObserver struct {
	events []affinityObservation
}

func (o *recordingAffinityObserver) ObserveAffinity(event AffinityEvent, authID string) {
	o.events = append(o.events, affinityObservation{event: event, authID: authID})
}

func TestSessionAffinitySelectorLegacyObserverCompatibility(t *testing.T) {
	observer := &recordingAffinityObserver{}
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		Observer: observer,
	})
	authA := &Auth{ID: "auth-a"}
	authB := &Auth{ID: "auth-b"}
	session := cliproxyexecutor.Options{Headers: http.Header{"X-Session-ID": []string{"private-session"}}}

	if _, err := selector.Pick(context.Background(), "provider", "model", session, []*Auth{authA, authB}); err != nil {
		t.Fatal(err)
	}
	if _, err := selector.Pick(context.Background(), "provider", "model", session, []*Auth{authA, authB}); err != nil {
		t.Fatal(err)
	}
	if _, err := selector.Pick(context.Background(), "provider", "model", session, []*Auth{authB}); err != nil {
		t.Fatal(err)
	}
	if _, err := selector.Pick(context.Background(), "provider", "model", cliproxyexecutor.Options{}, []*Auth{authB}); err != nil {
		t.Fatal(err)
	}

	want := []affinityObservation{
		{event: AffinityEventMiss, authID: "auth-a"},
		{event: AffinityEventHit, authID: "auth-a"},
		{event: AffinityEventRebind, authID: "auth-b"},
		{event: AffinityEventNoSession, authID: "auth-b"},
	}
	if len(observer.events) != len(want) {
		t.Fatalf("events = %#v, want %#v", observer.events, want)
	}
	for index := range want {
		if observer.events[index] != want[index] {
			t.Fatalf("event %d = %#v, want %#v", index, observer.events[index], want[index])
		}
	}
}

type recordingVersionedAffinityObserver struct {
	legacyCalls int
	events      []affinityObservation
}

func (o *recordingVersionedAffinityObserver) ObserveAffinity(AffinityEvent, string) {
	o.legacyCalls++
}

func (o *recordingVersionedAffinityObserver) ObserveAffinityVersioned(event AffinityEvent, authID string, registrationEpoch uint64) {
	o.events = append(o.events, affinityObservation{event: event, authID: authID, registrationEpoch: registrationEpoch})
}

func TestSessionAffinitySelectorPrefersExactVersionedObservation(t *testing.T) {
	observer := &recordingVersionedAffinityObserver{}
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		Observer: observer,
	})
	defer selector.Stop()
	auth := &Auth{ID: "versioned-auth", RegistrationEpoch: 17}

	selected, err := selector.Pick(context.Background(), "provider", "model", cliproxyexecutor.Options{}, []*Auth{auth})
	if err != nil || selected != auth {
		t.Fatalf("Pick() = (%#v, %v)", selected, err)
	}
	if observer.legacyCalls != 0 {
		t.Fatalf("legacy calls = %d, want 0", observer.legacyCalls)
	}
	want := []affinityObservation{{event: AffinityEventNoSession, authID: auth.ID, registrationEpoch: 17}}
	assertAffinityObservations(t, observer.events, want)
}

func TestManagerLightweightAuthMembership(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	registered, err := manager.Register(context.Background(), &Auth{
		ID:       "membership-account",
		Provider: "private-provider",
		Metadata: map[string]any{"access_token": "private-token"},
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	epoch, ok := manager.RegistrationEpoch(registered.ID)
	if !ok || epoch != registered.RegistrationEpoch || epoch == 0 {
		t.Fatalf("RegistrationEpoch() = %d/%v, want %d/true", epoch, ok, registered.RegistrationEpoch)
	}
	memberships := manager.ListAuthMemberships()
	if len(memberships) != 1 || memberships[0] != (AuthMembership{ID: registered.ID, RegistrationEpoch: epoch}) {
		t.Fatalf("ListAuthMemberships() = %#v", memberships)
	}
	manager.Remove(context.Background(), registered.ID)
	if _, ok = manager.RegistrationEpoch(registered.ID); ok || len(manager.ListAuthMemberships()) != 0 {
		t.Fatal("removed auth remained in lightweight membership")
	}
}

type membershipGenerationStore struct {
	auths []*Auth
}

func (s *membershipGenerationStore) List(context.Context) ([]*Auth, error) {
	result := make([]*Auth, 0, len(s.auths))
	for _, auth := range s.auths {
		result = append(result, auth.Clone())
	}
	return result, nil
}

func (*membershipGenerationStore) Save(context.Context, *Auth) (string, error) { return "", nil }
func (*membershipGenerationStore) Delete(context.Context, string) error        { return nil }

func TestManagerAuthMembershipGenerationChangesOnlyWithMembership(t *testing.T) {
	ctx := context.Background()
	store := &membershipGenerationStore{}
	manager := NewManager(store, nil, nil)
	initialGeneration, memberships := manager.AuthMembershipSnapshot()
	if initialGeneration == 0 || len(memberships) != 0 {
		t.Fatalf("initial membership = %d/%#v", initialGeneration, memberships)
	}
	if err := manager.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if generation, _ := manager.AuthMembershipSnapshot(); generation != initialGeneration {
		t.Fatalf("empty Load generation = %d, want %d", generation, initialGeneration)
	}

	registered, err := manager.Register(ctx, &Auth{ID: "member", Status: StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	registeredGeneration, epoch, ok := manager.AuthMembership(registered.ID)
	if !ok || registeredGeneration != initialGeneration+1 || epoch != registered.RegistrationEpoch {
		t.Fatalf("registered membership = %d/%d/%v, want %d/%d/true", registeredGeneration, epoch, ok, initialGeneration+1, registered.RegistrationEpoch)
	}
	if _, err = manager.Update(ctx, registered.Clone()); err != nil {
		t.Fatal(err)
	}
	if generation, _, _ := manager.AuthMembership(registered.ID); generation != registeredGeneration {
		t.Fatalf("ordinary Update changed membership generation to %d", generation)
	}
	newIncarnation := registered.Clone()
	newIncarnation.RegistrationEpoch++
	updatedIncarnation, err := manager.Update(ctx, newIncarnation)
	if err != nil {
		t.Fatal(err)
	}
	updatedGeneration, updatedEpoch, ok := manager.AuthMembership(registered.ID)
	if !ok || updatedGeneration != registeredGeneration+1 || updatedEpoch != updatedIncarnation.RegistrationEpoch {
		t.Fatalf("updated incarnation = %d/%d/%v, want %d/%d/true", updatedGeneration, updatedEpoch, ok, registeredGeneration+1, updatedIncarnation.RegistrationEpoch)
	}
	reregistered, err := manager.Register(ctx, registered.Clone())
	if err != nil {
		t.Fatal(err)
	}
	reregisteredGeneration, reregisteredEpoch, ok := manager.AuthMembership(registered.ID)
	if !ok || reregisteredGeneration != updatedGeneration+1 || reregisteredEpoch != reregistered.RegistrationEpoch || reregisteredEpoch <= updatedEpoch {
		t.Fatalf("re-registered membership = %d/%d/%v, previous %d/%d", reregisteredGeneration, reregisteredEpoch, ok, updatedGeneration, updatedEpoch)
	}
	manager.Remove(ctx, "missing")
	if generation, _ := manager.AuthMembershipSnapshot(); generation != reregisteredGeneration {
		t.Fatalf("missing Remove changed membership generation to %d", generation)
	}
	manager.Remove(ctx, registered.ID)
	removedGeneration, memberships := manager.AuthMembershipSnapshot()
	if removedGeneration != reregisteredGeneration+1 || len(memberships) != 0 {
		t.Fatalf("removed membership = %d/%#v", removedGeneration, memberships)
	}

	store.auths = []*Auth{{ID: "loaded", Status: StatusActive}}
	if err = manager.Load(ctx); err != nil {
		t.Fatal(err)
	}
	loadedGeneration, loadedEpoch, ok := manager.AuthMembership("loaded")
	if !ok || loadedGeneration != removedGeneration+1 || loadedEpoch == 0 {
		t.Fatalf("loaded membership = %d/%d/%v", loadedGeneration, loadedEpoch, ok)
	}
	if err = manager.Load(ctx); err != nil {
		t.Fatal(err)
	}
	reloadedGeneration, reloadedEpoch, ok := manager.AuthMembership("loaded")
	if !ok || reloadedGeneration != loadedGeneration+1 || reloadedEpoch <= loadedEpoch {
		t.Fatalf("reloaded membership = %d/%d/%v, previous %d/%d", reloadedGeneration, reloadedEpoch, ok, loadedGeneration, loadedEpoch)
	}
	store.auths = nil
	if err = manager.Load(ctx); err != nil {
		t.Fatal(err)
	}
	finalGeneration, memberships := manager.AuthMembershipSnapshot()
	if finalGeneration != reloadedGeneration+1 || len(memberships) != 0 {
		t.Fatalf("final membership = %d/%#v", finalGeneration, memberships)
	}
}

func TestManagerAuthMembershipGenerationWrapsNonzero(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.authMembershipGeneration = ^uint64(0)
	if _, err := manager.Register(context.Background(), &Auth{ID: "wrapped"}); err != nil {
		t.Fatal(err)
	}
	generation, _, ok := manager.AuthMembership("wrapped")
	if !ok || generation != 1 {
		t.Fatalf("wrapped generation = %d/%v, want 1/true", generation, ok)
	}
}
