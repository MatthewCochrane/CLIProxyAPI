package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type affinityObservation struct {
	event  AffinityEvent
	authID string
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

func TestSessionAffinitySelectorEmitsFixedOutcomes(t *testing.T) {
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
