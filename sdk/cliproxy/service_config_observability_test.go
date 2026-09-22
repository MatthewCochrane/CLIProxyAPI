package cliproxy

import (
	"context"
	"net/http"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type reloadAffinityObserver struct {
	event  coreauth.AffinityEvent
	authID string
}

func (o *reloadAffinityObserver) ObserveAffinity(event coreauth.AffinityEvent, authID string) {
	o.event = event
	o.authID = authID
}

func TestApplyManagerConfigRetainsRoutingObserver(t *testing.T) {
	observer := &reloadAffinityObserver{}
	initialCfg := &internalconfig.Config{
		Routing: internalconfig.RoutingConfig{
			Strategy:        "round-robin",
			SessionAffinity: true,
		},
	}
	service, errBuild := NewBuilder().
		WithConfig(initialCfg).
		WithConfigPath(t.TempDir() + "/config.yaml").
		WithRoutingObserver(observer).
		Build()
	if errBuild != nil {
		t.Fatal(errBuild)
	}
	assertSelectorObservation(t, service, observer, "before-reload")

	observer.event = 0
	observer.authID = ""
	cfg := &internalconfig.Config{
		Routing: internalconfig.RoutingConfig{
			Strategy:        "fill-first",
			SessionAffinity: true,
		},
	}
	if !service.applyManagerConfig(context.Background(), configCommit{cfg: cfg, sequence: 1}) {
		t.Fatal("applyManagerConfig failed")
	}
	assertSelectorObservation(t, service, observer, "after-reload")
}

func assertSelectorObservation(t *testing.T, service *Service, observer *reloadAffinityObserver, sessionID string) {
	t.Helper()
	selector, ok := service.coreManager.Selector().(*coreauth.SessionAffinitySelector)
	if !ok {
		t.Fatalf("selector type = %T, want *auth.SessionAffinitySelector", service.coreManager.Selector())
	}
	selected, err := selector.Pick(
		context.Background(),
		"provider",
		"model",
		cliproxyexecutor.Options{Headers: http.Header{"X-Session-ID": []string{sessionID}}},
		[]*coreauth.Auth{{ID: "raw-auth-id"}},
	)
	if err != nil || selected == nil {
		t.Fatalf("Pick() = %#v, %v", selected, err)
	}
	if observer.event != coreauth.AffinityEventMiss || observer.authID != selected.ID {
		t.Fatalf("observation = (%d, %q), want miss for %q", observer.event, observer.authID, selected.ID)
	}
}
