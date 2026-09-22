package cmd

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	routingobs "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/observability"
)

func envLookup(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func TestLoadRoutingObservabilityConfigDisabled(t *testing.T) {
	cfg, err := loadRoutingObservabilityConfig(envLookup(nil))
	if err != nil || cfg != nil {
		t.Fatalf("disabled config = %#v, %v; want nil, nil", cfg, err)
	}
}

func TestLoadRoutingObservabilityConfigRejectsPartialAndUnsafe(t *testing.T) {
	valid := map[string]string{
		observabilityAddrEnv:    "127.0.0.1:9191",
		observabilityTokenEnv:   strings.Repeat("t", 32),
		observabilityHMACKeyEnv: strings.Repeat("k", 32),
	}
	tests := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{name: "partial", mutate: func(values map[string]string) { delete(values, observabilityTokenEnv) }},
		{name: "empty", mutate: func(values map[string]string) { values[observabilityTokenEnv] = "" }},
		{name: "short token", mutate: func(values map[string]string) { values[observabilityTokenEnv] = "short" }},
		{name: "short key", mutate: func(values map[string]string) { values[observabilityHMACKeyEnv] = "short" }},
		{name: "reused secret", mutate: func(values map[string]string) { values[observabilityHMACKeyEnv] = values[observabilityTokenEnv] }},
		{name: "wildcard", mutate: func(values map[string]string) { values[observabilityAddrEnv] = "0.0.0.0:9191" }},
		{name: "hostname", mutate: func(values map[string]string) { values[observabilityAddrEnv] = "localhost:9191" }},
		{name: "non-loopback", mutate: func(values map[string]string) { values[observabilityAddrEnv] = "192.0.2.1:9191" }},
		{name: "zero port", mutate: func(values map[string]string) { values[observabilityAddrEnv] = "127.0.0.1:0" }},
		{name: "missing port", mutate: func(values map[string]string) { values[observabilityAddrEnv] = "127.0.0.1" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values := make(map[string]string, len(valid))
			for key, value := range valid {
				values[key] = value
			}
			tt.mutate(values)
			if cfg, err := loadRoutingObservabilityConfig(envLookup(values)); err == nil || cfg != nil {
				t.Fatalf("config = %#v, err = %v; want rejection", cfg, err)
			}
		})
	}
}

func TestLoadRoutingObservabilityConfigAcceptsLiteralLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:9191", "[::1]:9191"} {
		values := map[string]string{
			observabilityAddrEnv:    addr,
			observabilityTokenEnv:   strings.Repeat("t", 32),
			observabilityHMACKeyEnv: strings.Repeat("k", 32),
		}
		cfg, err := loadRoutingObservabilityConfig(envLookup(values))
		if err != nil || cfg == nil || cfg.addr != addr {
			t.Fatalf("addr %q: cfg = %#v, err = %v", addr, cfg, err)
		}
	}
}

func TestRoutingObservabilityRuntimeDrainsOnContextCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	runtime := &routingObservabilityRuntime{
		listener: listener,
		server:   &http.Server{Handler: http.NotFoundHandler()},
		observer: routingobs.NewObserver([]byte(strings.Repeat("k", 32)), 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runtime.start(ctx, cancel)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("observability listener did not stop")
	}
}
