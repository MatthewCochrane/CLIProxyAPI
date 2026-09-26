package cmd

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
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

func TestLoadControlConfigFailClosed(t *testing.T) {
	routing := &routingObservabilityConfig{addr: "127.0.0.1:9191", token: strings.Repeat("r", 32), hmacKey: []byte(strings.Repeat("h", 32))}
	valid := map[string]string{controlAddrEnv: "127.0.0.1:9192", controlTokenEnv: strings.Repeat("c", 32)}
	if cfg, err := loadControlConfig(envLookup(nil), routing); err != nil || cfg != nil {
		t.Fatalf("disabled control = %#v, %v", cfg, err)
	}
	for _, addr := range []string{"127.0.0.1:9192", "[::1]:9192"} {
		values := map[string]string{controlAddrEnv: addr, controlTokenEnv: valid[controlTokenEnv]}
		if cfg, err := loadControlConfig(envLookup(values), routing); err != nil || cfg == nil || cfg.addr != addr {
			t.Fatalf("private loopback %s: cfg = %#v, error = %v", addr, cfg, err)
		}
	}
	withEnrollment := map[string]string{controlAddrEnv: valid[controlAddrEnv], controlTokenEnv: valid[controlTokenEnv], controlEnrollmentEnv: "true"}
	if cfg, err := loadControlConfig(envLookup(withEnrollment), routing); err != nil || cfg == nil || !cfg.enrollment {
		t.Fatal("explicit private enrollment was not admitted")
	}
	if cfg, err := loadControlConfig(envLookup(map[string]string{controlEnrollmentEnv: "true"}), routing); err == nil || cfg != nil {
		t.Fatal("enrollment flag enabled without independent control credentials")
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]string)
		route  *routingObservabilityConfig
	}{
		{"no observer", func(map[string]string) {}, nil},
		{"partial", func(v map[string]string) { delete(v, controlTokenEnv) }, routing},
		{"empty", func(v map[string]string) { v[controlTokenEnv] = "" }, routing},
		{"short", func(v map[string]string) { v[controlTokenEnv] = "short" }, routing},
		{"shared observer bearer", func(v map[string]string) { v[controlTokenEnv] = routing.token }, routing},
		{"shared handle key", func(v map[string]string) { v[controlTokenEnv] = string(routing.hmacKey) }, routing},
		{"shared listener", func(v map[string]string) { v[controlAddrEnv] = routing.addr }, routing},
		{"wildcard", func(v map[string]string) { v[controlAddrEnv] = "0.0.0.0:9192" }, routing},
		{"hostname", func(v map[string]string) { v[controlAddrEnv] = "localhost:9192" }, routing},
		{"zero port", func(v map[string]string) { v[controlAddrEnv] = "127.0.0.1:0" }, routing},
		{"malformed enrollment flag", func(v map[string]string) { v[controlEnrollmentEnv] = "yes" }, routing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]string{controlAddrEnv: valid[controlAddrEnv], controlTokenEnv: valid[controlTokenEnv]}
			tc.mutate(values)
			if cfg, err := loadControlConfig(envLookup(values), tc.route); err == nil || cfg != nil {
				t.Fatalf("config = %#v, err = %v; want rejection", cfg, err)
			}
		})
	}
}

func TestControlEnrollmentRuntimeAdmissionIsDefaultOffAndRequiresPrivateAuthDir(t *testing.T) {
	routingPort, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controlPort, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = routingPort.Close()
		t.Fatal(err)
	}
	t.Setenv(observabilityAddrEnv, routingPort.Addr().String())
	t.Setenv(observabilityTokenEnv, strings.Repeat("r", 32))
	t.Setenv(observabilityHMACKeyEnv, strings.Repeat("h", 32))
	t.Setenv(controlAddrEnv, controlPort.Addr().String())
	t.Setenv(controlTokenEnv, strings.Repeat("c", 32))
	t.Setenv(controlEnrollmentEnv, "false")
	_ = routingPort.Close()
	_ = controlPort.Close()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	runtime, err := newRoutingObservabilityRuntime(&config.Config{AuthDir: dir})
	if err != nil || runtime == nil || runtime.enrollment != nil {
		t.Fatalf("default-off listener = %v, %v", runtime, err)
	}
	runtime.close()
	t.Setenv(controlEnrollmentEnv, "true")
	if runtime, err := newRoutingObservabilityRuntime(&config.Config{AuthDir: "/nonexistent-private-auth-dir"}); err == nil || runtime != nil {
		t.Fatal("enrollment admitted a missing auth directory")
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime, err := newRoutingObservabilityRuntime(&config.Config{AuthDir: dir}); err == nil || runtime != nil {
		t.Fatal("enrollment admitted a group-readable auth directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	runtime, err = newRoutingObservabilityRuntime(&config.Config{AuthDir: dir})
	if err != nil || runtime == nil || runtime.enrollment == nil {
		t.Fatalf("private enrollment listener = %v, %v", runtime, err)
	}
	runtime.close()
}

func TestControlAndRoutingListenersShutDownTogether(t *testing.T) {
	routingListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controlListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = routingListener.Close()
		t.Fatal(err)
	}
	runtime := &routingObservabilityRuntime{
		listener: routingListener, server: &http.Server{Handler: http.NotFoundHandler()},
		controlListener: controlListener, controlServer: &http.Server{Handler: http.NotFoundHandler()},
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
		t.Fatal("control and observer listeners did not stop")
	}
}

func TestPrivateControlListenerDoesNotAcceptObserverBearer(t *testing.T) {
	routingListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controlListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = routingListener.Close()
		t.Fatal(err)
	}
	observer := routingobs.NewObserver([]byte(strings.Repeat("h", 32)), 24)
	routingToken, controlToken := strings.Repeat("r", 32), strings.Repeat("c", 32)
	runtime := &routingObservabilityRuntime{
		listener: routingListener, server: &http.Server{Handler: observer.Handler(routingToken)},
		controlListener: controlListener, controlServer: newControlServer(observer, controlToken),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runtime.start(ctx, cancel)
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("shutdown returned %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("listeners did not shut down")
		}
	}()
	client := &http.Client{Timeout: time.Second}
	for _, tc := range []struct {
		addr, path, token string
		want              int
	}{
		{controlListener.Addr().String(), routingobs.ControlHealthPath, controlToken, 200},
		{controlListener.Addr().String(), routingobs.ControlStatePath, routingToken, 401},
		{routingListener.Addr().String(), routingobs.SnapshotPath, controlToken, 401},
		{routingListener.Addr().String(), routingobs.ControlStatePath, routingToken, 404},
		{controlListener.Addr().String(), "/v0/management/auth-files", controlToken, 404},
	} {
		request, err := http.NewRequest("GET", "http://"+tc.addr+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+tc.token)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != tc.want {
			t.Fatalf("%s on %s returned %d, want %d", tc.path, tc.addr, response.StatusCode, tc.want)
		}
	}
}
