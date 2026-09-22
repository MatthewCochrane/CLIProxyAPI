package helps

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestCodexHTTPTimeoutConnect(t *testing.T) {
	client := newTimeoutTestClientWithTransport(t, config.CodexHTTPTimeoutConfig{
		Connect: "40ms", ResponseHeader: "1s", StreamIdle: "1s", Total: "1s",
	}, tracedTimeoutRoundTripper{roundTrip: func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}})

	_, err := client.Get("https://timeout.test/connect/private/path")
	err = NormalizeCodexHTTPTimeout(err)
	assertFixedTimeout(t, err, ErrCodexConnectTimeout)
}

func TestCodexHTTPTimeoutResponseHeader(t *testing.T) {
	client := newTimeoutTestClientWithTransport(t, config.CodexHTTPTimeoutConfig{
		Connect: "1s", ResponseHeader: "40ms", StreamIdle: "1s", Total: "1s",
	}, tracedTimeoutRoundTripper{roundTrip: func(req *http.Request) (*http.Response, error) {
		trace := httptrace.ContextClientTrace(req.Context())
		trace.GotConn(httptrace.GotConnInfo{Conn: &testNetConn{}})
		<-req.Context().Done()
		return nil, req.Context().Err()
	}})

	_, err := client.Get("https://timeout.test/header/private/path")
	err = NormalizeCodexHTTPTimeout(err)
	assertFixedTimeout(t, err, ErrCodexResponseHeaderTimeout)
}

func TestCodexHTTPTimeoutResponseHeaderDoesNotStopAtFirstByte(t *testing.T) {
	client := newTimeoutTestClientWithTransport(t, config.CodexHTTPTimeoutConfig{
		Connect: "1s", ResponseHeader: "40ms", StreamIdle: "1s", Total: "1s",
	}, tracedTimeoutRoundTripper{roundTrip: func(req *http.Request) (*http.Response, error) {
		trace := httptrace.ContextClientTrace(req.Context())
		trace.GotConn(httptrace.GotConnInfo{Conn: &testNetConn{}})
		trace.GotFirstResponseByte()
		<-req.Context().Done()
		return nil, req.Context().Err()
	}})

	_, err := client.Get("https://timeout.test/header/one-byte/private/path")
	assertFixedTimeout(t, NormalizeCodexHTTPTimeout(err), ErrCodexResponseHeaderTimeout)
}

func TestCodexHTTPTimeoutRealTransportPartialHeader(t *testing.T) {
	listener, errListen := net.Listen("tcp", "127.0.0.1:0")
	if errListen != nil {
		t.Fatalf("Listen() error = %v", errListen)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	defer close(serverDone)
	go func() {
		conn, errAccept := listener.Accept()
		if errAccept != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, errRead := reader.ReadString('\n')
			if errRead != nil || line == "\r\n" {
				break
			}
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nX-Partial: yes"))
		<-serverDone
	}()

	cfg := &config.Config{Codex: config.CodexConfig{HTTPTimeouts: config.CodexHTTPTimeoutConfig{
		Connect: "1s", ResponseHeader: "40ms", StreamIdle: "1s", Total: "1s",
	}}}
	client := WrapCodexHTTPClient(&http.Client{Transport: &http.Transport{}}, cfg)
	_, err := client.Get("http://" + listener.Addr().String() + "/private/path")
	assertFixedTimeout(t, NormalizeCodexHTTPTimeout(err), ErrCodexResponseHeaderTimeout)
}

func TestCodexHTTPTimeoutOpaqueRoundTripperUsesHeaderBound(t *testing.T) {
	client := newTimeoutTestClient(t, config.CodexHTTPTimeoutConfig{
		Connect: "20ms", ResponseHeader: "100ms", StreamIdle: "1s", Total: "1s",
	}, func(req *http.Request) (*http.Response, error) {
		time.Sleep(50 * time.Millisecond)
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
	})

	resp, err := client.Get("https://timeout.test/no-trace")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	resp.Body.Close()
}

func TestCodexHTTPTimeoutRejectsRedirectWithoutReplayOrBudgetReset(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetRequests.Add(1)
	}))
	defer target.Close()

	var sourceRequests atomic.Int32
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceRequests.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer private-token" {
			t.Errorf("Authorization = %q", got)
		}
		body, errRead := io.ReadAll(r.Body)
		if errRead != nil {
			t.Errorf("ReadAll() error = %v", errRead)
		}
		if string(body) != "private prompt" {
			t.Errorf("body = %q", body)
		}
		w.Header().Set("Location", target.URL+"/second-hop")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	cfg := &config.Config{Codex: config.CodexConfig{HTTPTimeouts: config.CodexHTTPTimeoutConfig{
		Connect: "1s", ResponseHeader: "1s", StreamIdle: "1s", Total: "40ms",
	}}}
	client := WrapCodexHTTPClient(source.Client(), cfg)
	req, errRequest := http.NewRequest(http.MethodPost, source.URL+"/first-hop", strings.NewReader("private prompt"))
	if errRequest != nil {
		t.Fatalf("NewRequest() error = %v", errRequest)
	}
	req.Header.Set("Authorization", "Bearer private-token")
	resp, errDo := client.Do(req)
	if errDo != nil {
		t.Fatalf("Do() error = %v", errDo)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusTemporaryRedirect)
	}
	if sourceRequests.Load() != 1 || targetRequests.Load() != 0 {
		t.Fatalf("requests = source:%d target:%d, want 1, 0", sourceRequests.Load(), targetRequests.Load())
	}
}

func TestCodexHTTPTimeoutRedirectPreservesStricterPolicy(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetRequests.Add(1)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer source.Close()

	strictErr := errors.New("strict redirect policy")
	checkCalls := 0
	client := source.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		checkCalls++
		return strictErr
	}
	client = WrapCodexHTTPClient(client, nil)
	_, err := client.Get(source.URL)
	if !errors.Is(err, strictErr) || checkCalls != 1 || targetRequests.Load() != 0 {
		t.Fatalf("Get() error = %v, check calls = %d, target requests = %d", err, checkCalls, targetRequests.Load())
	}
}

func TestCodexConnectTimeoutFallsBackWithoutCoolingCredential(t *testing.T) {
	manager := cliproxyauth.NewManager(nil, nil, nil)
	manager.SetRetryConfig(0, 0, 0)
	executor := &connectTimeoutThenSuccessExecutor{firstAuthID: "codex-connect-timeout-first"}
	manager.RegisterExecutor(executor)

	model := fmt.Sprintf("codex-connect-timeout-%d", time.Now().UnixNano())
	auths := []*cliproxyauth.Auth{
		{ID: executor.firstAuthID, Provider: "codex", Status: cliproxyauth.StatusActive, Attributes: map[string]string{"priority": "10"}},
		{ID: "codex-connect-timeout-second", Provider: "codex", Status: cliproxyauth.StatusActive, Attributes: map[string]string{"priority": "1"}},
	}
	for _, auth := range auths {
		registry.GetGlobalRegistry().RegisterClient(auth.ID, "codex", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
		if _, errRegister := manager.Register(t.Context(), auth); errRegister != nil {
			t.Fatalf("Register(%s) error = %v", auth.ID, errRegister)
		}
	}

	resp, errExecute := manager.Execute(t.Context(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if string(resp.Payload) != "ok" || executor.calls != 2 {
		t.Fatalf("Execute() payload = %q, calls = %d; want ok, 2", resp.Payload, executor.calls)
	}
	first, ok := manager.GetByID(executor.firstAuthID)
	if !ok || first.Unavailable || !first.NextRetryAfter.IsZero() {
		t.Fatalf("first credential cooled: found=%t unavailable=%t next-retry=%v", ok, first.Unavailable, first.NextRetryAfter)
	}
}

func TestCodexHTTPTimeoutBodyPreservesBytesWithTimeoutError(t *testing.T) {
	client := newTimeoutTestClient(t, config.CodexHTTPTimeoutConfig{
		Connect: "1s", ResponseHeader: "1s", StreamIdle: "40ms", Total: "1s",
	}, func(req *http.Request) (*http.Response, error) {
		return responseWithPacedBody(req, &bytesOnCancellationBody{ctx: req.Context()}), nil
	})

	resp, err := client.Get("https://timeout.test/body/private/path")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()
	body, errRead := io.ReadAll(resp.Body)
	if string(body) != "x" {
		t.Fatalf("body = %q, want one byte", body)
	}
	assertFixedTimeout(t, errRead, ErrCodexStreamIdleTimeout)
}

func TestCodexHTTPTimeoutStreamIdle(t *testing.T) {
	client := newTimeoutTestClient(t, config.CodexHTTPTimeoutConfig{
		Connect: "1s", ResponseHeader: "1s", StreamIdle: "40ms", Total: "1s",
	}, func(req *http.Request) (*http.Response, error) {
		return responseWithPacedBody(req, &pacedBody{ctx: req.Context(), chunks: -1, delay: time.Second}), nil
	})

	resp, err := client.Get("https://timeout.test/idle/private/path")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	assertFixedTimeout(t, err, ErrCodexStreamIdleTimeout)
}

func TestCodexHTTPTimeoutTotalDespiteActiveReads(t *testing.T) {
	client := newTimeoutTestClient(t, config.CodexHTTPTimeoutConfig{
		Connect: "1s", ResponseHeader: "1s", StreamIdle: "100ms", Total: "40ms",
	}, responseWithContextBody)

	resp, err := client.Get("https://timeout.test/total/private/path")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()
	buffer := make([]byte, 1)
	deadline := time.Now().Add(time.Second)
	for err == nil && time.Now().Before(deadline) {
		_, err = resp.Body.Read(buffer)
	}
	assertFixedTimeout(t, err, ErrCodexTotalTimeout)
}

func TestCodexHTTPTimeoutHealthySuccessAndIdleReset(t *testing.T) {
	client := newTimeoutTestClient(t, config.CodexHTTPTimeoutConfig{
		Connect: "100ms", ResponseHeader: "100ms", StreamIdle: "40ms", Total: "500ms",
	}, func(req *http.Request) (*http.Response, error) {
		trace := httptrace.ContextClientTrace(req.Context())
		trace.GotConn(httptrace.GotConnInfo{})
		trace.GotFirstResponseByte()
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       &pacedBody{ctx: req.Context(), chunks: 3, delay: 25 * time.Millisecond},
			Header:     make(http.Header),
		}, nil
	})

	resp, err := client.Get("https://timeout.test/healthy")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(body) != "xxx" {
		t.Fatalf("body = %q, want %q", body, "xxx")
	}
}

func newTimeoutTestClient(t *testing.T, timeouts config.CodexHTTPTimeoutConfig, roundTrip utlsClientRoundTripFunc) *http.Client {
	return newTimeoutTestClientWithTransport(t, timeouts, roundTrip)
}

func newTimeoutTestClientWithTransport(t *testing.T, timeouts config.CodexHTTPTimeoutConfig, roundTrip http.RoundTripper) *http.Client {
	t.Helper()
	ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", roundTrip)
	return NewCodexHTTPClient(ctx, &config.Config{Codex: config.CodexConfig{HTTPTimeouts: timeouts}}, nil)
}

type tracedTimeoutRoundTripper struct {
	roundTrip utlsClientRoundTripFunc
}

func (t tracedTimeoutRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.roundTrip(req)
}

func (tracedTimeoutRoundTripper) codexConnectTraceReliable(*http.Request) bool { return true }

type testNetConn struct{ net.Conn }

type connectTimeoutThenSuccessExecutor struct {
	firstAuthID string
	calls       int
}

func (*connectTimeoutThenSuccessExecutor) Identifier() string { return "codex" }

func (e *connectTimeoutThenSuccessExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.calls++
	cliproxyexecutor.MarkUpstreamAttempt(ctx)
	if auth.ID == e.firstAuthID {
		cfg := &config.Config{Codex: config.CodexConfig{HTTPTimeouts: config.CodexHTTPTimeoutConfig{
			Connect: "30ms", ResponseHeader: "1s", StreamIdle: "1s", Total: "1s",
		}}}
		client := WrapCodexHTTPClient(&http.Client{Transport: tracedTimeoutRoundTripper{roundTrip: func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		}}}, cfg)
		_, err := client.Get("https://timeout.test/manager/private/path")
		return cliproxyexecutor.Response{}, NormalizeCodexHTTPTimeout(err)
	}
	return cliproxyexecutor.Response{Payload: []byte("ok")}, nil
}

func (*connectTimeoutThenSuccessExecutor) ExecuteStream(context.Context, *cliproxyauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, errors.New("not implemented")
}

func (*connectTimeoutThenSuccessExecutor) Refresh(_ context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	return auth, nil
}

func (*connectTimeoutThenSuccessExecutor) CountTokens(context.Context, *cliproxyauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, errors.New("not implemented")
}

func (*connectTimeoutThenSuccessExecutor) HttpRequest(context.Context, *cliproxyauth.Auth, *http.Request) (*http.Response, error) {
	return nil, errors.New("not implemented")
}

func responseWithContextBody(req *http.Request) (*http.Response, error) {
	return responseWithPacedBody(req, &pacedBody{ctx: req.Context(), chunks: -1, delay: 10 * time.Millisecond}), nil
}

func responseWithPacedBody(req *http.Request, body io.ReadCloser) *http.Response {
	trace := httptrace.ContextClientTrace(req.Context())
	trace.GotConn(httptrace.GotConnInfo{})
	trace.GotFirstResponseByte()
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       body,
		Header:     make(http.Header),
	}
}

type pacedBody struct {
	ctx    context.Context
	chunks int
	delay  time.Duration
}

func (b *pacedBody) Read(p []byte) (int, error) {
	if b.chunks == 0 {
		return 0, io.EOF
	}
	select {
	case <-b.ctx.Done():
		return 0, b.ctx.Err()
	case <-time.After(b.delay):
		if b.chunks > 0 {
			b.chunks--
		}
		p[0] = 'x'
		return 1, nil
	}
}

func (*pacedBody) Close() error { return nil }

type bytesOnCancellationBody struct {
	ctx  context.Context
	done bool
}

func (b *bytesOnCancellationBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, io.EOF
	}
	b.done = true
	<-b.ctx.Done()
	p[0] = 'x'
	return 1, b.ctx.Err()
}

func (*bytesOnCancellationBody) Close() error { return nil }

func assertFixedTimeout(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
	if got.Error() != want.Error() {
		t.Fatalf("timeout error = %q, want fixed %q", got, want)
	}
	var requestScoped interface{ IsRequestScoped() bool }
	if want == ErrCodexConnectTimeout {
		if errors.As(got, &requestScoped) && requestScoped.IsRequestScoped() {
			t.Fatalf("connect timeout error %T is request-scoped", got)
		}
		var netErr net.Error
		if !errors.As(got, &netErr) || !netErr.Timeout() {
			t.Fatalf("connect timeout error %T is not a timeout net.Error", got)
		}
	} else if !errors.As(got, &requestScoped) || !requestScoped.IsRequestScoped() {
		t.Fatalf("timeout error %T is not request-scoped", got)
	}
	for _, secret := range []string{"private", "/path", "timeout.test"} {
		if strings.Contains(got.Error(), secret) {
			t.Fatalf("timeout error leaked %q: %q", secret, got)
		}
	}
}
