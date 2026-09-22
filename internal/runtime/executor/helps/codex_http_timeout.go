package helps

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type codexHTTPTimeoutError string

func (e codexHTTPTimeoutError) Error() string       { return string(e) }
func (codexHTTPTimeoutError) IsRequestScoped() bool { return true }

type codexHTTPConnectTimeoutError string

func (e codexHTTPConnectTimeoutError) Error() string { return string(e) }
func (codexHTTPConnectTimeoutError) Timeout() bool   { return true }
func (codexHTTPConnectTimeoutError) Temporary() bool { return true }

const (
	ErrCodexConnectTimeout        codexHTTPConnectTimeoutError = "codex upstream connect timeout"
	ErrCodexResponseHeaderTimeout codexHTTPTimeoutError        = "codex upstream response header timeout"
	ErrCodexStreamIdleTimeout     codexHTTPTimeoutError        = "codex upstream stream idle timeout"
	ErrCodexTotalTimeout          codexHTTPTimeoutError        = "codex upstream total timeout"
)

// NewCodexHTTPClient preserves the proxy, context RoundTripper, and uTLS selection
// of NewUtlsHTTPClient while bounding every Codex HTTP Responses request phase.
func NewCodexHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth) *http.Client {
	return WrapCodexHTTPClient(NewUtlsHTTPClient(ctx, cfg, auth, 0), cfg)
}

// WrapCodexHTTPClient adds Codex request bounds without changing the client's
// existing proxy or transport selection.
func WrapCodexHTTPClient(client *http.Client, cfg *config.Config) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	timeouts := config.CodexHTTPTimeoutConfig{}.Durations()
	if cfg != nil {
		timeouts = cfg.Codex.HTTPTimeouts.Durations()
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client.Transport = &codexTimeoutRoundTripper{base: base, timeouts: timeouts}
	existingCheckRedirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if existingCheckRedirect != nil {
			if err := existingCheckRedirect(req, via); err != nil {
				return err
			}
		}
		return http.ErrUseLastResponse
	}
	return client
}

// NormalizeCodexHTTPTimeout removes net/http's URL-bearing wrapper while retaining
// fixed errors that callers can classify with errors.Is.
func NormalizeCodexHTTPTimeout(err error) error {
	for _, timeoutErr := range []error{
		ErrCodexConnectTimeout,
		ErrCodexResponseHeaderTimeout,
		ErrCodexStreamIdleTimeout,
		ErrCodexTotalTimeout,
	} {
		if errors.Is(err, timeoutErr) {
			return timeoutErr
		}
	}
	return err
}

// IsCodexHTTPTimeout reports whether err is one of the fixed timeout classes.
func IsCodexHTTPTimeout(err error) bool {
	return errors.Is(err, ErrCodexConnectTimeout) ||
		errors.Is(err, ErrCodexResponseHeaderTimeout) ||
		errors.Is(err, ErrCodexStreamIdleTimeout) ||
		errors.Is(err, ErrCodexTotalTimeout)
}

type codexTimeoutRoundTripper struct {
	base     http.RoundTripper
	timeouts config.CodexHTTPTimeoutDurations
}

// codexConnectTraceReporter is implemented only by transports that can reliably
// report completion of connection establishment through httptrace.GotConn.
type codexConnectTraceReporter interface {
	codexConnectTraceReliable(*http.Request) bool
}

func codexTransportConnectTraceReliable(transport http.RoundTripper, req *http.Request) bool {
	if transport == nil {
		transport = http.DefaultTransport
	}
	if _, ok := transport.(*http.Transport); ok {
		return true
	}
	reporter, ok := transport.(codexConnectTraceReporter)
	return ok && reporter.codexConnectTraceReliable(req)
}

func (t *codexTimeoutRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancelCause(req.Context())
	state := &codexRequestTimeoutState{cancel: cancel, idle: t.timeouts.StreamIdle}
	state.totalTimer = time.AfterFunc(t.timeouts.Total, func() { state.expire(ErrCodexTotalTimeout) })
	connectTraceReliable := codexTransportConnectTraceReliable(t.base, req)
	if connectTraceReliable {
		state.startPhaseWait(t.timeouts.Connect, ErrCodexConnectTimeout)
	} else {
		// An opaque RoundTripper cannot reliably separate connection setup from
		// header waiting. Conservatively apply the header bound to the whole call.
		state.startPhaseWait(t.timeouts.ResponseHeader, ErrCodexResponseHeaderTimeout)
	}

	trace := &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) {
			if connectTraceReliable {
				state.startHeaderWait(t.timeouts.ResponseHeader)
			}
		},
		// A first byte is not a complete response header block. Header timing ends
		// only when RoundTrip returns the parsed response.
		GotFirstResponseByte: func() {},
	}
	resp, err := t.base.RoundTrip(req.WithContext(httptrace.WithClientTrace(ctx, trace)))
	state.finishHeaderWait()
	if timeoutErr := state.timeoutError(); timeoutErr != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		state.finish()
		return nil, timeoutErr
	}
	if err != nil {
		state.finish()
		return nil, err
	}
	if resp == nil {
		state.finish()
		return nil, errors.New("codex upstream returned an empty response")
	}
	if resp.Body == nil || resp.Body == http.NoBody {
		state.finish()
		return resp, nil
	}
	resp.Body = &codexTimeoutBody{ReadCloser: resp.Body, state: state}
	state.startIdleWait()
	return resp, nil
}

type codexRequestTimeoutState struct {
	mu         sync.Mutex
	cancel     context.CancelCauseFunc
	idle       time.Duration
	totalTimer *time.Timer
	phaseTimer *time.Timer
	idleTimer  *time.Timer
	phaseGen   uint64
	idleGen    uint64
	timeoutErr error
	done       bool
}

func (s *codexRequestTimeoutState) expire(err error) {
	s.mu.Lock()
	if s.done || s.timeoutErr != nil {
		s.mu.Unlock()
		return
	}
	s.timeoutErr = err
	s.cancel(err)
	s.mu.Unlock()
}

func (s *codexRequestTimeoutState) startHeaderWait(timeout time.Duration) {
	s.startPhaseWait(timeout, ErrCodexResponseHeaderTimeout)
}

func (s *codexRequestTimeoutState) startPhaseWait(timeout time.Duration, timeoutErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.timeoutErr != nil {
		return
	}
	if s.phaseTimer != nil {
		s.phaseTimer.Stop()
	}
	s.phaseGen++
	generation := s.phaseGen
	s.phaseTimer = time.AfterFunc(timeout, func() { s.expirePhase(generation, timeoutErr) })
}

func (s *codexRequestTimeoutState) expirePhase(generation uint64, err error) {
	s.mu.Lock()
	if s.done || s.timeoutErr != nil || generation != s.phaseGen {
		s.mu.Unlock()
		return
	}
	s.timeoutErr = err
	s.cancel(err)
	s.mu.Unlock()
}

func (s *codexRequestTimeoutState) finishHeaderWait() {
	s.mu.Lock()
	s.phaseGen++
	if s.phaseTimer != nil {
		s.phaseTimer.Stop()
		s.phaseTimer = nil
	}
	s.mu.Unlock()
}

func (s *codexRequestTimeoutState) startIdleWait() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.timeoutErr != nil {
		return
	}
	s.resetIdleTimerLocked()
}

func (s *codexRequestTimeoutState) successfulRead() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.timeoutErr != nil {
		return
	}
	s.resetIdleTimerLocked()
}

func (s *codexRequestTimeoutState) resetIdleTimerLocked() {
	if s.idleTimer != nil {
		s.idleTimer.Stop()
	}
	s.idleGen++
	generation := s.idleGen
	s.idleTimer = time.AfterFunc(s.idle, func() { s.expireIdle(generation) })
}

func (s *codexRequestTimeoutState) expireIdle(generation uint64) {
	s.mu.Lock()
	if s.done || s.timeoutErr != nil || generation != s.idleGen {
		s.mu.Unlock()
		return
	}
	s.timeoutErr = ErrCodexStreamIdleTimeout
	s.cancel(ErrCodexStreamIdleTimeout)
	s.mu.Unlock()
}

func (s *codexRequestTimeoutState) timeoutError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.timeoutErr
}

func (s *codexRequestTimeoutState) finish() {
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		return
	}
	s.done = true
	s.phaseGen++
	s.idleGen++
	if s.totalTimer != nil {
		s.totalTimer.Stop()
	}
	if s.phaseTimer != nil {
		s.phaseTimer.Stop()
	}
	if s.idleTimer != nil {
		s.idleTimer.Stop()
	}
	s.cancel(nil)
	s.mu.Unlock()
}

type codexTimeoutBody struct {
	io.ReadCloser
	state *codexRequestTimeoutState
}

func (b *codexTimeoutBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.state.successfulRead()
	}
	if timeoutErr := b.state.timeoutError(); timeoutErr != nil {
		return n, timeoutErr
	}
	if errors.Is(err, io.EOF) {
		b.state.finish()
	}
	return n, err
}

func (b *codexTimeoutBody) Close() error {
	err := b.ReadCloser.Close()
	b.state.finish()
	return err
}
