package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	routingobs "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/observability"
)

const enrollmentPath = routingobs.ControlEnrollmentPath

type deviceLogin func(context.Context, func(string, string) error) (*codex.CodexTokenStorage, error)
type accountCommit func(*codex.CodexTokenStorage, string) (string, error)

type enrollmentAttempt struct {
	id           string
	expected     string
	expectedHash [32]byte
	state        string
	code         string
	url          string
	expires      time.Time
	cancel       context.CancelFunc
	done         chan struct{}
}

type enrollmentController struct {
	mu      sync.Mutex
	attempt *enrollmentAttempt
	// Cancelled IDs fence a delayed start after an absent-worker acknowledgement.
	// A full fence fails closed; it is reset only when the listener restarts,
	// which also terminates connections to the former listener.
	cancelled map[string]struct{}
	closed    bool
	parent    context.Context
	login     deviceLogin
	commit    accountCommit
	preflight func(string) error
	present   func(string) (bool, error)
	authDir   string
}

func newEnrollmentController(cfg *config.Config) *enrollmentController {
	authDir := cfg.AuthDir
	return &enrollmentController{
		authDir: authDir,
		login: func(ctx context.Context, challenge func(string, string) error) (*codex.CodexTokenStorage, error) {
			authenticator := sdkauth.NewCodexAuthenticator()
			record, err := authenticator.Login(ctx, cfg, &sdkauth.LoginOptions{
				NoBrowser:         true,
				Metadata:          map[string]string{"codex_login_mode": "device"},
				OnCodexDeviceCode: challenge,
			})
			if err != nil || record == nil {
				return nil, err
			}
			storage, _ := record.Storage.(*codex.CodexTokenStorage)
			return storage, nil
		},
		commit: func(storage *codex.CodexTokenStorage, identity string) (string, error) {
			return storage.SaveNewAccountTokenToDir(authDir, identity)
		},
		preflight: func(identity string) error {
			return codex.CheckAccountNotPresentInDir(authDir, identity)
		},
		present: func(identity string) (bool, error) {
			return codex.AccountPresentInDir(authDir, identity)
		},
	}
}

func (c *enrollmentController) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.attempt != nil {
		c.attempt.cancel()
		c.attempt.expected = ""
		c.attempt.code = ""
	}
}

func (c *enrollmentController) bindService(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.parent = ctx
}

// handle is called only after the distinct, local-only control bearer and
// browser/request-shape checks have succeeded. It never returns raw provider
// errors, token material, account identities, or credential paths.
func (c *enrollmentController) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeEnrollmentError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	consume := r.Header.Get("X-Consume-Challenge")
	if consume != "" && (r.Method != http.MethodGet || consume != "1") {
		writeEnrollmentError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if r.URL.Path == enrollmentPath && r.Method == http.MethodPost {
		c.start(w, r)
		return
	}
	if r.URL.Path == enrollmentPath+"/match" && r.Method == http.MethodPost {
		c.match(w, r)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, enrollmentPath+"/")
	if len(id) != 32 || !strings.HasPrefix(r.URL.Path, enrollmentPath+"/") || !isLowerHex(id) {
		writeEnrollmentError(w, http.StatusNotFound, "not_found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		c.status(w, id, consume == "1")
	case http.MethodDelete:
		c.cancel(w, id)
	default:
		writeEnrollmentError(w, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (c *enrollmentController) start(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		writeEnrollmentError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 513))
	if err != nil || len(body) > 512 {
		writeEnrollmentError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	var request struct {
		AttemptID         string `json:"attemptId"`
		ExpectedAccountID string `json:"expectedAccountId"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || len(request.AttemptID) != 32 || !isLowerHex(request.AttemptID) || !validExpectedAccountID(request.ExpectedAccountID) {
		writeEnrollmentError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	expectedHash := sha256.Sum256([]byte(request.ExpectedAccountID))
	c.mu.Lock()
	if _, cancelled := c.cancelled[request.AttemptID]; cancelled {
		c.mu.Unlock()
		writeEnrollmentError(w, http.StatusConflict, "cancelled")
		return
	}
	if c.attempt != nil && c.attempt.id == request.AttemptID {
		if c.attempt.expectedHash != expectedHash {
			c.mu.Unlock()
			writeEnrollmentError(w, http.StatusConflict, "conflict")
			return
		}
		state := c.attempt.state
		c.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(struct {
			ID    string `json:"id"`
			State string `json:"state"`
		}{request.AttemptID, state})
		return
	}
	c.mu.Unlock()
	if c.preflight != nil {
		if err := c.preflight(request.ExpectedAccountID); err != nil {
			if errors.Is(err, codex.ErrCodexAccountExists) {
				writeEnrollmentError(w, http.StatusConflict, "already_connected")
			} else {
				writeEnrollmentError(w, http.StatusServiceUnavailable, "unavailable")
			}
			return
		}
	}
	if r.Context().Err() != nil {
		writeEnrollmentError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	c.mu.Lock()
	parent := c.parent
	if parent == nil {
		parent = context.Background()
	}
	if c.closed || parent.Err() != nil {
		c.mu.Unlock()
		writeEnrollmentError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
	attempt := &enrollmentAttempt{id: request.AttemptID, expected: request.ExpectedAccountID, expectedHash: expectedHash, state: "pending", expires: time.Now().Add(15 * time.Minute), cancel: cancel, done: make(chan struct{})}
	c.mu.Lock()
	_, cancelled := c.cancelled[request.AttemptID]
	if c.closed || parent.Err() != nil || c.attempt != nil || cancelled {
		c.mu.Unlock()
		cancel()
		writeEnrollmentError(w, http.StatusConflict, "in_progress")
		return
	}
	c.attempt = attempt
	c.mu.Unlock()
	go c.run(ctx, attempt)
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(struct {
		ID    string `json:"id"`
		State string `json:"state"`
	}{attempt.id, "pending"})
}

func (c *enrollmentController) match(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" || c.present == nil {
		writeEnrollmentError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	var request struct {
		ExpectedAccountID string `json:"expectedAccountId"`
	}
	if !readPrivateControlJSON(r.Body, &request) || !validExpectedAccountID(request.ExpectedAccountID) {
		writeEnrollmentError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	present, err := c.present(request.ExpectedAccountID)
	if err != nil {
		writeEnrollmentError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	_ = json.NewEncoder(w).Encode(struct {
		Present bool `json:"present"`
	}{present})
}

func (c *enrollmentController) run(ctx context.Context, attempt *enrollmentAttempt) {
	defer func() { attempt.cancel(); close(attempt.done) }()
	storage, err := c.login(ctx, func(url, code string) error {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.closed || c.attempt != attempt || ctx.Err() != nil || attempt.state != "pending" || url != "https://auth.openai.com/codex/device" || !validChallenge(code) {
			return errors.New("challenge rejected")
		}
		attempt.url, attempt.code, attempt.state = url, code, "awaiting_authorization"
		return nil
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.attempt != attempt || attempt.state == "cancelled" || ctx.Err() != nil {
		return
	}
	attempt.code = ""
	if err != nil || storage == nil || attempt.expected == "" || attempt.state != "awaiting_authorization" {
		attempt.state = "failed"
		attempt.expected = ""
		return
	}
	_, err = c.commit(storage, attempt.expected)
	attempt.expected = ""
	switch {
	case err == nil:
		attempt.state = "committed"
	case errors.Is(err, codex.ErrTokenCommitDurabilityUncertain):
		attempt.state = "commit_uncertain"
	default:
		attempt.state = "failed"
	}
}

func (c *enrollmentController) status(w http.ResponseWriter, id string, consume bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a := c.current(id)
	if a == nil {
		writeEnrollmentError(w, http.StatusNotFound, "not_found")
		return
	}
	result := struct {
		State string `json:"state"`
		URL   string `json:"verificationUrl,omitempty"`
		Code  string `json:"code,omitempty"`
	}{State: a.state}
	if consume && a.state == "awaiting_authorization" && a.code != "" {
		result.URL, result.Code = a.url, a.code
		a.code = "" // The challenge is delivered at most once.
	}
	_ = json.NewEncoder(w).Encode(result)
}

func (c *enrollmentController) cancel(w http.ResponseWriter, id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, cancelled := c.cancelled[id]; cancelled {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	a := c.current(id)
	if a == nil {
		if !c.rememberCancelled(id) {
			writeEnrollmentError(w, http.StatusServiceUnavailable, "unavailable")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if a.state == "committed" || a.state == "commit_uncertain" {
		// Acknowledgement does not revoke or undo an authoritative commit.
		c.attempt = nil
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !c.rememberCancelled(id) {
		writeEnrollmentError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	a.cancel()
	a.state, a.code, a.expected = "cancelled", "", ""
	c.attempt = nil
	w.WriteHeader(http.StatusNoContent)
}

// The caller holds c.mu. Refuse to acknowledge cancellation when the bounded
// in-process fence cannot be retained; an unknown late POST must remain unsafe.
func (c *enrollmentController) rememberCancelled(id string) bool {
	if c.cancelled == nil {
		c.cancelled = make(map[string]struct{})
	}
	if len(c.cancelled) >= 1024 {
		return false
	}
	c.cancelled[id] = struct{}{}
	return true
}

func (c *enrollmentController) current(id string) *enrollmentAttempt {
	if c.closed || c.attempt == nil || c.attempt.id != id {
		return nil
	}
	if time.Now().After(c.attempt.expires) && c.attempt.state != "committed" && c.attempt.state != "commit_uncertain" {
		c.attempt.cancel()
		c.attempt.state, c.attempt.code, c.attempt.expected = "expired", "", ""
	}
	return c.attempt
}

func validExpectedAccountID(identity string) bool {
	if len(identity) < 1 || len(identity) > 256 || strings.TrimSpace(identity) != identity {
		return false
	}
	for i := range identity {
		if identity[i] < 33 || identity[i] > 126 {
			return false
		}
	}
	return true
}

func validChallenge(code string) bool {
	if len(code) < 4 || len(code) > 64 {
		return false
	}
	for i := range code {
		ch := code[i]
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
			return false
		}
	}
	return true
}

func isLowerHex(value string) bool {
	for i := range value {
		if value[i] < '0' || value[i] > '9' && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}

func writeEnrollmentError(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{code})
}
