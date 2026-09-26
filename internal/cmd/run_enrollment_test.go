package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	routingobs "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/observability"
)

const testControlBearer = "separate-local-control-token-with-32-bytes"
const testEnrollmentAttemptID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func enrollmentStartBody(id, account string) string {
	return `{"attemptId":"` + id + `","expectedAccountId":"` + account + `"}`
}

func enrollmentRequest(handler http.Handler, method, path, bearer, body string, consume ...bool) *httptest.ResponseRecorder {
	record := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:54123"
	request.Header.Set("Authorization", "Bearer "+bearer)
	if len(consume) != 0 && consume[0] {
		request.Header.Set("X-Consume-Challenge", "1")
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	handler.ServeHTTP(record, request)
	return record
}

func enrollmentHandler(c *enrollmentController) http.Handler {
	observer := routingobs.NewObserver([]byte(strings.Repeat("h", 32)), 24)
	return observer.ControlHandlerWithEnrollment(testControlBearer, http.HandlerFunc(c.handle))
}

func testEnrollmentStorage(identity string) *codex.CodexTokenStorage {
	claims := `{"https://api.openai.com/auth":{"chatgpt_account_id":"` + identity + `"}}`
	return &codex.CodexTokenStorage{
		AccountID:    identity,
		IDToken:      "header." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".signature",
		AccessToken:  "private-access",
		RefreshToken: "private-refresh",
	}
}

func startEnrollment(t *testing.T, handler http.Handler) string {
	t.Helper()
	response := enrollmentRequest(handler, http.MethodPost, enrollmentPath, testControlBearer, enrollmentStartBody(testEnrollmentAttemptID, "private-account"))
	if response.Code != http.StatusAccepted || strings.Contains(response.Body.String(), "private-account") {
		t.Fatalf("start status = %d; expected private accepted response", response.Code)
	}
	var parsed struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(response.Body.Bytes(), &parsed) != nil || len(parsed.ID) != 32 {
		t.Fatal("start did not return an opaque bounded handle")
	}
	return parsed.ID
}

func waitForEnrollmentState(t *testing.T, handler http.Handler, id, state string) *httptest.ResponseRecorder {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		response := enrollmentRequest(handler, http.MethodGet, enrollmentPath+"/"+id, testControlBearer, "")
		if response.Code == http.StatusOK && strings.Contains(response.Body.String(), `"state":"`+state+`"`) {
			return response
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("attempt did not reach %s", state)
	return nil
}

func TestPrivateEnrollmentAbsentCancellationFencesDelayedStart(t *testing.T) {
	var logins atomic.Int32
	c := &enrollmentController{login: func(context.Context, func(string, string) error) (*codex.CodexTokenStorage, error) {
		logins.Add(1)
		return nil, errors.New("unexpected login")
	}}
	handler := enrollmentHandler(c)
	path := enrollmentPath + "/" + testEnrollmentAttemptID
	if response := enrollmentRequest(handler, http.MethodDelete, path, testControlBearer, ""); response.Code != http.StatusNoContent {
		t.Fatalf("absent cancellation status = %d", response.Code)
	}
	if response := enrollmentRequest(handler, http.MethodDelete, path, testControlBearer, ""); response.Code != http.StatusNoContent {
		t.Fatalf("idempotent cancellation status = %d", response.Code)
	}
	if response := enrollmentRequest(handler, http.MethodPost, enrollmentPath, testControlBearer, enrollmentStartBody(testEnrollmentAttemptID, "private-account")); response.Code != http.StatusConflict {
		t.Fatalf("late start status = %d", response.Code)
	}
	if logins.Load() != 0 {
		t.Fatal("late start initiated an OAuth family")
	}
	c.mu.Lock()
	for len(c.cancelled) < 1024 {
		id := fmt.Sprintf("%032x", len(c.cancelled)+1)
		c.cancelled[id] = struct{}{}
	}
	c.mu.Unlock()
	if response := enrollmentRequest(handler, http.MethodDelete, enrollmentPath+"/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", testControlBearer, ""); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("full cancellation fence status = %d", response.Code)
	}
}

func TestPrivateEnrollmentChallengeOneTimeAndExactCommit(t *testing.T) {
	release := make(chan struct{})
	var saves atomic.Int32
	c := &enrollmentController{
		login: func(_ context.Context, deliver func(string, string) error) (*codex.CodexTokenStorage, error) {
			if err := deliver("https://auth.openai.com/codex/device", "PRIVATE-CODE"); err != nil {
				return nil, err
			}
			<-release
			return testEnrollmentStorage("private-account"), nil
		},
		commit: func(storage *codex.CodexTokenStorage, expected string) (string, error) {
			if storage.AccountID != expected || expected != "private-account" {
				t.Error("commit did not receive exactly the transient expected identity")
			}
			saves.Add(1)
			return "/private/credential", nil
		},
	}
	defer c.close()
	handler := enrollmentHandler(c)
	if got := enrollmentRequest(handler, http.MethodPost, enrollmentPath, "wrong-token", enrollmentStartBody(testEnrollmentAttemptID, "private-account")); got.Code != 401 {
		t.Fatal("wrong bearer reached enrollment")
	}
	id := startEnrollment(t, handler)
	if got := enrollmentRequest(handler, http.MethodPost, enrollmentPath, testControlBearer, enrollmentStartBody(id, "private-account")); got.Code != http.StatusAccepted || strings.Contains(got.Body.String(), "private-account") {
		t.Fatal("exact retry did not return the existing attempt privately")
	}
	if got := enrollmentRequest(handler, http.MethodPost, enrollmentPath, testControlBearer, enrollmentStartBody(id, "other-account")); got.Code != http.StatusConflict {
		t.Fatal("attempt id was accepted for a different stable identity")
	}
	if got := enrollmentRequest(handler, http.MethodPost, enrollmentPath, testControlBearer, enrollmentStartBody("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "private-account")); got.Code != 409 {
		t.Fatal("second simultaneous attempt admitted")
	}
	first := waitForEnrollmentState(t, handler, id, "awaiting_authorization")
	if strings.Contains(first.Body.String(), "PRIVATE-CODE") {
		t.Fatal("status reconciliation consumed the transient challenge")
	}
	first = enrollmentRequest(handler, http.MethodGet, enrollmentPath+"/"+id, testControlBearer, "", true)
	if !strings.Contains(first.Body.String(), "PRIVATE-CODE") || strings.Contains(first.Body.String(), "private-account") {
		t.Fatal("explicit challenge read did not deliver privately")
	}
	second := enrollmentRequest(handler, http.MethodGet, enrollmentPath+"/"+id, testControlBearer, "", true)
	if second.Code != 200 || strings.Contains(second.Body.String(), "PRIVATE-CODE") {
		t.Fatal("one-time challenge was redelivered")
	}
	close(release)
	completed := waitForEnrollmentState(t, handler, id, "committed")
	if saves.Load() != 1 || strings.Contains(completed.Body.String(), "PRIVATE-CODE") || strings.Contains(completed.Body.String(), "private-account") || strings.Contains(completed.Body.String(), "/private/") {
		t.Fatal("completed attempt leaked sensitive state or did not commit exactly once")
	}
	if ack := enrollmentRequest(handler, http.MethodDelete, enrollmentPath+"/"+id, testControlBearer, ""); ack.Code != 204 {
		t.Fatal("committed attempt was not acknowledged")
	}
}

func TestPrivateEnrollmentIdentityMatchReturnsOnlyPresence(t *testing.T) {
	c := &enrollmentController{
		present: func(identity string) (bool, error) {
			if identity != "private-account" {
				t.Fatal("private identity was not passed internally")
			}
			return true, nil
		},
	}
	defer c.close()
	response := enrollmentRequest(enrollmentHandler(c), http.MethodPost, enrollmentPath+"/match", testControlBearer, `{"expectedAccountId":"private-account"}`)
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"present":true}` || strings.Contains(response.Body.String(), "private-account") {
		t.Fatal("identity presence response was not minimal and private")
	}
	c.present = func(string) (bool, error) { return false, errors.New("PRIVATE-INVENTORY") }
	response = enrollmentRequest(enrollmentHandler(c), http.MethodPost, enrollmentPath+"/match", testControlBearer, `{"expectedAccountId":"private-account"}`)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "PRIVATE-INVENTORY") || strings.Contains(response.Body.String(), "private-account") {
		t.Fatal("identity inventory failure was not fixed and private")
	}
}

func TestPrivateEnrollmentCancelAndShutdownFenceLateCompletion(t *testing.T) {
	for _, operation := range []string{"cancel", "shutdown", "service context"} {
		t.Run(operation, func(t *testing.T) {
			release := make(chan struct{})
			var saves atomic.Int32
			c := &enrollmentController{
				login: func(_ context.Context, deliver func(string, string) error) (*codex.CodexTokenStorage, error) {
					if err := deliver("https://auth.openai.com/codex/device", "PRIVATE-CODE"); err != nil {
						return nil, err
					}
					<-release // Model an upstream that ignores context cancellation.
					return testEnrollmentStorage("private-account"), nil
				},
				commit: func(*codex.CodexTokenStorage, string) (string, error) {
					saves.Add(1)
					return "", nil
				},
			}
			parent, cancelParent := context.WithCancel(context.Background())
			defer cancelParent()
			c.bindService(parent)
			handler := enrollmentHandler(c)
			id := startEnrollment(t, handler)
			_ = waitForEnrollmentState(t, handler, id, "awaiting_authorization")
			c.mu.Lock()
			done := c.attempt.done
			c.mu.Unlock()
			if operation == "cancel" {
				if got := enrollmentRequest(handler, http.MethodDelete, enrollmentPath+"/"+id, testControlBearer, ""); got.Code != 204 {
					t.Fatal("cancel request failed")
				}
			} else if operation == "shutdown" {
				c.close()
			} else {
				cancelParent()
			}
			close(release)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("fake login failed to release")
			}
			if saves.Load() != 0 {
				t.Error("late completion committed after cancel or shutdown")
			}
		})
	}
}

func TestPrivateEnrollmentFixedFailuresAndInputBounds(t *testing.T) {
	c := &enrollmentController{login: func(context.Context, func(string, string) error) (*codex.CodexTokenStorage, error) {
		return nil, errors.New("PRIVATE-PROVIDER-BODY")
	}}
	defer c.close()
	handler := enrollmentHandler(c)
	for _, body := range []string{`{"attemptId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expectedAccountId":""}`, `{"attemptId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expectedAccountId":"private-account","extra":"token"}`, strings.Repeat("x", 600), `{"attemptId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expectedAccountId":"private-account"} {}`, `{"attemptId":"short","expectedAccountId":"private-account"}`} {
		if got := enrollmentRequest(handler, http.MethodPost, enrollmentPath, testControlBearer, body); got.Code != 400 || strings.Contains(got.Body.String(), "private-account") {
			t.Fatal("invalid request was admitted or echoed an identity")
		}
	}
	id := startEnrollment(t, handler)
	response := waitForEnrollmentState(t, handler, id, "failed")
	if strings.Contains(response.Body.String(), "PRIVATE-PROVIDER-BODY") || strings.Contains(response.Body.String(), "private-account") {
		t.Fatal("provider error or identity escaped fixed result")
	}
}

func TestPrivateEnrollmentVisibleCommitIsNotCancelledAsPrecommit(t *testing.T) {
	c := &enrollmentController{
		login: func(_ context.Context, deliver func(string, string) error) (*codex.CodexTokenStorage, error) {
			if err := deliver("https://auth.openai.com/codex/device", "PRIVATE-CODE"); err != nil {
				return nil, err
			}
			return testEnrollmentStorage("private-account"), nil
		},
		commit: func(*codex.CodexTokenStorage, string) (string, error) {
			return "/private/credential", codex.ErrTokenCommitDurabilityUncertain
		},
	}
	defer c.close()
	handler := enrollmentHandler(c)
	id := startEnrollment(t, handler)
	response := waitForEnrollmentState(t, handler, id, "commit_uncertain")
	if strings.Contains(response.Body.String(), "/private/") || strings.Contains(response.Body.String(), "private-account") {
		t.Fatal("uncertain visible commit exposed private state")
	}
	if got := enrollmentRequest(handler, http.MethodDelete, enrollmentPath+"/"+id, testControlBearer, ""); got.Code != 204 {
		t.Fatal("uncertain commit could not be acknowledged without deleting credential")
	}
}

func TestPrivateEnrollmentPreflightRefusesOwnedAccountBeforeOAuth(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := testEnrollmentStorage("private-account").SaveTokenToFile(filepath.Join(dir, "codex-legacy-name.json")); err != nil {
		t.Fatal(err)
	}
	c := newEnrollmentController(&config.Config{AuthDir: dir})
	defer c.close()
	called := false
	c.login = func(context.Context, func(string, string) error) (*codex.CodexTokenStorage, error) {
		called = true
		return nil, nil
	}
	got := enrollmentRequest(enrollmentHandler(c), http.MethodPost, enrollmentPath, testControlBearer, enrollmentStartBody(testEnrollmentAttemptID, "private-account"))
	if got.Code != http.StatusConflict || called || strings.Contains(got.Body.String(), "private-account") || strings.Contains(got.Body.String(), "legacy") {
		t.Fatal("duplicate proxy-owned account issued a second OAuth family")
	}
}

func TestPrivateEnrollmentRealCreateOnlyCommitAndDuplicateRetry(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	c := newEnrollmentController(&config.Config{AuthDir: dir})
	defer c.close()
	c.login = func(_ context.Context, deliver func(string, string) error) (*codex.CodexTokenStorage, error) {
		if err := deliver("https://auth.openai.com/codex/device", "PRIVATE-CODE"); err != nil {
			return nil, err
		}
		return testEnrollmentStorage("private-account"), nil
	}
	handler := enrollmentHandler(c)
	id := startEnrollment(t, handler)
	_ = waitForEnrollmentState(t, handler, id, "committed")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "codex-account-") {
		t.Fatal("exact identity was not privately committed once")
	}
	store := sdkauth.NewFileTokenStore()
	store.SetBaseDir(dir)
	loaded, err := store.List(context.Background())
	if err != nil || len(loaded) != 1 || loaded[0].Provider != "codex" || loaded[0].Metadata["account_id"] != "private-account" {
		t.Fatal("committed credential was not discoverable by the normal auth file store")
	}
	if got := enrollmentRequest(handler, http.MethodDelete, enrollmentPath+"/"+id, testControlBearer, ""); got.Code != 204 {
		t.Fatal("committed enrollment acknowledgement failed")
	}
	if got := enrollmentRequest(handler, http.MethodPost, enrollmentPath, testControlBearer, enrollmentStartBody(testEnrollmentAttemptID, "private-account")); got.Code != http.StatusConflict {
		t.Fatal("duplicate retry did not fail before new OAuth")
	}
	c.close()
	restarted := newEnrollmentController(&config.Config{AuthDir: dir})
	defer restarted.close()
	if got := enrollmentRequest(enrollmentHandler(restarted), http.MethodPost, enrollmentPath, testControlBearer, enrollmentStartBody(testEnrollmentAttemptID, "private-account")); got.Code != http.StatusConflict {
		t.Fatal("process restart lost the durable duplicate fence")
	}
}

func TestPrivateEnrollmentRechecksDuplicateAfterOAuth(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	c := newEnrollmentController(&config.Config{AuthDir: dir})
	defer c.close()
	release := make(chan struct{})
	c.login = func(_ context.Context, deliver func(string, string) error) (*codex.CodexTokenStorage, error) {
		if err := deliver("https://auth.openai.com/codex/device", "PRIVATE-CODE"); err != nil {
			return nil, err
		}
		<-release
		return testEnrollmentStorage("private-account"), nil
	}
	handler := enrollmentHandler(c)
	id := startEnrollment(t, handler)
	_ = waitForEnrollmentState(t, handler, id, "awaiting_authorization")
	path := filepath.Join(dir, "codex-legacy-name.json")
	if err := testEnrollmentStorage("private-account").SaveTokenToFile(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	close(release)
	_ = waitForEnrollmentState(t, handler, id, "failed")
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatal("new OAuth result replaced an account introduced after preflight")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("late duplicate left a second credential")
	}
}
