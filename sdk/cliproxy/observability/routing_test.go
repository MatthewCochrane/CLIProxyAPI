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
	"strings"
	"sync"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const (
	testToken = "0123456789abcdef0123456789abcdef"
	testKey   = "abcdef0123456789abcdef0123456789"
)

func TestObserverAggregatesOpaqueBoundedAccounts(t *testing.T) {
	observer := NewObserver([]byte(testKey), 2)
	rawID := "raw-auth-id-user@example.test"
	observer.OnResult(context.Background(), coreauth.Result{
		AuthID: rawID, Success: false,
		Error:    &coreauth.Error{Code: "provider-secret", Message: "raw upstream failure"},
		Provider: "sensitive-provider", Model: "sensitive-model",
	})
	observer.OnResult(context.Background(), coreauth.Result{AuthID: rawID, Success: true})
	observer.ObserveAffinity(coreauth.AffinityEventMiss, rawID)
	observer.ObserveAffinity(coreauth.AffinityEventHit, rawID)
	observer.ObserveAffinity(coreauth.AffinityEventRebind, rawID)
	observer.ObserveAffinity(coreauth.AffinityEventNoSession, rawID)
	observer.OnResult(context.Background(), coreauth.Result{AuthID: "second", Success: true})
	observer.OnResult(context.Background(), coreauth.Result{AuthID: "third", Success: true})

	snapshot := observer.Snapshot(time.Unix(123, 0))
	if snapshot.SchemaVersion != 1 || len(snapshot.Accounts) != 2 {
		t.Fatalf("snapshot schema/accounts = %d/%d, want 1/2", snapshot.SchemaVersion, len(snapshot.Accounts))
	}
	if snapshot.Totals != (Counters{Success: 3, Failure: 1, Hit: 1, Miss: 1, Rebind: 1, NoSession: 1}) {
		t.Fatalf("totals = %#v", snapshot.Totals)
	}
	mac := hmac.New(sha256.New, []byte(testKey))
	_, _ = mac.Write([]byte(rawID))
	wantHandle := "acct_" + hex.EncodeToString(mac.Sum(nil))
	found := false
	for _, account := range snapshot.Accounts {
		if strings.Contains(account.Account, rawID) || !strings.HasPrefix(account.Account, "acct_") {
			t.Fatalf("unsafe account handle %q", account.Account)
		}
		if account.Account == wantHandle {
			found = true
			if account.Counters != (Counters{Success: 1, Failure: 1, Hit: 1, Miss: 1, Rebind: 1, NoSession: 1}) {
				t.Fatalf("raw account counters = %#v", account.Counters)
			}
		}
	}
	if !found {
		t.Fatalf("stable HMAC handle %q not found", wantHandle)
	}
	otherKey := NewObserver([]byte("different-key-0123456789abcdef0000"), 2)
	otherKey.OnResult(context.Background(), coreauth.Result{AuthID: rawID, Success: true})
	if otherKey.Snapshot(time.Now()).Accounts[0].Account == wantHandle {
		t.Fatal("different HMAC keys produced the same handle")
	}
}

func TestObserverConcurrentUpdates(t *testing.T) {
	observer := NewObserver([]byte(testKey), 4)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			observer.OnResult(context.Background(), coreauth.Result{AuthID: "account", Success: true})
			observer.ObserveAffinity(coreauth.AffinityEventHit, "account")
		}()
	}
	wg.Wait()
	if got := observer.Snapshot(time.Now()).Totals; got.Success != 100 || got.Hit != 100 {
		t.Fatalf("concurrent totals = %#v", got)
	}
}

func TestHandlerContractAndNoLeakage(t *testing.T) {
	observer := NewObserver([]byte(testKey), 64)
	rawValues := []string{
		"raw-auth-secret", "session-secret", "model-secret", "provider-secret",
		"prompt-secret", "response-secret", "tool-secret", "/sensitive/path", "user@example.test",
	}
	observer.OnResult(context.Background(), coreauth.Result{
		AuthID: rawValues[0], Success: false, Provider: rawValues[3], Model: rawValues[2],
		Error: &coreauth.Error{Code: rawValues[1], Message: strings.Join(rawValues[4:], " ")},
	})
	handler := observer.Handler(testToken)

	tests := []struct {
		name, method, target, auth string
		want                       int
	}{
		{name: "authorized", method: http.MethodGet, target: SnapshotPath, auth: "Bearer " + testToken, want: http.StatusOK},
		{name: "missing auth", method: http.MethodGet, target: SnapshotPath, want: http.StatusUnauthorized},
		{name: "wrong auth", method: http.MethodGet, target: SnapshotPath, auth: "Bearer wrong", want: http.StatusUnauthorized},
		{name: "unauthenticated query", method: http.MethodGet, target: SnapshotPath + "?detail=1", want: http.StatusUnauthorized},
		{name: "unauthenticated method", method: http.MethodPost, target: SnapshotPath, want: http.StatusUnauthorized},
		{name: "unauthenticated path", method: http.MethodDelete, target: "/private?detail=1", want: http.StatusUnauthorized},
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
			if recorder.Header().Get("Content-Type") != "application/json" || recorder.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("unsafe headers: %#v", recorder.Header())
			}
			if recorder.Header().Get("Content-Length") != fmt.Sprint(recorder.Body.Len()) {
				t.Fatalf("content length = %q, body = %d", recorder.Header().Get("Content-Length"), recorder.Body.Len())
			}
			if recorder.Body.Len() > 32<<10 {
				t.Fatalf("response is not bounded: %d bytes", recorder.Body.Len())
			}
			if tt.want == http.StatusUnauthorized {
				if got := recorder.Body.String(); got != `{"error":"unauthorized"}` {
					t.Fatalf("unauthorized body = %q", got)
				}
				if got := recorder.Header().Get("WWW-Authenticate"); got != "Bearer" {
					t.Fatalf("WWW-Authenticate = %q", got)
				}
				if got := recorder.Header().Get("Allow"); got != "" {
					t.Fatalf("unauthenticated response leaked method metadata: Allow = %q", got)
				}
			}
			for _, raw := range rawValues {
				if strings.Contains(recorder.Body.String(), raw) {
					t.Fatalf("response leaked %q: %s", raw, recorder.Body.String())
				}
			}
		})
	}

	req := httptest.NewRequest(http.MethodGet, SnapshotPath, nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &shape); err != nil {
		t.Fatal(err)
	}
	if len(shape) != 4 || shape["schemaVersion"] == nil || shape["generatedAt"] == nil || shape["totals"] == nil || shape["accounts"] == nil {
		t.Fatalf("unexpected top-level schema: %v", shape)
	}
}
