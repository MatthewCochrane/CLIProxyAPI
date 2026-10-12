package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestPrivateControlAllowlistAndCredentialBoundary(t *testing.T) {
	observer := NewObserver([]byte(strings.Repeat("h", 32)), 24)
	observer.SetAuthSource(func() []*coreauth.Auth {
		return []*coreauth.Auth{{
			ID: "private-provider-id", Provider: "codex", Status: coreauth.StatusActive,
			Metadata: map[string]any{"email": "private@example.test", "refresh_token": "secret-refresh"},
		}}
	})
	handler := observer.ControlHandler(strings.Repeat("c", 32))
	for _, tc := range []struct {
		name, method, path, bearer, remote, origin, cookie string
		want                                               int
	}{
		{"health", "GET", ControlHealthPath, strings.Repeat("c", 32), "127.0.0.1:3333", "", "", 200},
		{"state", "GET", ControlStatePath, strings.Repeat("c", 32), "[::1]:3333", "", "", 200},
		{"missing bearer", "GET", ControlStatePath, "", "127.0.0.1:3333", "", "", 401},
		{"wrong bearer", "GET", ControlStatePath, strings.Repeat("o", 32), "127.0.0.1:3333", "", "", 401},
		{"remote caller", "GET", ControlStatePath, strings.Repeat("c", 32), "100.64.0.1:3333", "", "", 404},
		{"spoofed origin", "GET", ControlStatePath, strings.Repeat("c", 32), "127.0.0.1:3333", "https://example.test", "", 401},
		{"cookie", "GET", ControlStatePath, strings.Repeat("c", 32), "127.0.0.1:3333", "", "session=secret", 401},
		{"raw management", "GET", "/v0/management/auth-files", strings.Repeat("c", 32), "127.0.0.1:3333", "", "", 404},
		{"mutation", "DELETE", ControlStatePath, strings.Repeat("c", 32), "127.0.0.1:3333", "", "", 405},
		{"retirement unavailable", "POST", "/v1/control/retire", strings.Repeat("c", 32), "127.0.0.1:3333", "", "", 404},
		{"query", "GET", ControlStatePath + "?token=secret", strings.Repeat("c", 32), "127.0.0.1:3333", "", "", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.path, nil)
			request.RemoteAddr = tc.remote
			if tc.bearer != "" {
				request.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			if tc.origin != "" {
				request.Header.Set("Origin", tc.origin)
			}
			if tc.cookie != "" {
				request.Header.Set("Cookie", tc.cookie)
			}
			request.Header.Set("X-Forwarded-For", "127.0.0.1")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.want || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("response status/cache = %d/%q, want %d/no-store", response.Code, response.Header().Get("Cache-Control"), tc.want)
			}
			for _, forbidden := range []string{"private-provider-id", "private@example.test", "secret-refresh", "Bearer " + strings.Repeat("c", 32)} {
				if strings.Contains(response.Body.String(), forbidden) {
					t.Fatal("control response included private credential material")
				}
			}
			if tc.want == http.StatusOK && tc.path == ControlStatePath && !strings.Contains(response.Body.String(), `"acct_`) {
				t.Fatal("sanitized state omitted opaque account handle")
			}
		})
	}
}

func TestPrivateControlNeverAcceptsMissingServerSecret(t *testing.T) {
	observer := NewObserver([]byte(strings.Repeat("h", 32)), 24)
	for _, secret := range []string{"", "short"} {
		request := httptest.NewRequest(http.MethodGet, ControlStatePath, nil)
		request.RemoteAddr = "127.0.0.1:3333"
		request.Header.Set("Authorization", "Bearer "+secret)
		response := httptest.NewRecorder()
		observer.ControlHandler(secret).ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("short/empty server secret admitted: status %d", response.Code)
		}
	}
}

func TestEnrollmentMutationIsAbsentByDefaultAndUsesCommonAdmission(t *testing.T) {
	observer := NewObserver([]byte(strings.Repeat("h", 32)), 24)
	secret := strings.Repeat("c", 32)
	called := 0
	mutation := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusAccepted)
	})
	for _, tc := range []struct {
		name                           string
		handler                        http.Handler
		remote, bearer, origin, cookie string
		want                           int
	}{
		{"default off", observer.ControlHandler(secret), "127.0.0.1:1234", secret, "", "", 404},
		{"remote", observer.ControlHandlerWithEnrollment(secret, mutation), "100.64.1.1:1234", secret, "", "", 404},
		{"wrong bearer", observer.ControlHandlerWithEnrollment(secret, mutation), "127.0.0.1:1234", "wrong", "", "", 401},
		{"browser origin", observer.ControlHandlerWithEnrollment(secret, mutation), "127.0.0.1:1234", secret, "https://example.test", "", 401},
		{"browser cookie", observer.ControlHandlerWithEnrollment(secret, mutation), "127.0.0.1:1234", secret, "", "session=1", 401},
		{"local authenticated", observer.ControlHandlerWithEnrollment(secret, mutation), "127.0.0.1:1234", secret, "", "", 202},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, ControlEnrollmentPath, nil)
			request.RemoteAddr = tc.remote
			request.Header.Set("Authorization", "Bearer "+tc.bearer)
			if tc.origin != "" {
				request.Header.Set("Origin", tc.origin)
			}
			if tc.cookie != "" {
				request.Header.Set("Cookie", tc.cookie)
			}
			response := httptest.NewRecorder()
			tc.handler.ServeHTTP(response, request)
			if response.Code != tc.want {
				t.Fatalf("status = %d, want %d", response.Code, tc.want)
			}
		})
	}
	if called != 1 {
		t.Fatalf("enrollment callback reached %d times, want once", called)
	}
}

func TestAccountControlsUsePrivateAdmissionAndAreAbsentByDefault(t *testing.T) {
	observer := NewObserver([]byte(strings.Repeat("h", 32)), 24)
	secret := strings.Repeat("c", 32)
	for _, path := range []string{ControlAccountsPath, ControlAccountAuthorizationsPath} {
		called := 0
		accountHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called++; w.WriteHeader(202) })
		for _, tc := range []struct {
			name, remote, bearer, origin, cookie string
			enabled                              bool
			want                                 int
		}{
			{"default off", "127.0.0.1:1234", secret, "", "", false, 404},
			{"remote", "100.64.1.1:1234", secret, "", "", true, 404},
			{"wrong bearer", "127.0.0.1:1234", "wrong", "", "", true, 401},
			{"browser origin", "127.0.0.1:1234", secret, "https://example.test", "", true, 401},
			{"browser cookie", "127.0.0.1:1234", secret, "", "session=1", true, 401},
			{"local authenticated", "127.0.0.1:1234", secret, "", "", true, 202},
		} {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				request := httptest.NewRequest("GET", path, nil)
				request.RemoteAddr = tc.remote
				request.Header.Set("Authorization", "Bearer "+tc.bearer)
				if tc.origin != "" {
					request.Header.Set("Origin", tc.origin)
				}
				if tc.cookie != "" {
					request.Header.Set("Cookie", tc.cookie)
				}
				handler := observer.ControlHandler(secret)
				if tc.enabled {
					handler = observer.ControlHandlerWithAccounts(secret, nil, nil, accountHandler)
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != tc.want {
					t.Fatalf("status %d want %d", response.Code, tc.want)
				}
			})
		}
		if called != 1 {
			t.Fatal("account callback admitted unqualified caller")
		}
	}
}
