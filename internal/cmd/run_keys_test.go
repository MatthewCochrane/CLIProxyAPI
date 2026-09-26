package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	routingobs "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/observability"
)

func TestEnvironmentKeyControlDefaultOffAndPrivateConfig(t *testing.T) {
	routing := &routingObservabilityConfig{addr: "127.0.0.1:9191", token: strings.Repeat("r", 32), hmacKey: []byte(strings.Repeat("h", 32))}
	base := map[string]string{controlAddrEnv: "127.0.0.1:9192", controlTokenEnv: testControlBearer}
	if cfg, err := loadControlConfig(envLookup(base), routing); err != nil || cfg == nil || cfg.keys {
		t.Fatalf("keys must default off: %#v, %v", cfg, err)
	}
	for _, tc := range []map[string]string{
		{controlKeysEnv: "true"},
		{controlKeysEnv: "yes", controlKeyStoreEnv: "/private"},
		{controlKeysEnv: "true", controlKeyStoreEnv: "relative"},
		{controlKeysEnv: "false", controlKeyStoreEnv: "/private"},
	} {
		values := map[string]string{}
		for k, v := range base {
			values[k] = v
		}
		for k, v := range tc {
			values[k] = v
		}
		if cfg, err := loadControlConfig(envLookup(values), routing); err == nil || cfg != nil {
			t.Fatalf("bad key config accepted: %#v, %v", cfg, err)
		}
	}
	values := map[string]string{controlAddrEnv: base[controlAddrEnv], controlTokenEnv: base[controlTokenEnv], controlKeysEnv: "true", controlKeyStoreEnv: "/private/keys"}
	if cfg, err := loadControlConfig(envLookup(values), routing); err != nil || cfg == nil || !cfg.keys {
		t.Fatalf("private key config rejected: %#v, %v", cfg, err)
	}
}

func TestEnvironmentKeyPrivateControllerAndInferenceDenial(t *testing.T) {
	base := t.TempDir()
	storeDir := filepath.Join(base, "key-store")
	if err := os.Mkdir(storeDir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := sdkaccess.NewEnvironmentKeyStore(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	controller := &environmentKeyController{store: store}
	observer := routingobs.NewObserver([]byte(strings.Repeat("h", 32)), 24)
	handler := observer.ControlHandlerWithMutations(testControlBearer, nil, http.HandlerFunc(controller.handle))
	key, err := sdkaccess.GenerateEnvironmentKey()
	if err != nil {
		t.Fatal(err)
	}
	body := `{"environmentId":"env-A","key":"` + key + `"}`
	issued := enrollmentRequest(handler, http.MethodPost, routingobs.ControlKeysPath, testControlBearer, body)
	if issued.Code != http.StatusCreated || !strings.Contains(issued.Body.String(), `"revision":1`) {
		t.Fatalf("issue: %d, %q", issued.Code, issued.Body.String())
	}
	if strings.Contains(issued.Body.String(), key) || strings.Contains(issued.Body.String(), "env-A") {
		t.Fatal("response leaked key or identity")
	}
	if _, ok := store.Verify(key); !ok {
		t.Fatal("issued key does not authorize")
	}
	read := enrollmentRequest(handler, http.MethodGet, routingobs.ControlKeysPath+"/env-A", testControlBearer, "")
	if read.Code != 200 || !strings.Contains(read.Body.String(), `"active":true`) {
		t.Fatalf("inspect: %d %q", read.Code, read.Body.String())
	}
	digest := sha256.Sum256([]byte(key))
	proofBody := `{"digest":"` + hex.EncodeToString(digest[:]) + `"}`
	matchPath := routingobs.ControlKeysPath + "/env-A/match"
	match := enrollmentRequest(handler, http.MethodPost, matchPath, testControlBearer, proofBody)
	if match.Code != http.StatusOK || !strings.Contains(match.Body.String(), `"matchesDigest":true`) || strings.Contains(match.Body.String(), key) || strings.Contains(match.Body.String(), hex.EncodeToString(digest[:])) {
		t.Fatalf("matching proof: %d %q", match.Code, match.Body.String())
	}
	other := enrollmentRequest(handler, http.MethodPost, matchPath, testControlBearer, `{"digest":"`+strings.Repeat("a", 64)+`"}`)
	if other.Code != http.StatusOK || !strings.Contains(other.Body.String(), `"matchesDigest":false`) {
		t.Fatalf("wrong proof: %d %q", other.Code, other.Body.String())
	}
	for _, tc := range []struct {
		method, path, bearer, body string
		want                       int
	}{
		{http.MethodPost, routingobs.ControlKeysPath, "wrong", body, 401},
		{http.MethodPost, routingobs.ControlKeysPath, testControlBearer, body, 409},
		{http.MethodPost, routingobs.ControlKeysPath, testControlBearer, `{"environmentId":"env-B","key":"` + key + `"}`, 409},
		{http.MethodPost, routingobs.ControlKeysPath + "?key=" + key, testControlBearer, body, 400},
		{http.MethodPost, routingobs.ControlKeysPath, testControlBearer, `{"environmentId":"env-B","key":"` + key + `","key":"` + key + `"}`, 400},
		{http.MethodDelete, routingobs.ControlKeysPath + "/env-A", testControlBearer, `{"revision":2}`, 409},
		{http.MethodGet, "/v0/management/auth-files", testControlBearer, "", 404},
		{http.MethodGet, matchPath, testControlBearer, "", 404},
		{http.MethodPost, matchPath, testControlBearer, `{"digest":"bad"}`, 503},
	} {
		response := enrollmentRequest(handler, tc.method, tc.path, tc.bearer, tc.body)
		if response.Code != tc.want || strings.Contains(response.Body.String(), key) || strings.Contains(response.Body.String(), "env-A") {
			t.Fatalf("unexpected response: %d %q", response.Code, response.Body.String())
		}
	}
	remote := httptest.NewRequest(http.MethodPost, routingobs.ControlKeysPath, strings.NewReader(body))
	remote.Header.Set("Authorization", "Bearer "+testControlBearer)
	remote.RemoteAddr = "192.0.2.1:4096"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, remote)
	if response.Code != http.StatusNotFound {
		t.Fatalf("remote key mutation: %d", response.Code)
	}
	browser := httptest.NewRequest(http.MethodPost, routingobs.ControlKeysPath, strings.NewReader(body))
	browser.Header.Set("Authorization", "Bearer "+testControlBearer)
	browser.Header.Set("Origin", "http://localhost")
	browser.RemoteAddr = "127.0.0.1:4096"
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, browser)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("browser key mutation: %d", response.Code)
	}
	revoked := enrollmentRequest(handler, http.MethodDelete, routingobs.ControlKeysPath+"/env-A", testControlBearer, `{"revision":1}`)
	if revoked.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %q", revoked.Code, revoked.Body.String())
	}
	if _, ok := store.Verify(key); ok {
		t.Fatal("revoked key authorized")
	}
	revokedProof := enrollmentRequest(handler, http.MethodPost, matchPath, testControlBearer, proofBody)
	if revokedProof.Code != http.StatusOK || !strings.Contains(revokedProof.Body.String(), `"revision":2`) || !strings.Contains(revokedProof.Body.String(), `"active":false`) || !strings.Contains(revokedProof.Body.String(), `"matchesDigest":true`) {
		t.Fatalf("revoked proof: %d %q", revokedProof.Code, revokedProof.Body.String())
	}
	if retry := enrollmentRequest(handler, http.MethodDelete, routingobs.ControlKeysPath+"/env-A", testControlBearer, `{"revision":1}`); retry.Code != 409 {
		t.Fatalf("stale revoke: %d", retry.Code)
	}
}

func TestEnvironmentKeyRuntimeRejectsCredentialStoreOverlap(t *testing.T) {
	auth := t.TempDir()
	if err := os.Chmod(auth, 0700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(auth, "keys")
	if err := os.Mkdir(keys, 0700); err != nil {
		t.Fatal(err)
	}
	if !pathContains(auth, keys) || !pathContains(auth, auth) || pathContains(keys, auth) {
		t.Fatal("private store overlap checker failed")
	}
	getAddr := func() string {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := listener.Addr().String()
		_ = listener.Close()
		return addr
	}
	t.Setenv(observabilityAddrEnv, getAddr())
	t.Setenv(observabilityTokenEnv, strings.Repeat("r", 32))
	t.Setenv(observabilityHMACKeyEnv, strings.Repeat("h", 32))
	t.Setenv(controlAddrEnv, getAddr())
	t.Setenv(controlTokenEnv, testControlBearer)
	t.Setenv(controlKeysEnv, "true")
	t.Setenv(controlKeyStoreEnv, keys)
	// A nested or equal key authority would be ingested by the auth-file watcher.
	if runtime, err := newRoutingObservabilityRuntime(&config.Config{AuthDir: auth}); err == nil || runtime != nil {
		t.Fatal("nested private key authority admitted")
	}
	separate := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(separate, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(controlKeyStoreEnv, separate)
	runtime, err := newRoutingObservabilityRuntime(&config.Config{AuthDir: auth})
	if err != nil || runtime == nil || runtime.keyStore == nil {
		t.Fatalf("separate private key authority rejected: %v", err)
	}
	runtime.close()
	if _, err := sdkaccess.NewEnvironmentKeyStore(filepath.Join(auth, "missing")); !errors.Is(err, sdkaccess.ErrEnvironmentKeyUnavailable) {
		t.Fatalf("missing key authority admitted: %v", err)
	}
}
