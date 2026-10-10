//go:build linux

package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func privateKeyStore(t *testing.T) (string, *EnvironmentKeyStore) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := NewEnvironmentKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return dir, store
}

func TestEnvironmentKeyDurableIssueRevokeAndRestart(t *testing.T) {
	dir, store := privateKeyStore(t)
	a, _ := GenerateEnvironmentKey()
	b, _ := GenerateEnvironmentKey()
	if !ValidEnvironmentKey(a) || a == b || ValidEnvironmentKey(a+"=") || ValidEnvironmentKey("pcx-env-v1-bad") {
		t.Fatal("keys must be independent canonical 256-bit values")
	}
	if revision, err := store.Issue("environment-A", a); err != nil || revision != 1 {
		t.Fatalf("issue A: %d, %v", revision, err)
	}
	if revision, err := store.Issue("environment-B", b); err != nil || revision != 1 {
		t.Fatalf("issue B: %d, %v", revision, err)
	}
	if _, err := store.Issue("environment-C", a); !errors.Is(err, ErrEnvironmentKeyConflict) {
		t.Fatalf("reuse must conflict: %v", err)
	}
	if _, err := store.Issue("environment-A", b); !errors.Is(err, ErrEnvironmentKeyConflict) {
		t.Fatalf("replace must conflict: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewEnvironmentKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, ok := reopened.Verify(a); !ok {
		t.Fatal("restart lost A")
	}
	if err := reopened.Revoke("environment-A", 2); !errors.Is(err, ErrEnvironmentKeyConflict) {
		t.Fatalf("stale revision must conflict: %v", err)
	}
	if err := reopened.Revoke("environment-A", 1); err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Verify(a); ok {
		t.Fatal("revoked A still accepted")
	}
	if _, ok := reopened.Verify(b); !ok {
		t.Fatal("B incorrectly revoked")
	}
	if rev, active, present, err := reopened.Inspect("environment-A"); err != nil || !present || active || rev != 2 {
		t.Fatalf("wrong persisted revocation: %d, %v, %v, %v", rev, active, present, err)
	}
	c, _ := GenerateEnvironmentKey()
	if rev, err := reopened.Issue("environment-A", c); err != nil || rev != 3 {
		t.Fatalf("new generation: %d, %v", rev, err)
	}
	if _, ok := reopened.Verify(a); ok {
		t.Fatal("revoked digest reactivated")
	}
	if _, ok := reopened.Verify(c); !ok {
		t.Fatal("new generation unavailable")
	}
	raw, err := os.ReadFile(filepath.Join(dir, environmentKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{a, b, c} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("persistent file contains bearer")
		}
	}
	st, err := os.Lstat(filepath.Join(dir, environmentKeyFile))
	if err != nil || st.Mode().Perm() != 0600 || !st.Mode().IsRegular() {
		t.Fatal("not private regular durable state")
	}
}

func TestEnvironmentKeyUncertaintyAndTamperingFailClosed(t *testing.T) {
	dir, store := privateKeyStore(t)
	key, _ := GenerateEnvironmentKey()
	store.syncDir = func(int) error { return errors.New("private disk error") }
	if _, err := store.Issue("environment-A", key); !errors.Is(err, ErrEnvironmentKeyUncertain) || strings.Contains(err.Error(), key) {
		t.Fatalf("unexpected commit result: %v", err)
	}
	if _, ok := store.Verify(key); !ok {
		t.Fatal("visible committed state must be authoritative")
	}
	store.syncDir = func(int) error { return nil }
	if _, err := store.Issue("environment-A", key); !errors.Is(err, ErrEnvironmentKeyConflict) {
		t.Fatalf("uncertain publication must not be repeated: %v", err)
	}
	file := filepath.Join(dir, environmentKeyFile)
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Verify(key); ok {
		t.Fatal("unsafe file admitted")
	}
	if _, err := NewEnvironmentKeyStore(dir); !errors.Is(err, ErrEnvironmentKeyUnavailable) {
		t.Fatalf("unsafe restart must fail: %v", err)
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".environment-keys-orphan"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Verify(key); ok {
		t.Fatal("orphan temp must fail closed")
	}
	if _, err := NewEnvironmentKeyStore(dir); !errors.Is(err, ErrEnvironmentKeyUnavailable) {
		t.Fatalf("orphan restart must fail: %v", err)
	}
}

func TestEnvironmentKeyRetiredGenerationsRemainReadableAfterRestart(t *testing.T) {
	dir, store := privateKeyStore(t)
	first, _ := GenerateEnvironmentKey()
	second, _ := GenerateEnvironmentKey()
	for index, key := range []string{first, second} {
		issued := uint64(index*2 + 1)
		if revision, err := store.Issue("environment-A", key); err != nil || revision != issued {
			t.Fatalf("issue: %d, %v", revision, err)
		}
		if err := store.Revoke("environment-A", issued); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.ReadFile(filepath.Join(dir, environmentKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewEnvironmentKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if revision, active, present, err := reopened.Inspect("environment-A"); err != nil || revision != 4 || active || !present {
		t.Fatalf("retirement history: %d, %v, %v, %v", revision, active, present, err)
	}
	for _, key := range []string{first, second} {
		if _, ok := reopened.Verify(key); ok {
			t.Fatal("retired credential accepted")
		}
	}
	after, err := os.ReadFile(filepath.Join(dir, environmentKeyFile))
	if err != nil || string(after) != string(before) {
		t.Fatal("read-only restart rewrote the ledger")
	}
	third, _ := GenerateEnvironmentKey()
	if revision, err := reopened.Issue("environment-A", third); err != nil || revision != 5 {
		t.Fatalf("next generation: %d, %v", revision, err)
	}
}

func TestEnvironmentKeyMalformedOrLinkedAuthorityFailsClosed(t *testing.T) {
	dir, store := privateKeyStore(t)
	key, _ := GenerateEnvironmentKey()
	if _, err := store.Issue("environment-A", key); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, environmentKeyFile)
	original, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		`{"keys":[]}`,
		`{"version":1,"keys":null}`,
		`{"version":1,"version":1,"keys":[]}`,
		string(original) + " ",
	} {
		if err := os.WriteFile(file, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, ok := store.Verify(key); ok {
			t.Fatal("malformed authority admitted")
		}
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", file); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Verify(key); ok {
		t.Fatal("symlink authority admitted")
	}
	if _, err := NewEnvironmentKeyStore(dir); !errors.Is(err, ErrEnvironmentKeyUnavailable) {
		t.Fatalf("symlink restart admitted: %v", err)
	}
}

func TestEnvironmentKeyConcurrentRevokeIsFenced(t *testing.T) {
	_, store := privateKeyStore(t)
	key, _ := GenerateEnvironmentKey()
	if _, err := store.Issue("environment-A", key); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- store.Revoke("environment-A", 1) }()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrEnvironmentKeyConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("exactly one revocation must commit: success=%d conflict=%d", success, conflict)
	}
}

type permissiveProvider struct{}

func (permissiveProvider) Identifier() string { return "legacy" }
func (permissiveProvider) Authenticate(context.Context, *http.Request) (*Result, *AuthError) {
	return &Result{Provider: "legacy", Principal: "legacy"}, nil
}

func TestManagedInferenceKeyCannotFallThroughLegacyProviders(t *testing.T) {
	_, store := privateKeyStore(t)
	key, _ := GenerateEnvironmentKey()
	if _, err := store.Issue("environment-A", key); err != nil {
		t.Fatal(err)
	}
	manager := NewManager()
	manager.SetProviders([]Provider{permissiveProvider{}})
	manager.SetEnvironmentKeyVerifier(store.Verify)
	request := func(path, bearer string) *http.Request {
		r, _ := http.NewRequest(http.MethodGet, path, nil)
		if bearer != "" {
			r.Header.Set("Authorization", bearer)
		}
		return r
	}
	good := request("http://localhost/v1/models", "Bearer "+key)
	result, err := manager.Authenticate(context.Background(), good)
	if err != nil || result == nil || result.Provider != "managed-inference-key" || result.Principal == key {
		t.Fatalf("managed admission: %#v, %v", result, err)
	}
	for _, bad := range []*http.Request{
		request("http://localhost/v1/models", "Bearer "+EnvironmentKeyPrefix+"bad"),
		request("http://localhost/v1/models?key="+key, ""),
		request("http://localhost/v1/models?key=legacy&key="+key, ""),
		request("http://localhost/v1/models", "Basic "+key),
	} {
		if result, err := manager.Authenticate(context.Background(), bad); result != nil || err == nil {
			t.Fatalf("managed key fell through: %#v, %v", result, err)
		}
	}
	good.Header.Set("X-Api-Key", "legacy")
	if result, err := manager.Authenticate(context.Background(), good); result != nil || err == nil {
		t.Fatalf("mixed bearer fell through: %#v, %v", result, err)
	}
	good.Header.Del("X-Api-Key")
	if legacy, authErr := manager.Authenticate(context.Background(), request("http://localhost/v1/models", "Bearer old-shared-pilot-key")); legacy != nil || authErr == nil {
		t.Fatalf("dedicated keys must replace legacy shared keys: %#v, %v", legacy, authErr)
	}
	if err := store.Revoke("environment-A", 1); err != nil {
		t.Fatal(err)
	}
	if result, err := manager.Authenticate(context.Background(), good); result != nil || err == nil {
		t.Fatalf("revoked key fell through: %#v, %v", result, err)
	}
	manager.SetProviders(nil)
	if result, err := manager.Authenticate(context.Background(), request("http://localhost/v1/models", "")); result != nil || err == nil {
		t.Fatalf("no providers must still require a key: %#v, %v", result, err)
	}
	// A verifier survives normal provider reloads, and no raw bearer becomes a principal.
	digest := sha256.Sum256([]byte(key))
	if result.Principal != "managed-env-"+hex.EncodeToString(digest[:16]) {
		t.Fatal("principal must be derived from the digest")
	}
}
