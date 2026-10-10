package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSharedInferenceCoexistsWithoutManagedKeyFallback(t *testing.T) {
	_, store := privateKeyStore(t)
	managed, _ := GenerateEnvironmentKey()
	if _, err := store.Issue("existing-environment", managed); err != nil {
		t.Fatal(err)
	}
	manager := NewManager()
	manager.SetProviders([]Provider{permissiveProvider{}})
	manager.SetEnvironmentKeyVerifier(store.Verify)
	shared := "unissued-shared-fixture-key-453"
	if err := manager.SetSharedInferenceKeys([]string{shared}); err != nil {
		t.Fatal(err)
	}
	authenticate := func(key string) (*Result, *AuthError) {
		request := httptest.NewRequest("GET", "http://localhost/v1/models", nil)
		request.Header.Set("Authorization", "Bearer "+key)
		return manager.Authenticate(context.Background(), request)
	}
	for key, provider := range map[string]string{shared: "shared-inference-key", managed: "managed-inference-key"} {
		result, err := authenticate(key)
		if err != nil || result == nil || result.Provider != provider || result.Principal == key {
			t.Fatalf("wrong authentication result for %s", provider)
		}
	}
	if err := store.Revoke("existing-environment", 1); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{managed, EnvironmentKeyPrefix + "invalid", "wrong-shared-fixture"} {
		if result, err := authenticate(key); result != nil || err == nil {
			t.Fatal("rejected credential fell through")
		}
	}
	mixed := httptest.NewRequest("GET", "http://localhost/v1/models?key=other", nil)
	mixed.Header.Set("Authorization", "Bearer "+shared)
	if result, err := manager.Authenticate(context.Background(), mixed); result != nil || err == nil {
		t.Fatal("mixed credentials accepted")
	}
	if err := manager.SetSharedInferenceKeys(nil); err != nil {
		t.Fatal(err)
	}
	if result, err := authenticate(shared); result != nil || err == nil {
		t.Fatal("removed shared key remained accepted")
	}
}

func TestEmptyExplicitSharedConfigurationNeverBecomesAnonymous(t *testing.T) {
	manager := NewManager()
	manager.SetProviders([]Provider{permissiveProvider{}})
	if err := manager.SetSharedInferenceKeys(nil); err != nil {
		t.Fatal(err)
	}
	for _, request := range []*http.Request{nil, httptest.NewRequest("GET", "http://localhost/v1/models", nil)} {
		if result, err := manager.Authenticate(context.Background(), request); result != nil || err == nil {
			t.Fatal("empty explicit shared configuration became anonymous")
		}
	}
}

func TestSharedInferenceConfigurationDoesNotOverwriteValidKeysOnError(t *testing.T) {
	manager := NewManager()
	valid := "unissued-valid-shared-fixture"
	control := "unissued-private-control-fixture"
	if err := manager.SetSharedInferenceKeys([]string{valid}, control); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"short", "key with whitespace invalid", EnvironmentKeyPrefix + "not-shared", control} {
		if manager.SetSharedInferenceKeys([]string{key}) == nil {
			t.Fatal("invalid shared configuration accepted")
		}
	}
	request := httptest.NewRequest("GET", "http://localhost/v1/models", nil)
	request.Header.Set("Authorization", "Bearer "+valid)
	if result, err := manager.Authenticate(context.Background(), request); err != nil || result == nil || result.Principal != "shared-pool" {
		t.Fatal("invalid reload erased valid credential")
	}
}
