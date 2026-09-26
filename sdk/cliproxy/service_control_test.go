package cliproxy

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
)

func TestPrivateControlPinsAuthDirectoryAcrossConfigReload(t *testing.T) {
	service := &Service{cfg: &config.Config{AuthDir: "/private/auth"}}
	if err := service.PinControlAuthDir("/different/auth"); err == nil || service.controlAuthDir != "" {
		t.Fatal("mismatched private control auth directory was pinned")
	}
	if err := service.PinControlAuthDir("/private/auth"); err != nil {
		t.Fatal(err)
	}
	if commit := service.commitConfigUpdate(&config.Config{AuthDir: "/different/auth"}); commit.cfg != nil || service.cfg.AuthDir != "/private/auth" {
		t.Fatal("hot reload redirected the enrolled credential store")
	}
	if commit := service.commitConfigUpdate(&config.Config{AuthDir: "/private/auth"}); commit.cfg == nil || service.cfg.AuthDir != "/private/auth" {
		t.Fatal("same-directory config reload was blocked")
	}
}

func TestPrivateInferenceAdmissionSurvivesProviderAndConfigReload(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "key-store")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := sdkaccess.NewEnvironmentKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	key, err := sdkaccess.GenerateEnvironmentKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Issue("env-A", key); err != nil {
		t.Fatal(err)
	}
	manager := sdkaccess.NewManager()
	service := &Service{cfg: &config.Config{AuthDir: "/private/auth"}, accessManager: manager}
	if err := service.PinControlAuthDir("/private/auth"); err != nil {
		t.Fatal(err)
	}
	if err := service.BindEnvironmentKeyStore(store); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "http://localhost/v1/models", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+key)
	check := func(accepted bool) {
		t.Helper()
		result, authErr := manager.Authenticate(context.Background(), request)
		if accepted && (authErr != nil || result == nil || result.Provider != "managed-inference-key") ||
			!accepted && (authErr == nil || result != nil) {
			t.Fatalf("accepted=%t, result=%#v, error=%v", accepted, result, authErr)
		}
	}
	check(true)
	manager.SetProviders(sdkaccess.RegisteredProviders())
	if commit := service.commitConfigUpdate(&config.Config{AuthDir: "/private/auth"}); commit.cfg == nil {
		t.Fatal("same-directory config reload failed")
	}
	check(true)
	if err := store.Revoke("env-A", 1); err != nil {
		t.Fatal(err)
	}
	check(false)
}
