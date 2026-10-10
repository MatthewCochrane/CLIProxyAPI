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

func TestExplicitSharedInferenceReloadAndControlSeparation(t *testing.T) {
	manager := sdkaccess.NewManager()
	first, second, control := "unissued-first-shared-fixture", "unissued-second-shared-fixture", "unissued-private-control-fixture"
	initial := &config.Config{AuthDir: "/private/auth"}
	initial.APIKeys = []string{first}
	service := &Service{cfg: initial, accessManager: manager}
	if err := service.EnableSharedInferenceKeys(control); err != nil {
		t.Fatal(err)
	}
	accepted := func(key string) bool {
		request, _ := http.NewRequest(http.MethodGet, "http://localhost/v1/models", nil)
		request.Header.Set("Authorization", "Bearer "+key)
		result, err := manager.Authenticate(context.Background(), request)
		return err == nil && result != nil && result.Provider == "shared-inference-key"
	}
	if !accepted(first) || accepted(control) {
		t.Fatal("incorrect initial shared admission")
	}
	bad := &config.Config{AuthDir: "/private/auth"}
	bad.APIKeys = []string{control}
	if service.commitConfigUpdate(bad).cfg != nil || !accepted(first) {
		t.Fatal("control credential reload must reject without changing admission")
	}
	replacement := &config.Config{AuthDir: "/private/auth"}
	replacement.APIKeys = []string{second}
	if service.commitConfigUpdate(replacement).cfg == nil || accepted(first) || !accepted(second) {
		t.Fatal("shared rotation did not replace the admission snapshot")
	}
	manager.SetProviders(sdkaccess.RegisteredProviders())
	if !accepted(second) {
		t.Fatal("ordinary provider reload erased explicit shared admission")
	}
	if service.commitConfigUpdate(&config.Config{AuthDir: "/private/auth"}).cfg == nil || accepted(second) {
		t.Fatal("empty reload must remove shared admission")
	}
}
