package auth_test

import (
	"context"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	filestore "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	auth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type usageRefreshExecutor struct {
	auth.ProviderExecutor
	calls atomic.Int32
}

func (e *usageRefreshExecutor) Identifier() string { return "codex" }
func (e *usageRefreshExecutor) Refresh(_ context.Context, a *auth.Auth) (*auth.Auth, error) {
	e.calls.Add(1)
	a.Metadata["access_token"] = "refreshed-token"
	a.Metadata["expired"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	return a, nil
}

func TestAccountUsageRefreshPersistsExcludedCredentialAndDeduplicates(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	storage := &codex.CodexTokenStorage{AccessToken: "old-token", RefreshToken: "refresh-token", AccountID: "one", Expire: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), Metadata: map[string]any{"disabled": true, auth.AccountIncludedKey: false}}
	if err := storage.SaveTokenToFile(filepath.Join(dir, "one.json")); err != nil {
		t.Fatal(err)
	}
	store := filestore.NewFileTokenStore()
	store.SetBaseDir(dir)
	manager := auth.NewManager(store, &auth.RoundRobinSelector{}, nil)
	if err := manager.Load(ctx); err != nil {
		t.Fatal(err)
	}
	executor := &usageRefreshExecutor{}
	manager.RegisterExecutor(executor)
	a, ok := manager.GetByID("one.json")
	if !ok {
		t.Fatal("missing account")
	}
	refreshed, err := manager.UsageCredential(ctx, a.ID, a.RegistrationEpoch, "")
	if err != nil || refreshed.Metadata["access_token"] != "refreshed-token" || !refreshed.Disabled || auth.AccountIncluded(refreshed) {
		t.Fatalf("excluded owned rotation failed: %v", err)
	}
	if _, err := manager.UsageCredential(ctx, a.ID, a.RegistrationEpoch, "old-token"); err != nil || executor.calls.Load() != 1 {
		t.Fatal("concurrent old token caused second rotation")
	}
	reloaded := auth.NewManager(store, &auth.RoundRobinSelector{}, nil)
	if err := reloaded.Load(ctx); err != nil {
		t.Fatal(err)
	}
	current, _ := reloaded.GetByID(a.ID)
	if current.Metadata["access_token"] != "refreshed-token" || !current.Disabled || auth.AccountIncluded(current) {
		t.Fatal("rotation or exclusion lost on restart")
	}
	if _, err := manager.RetireAccount(ctx, a.ID, "retire", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.UsageCredential(ctx, a.ID, a.RegistrationEpoch, ""); err == nil {
		t.Fatal("retired owner reused")
	}
}
