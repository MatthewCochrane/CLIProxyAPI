package cliproxy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	filestore "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestControlledMembershipCoordinatesRegistryAndRouting(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	id := "controlled-routing-account.json"
	storage := &codex.CodexTokenStorage{AccountID: "controlled-routing", Email: "routing@example.invalid", AccessToken: "dummy-access", RefreshToken: "dummy-refresh", IDToken: "dummy-id", Metadata: map[string]any{"disabled": false}}
	if err := storage.SaveTokenToFile(filepath.Join(dir, id)); err != nil {
		t.Fatal(err)
	}
	store := filestore.NewFileTokenStore()
	store.SetBaseDir(dir)
	manager := coreauth.NewManager(store, &coreauth.RoundRobinSelector{}, nil)
	if err := manager.Load(ctx); err != nil {
		t.Fatal(err)
	}
	service := &Service{coreManager: manager, cfg: &config.Config{AuthDir: dir}}
	if _, err := service.ControlledAccounts(); !errors.Is(err, coreauth.ErrAccountUnavailable) {
		t.Fatal("unready service exposed accounts")
	}
	service.accountControlReady.Store(true)
	t.Cleanup(func() { GlobalModelRegistry().UnregisterClient(id) })
	current, _ := manager.GetByID(id)
	service.ensureExecutorsForAuthWithContext(ctx, current, false)
	service.completeModelRegistrationForAuth(ctx, current)
	models := GlobalModelRegistry().GetModelsForClient(id)
	if len(models) == 0 {
		t.Fatal("initial registry missing")
	}
	model := models[0].ID
	if _, err := manager.SelectAuth(ctx, "codex", model, executor.Options{}); err != nil {
		t.Fatalf("initial selection: %v", err)
	}
	if _, err := service.SetControlledMembership(ctx, id, "remove", 0, false); err != nil {
		t.Fatal(err)
	}
	if len(GlobalModelRegistry().GetModelsForClient(id)) != 0 {
		t.Fatal("excluded account registry retained")
	}
	if _, err := manager.SelectAuth(ctx, "codex", model, executor.Options{}); err == nil {
		t.Fatal("excluded account routed")
	}
	if _, err := service.SetControlledMembership(ctx, id, "include", 1, true); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.SelectAuth(ctx, "codex", model, executor.Options{}); err != nil {
		t.Fatalf("included account not selectable: %v", err)
	}
	if _, err := service.RetireControlledAccount(ctx, id, "retire", 2); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.SelectAuth(ctx, "codex", model, executor.Options{}); err == nil {
		t.Fatal("retired account routed")
	}
}
