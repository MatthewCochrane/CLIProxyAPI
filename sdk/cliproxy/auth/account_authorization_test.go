package auth_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	auth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func accountTokens(identity, token string) *codex.CodexTokenStorage {
	claims, _ := json.Marshal(map[string]any{"https://api.openai.com/auth": map[string]string{"chatgpt_account_id": identity}, "email": identity + "@example.invalid"})
	return &codex.CodexTokenStorage{AccountID: identity, AccessToken: token + "-access", RefreshToken: token + "-refresh", IDToken: "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".signature", Email: identity + "@example.invalid", Expire: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
}

func TestAccountAuthorizationIdentityAndRefreshOwnership(t *testing.T) {
	ctx := context.Background()
	manager, _, dir := membershipDisk(t)
	base := membershipState(t, manager, true, 0)
	before, _ := os.ReadFile(filepath.Join(dir, "one.json"))
	if _, err := manager.CommitAccountAuthorization(ctx, "one.json", "wrong-login", 0, accountTokens("different", "new")); !errors.Is(err, auth.ErrAccountIdentityMismatch) {
		t.Fatal("wrong identity replaced account")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "one.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("wrong login wrote credentials")
	}
	updated, err := manager.CommitAccountAuthorization(ctx, "one.json", "reauthorize", 0, accountTokens("one", "new"))
	if err != nil || updated.Disabled || !auth.AccountIncluded(updated) || updated.RegistrationEpoch == base.RegistrationEpoch {
		t.Fatal("reauthorization did not retain membership and fence old refresh")
	}
	rotated := base.Clone()
	rotated.Metadata["refresh_token"] = "obsolete-late-refresh"
	if _, err := manager.UpdateRefreshedAuth(ctx, base, rotated); err == nil {
		t.Fatal("old credential family refresh accepted")
	}
	reloaded, _ := membershipLoad(t, dir)
	current := membershipState(t, reloaded, true, 1)
	if current.Metadata["refresh_token"] != "new-refresh" {
		t.Fatal("credential replacement lost")
	}
	if _, err := reloaded.CommitAccountAuthorization(ctx, "one.json", "reauthorize", 0, accountTokens("one", "unused")); err != nil {
		t.Fatal(err)
	}
	current = membershipState(t, reloaded, true, 1)
	if current.Metadata["refresh_token"] != "new-refresh" {
		t.Fatal("reply retry installed a second token family")
	}
}

func TestAccountNewAuthorizationRetirementAndCleanStart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	manager, _ := membershipLoad(t, dir)
	first, err := manager.CommitAccountAuthorization(ctx, "", "authorize", 0, accountTokens("new", "first"))
	if err != nil || !first.Disabled || auth.AccountIncluded(first) {
		t.Fatalf("new account not excluded: %v", err)
	}
	if _, err := manager.CommitAccountAuthorization(ctx, "", "duplicate", 0, accountTokens("new", "duplicate")); !errors.Is(err, auth.ErrAccountConflict) {
		t.Fatal("duplicate active owner created")
	}
	if _, err := manager.SetAccountMembership(ctx, first.ID, "include", 1, true); err != nil {
		t.Fatal(err)
	}
	retired, err := manager.RetireAccount(ctx, first.ID, "retire", 2)
	if err != nil || retired.Metadata[auth.AccountRetiredKey] != true || auth.AccountIncluded(retired) {
		t.Fatal("retirement failed")
	}
	if _, err := manager.SetAccountMembership(ctx, first.ID, "bad-include", 3, true); !errors.Is(err, auth.ErrAccountUnavailable) {
		t.Fatal("retired account reincluded")
	}
	second, err := manager.CommitAccountAuthorization(ctx, "", "fresh-login", 0, accountTokens("new", "second"))
	if err != nil || second.ID != first.ID || auth.AccountIncluded(second) {
		t.Fatalf("clean start did not preserve one owner: %v", err)
	}
	reloaded, _ := membershipLoad(t, dir)
	values := reloaded.List()
	if len(values) != 1 || values[0].Metadata["refresh_token"] != "second-refresh" || values[0].Metadata[auth.AccountRetiredKey] != false {
		t.Fatal("clean start created competing persistent owners")
	}
}

func TestAccountControlRejectsUnversionedStaleWatcher(t *testing.T) {
	manager, _, dir := membershipDisk(t)
	old := membershipState(t, manager, true, 0)
	if _, err := manager.SetAccountMembership(context.Background(), old.ID, "remove", 0, false); err != nil {
		t.Fatal(err)
	}
	old.Generation = 0
	old.RegistrationEpoch = 0
	if _, err := manager.Update(auth.WithSkipPersist(context.Background()), old); !errors.Is(err, auth.ErrAccountConflict) {
		t.Fatal("stale watcher undid membership")
	}
	reloaded, _ := membershipLoad(t, dir)
	membershipState(t, reloaded, false, 1)
}

func TestAccountDesiredMembershipSurvivesAuthenticationFailure(t *testing.T) {
	manager, _, dir := membershipDisk(t)
	base := membershipState(t, manager, true, 0)
	if _, err := manager.SetAccountMembership(context.Background(), base.ID, "include", 0, true); err != nil {
		t.Fatal(err)
	}
	latest, _ := manager.GetByID(base.ID)
	failed := latest.Clone()
	failed.Disabled = true
	failed.Status = auth.StatusDisabled
	failed.LastError = &auth.Error{HTTPStatus: 401, Code: "authentication_failed", Message: "dummy"}
	if _, err := manager.UpdateRefreshedAuth(context.Background(), latest, failed); err != nil {
		t.Fatal(err)
	}
	current, _ := manager.GetByID(base.ID)
	if !auth.AccountIncluded(current) {
		t.Fatal("authentication failure erased desired membership")
	}
	manager, _ = membershipLoad(t, dir)
	current, _ = manager.GetByID(base.ID)
	if !auth.AccountRequiresReauthorization(current) {
		t.Fatal("reload lost terminal credential failure")
	}
	if _, err := manager.SetAccountMembership(context.Background(), base.ID, "remove", 1, false); err != nil {
		t.Fatal(err)
	}
	manager, _ = membershipLoad(t, dir)
	if _, err := manager.SetAccountMembership(context.Background(), base.ID, "include-again", 2, true); err != nil {
		t.Fatal(err)
	}
	current, _ = manager.GetByID(base.ID)
	if !current.Disabled || !auth.AccountRequiresReauthorization(current) || !auth.AccountIncluded(current) {
		t.Fatal("membership repaired credentials without authorization")
	}
	reauthorized, err := manager.CommitAccountAuthorization(context.Background(), base.ID, "reauthorize", 3, accountTokens("one", "new"))
	if err != nil || reauthorized.Disabled || !auth.AccountIncluded(reauthorized) {
		t.Fatal("reauthorization failed to restore included account")
	}
}
