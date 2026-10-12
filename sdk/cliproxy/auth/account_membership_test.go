package auth_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	filestore "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	auth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type membershipStore struct {
	*filestore.FileTokenStore
	fail, visible bool
	exitAt        string
}

func (s *membershipStore) Save(ctx context.Context, value *auth.Auth) (string, error) {
	if s.fail {
		return "", errors.New("injected pre-publication failure")
	}
	if s.exitAt == "before-save" {
		os.Exit(73)
	}
	path, err := s.FileTokenStore.Save(ctx, value)
	if err == nil && s.exitAt == "after-save" {
		os.Exit(73)
	}
	if err == nil && s.visible {
		return path, codex.ErrTokenCommitDurabilityUncertain
	}
	return path, err
}

func membershipLoad(t *testing.T, dir string) (*auth.Manager, *membershipStore) {
	t.Helper()
	store := &membershipStore{FileTokenStore: filestore.NewFileTokenStore()}
	store.SetBaseDir(dir)
	manager := auth.NewManager(store, &auth.RoundRobinSelector{}, nil)
	if err := manager.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	return manager, store
}

func membershipDisk(t *testing.T) (*auth.Manager, *membershipStore, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"one", "other"} {
		value := &codex.CodexTokenStorage{AccountID: id, AccessToken: "dummy-access", RefreshToken: "dummy-refresh", IDToken: "dummy-id", Email: id + "@example.invalid", Metadata: map[string]any{"disabled": false}}
		if err := value.SaveTokenToFile(filepath.Join(dir, id+".json")); err != nil {
			t.Fatal(err)
		}
	}
	manager, store := membershipLoad(t, dir)
	return manager, store, dir
}

func membershipState(t *testing.T, manager *auth.Manager, included bool, revision uint64) *auth.Auth {
	t.Helper()
	value, ok := manager.GetByID("one.json")
	if !ok || value.Disabled == included {
		t.Fatal("unexpected membership")
	}
	actual, err := auth.AccountRevision(value)
	if err != nil || actual != revision {
		t.Fatal("unexpected revision")
	}
	return value
}

func TestAccountMembershipFailureReplayRefreshAndIsolation(t *testing.T) {
	ctx := context.Background()
	manager, store, dir := membershipDisk(t)
	before, _ := os.ReadFile(filepath.Join(dir, "one.json"))
	other, _ := os.ReadFile(filepath.Join(dir, "other.json"))
	base := membershipState(t, manager, true, 0)
	store.fail = true
	if _, err := manager.SetAccountMembership(ctx, "one.json", "remove", 0, false); err == nil {
		t.Fatal("failed save acknowledged")
	}
	membershipState(t, manager, true, 0)
	after, _ := os.ReadFile(filepath.Join(dir, "one.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("failed save changed disk")
	}
	store.fail = false
	if _, err := manager.SetAccountMembership(ctx, "one.json", "remove", 0, false); err != nil {
		t.Fatal(err)
	}
	rotated := base.Clone()
	rotated.Metadata["access_token"], rotated.Metadata["refresh_token"] = "new-access", "new-refresh"
	if _, err := manager.UpdateRefreshedAuth(ctx, base, rotated); err != nil {
		t.Fatal(err)
	}
	reloaded, _ := membershipLoad(t, dir)
	current := membershipState(t, reloaded, false, 1)
	if current.Metadata["refresh_token"] != "new-refresh" {
		t.Fatal("refresh rotation lost")
	}
	if _, err := reloaded.SetAccountMembership(ctx, "one.json", "remove", 0, false); err != nil {
		t.Fatal(err)
	}
	membershipState(t, reloaded, false, 1)
	if _, err := reloaded.SetAccountMembership(ctx, "one.json", "include", 1, true); err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct {
		op       string
		expected uint64
		included bool
	}{{"remove", 0, false}, {"stale", 0, false}, {"include", 1, false}} {
		if _, err := reloaded.SetAccountMembership(ctx, "one.json", request.op, request.expected, request.included); !errors.Is(err, auth.ErrAccountConflict) {
			t.Fatal("stale request accepted")
		}
	}
	latest, _ := membershipLoad(t, dir)
	membershipState(t, latest, true, 2)
	afterOther, _ := os.ReadFile(filepath.Join(dir, "other.json"))
	if !bytes.Equal(other, afterOther) {
		t.Fatal("unrelated account changed")
	}
}

func TestAccountMembershipRejectsEqualRevisionStaleWatcherTokens(t *testing.T) {
	ctx := context.Background()
	manager, _, dir := membershipDisk(t)
	if _, err := manager.SetAccountMembership(ctx, "one.json", "include", 0, true); err != nil {
		t.Fatal(err)
	}
	base := membershipState(t, manager, true, 1)
	stale := base.Clone()
	stale.Generation = 0
	stale.RegistrationEpoch = 0
	rotated := base.Clone()
	rotated.Metadata["access_token"] = "rotated-access"
	rotated.Metadata["refresh_token"] = "rotated-refresh"
	if _, err := manager.UpdateRefreshedAuth(ctx, base, rotated); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Update(auth.WithSkipPersist(ctx), stale); !errors.Is(err, auth.ErrAccountConflict) {
		t.Fatalf("stale watcher accepted: %v", err)
	}
	current := membershipState(t, manager, true, 1)
	if current.Metadata["refresh_token"] != "rotated-refresh" {
		t.Fatal("watcher restored stale credentials")
	}
	reloaded, _ := membershipLoad(t, dir)
	if membershipState(t, reloaded, true, 1).Metadata["refresh_token"] != "rotated-refresh" {
		t.Fatal("disk rotation lost")
	}
	observed := current.Clone()
	observed.Generation = 0
	observed.RegistrationEpoch = 0
	if _, err := manager.Update(auth.WithSkipPersist(ctx), observed); err != nil {
		t.Fatalf("current observation rejected: %v", err)
	}
}

func TestAccountMembershipAtomicWriterAndVisibleUncertainty(t *testing.T) {
	manager, store, dir := membershipDisk(t)
	path := filepath.Join(dir, "one.json")
	if err := os.Link(path, filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.SetAccountMembership(context.Background(), "one.json", "remove", 0, false); err == nil {
		t.Fatal("hardlink accepted")
	}
	membershipState(t, manager, true, 0)
	if err := os.Remove(filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	store.visible = true
	if _, err := manager.SetAccountMembership(context.Background(), "one.json", "remove", 0, false); !errors.Is(err, auth.ErrAccountUncertain) {
		t.Fatal("uncertain commit acknowledged")
	}
	membershipState(t, manager, false, 1)
	store.visible = false
	if _, err := manager.SetAccountMembership(context.Background(), "one.json", "remove", 0, false); err != nil {
		t.Fatal(err)
	}
}

func TestAccountMembershipProcessExit(t *testing.T) {
	if dir := os.Getenv("MEMBERSHIP_TEST_DIR"); dir != "" {
		manager, store := membershipLoad(t, dir)
		store.exitAt = os.Getenv("MEMBERSHIP_TEST_EXIT")
		if _, err := manager.SetAccountMembership(context.Background(), "one.json", "remove", 0, false); err != nil {
			t.Fatal(err)
		}
		os.Exit(73)
	}
	for _, point := range []string{"before-save", "after-save", "before-reply"} {
		t.Run(point, func(t *testing.T) {
			_, _, dir := membershipDisk(t)
			child := exec.Command(os.Args[0], "-test.run=^TestAccountMembershipProcessExit$")
			child.Env = append(os.Environ(), "MEMBERSHIP_TEST_DIR="+dir, "MEMBERSHIP_TEST_EXIT="+point)
			output, err := child.CombinedOutput()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 73 {
				t.Fatalf("unexpected child exit: %v %s", err, output)
			}
			manager, _ := membershipLoad(t, dir)
			if point == "before-save" {
				membershipState(t, manager, true, 0)
			} else {
				membershipState(t, manager, false, 1)
			}
			if _, err := manager.SetAccountMembership(context.Background(), "one.json", "remove", 0, false); err != nil {
				t.Fatal(err)
			}
			membershipState(t, manager, false, 1)
		})
	}
}
