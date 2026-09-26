//go:build linux

package codex

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("os.Chmod(%s): %v", dir, err)
	}
	return dir
}

func TestSaveTokenToFileExactContentAndMode(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, "codex.json")
	storage := &CodexTokenStorage{AccessToken: "access"}

	if err := storage.SaveTokenToFile(path); err != nil {
		t.Fatalf("SaveTokenToFile: %v", err)
	}
	want := "{\n  \"access_token\": \"access\",\n  \"account_id\": \"\",\n  \"email\": \"\",\n  \"expired\": \"\",\n  \"id_token\": \"\",\n  \"last_refresh\": \"\",\n  \"refresh_token\": \"\",\n  \"type\": \"codex\"\n}\n"
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != want {
		t.Fatalf("content = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestSaveTokenToFileReplacement(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, "codex.json")
	if err := os.WriteFile(path, []byte("old-token"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := (&CodexTokenStorage{AccessToken: "new-token"}).SaveTokenToFile(path); err != nil {
		t.Fatalf("SaveTokenToFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytes.Contains(got, []byte("old-token")) || !bytes.Contains(got, []byte("new-token")) {
		t.Fatalf("replacement content = %q", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "codex.json" {
		t.Fatalf("directory entries after replacement = %+v", entries)
	}
}

func TestSaveNewTokenToFileNeverReplacesExistingCredential(t *testing.T) {
	root := privateTempDir(t)
	path := filepath.Join(root, "codex-new.json")
	first := &CodexTokenStorage{AccountID: "account-a", AccessToken: "first-access", RefreshToken: "first-refresh"}
	second := &CodexTokenStorage{AccountID: "account-a", AccessToken: "second-access", RefreshToken: "second-refresh"}
	if err := first.SaveNewTokenToFile(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.SaveNewTokenToFile(path); !errors.Is(err, unix.EEXIST) {
		t.Fatal("create-only commit replaced a preexisting credential")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed create-only commit changed existing credential")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatal("failed create-only commit left a temporary token file")
	}
}

func TestSaveNewTokenToFileConcurrentCreatorsHaveOneWinner(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "codex-new.json")
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, access := range []string{"first", "second"} {
		go func() {
			<-start
			results <- (&CodexTokenStorage{AccountID: "same-account", AccessToken: access}).SaveNewTokenToFile(path)
		}()
	}
	close(start)
	first, second := <-results, <-results
	if !((first == nil && errors.Is(second, unix.EEXIST)) || (second == nil && errors.Is(first, unix.EEXIST))) {
		t.Fatalf("create-only writers did not have exactly one winner: %v, %v", first, second)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(contents, []byte(`"access_token": "first"`)) && !bytes.Contains(contents, []byte(`"access_token": "second"`)) {
		t.Fatal("winner's credential was not atomically published")
	}
}

func newEnrollmentStorage(id string) *CodexTokenStorage {
	claims := `{"https://api.openai.com/auth":{"chatgpt_account_id":"` + id + `"}}`
	return &CodexTokenStorage{
		AccountID:    id,
		IDToken:      "header." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".signature",
		AccessToken:  "access-" + id,
		RefreshToken: "refresh-" + id,
	}
}

func TestSaveNewAccountTokenToDirFencesIdentityAndLegacyFilenames(t *testing.T) {
	root := privateTempDir(t)
	first := newEnrollmentStorage("account-a")
	if _, err := first.SaveNewAccountTokenToDir(root, "account-b"); err == nil {
		t.Fatal("mismatched expected account admitted")
	}
	first.Metadata = map[string]any{"account_id": "account-b"}
	if _, err := first.SaveNewAccountTokenToDir(root, "account-a"); err == nil {
		t.Fatal("metadata overrode checked identity")
	}
	first.Metadata = nil
	path, err := first.SaveNewAccountTokenToDir(root, "account-a")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Base(path), "codex-account-") || strings.Contains(path, "account-a") {
		t.Fatal("account identity leaked through generated filename")
	}
	if _, err := newEnrollmentStorage("account-b").SaveNewAccountTokenToDir(root, "account-b"); err != nil {
		t.Fatal("independent account was blocked by prior scan: ", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newEnrollmentStorage("account-a").SaveNewAccountTokenToDir(root, "account-a"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatal("duplicate identity under generated filename was admitted")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("duplicate identity changed existing credential")
	}

	legacy := filepath.Join(privateTempDir(t), "codex-old-email-and-plan.json")
	if err := newEnrollmentStorage("legacy-account").SaveTokenToFile(legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := newEnrollmentStorage("legacy-account").SaveNewAccountTokenToDir(filepath.Dir(legacy), "legacy-account"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatal("duplicate identity under legacy email filename was admitted")
	}
}

func TestSaveNewAccountTokenToDirRejectsUnsafeInventory(t *testing.T) {
	for _, name := range []string{"malformed", "symlink", "identity-conflict", "orphan-temp"} {
		t.Run(name, func(t *testing.T) {
			root := privateTempDir(t)
			path := filepath.Join(root, "old.json")
			if name == "malformed" {
				if err := os.WriteFile(path, []byte("PRIVATE-MALFORMED"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if name == "orphan-temp" {
				if err := os.WriteFile(filepath.Join(root, ".codex-private.tmp"), []byte("PRIVATE-ORPHANED-TOKEN"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if name == "symlink" {
				if err := os.Symlink(filepath.Join(root, "absent"), path); err != nil {
					t.Fatal(err)
				}
			} else {
				storage := newEnrollmentStorage("one-identity")
				storage.AccountID = "another-identity"
				if err := storage.SaveTokenToFile(path); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := newEnrollmentStorage("fresh-account").SaveNewAccountTokenToDir(root, "fresh-account"); err == nil || strings.Contains(err.Error(), "PRIVATE-MALFORMED") || strings.Contains(err.Error(), "PRIVATE-ORPHANED-TOKEN") || strings.Contains(err.Error(), "old.json") {
				t.Fatal("unsafe inventory was skipped or leaked")
			}
		})
	}
}

func TestSaveNewAccountTokenToDirPostCommitUncertaintyCannotCreateSecondFamily(t *testing.T) {
	root := privateTempDir(t)
	previous := syncTokenParent
	syncTokenParent = func(int) error { return unix.EIO }
	defer func() { syncTokenParent = previous }()
	path, err := newEnrollmentStorage("uncertain-account").SaveNewAccountTokenToDir(root, "uncertain-account")
	if !errors.Is(err, ErrTokenCommitDurabilityUncertain) {
		t.Fatal("visible new credential lost its durability-uncertain signal")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("post-commit error falsely removed the visible credential")
	}
	if _, err := newEnrollmentStorage("uncertain-account").SaveNewAccountTokenToDir(root, "uncertain-account"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatal("second authorization was admitted after uncertain visible commit")
	}
}

func TestSaveTokenToFileEmptyPath(t *testing.T) {
	for _, path := range []string{"", " \t\n"} {
		if err := (&CodexTokenStorage{}).SaveTokenToFile(path); err == nil || !strings.Contains(err.Error(), "path is empty") {
			t.Errorf("SaveTokenToFile(%q) error = %v, want empty path error", path, err)
		}
	}
}

func TestSaveTokenToFileParentSyncFailureReportsCommittedUncertainty(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, "codex.json")
	originalSync := syncTokenParent
	syncTokenParent = func(int) error { return unix.EIO }
	t.Cleanup(func() { syncTokenParent = originalSync })

	err := (&CodexTokenStorage{AccessToken: "committed-token"}).SaveTokenToFile(path)
	if !errors.Is(err, ErrTokenCommitDurabilityUncertain) {
		t.Fatalf("SaveTokenToFile error = %v, want committed durability uncertainty", err)
	}
	if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "committed-token") {
		t.Fatalf("parent sync error exposed credential data or path: %q", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Contains(data, []byte("committed-token")) {
		t.Fatalf("committed file content = %q", data)
	}
}

func TestSaveTokenToFile_PreservesCustomMetadata(t *testing.T) {
	tempDir := privateTempDir(t)
	authFilePath := filepath.Join(tempDir, "codex-test.json")

	storage := &CodexTokenStorage{
		Type:         "codex",
		Email:        "user@example.com",
		AccessToken:  "new-access-token",
		RefreshToken: "new-refresh-token",
		IDToken:      "new-id-token",
		AccountID:    "new-account",
		Expire:       "2026-12-31T23:59:59Z",
		LastRefresh:  "2026-04-14T12:00:00Z",
	}
	storage.SetMetadata(map[string]any{
		"disabled":   false,
		"prefix":     "my-prefix",
		"websockets": false,
		"note":       "my important note",
		"proxy_url":  "http://proxy:8080",
		"weight":     float64(42),
	})

	if errSave := storage.SaveTokenToFile(authFilePath); errSave != nil {
		t.Fatalf("SaveTokenToFile() error = %v", errSave)
	}

	savedRaw, errRead := os.ReadFile(authFilePath)
	if errRead != nil {
		t.Fatalf("os.ReadFile error = %v", errRead)
	}

	var saved map[string]any
	if errUnmarshal := json.Unmarshal(savedRaw, &saved); errUnmarshal != nil {
		t.Fatalf("json.Unmarshal error = %v", errUnmarshal)
	}

	// Verify updated OAuth token fields
	if saved["access_token"] != "new-access-token" {
		t.Errorf("access_token = %v, want new-access-token", saved["access_token"])
	}
	if saved["refresh_token"] != "new-refresh-token" {
		t.Errorf("refresh_token = %v, want new-refresh-token", saved["refresh_token"])
	}
	if saved["id_token"] != "new-id-token" {
		t.Errorf("id_token = %v, want new-id-token", saved["id_token"])
	}
	if saved["account_id"] != "new-account" {
		t.Errorf("account_id = %v, want new-account", saved["account_id"])
	}

	// Verify custom fields in metadata
	if saved["prefix"] != "my-prefix" {
		t.Errorf("prefix = %v, want my-prefix", saved["prefix"])
	}
	if saved["websockets"] != false {
		t.Errorf("websockets = %v, want false", saved["websockets"])
	}
	if saved["note"] != "my important note" {
		t.Errorf("note = %v, want my important note", saved["note"])
	}
	if saved["proxy_url"] != "http://proxy:8080" {
		t.Errorf("proxy_url = %v, want http://proxy:8080", saved["proxy_url"])
	}
	if saved["weight"] != float64(42) {
		t.Errorf("weight = %v, want 42", saved["weight"])
	}
}

func TestSaveTokenToFilePrecommitFailurePreservesDestination(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, "codex.json")
	want := []byte("existing-token-data")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	storage := &CodexTokenStorage{Metadata: map[string]any{"invalid": make(chan int)}}
	if err := storage.SaveTokenToFile(path); err == nil {
		t.Fatal("SaveTokenToFile error = nil, want encoding error")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("destination after precommit failure = %q, want %q", got, want)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "codex.json" {
		t.Fatalf("directory entries after precommit failure = %+v", entries)
	}
}

func TestSaveTokenToFileRejectsUnsafeFilesystemObjects(t *testing.T) {
	t.Run("missing parent", func(t *testing.T) {
		root := privateTempDir(t)
		parent := filepath.Join(root, "missing")
		err := (&CodexTokenStorage{AccessToken: "secret"}).SaveTokenToFile(filepath.Join(parent, "codex.json"))
		if err == nil {
			t.Fatal("SaveTokenToFile error = nil, want missing parent error")
		}
		if _, statErr := os.Stat(parent); !os.IsNotExist(statErr) {
			t.Fatalf("missing parent was created: %v", statErr)
		}
	})

	t.Run("parent mode", func(t *testing.T) {
		root := privateTempDir(t)
		parent := filepath.Join(root, "auth")
		if err := os.Mkdir(parent, 0o750); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		if err := (&CodexTokenStorage{AccessToken: "secret"}).SaveTokenToFile(filepath.Join(parent, "codex.json")); err == nil {
			t.Fatal("SaveTokenToFile error = nil, want unsafe parent mode error")
		}
	})

	t.Run("parent symlink component", func(t *testing.T) {
		root := privateTempDir(t)
		realParent := filepath.Join(root, "real")
		if err := os.MkdirAll(filepath.Join(realParent, "nested"), 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		linkedParent := filepath.Join(root, "linked")
		if err := os.Symlink(realParent, linkedParent); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		path := filepath.Join(linkedParent, "nested", "codex.json")
		if err := (&CodexTokenStorage{AccessToken: "secret"}).SaveTokenToFile(path); err == nil {
			t.Fatal("SaveTokenToFile error = nil, want parent symlink error")
		}
		if _, err := os.Stat(filepath.Join(realParent, "nested", "codex.json")); !os.IsNotExist(err) {
			t.Fatalf("token written through parent symlink: %v", err)
		}
	})

	t.Run("destination symlink", func(t *testing.T) {
		dir := privateTempDir(t)
		target := filepath.Join(dir, "target.json")
		if err := os.WriteFile(target, []byte("target-data"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		path := filepath.Join(dir, "codex.json")
		if err := os.Symlink(target, path); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		if err := (&CodexTokenStorage{AccessToken: "secret"}).SaveTokenToFile(path); err == nil {
			t.Fatal("SaveTokenToFile error = nil, want destination symlink error")
		}
		got, err := os.ReadFile(target)
		if err != nil || string(got) != "target-data" {
			t.Fatalf("symlink target changed: data=%q err=%v", got, err)
		}
	})

	t.Run("destination hardlink", func(t *testing.T) {
		dir := privateTempDir(t)
		target := filepath.Join(dir, "target.json")
		if err := os.WriteFile(target, []byte("target-data"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		path := filepath.Join(dir, "codex.json")
		if err := os.Link(target, path); err != nil {
			t.Fatalf("Link: %v", err)
		}
		if err := (&CodexTokenStorage{AccessToken: "secret"}).SaveTokenToFile(path); err == nil {
			t.Fatal("SaveTokenToFile error = nil, want destination hardlink error")
		}
		got, err := os.ReadFile(target)
		if err != nil || string(got) != "target-data" {
			t.Fatalf("hardlink target changed: data=%q err=%v", got, err)
		}
	})

	t.Run("destination mode", func(t *testing.T) {
		dir := privateTempDir(t)
		path := filepath.Join(dir, "codex.json")
		if err := os.WriteFile(path, []byte("old"), 0o640); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := (&CodexTokenStorage{AccessToken: "secret"}).SaveTokenToFile(path); err == nil {
			t.Fatal("SaveTokenToFile error = nil, want unsafe destination mode error")
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "old" {
			t.Fatalf("destination changed: data=%q err=%v", got, err)
		}
	})
}

func TestSaveTokenToFileRejectsWrongOwnerWhenPrivileged(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing ownership requires root")
	}
	t.Run("parent", func(t *testing.T) {
		root := privateTempDir(t)
		parent := filepath.Join(root, "auth")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		if err := os.Chown(parent, 1, -1); err != nil {
			t.Fatalf("Chown: %v", err)
		}
		if err := (&CodexTokenStorage{}).SaveTokenToFile(filepath.Join(parent, "codex.json")); err == nil {
			t.Fatal("SaveTokenToFile error = nil, want wrong-owner parent error")
		}
	})
	t.Run("destination", func(t *testing.T) {
		dir := privateTempDir(t)
		path := filepath.Join(dir, "codex.json")
		if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := os.Chown(path, 1, -1); err != nil {
			t.Fatalf("Chown: %v", err)
		}
		if err := (&CodexTokenStorage{}).SaveTokenToFile(path); err == nil {
			t.Fatal("SaveTokenToFile error = nil, want wrong-owner destination error")
		}
	})
}
