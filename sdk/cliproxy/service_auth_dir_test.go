package cliproxy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestEnsureAuthDirCreatesPrivateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "auth")
	service := &Service{cfg: &config.Config{AuthDir: dir}}
	if err := service.ensureAuthDir(); err != nil {
		t.Fatalf("ensureAuthDir returned error: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat returned error: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("auth directory mode = %04o, want 0700", got)
	}
}

func TestEnsureAuthDirRejectsNonPrivateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "auth")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir returned error: %v", err)
	}
	service := &Service{cfg: &config.Config{AuthDir: dir}}
	if err := service.ensureAuthDir(); err == nil {
		t.Fatal("ensureAuthDir returned nil, want unsafe-mode error")
	}
}

func TestEnsureAuthDirRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir returned error: %v", err)
	}
	dir := filepath.Join(root, "auth")
	if err := os.Symlink(target, dir); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}
	service := &Service{cfg: &config.Config{AuthDir: dir}}
	if err := service.ensureAuthDir(); err == nil {
		t.Fatal("ensureAuthDir returned nil, want symlink error")
	}
}

func TestEnsureAuthDirRejectsSymlinkedAncestor(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir returned error: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}
	dir := filepath.Join(link, "auth")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir returned error: %v", err)
	}
	service := &Service{cfg: &config.Config{AuthDir: dir}}
	if err := service.ensureAuthDir(); err == nil {
		t.Fatal("ensureAuthDir returned nil, want ancestor-symlink error")
	}
}
