//go:build !linux

package codex

import (
	"strings"
	"testing"
)

func TestSaveTokenToFileFailsClosedOutsideLinux(t *testing.T) {
	err := (&CodexTokenStorage{AccessToken: "credential-secret"}).SaveTokenToFile("codex.json")
	if err == nil || !strings.Contains(err.Error(), "only supported on Linux") {
		t.Fatalf("SaveTokenToFile() error = %v, want Linux compatibility error", err)
	}
	if strings.Contains(err.Error(), "credential-secret") {
		t.Fatalf("SaveTokenToFile() exposed credential data: %v", err)
	}
}
