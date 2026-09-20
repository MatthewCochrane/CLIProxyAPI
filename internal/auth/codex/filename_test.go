package codex

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialFileName(t *testing.T) {
	tests := []struct {
		name                  string
		email                 string
		planType              string
		hashAccountID         string
		includeProviderPrefix bool
		want                  string
	}{
		{
			name:                  "team includes account hash",
			email:                 "user@example.com",
			planType:              "team",
			hashAccountID:         "abc12345",
			includeProviderPrefix: true,
			want:                  "codex-abc12345-user@example.com-team.json",
		},
		{
			name:                  "k12 includes account hash",
			email:                 "user@example.com",
			planType:              "k12",
			hashAccountID:         "def67890",
			includeProviderPrefix: true,
			want:                  "codex-def67890-user@example.com-k12.json",
		},
		{
			name:                  "k12 without account hash falls back to email and plan",
			email:                 "user@example.com",
			planType:              "k12",
			hashAccountID:         "",
			includeProviderPrefix: true,
			want:                  "codex-user@example.com-k12.json",
		},
		{
			name:                  "plus includes account hash",
			email:                 " user@example.com ",
			planType:              "Plus",
			hashAccountID:         " abc12345 ",
			includeProviderPrefix: true,
			want:                  "codex-abc12345-user@example.com-plus.json",
		},
		{
			name:                  "plus without account hash falls back to email and plan",
			email:                 "user@example.com",
			planType:              "plus",
			hashAccountID:         "",
			includeProviderPrefix: true,
			want:                  "codex-user@example.com-plus.json",
		},
		{
			name:                  "plan is normalized",
			email:                 "user@example.com",
			planType:              " Team Plan ",
			hashAccountID:         "abc12345",
			includeProviderPrefix: true,
			want:                  "codex-abc12345-user@example.com-team-plan.json",
		},
		{
			name:                  "account hash is used without plan",
			email:                 "user@example.com",
			planType:              "",
			hashAccountID:         "abc12345",
			includeProviderPrefix: true,
			want:                  "codex-abc12345-user@example.com.json",
		},
		{
			name:                  "missing plan and account hash falls back to email",
			email:                 "user@example.com",
			planType:              "",
			hashAccountID:         "",
			includeProviderPrefix: true,
			want:                  "codex-user@example.com.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CredentialFileName(tt.email, tt.planType, tt.hashAccountID, tt.includeProviderPrefix)
			if got != tt.want {
				t.Fatalf("CredentialFileName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAccountIDHashIsBoundedAndCollisionResistant(t *testing.T) {
	first := AccountIDHash("account-a")
	second := AccountIDHash("account-b")
	if len(first) != 32 || len(second) != 32 {
		t.Fatalf("hash lengths = %d, %d; want 32", len(first), len(second))
	}
	if first == second {
		t.Fatal("distinct account IDs produced the same hash")
	}
	if got := AccountIDHash("  account-a  "); got != first {
		t.Fatalf("trimmed hash = %q, want %q", got, first)
	}
	if got := AccountIDHash("   "); got != "" {
		t.Fatalf("blank account hash = %q, want empty", got)
	}
}

func TestCredentialFileNameCannotEscapeAuthDirectory(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		hashAccountID string
	}{
		{name: "email traversal", email: "../../outside"},
		{name: "email absolute path", email: "/tmp/outside"},
		{name: "email separator", email: "user/name@example.com"},
		{name: "hash traversal", email: "user@example.com", hashAccountID: "../../outside"},
		{name: "control characters", email: "user\x00\n@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CredentialFileName(tt.email, "plus", tt.hashAccountID, true)
			if filepath.Base(got) != got || strings.ContainsAny(got, `/\\`) || got == "." || got == ".." {
				t.Fatalf("credential filename escaped its parent: %q", got)
			}
		})
	}
}

func TestCredentialFileNameBoundsLongPlanAndCombinedComponents(t *testing.T) {
	got := CredentialFileName(strings.Repeat("a", 300)+"@example.com", strings.Repeat("Enterprise Plan ", 40), strings.Repeat("b", 300), true)
	if len(got) > 240 {
		t.Fatalf("credential filename length = %d, want at most 240", len(got))
	}
	if filepath.Base(got) != got || !strings.HasSuffix(got, ".json") {
		t.Fatalf("credential filename is invalid: %q", got)
	}
}
