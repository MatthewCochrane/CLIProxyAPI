package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCodexHTTPTimeoutConfigDurations(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte(`codex:
  http-timeouts:
    connect: 11ms
    response-header: 22ms
    stream-idle: 33ms
    total: 44ms
`))
	if err != nil {
		t.Fatalf("ParseConfigBytes() error = %v", err)
	}
	got := cfg.Codex.HTTPTimeouts.Durations()
	if got.Connect != 11*time.Millisecond || got.ResponseHeader != 22*time.Millisecond || got.StreamIdle != 33*time.Millisecond || got.Total != 44*time.Millisecond {
		t.Fatalf("Durations() = %+v", got)
	}
}

func TestCodexHTTPTimeoutConfigEmptyValuesDefault(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte("codex:\n  http-timeouts: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Codex.HTTPTimeouts.Durations()
	if got.Connect != DefaultCodexHTTPConnectTimeout || got.ResponseHeader != DefaultCodexHTTPResponseHeaderTimeout || got.StreamIdle != DefaultCodexHTTPStreamIdleTimeout || got.Total != DefaultCodexHTTPTotalTimeout {
		t.Fatalf("Durations() = %+v, want defaults", got)
	}
}

func TestCodexHTTPTimeoutConfigRejectsInvalidValues(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		value string
		want  error
	}{
		{"connect unitless", "connect", `"15"`, ErrCodexHTTPConnectTimeoutInvalid},
		{"response header invalid", "response-header", "invalid", ErrCodexHTTPResponseHeaderTimeoutInvalid},
		{"stream idle zero", "stream-idle", "0s", ErrCodexHTTPStreamIdleTimeoutInvalid},
		{"total negative", "total", "-1s", ErrCodexHTTPTotalTimeoutInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte("codex:\n  http-timeouts:\n    " + test.field + ": " + test.value + "\n")
			if _, err := ParseConfigBytes(payload); !errors.Is(err, test.want) || err.Error() != test.want.Error() {
				t.Fatalf("ParseConfigBytes() error = %v, want fixed %v", err, test.want)
			}
		})
	}
}

func TestLoadConfigRejectsInvalidCodexHTTPTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("codex:\n  http-timeouts:\n    total: 0s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); !errors.Is(err, ErrCodexHTTPTotalTimeoutInvalid) {
		t.Fatalf("LoadConfig() error = %v, want %v", err, ErrCodexHTTPTotalTimeoutInvalid)
	}
}
