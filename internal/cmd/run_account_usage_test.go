package cmd

import (
	"context"
	"errors"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	routingobs "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/observability"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type usageTransport func(*http.Request) (*http.Response, error)

func (f usageTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func (s accountTestRuntime) ControlledUsageCredential(ctx context.Context, id string, epoch uint64, failed string) (*coreauth.Auth, error) {
	return s.manager.UsageCredential(ctx, id, epoch, failed)
}

func TestPrivateAccountUsageNormalizationAndIsolation(t *testing.T) {
	now := time.Now().UTC()
	body := `{"rate_limit":{"primary_window":{"used_percent":21,"limit_window_seconds":604800,"reset_at":1792295866},"secondary_window":null},"credits":{"private":"must not project"}}`
	quota, err := normalizeAccountUsage([]byte(body), now)
	if err != nil || len(quota.Windows) != 1 || quota.Windows[0].Category != "seven_day" || *quota.Windows[0].UsedPercent != 21 {
		t.Fatalf("wrong genuine window: %v", err)
	}
	monthly, err := normalizeAccountUsage([]byte(`{"rate_limit":{"primary_window":{"used_percent":1,"limit_window_seconds":2592000,"reset_at":1792478964},"secondary_window":null}}`), now)
	if err != nil || len(monthly.Windows) != 1 || monthly.Windows[0].Category != "primary" || *monthly.Windows[0].WindowMinutes != 43200 || *monthly.Windows[0].UsedPercent != 1 {
		t.Fatalf("Free account's reported 30-day window was lost or relabeled: %v", err)
	}
	for _, bad := range []string{`{}`, `{"rate_limit":{"primary_window":{"used_percent":120,"limit_window_seconds":18000}}}`, `{"rate_limit":{"primary_window":{"used_percent":20,"limit_window_seconds":18000},"secondary_window":{"used_percent":30,"limit_window_seconds":18000}}}`} {
		if _, err := normalizeAccountUsage([]byte(bad), now); err == nil {
			t.Fatal("accepted absent, invalid or ambiguous quota")
		}
	}
	a := &coreauth.Auth{Metadata: map[string]any{"access_token": "secret-access", "account_id": "private-owner"}}
	client := &http.Client{Transport: usageTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.String() != "https://chatgpt.com/backend-api/wham/usage" || r.Header.Get("Authorization") != "Bearer secret-access" || r.Header.Get("ChatGPT-Account-Id") != "private-owner" {
			t.Fatal("unexpected usage request")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	if _, err := readAccountUsage(context.Background(), a, client); err != nil {
		t.Fatal(err)
	}
	client.Transport = usageTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("private body"))}, nil
	})
	if _, err := readAccountUsage(context.Background(), a, client); !errors.Is(err, errUsageAuthentication) {
		t.Fatal("authentication classification")
	}
}

func TestPrivateAccountUsageExcludedAndLateReplacement(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	c := accountTestController(t, dir)
	tokens := accountTestTokens("one")
	tokens.Expire = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	a, err := c.service.CommitControlledAuthorization(context.Background(), "", "first", 0, tokens)
	if err != nil {
		t.Fatal(err)
	}
	id := publicAccountID(a)
	c.readUsage = func(context.Context, *coreauth.Auth) (routingobs.QuotaSnapshot, error) {
		return normalizeAccountUsage([]byte(`{"rate_limit":{"primary_window":{"used_percent":20,"limit_window_seconds":18000,"reset_at":1792295866}}}`), time.Now().UTC())
	}
	response := accountRequest(c, "POST", routingobs.ControlAccountsPath+"/"+id+"/usage", "{}")
	if response.Code != 200 || strings.Contains(response.Body.String(), "sensitive-") {
		t.Fatalf("excluded usage read failed: %s", response.Body.String())
	}
	values, _ := c.service.ControlledAccounts()
	if coreauth.AccountIncluded(values[0]) || !values[0].Disabled {
		t.Fatal("usage changed membership")
	}
	c.readUsage = func(context.Context, *coreauth.Auth) (routingobs.QuotaSnapshot, error) {
		_, err := c.service.RetireControlledAccount(context.Background(), a.ID, "retire", 1)
		if err != nil {
			t.Fatal(err)
		}
		return normalizeAccountUsage([]byte(`{"rate_limit":{"primary_window":{"used_percent":20,"limit_window_seconds":18000}}}`), time.Now().UTC())
	}
	if response := accountRequest(c, "POST", routingobs.ControlAccountsPath+"/"+id+"/usage", "{}"); response.Code != 503 {
		t.Fatal("retired late result accepted")
	}
}
