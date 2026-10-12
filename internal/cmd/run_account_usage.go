package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	routingobs "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/observability"
)

var errUsageAuthentication = errors.New("usage authentication required")
var errUsageUnavailable = errors.New("usage unavailable")

type usageCredentialOwner interface {
	ControlledUsageCredential(context.Context, string, uint64, string) (*coreauth.Auth, error)
}

func newAccountUsageReader(cfg *config.Config) func(context.Context, *coreauth.Auth) (routingobs.QuotaSnapshot, error) {
	return func(ctx context.Context, a *coreauth.Auth) (routingobs.QuotaSnapshot, error) {
		sdk := cfg.SDKConfig
		if a.ProxyURL != "" {
			sdk.ProxyURL = a.ProxyURL
		}
		client := util.SetProxy(&sdk, &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }})
		return readAccountUsage(ctx, a, client)
	}
}

func readAccountUsage(ctx context.Context, a *coreauth.Auth, client *http.Client) (routingobs.QuotaSnapshot, error) {
	var empty routingobs.QuotaSnapshot
	access, _ := a.Metadata["access_token"].(string)
	identity, _ := a.Metadata["account_id"].(string)
	if access == "" || identity == "" || len(access) > 16384 || len(identity) > 256 || strings.ContainsAny(access+identity, "\r\n") {
		return empty, errUsageUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://chatgpt.com/backend-api/wham/usage", nil)
	if err != nil {
		return empty, errUsageUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("ChatGPT-Account-Id", identity)
	req.Header.Set("Accept", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return empty, errUsageUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == 401 {
		return empty, errUsageAuthentication
	}
	if response.StatusCode != 200 {
		return empty, errUsageUnavailable
	}
	contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" || response.ContentLength > 256*1024 {
		return empty, errUsageUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 256*1024+1))
	if err != nil || len(body) > 256*1024 {
		return empty, errUsageUnavailable
	}
	return normalizeAccountUsage(body, time.Now().UTC())
}

func normalizeAccountUsage(body []byte, now time.Time) (routingobs.QuotaSnapshot, error) {
	var raw struct {
		RateLimit *struct {
			Primary   json.RawMessage `json:"primary_window"`
			Secondary json.RawMessage `json:"secondary_window"`
		} `json:"rate_limit"`
	}
	if json.Unmarshal(body, &raw) != nil || raw.RateLimit == nil {
		return routingobs.QuotaSnapshot{}, errUsageUnavailable
	}
	windows := make([]routingobs.QuotaWindow, 0, 2)
	seen := make(map[int]bool)
	for _, candidate := range []json.RawMessage{raw.RateLimit.Primary, raw.RateLimit.Secondary} {
		if len(candidate) == 0 || string(candidate) == "null" {
			continue
		}
		var value struct {
			Duration *int     `json:"limit_window_seconds"`
			Used     *float64 `json:"used_percent"`
			ResetAt  *int64   `json:"reset_at"`
		}
		if json.Unmarshal(candidate, &value) != nil {
			return routingobs.QuotaSnapshot{}, errUsageUnavailable
		}
		if value.Duration == nil || (*value.Duration != 18000 && *value.Duration != 604800) {
			continue
		}
		if seen[*value.Duration] || value.Used == nil || math.IsNaN(*value.Used) || math.IsInf(*value.Used, 0) || *value.Used < 0 || *value.Used > 100 {
			return routingobs.QuotaSnapshot{}, errUsageUnavailable
		}
		seen[*value.Duration] = true
		minutes := int64(*value.Duration / 60)
		category := "five_hour"
		if minutes == 10080 {
			category = "seven_day"
		}
		var reset *time.Time
		if value.ResetAt != nil {
			if *value.ResetAt <= 0 || *value.ResetAt > 253402300799 {
				return routingobs.QuotaSnapshot{}, errUsageUnavailable
			}
			timestamp := time.Unix(*value.ResetAt, 0).UTC()
			reset = &timestamp
		}
		windows = append(windows, routingobs.QuotaWindow{Category: category, UsedPercent: value.Used, WindowMinutes: &minutes, ResetsAt: reset})
	}
	if len(windows) == 0 {
		return routingobs.QuotaSnapshot{}, errUsageUnavailable
	}
	return routingobs.QuotaSnapshot{Status: "fresh", ObservedAt: &now, Windows: windows}, nil
}

func (c *accountController) checkAccountUsage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, routingobs.ControlAccountsPath+"/"), "/usage")
	var body struct{}
	if len(id) != 64 || !isLowerHex(id) || r.Header.Get("Content-Type") != "application/json" || !readPrivateControlJSON(r.Body, &body) || r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeEnrollmentError(w, 400, "invalid_request")
		return
	}
	c.mu.Lock()
	values, err := c.accounts()
	a := findAccount(values, id, false)
	owner, owned := c.service.(usageCredentialOwner)
	parent, read, closed := c.parent, c.readUsage, c.closed
	c.mu.Unlock()
	if err != nil || a == nil || !owned || read == nil || parent == nil || closed || coreauth.AccountRequiresReauthorization(a) {
		writeEnrollmentError(w, 503, "usage_unavailable")
		return
	}
	// Credential rotation uses the service lifetime, not the caller's short HTTP
	// deadline: an acquired rotation must complete its owned durable publication.
	credential, err := owner.ControlledUsageCredential(parent, a.ID, a.RegistrationEpoch, "")
	if err != nil {
		writeEnrollmentError(w, 503, "usage_unavailable")
		return
	}
	quota, err := read(r.Context(), credential)
	if errors.Is(err, errUsageAuthentication) && r.Context().Err() == nil {
		failedToken, _ := credential.Metadata["access_token"].(string)
		credential, err = owner.ControlledUsageCredential(parent, a.ID, a.RegistrationEpoch, failedToken)
		if err == nil {
			quota, err = read(r.Context(), credential)
		}
	}
	c.mu.Lock()
	current, currentErr := c.accounts()
	latest := findAccount(current, id, false)
	c.mu.Unlock()
	if err != nil || currentErr != nil || latest == nil || latest.RegistrationEpoch != a.RegistrationEpoch || coreauth.AccountRequiresReauthorization(latest) || r.Context().Err() != nil {
		writeEnrollmentError(w, 503, "usage_unavailable")
		return
	}
	_ = json.NewEncoder(w).Encode(struct {
		ID    string                   `json:"id"`
		Quota routingobs.QuotaSnapshot `json:"quota"`
	}{id, quota})
}
