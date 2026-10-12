package cmd

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	routingobs "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/observability"
)

type accountRequestCounts struct {
	Requests uint64 `json:"requests"`
	Success  uint64 `json:"success"`
	Failure  uint64 `json:"failure"`
}

func requestCounts(c routingobs.Counters) accountRequestCounts {
	return accountRequestCounts{c.Requests, c.Success, c.Failure}
}

type namedAccountObservation struct {
	Eligibility string                      `json:"eligibility"`
	Cooldown    routingobs.CooldownSnapshot `json:"cooldown"`
	Quota       routingobs.QuotaSnapshot    `json:"quota"`
	Counters    accountRequestCounts        `json:"counters"`
}

type observedAccountView struct {
	accountView
	Provider    string                   `json:"provider"`
	Plan        *string                  `json:"plan"`
	Observation *namedAccountObservation `json:"observation"`
}

// Only a matching, already validated account token's allowlisted plan claim is
// projected. Subscription expiry is not a payment date; tokens never leave here.
func accountPlan(a *coreauth.Auth) *string {
	token, _ := a.Metadata["id_token"].(string)
	identity, _ := a.Metadata["account_id"].(string)
	if token == "" || len(token) > 65536 || identity == "" {
		return nil
	}
	claims, err := codex.ParseJWTToken(token)
	if err != nil || claims.GetAccountID() != identity {
		return nil
	}
	plan := claims.CodexAuthInfo.ChatgptPlanType
	switch plan {
	case "free", "plus", "pro", "team", "business", "enterprise", "edu":
		return &plan
	default:
		return nil
	}
}

func (c *accountController) observeAccounts(w http.ResponseWriter, values []*coreauth.Auth) {
	now := time.Now().UTC()
	rows := make([]observedAccountView, 0)
	seen := make(map[string]bool)
	for _, a := range values {
		if a.Provider != "codex" || a.Metadata[coreauth.AccountRetiredKey] == true || coreauth.IsPluginVirtualAuth(a) || a.Attributes["runtime_only"] == "true" {
			continue
		}
		row, err := projectAccount(a)
		if err != nil || seen[row.ID] {
			writeEnrollmentError(w, 503, "unavailable")
			return
		}
		seen[row.ID] = true
		view := observedAccountView{accountView: row, Provider: "openai", Plan: accountPlan(a)}
		if observation := c.observer.SnapshotAccount(a, now); observation != nil {
			view.Observation = &namedAccountObservation{observation.Eligibility, observation.Cooldown, observation.Quota, requestCounts(observation.Counters)}
		}
		rows = append(rows, view)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	var counters *accountRequestCounts
	var startedAt *time.Time
	if c.observer != nil {
		started := c.observer.StartedAt()
		startedAt = &started
		counts, complete := accountRequestCounts{}, true
		for _, row := range rows {
			if row.Observation == nil {
				complete = false
				break
			}
			counts.Requests += row.Observation.Counters.Requests
			counts.Success += row.Observation.Counters.Success
			counts.Failure += row.Observation.Counters.Failure
		}
		if complete {
			counters = &counts
		}
	}
	_ = json.NewEncoder(w).Encode(struct {
		GeneratedAt time.Time             `json:"generatedAt"`
		StartedAt   *time.Time            `json:"startedAt"`
		Counters    *accountRequestCounts `json:"counters"`
		Accounts    []observedAccountView `json:"accounts"`
	}{now, startedAt, counters, rows})
}
