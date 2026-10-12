package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	routingobs "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/observability"
)

func TestPrivateNamedAccountObservationsJoinExactEpochWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := accountTestController(t, dir)
	m := c.service.(accountTestRuntime).manager
	tokens := accountTestTokens("one")
	claims := `{"https://api.openai.com/auth":{"chatgpt_account_id":"one","chatgpt_plan_type":"plus","chatgpt_subscription_active_until":"2030-01-01"}}`
	tokens.IDToken = "e30." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".signature"
	a, err := m.CommitAccountAuthorization(context.Background(), "", strings.Repeat("1", 32), 0, tokens)
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.CommitAccountAuthorization(context.Background(), "", strings.Repeat("2", 32), 0, accountTestTokens("two"))
	if err != nil {
		t.Fatal(err)
	}
	a.Quota = coreauth.QuotaState{ObservedAt: time.Now(), Signals: map[string]string{
		"X-Codex-Primary-Used-Percent": "25", "X-Codex-Primary-Window-Minutes": "300", "X-Codex-Primary-Reset-After-Seconds": "1800",
	}}
	if _, err = m.Update(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	c.observer = routingobs.NewObserver([]byte(strings.Repeat("k", 32)), 24)
	c.observer.SetAuthSources(m.List, m.AuthMembership, m.AuthMembershipSnapshot)
	c.observer.OnResult(context.Background(), coreauth.Result{AuthID: a.ID, Success: true})
	response := accountRequest(c, "GET", routingobs.ControlAccountsPath+"/observations", "")
	if response.Code != 200 {
		t.Fatalf("observations: %d %s", response.Code, response.Body.String())
	}
	var body struct {
		Accounts []observedAccountView `json:"accounts"`
		Counters accountRequestCounts  `json:"counters"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Accounts) != 2 || body.Counters.Requests != 1 || body.Counters.Success != 1 {
		t.Fatalf("bad counters: %#v", body)
	}
	for _, row := range body.Accounts {
		if row.ID == publicAccountID(a) {
			if row.Plan == nil || *row.Plan != "plus" || row.Observation == nil || row.Observation.Counters.Requests != 1 || len(row.Observation.Quota.Windows) != 1 || *row.Observation.Quota.Windows[0].UsedPercent != 25 {
				t.Fatalf("wrong named join: %#v", row)
			}
		} else if row.ID != publicAccountID(b) || row.Observation.Counters.Requests != 0 || row.Plan != nil {
			t.Fatal("observation crossed account identities")
		}
	}
	for _, secret := range []string{a.ID, b.ID, tokens.IDToken, tokens.RefreshToken, "acct_", dir, "2030-01-01"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatalf("private value leaked: %q", secret)
		}
	}
	old, _ := m.GetByID(a.ID)
	_, err = m.CommitAccountAuthorization(context.Background(), a.ID, strings.Repeat("3", 32), 1, tokens)
	if err != nil {
		t.Fatal(err)
	}
	if c.observer.SnapshotAccount(old, time.Now()) != nil {
		t.Fatal("old detached epoch adopted new credential counters")
	}
	current, _ := m.GetByID(a.ID)
	if view := c.observer.SnapshotAccount(current, time.Now()); view == nil || view.Counters.Requests != 0 {
		t.Fatal("new epoch inherited old counter history")
	}
	// The existing strict inventory is byte-shape compatible.
	legacy := accountRequest(c, "GET", routingobs.ControlAccountsPath, "")
	if strings.Contains(legacy.Body.String(), "observation") || strings.Contains(legacy.Body.String(), "plan") {
		t.Fatal("old inventory contract changed")
	}
	// Observer capacity limits remain honest unknown coverage, not zero usage.
	c.observer = routingobs.NewObserver([]byte(strings.Repeat("k", 32)), 1)
	c.observer.SetAuthSources(m.List, m.AuthMembership, m.AuthMembershipSnapshot)
	limited := accountRequest(c, "GET", routingobs.ControlAccountsPath+"/observations", "")
	var coverage struct {
		Accounts []observedAccountView `json:"accounts"`
		Counters *accountRequestCounts `json:"counters"`
	}
	if err := json.Unmarshal(limited.Body.Bytes(), &coverage); err != nil {
		t.Fatal(err)
	}
	unknown := 0
	for _, row := range coverage.Accounts {
		if row.Observation == nil {
			unknown++
		}
	}
	if unknown != 1 || coverage.Counters != nil {
		t.Fatal("incomplete observation coverage became zero counters")
	}
	// New reads retain the independent control bearer, loopback and browser gates.
	handler := c.observer.ControlHandlerWithAccounts(strings.Repeat("s", 32), nil, nil, http.HandlerFunc(c.handle))
	for _, remote := range []string{"203.0.113.2:4000", "127.0.0.1:4000"} {
		r := httptest.NewRequest("GET", routingobs.ControlAccountsPath+"/observations", nil)
		r.RemoteAddr = remote
		if strings.HasPrefix(remote, "127.") {
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("s", 32))
			r.Header.Set("Origin", "https://browser.invalid")
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code == 200 {
			t.Fatal("browser or remote caller admitted")
		}
	}
}
