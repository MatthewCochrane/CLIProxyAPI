package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	filestore "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type accountTestRuntime struct{ manager *coreauth.Manager }

func (s accountTestRuntime) ControlledAccounts() ([]*coreauth.Auth, error) {
	return s.manager.List(), nil
}
func (s accountTestRuntime) SetControlledMembership(ctx context.Context, id, op string, rev uint64, included bool) (*coreauth.Auth, error) {
	return s.manager.SetAccountMembership(ctx, id, op, rev, included)
}
func (s accountTestRuntime) CommitControlledAuthorization(ctx context.Context, id, op string, rev uint64, value *codex.CodexTokenStorage) (*coreauth.Auth, error) {
	return s.manager.CommitAccountAuthorization(ctx, id, op, rev, value)
}
func (s accountTestRuntime) ConfirmControlledAuthorization(ctx context.Context, id, op string) (*coreauth.Auth, error) {
	return s.manager.ConfirmAccountAuthorization(ctx, id, op)
}
func (s accountTestRuntime) RetireControlledAccount(ctx context.Context, id, op string, rev uint64) (*coreauth.Auth, error) {
	return s.manager.RetireAccount(ctx, id, op, rev)
}

func accountTestController(t *testing.T, dir string) *accountController {
	t.Helper()
	store := filestore.NewFileTokenStore()
	store.SetBaseDir(dir)
	manager := coreauth.NewManager(store, &coreauth.RoundRobinSelector{}, nil)
	if err := manager.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &accountController{authDir: dir, dir: dir + "/.submind-account-operations", parent: context.Background(), service: accountTestRuntime{manager}, attempts: make(map[string]*accountAttempt)}
}

func accountTestTokens(identity string) *codex.CodexTokenStorage {
	claims, _ := json.Marshal(map[string]any{"https://api.openai.com/auth": map[string]string{"chatgpt_account_id": identity}})
	return &codex.CodexTokenStorage{AccountID: identity, Email: identity + "@example.invalid", AccessToken: "sensitive-access", RefreshToken: "sensitive-refresh", IDToken: "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"}
}

func accountRequest(c *accountController, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	c.handle(response, request)
	return response
}

func waitAccountState(t *testing.T, c *accountController, id, state string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		a := c.attempts[id]
		matched := a != nil && a.State == state
		c.mu.Unlock()
		if matched {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("attempt did not reach %s", state)
}

func TestPrivateAccountLifecyclePersistsAndProjectsNoTokens(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := accountTestController(t, dir)
	loginRelease := make(chan struct{})
	c.login = func(ctx context.Context, challenge func(string, string) error) (*codex.CodexTokenStorage, error) {
		if err := challenge("https://auth.openai.com/codex/device", "TEST-CODE"); err != nil {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-loginRelease:
			return accountTestTokens("one"), nil
		}
	}
	id := strings.Repeat("1", 32)
	start := accountRequest(c, "POST", "/v1/control/account-authorizations", `{"attemptId":"`+id+`","targetId":"","expectedRevision":0}`)
	if start.Code != 202 {
		t.Fatalf("start: %d %s", start.Code, start.Body.String())
	}
	waitAccountState(t, c, id, "awaiting_authorization")
	status := accountRequest(c, "GET", "/v1/control/account-authorizations/"+id, "")
	if !strings.Contains(status.Body.String(), "TEST-CODE") {
		t.Fatal("challenge missing")
	}
	close(loginRelease)
	waitAccountState(t, c, id, "completed")
	rows := accountRequest(c, "GET", "/v1/control/accounts", "")
	if rows.Code != 200 || strings.Contains(rows.Body.String(), "sensitive-") || strings.Contains(rows.Body.String(), dir) {
		t.Fatal("unsafe inventory")
	}
	var inventory struct {
		Accounts []accountView `json:"accounts"`
	}
	if json.Unmarshal(rows.Body.Bytes(), &inventory) != nil || len(inventory.Accounts) != 1 || inventory.Accounts[0].Included {
		t.Fatal("new account should be excluded")
	}
	account := inventory.Accounts[0]
	member := accountRequest(c, "POST", "/v1/control/accounts/"+account.ID+"/membership", `{"operationId":"`+strings.Repeat("2", 32)+`","expectedRevision":1,"included":true}`)
	if member.Code != 200 {
		t.Fatalf("include: %d %s", member.Code, member.Body.String())
	}
	reloaded := accountTestController(t, dir)
	rows = accountRequest(reloaded, "GET", "/v1/control/accounts", "")
	if rows.Code != 200 || !strings.Contains(rows.Body.String(), `"included":true`) {
		t.Fatal("membership did not survive restart")
	}
	completed := accountRequest(reloaded, "GET", "/v1/control/account-authorizations/"+id, "")
	if completed.Code != 200 || !strings.Contains(completed.Body.String(), `"state":"completed"`) {
		t.Fatal("authorization receipt lost")
	}
	retire := accountRequest(reloaded, "POST", "/v1/control/accounts/"+account.ID+"/retire", `{"operationId":"`+strings.Repeat("3", 32)+`","expectedRevision":2}`)
	if retire.Code != 200 {
		t.Fatal("retirement failed")
	}
	rows = accountRequest(reloaded, "GET", "/v1/control/accounts", "")
	if rows.Body.String() != "{\"accounts\":[]}\n" {
		t.Fatal("retired account still listed")
	}
}

func TestPrivateAccountCancellationFencesLateStartAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := accountTestController(t, dir)
	id := strings.Repeat("4", 32)
	if response := accountRequest(c, "DELETE", "/v1/control/account-authorizations/"+id, ""); response.Code != 204 {
		t.Fatal("cancel failed")
	}
	reloaded := accountTestController(t, dir)
	if response := accountRequest(reloaded, "POST", "/v1/control/account-authorizations", `{"attemptId":"`+id+`","targetId":"","expectedRevision":0}`); response.Code != 409 {
		t.Fatal("cancelled operation restarted")
	}
}

func TestPrivateAccountInterruptedAuthorizationExpiresWithoutRestartingOAuth(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := accountTestController(t, dir)
	id := strings.Repeat("5", 32)
	values, _ := c.accounts()
	if err := c.load(values); err != nil {
		t.Fatal(err)
	}
	a := &accountAttempt{ID: id, State: "awaiting_authorization", Expires: time.Now().Add(time.Hour), Code: "SECRET-CODE"}
	if err := c.save(a); err != nil {
		t.Fatal(err)
	}
	reloaded := accountTestController(t, dir)
	response := accountRequest(reloaded, "GET", "/v1/control/account-authorizations/"+id, "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"expired"`) || strings.Contains(response.Body.String(), "SECRET-CODE") {
		t.Fatal("interrupted OAuth was not safely expired")
	}
}

func TestPrivateAccountMissingCommitEvidenceRemainsUncertain(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := accountTestController(t, dir)
	values, _ := c.accounts()
	if err := c.load(values); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("9", 32)
	if err := c.save(&accountAttempt{ID: id, State: "committing", Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	reloaded := accountTestController(t, dir)
	if response := accountRequest(reloaded, "GET", "/v1/control/accounts", ""); response.Code != 200 {
		t.Fatal("uncertain authorization blocked unrelated inventory")
	}
	if response := accountRequest(reloaded, "GET", "/v1/control/account-authorizations/"+id, ""); response.Code != 503 {
		t.Fatal("missing evidence invented a terminal authorization result")
	}
	reloaded.mu.Lock()
	state := reloaded.attempts[id].State
	reloaded.mu.Unlock()
	if state != "commit_uncertain" {
		t.Fatal("uncertain commit lost its fence")
	}
	if response := accountRequest(reloaded, "DELETE", "/v1/control/account-authorizations/"+id, ""); response.Code != 409 {
		t.Fatal("cancellation erased an uncertain commit")
	}
}

func TestPrivateAccountInventoryReconcilesRecordedCommitAfterBrowserReload(t *testing.T) {
	for _, path := range []string{"/v1/control/accounts", "/v1/control/accounts/observations"} {
		t.Run(path, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			c := accountTestController(t, dir)
			values, err := c.accounts()
			if err != nil || c.load(values) != nil {
				t.Fatal("private store unavailable")
			}
			op := strings.Repeat("a", 32)
			account, err := c.service.CommitControlledAuthorization(context.Background(), "", op, 0, accountTestTokens("browser-reload"))
			if err != nil {
				t.Fatal(err)
			}
			attempt := &accountAttempt{ID: op, State: "commit_uncertain", Expires: time.Now().Add(time.Minute)}
			if err := c.save(attempt); err != nil {
				t.Fatal(err)
			}
			c.attempts[op] = attempt
			response := accountRequest(c, "GET", path, "")
			if response.Code != 200 || attempt.State != "completed" || attempt.AccountID != publicAccountID(account) {
				t.Fatal("inventory did not reconcile the positively recorded commit")
			}
			reloaded := accountTestController(t, dir)
			response = accountRequest(reloaded, "GET", "/v1/control/account-authorizations/"+op, "")
			if response.Code != 200 || !strings.Contains(response.Body.String(), `"state":"completed"`) {
				t.Fatal("reconciled completion was not durable")
			}
		})
	}
}

func TestPrivateAccountPreservesUnpublishedAtomicReceiptTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := accountTestController(t, dir)
	values, _ := c.accounts()
	if err := c.load(values); err != nil {
		t.Fatal(err)
	}
	path := c.dir + "/." + strings.Repeat("a", 32) + ".receipt.tmp-" + strings.Repeat("b", 24)
	if err := os.WriteFile(path, []byte("incomplete-private-intent"), 0600); err != nil {
		t.Fatal(err)
	}
	reloaded := accountTestController(t, dir)
	if response := accountRequest(reloaded, "GET", "/v1/control/accounts", ""); response.Code != 200 {
		t.Fatal("unpublished atomic temporary file blocked account inventory")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("private temporary evidence was deleted")
	}
	if len(reloaded.attempts) != 0 {
		t.Fatal("unpublished temporary file became an authorization receipt")
	}
}

func TestPrivateAccountRejectsMissingAndNullRevisionBeforeMutation(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := accountTestController(t, dir)
	for _, body := range []string{
		`{"attemptId":"` + strings.Repeat("6", 32) + `","targetId":""}`,
		`{"attemptId":"` + strings.Repeat("6", 32) + `","targetId":"","expectedRevision":null}`,
		`{"attemptId":"` + strings.Repeat("6", 32) + `","expectedRevision":0}`,
	} {
		if response := accountRequest(c, "POST", "/v1/control/account-authorizations", body); response.Code != 400 {
			t.Fatalf("invalid start admitted: %d", response.Code)
		}
	}
	for _, body := range []string{
		`{"operationId":"` + strings.Repeat("6", 32) + `","included":false}`,
		`{"operationId":"` + strings.Repeat("6", 32) + `","expectedRevision":null,"included":false}`,
	} {
		if response := accountRequest(c, "POST", "/v1/control/accounts/"+strings.Repeat("7", 64)+"/membership", body); response.Code != 400 {
			t.Fatalf("invalid mutation admitted: %d", response.Code)
		}
	}
}

func TestPrivateAccountAuthorizationsAreIndependentAndLateLoginIsCancelled(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := accountTestController(t, dir)
	var calls atomic.Uint32
	release := make(chan struct{})
	c.login = func(ctx context.Context, challenge func(string, string) error) (*codex.CodexTokenStorage, error) {
		call := calls.Add(1)
		if err := challenge("https://auth.openai.com/codex/device", "TEST-CODE"); err != nil {
			return nil, err
		}
		<-release // Deliberately model a provider reply arriving after cancellation.
		if call == 1 {
			return accountTestTokens("one"), nil
		}
		return accountTestTokens("two"), nil
	}
	one, two := strings.Repeat("8", 32), strings.Repeat("9", 32)
	for _, id := range []string{one, two} {
		response := accountRequest(c, "POST", "/v1/control/account-authorizations", `{"attemptId":"`+id+`","targetId":"","expectedRevision":0}`)
		if response.Code != 202 {
			t.Fatal("unrelated authorization blocked")
		}
		waitAccountState(t, c, id, "awaiting_authorization")
	}
	if response := accountRequest(c, "DELETE", "/v1/control/account-authorizations/"+one, ""); response.Code != 204 {
		t.Fatal("cancel failed")
	}
	close(release)
	waitAccountState(t, c, two, "completed")
	waitAccountState(t, c, one, "cancelled")
	values, err := c.accounts()
	if err != nil || len(values) != 1 || values[0].Metadata["account_id"] != "two" {
		t.Fatal("cancelled login published credentials or unrelated authorization failed")
	}
}
