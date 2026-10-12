package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	routingobs "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/observability"
)

type accountRuntime interface {
	ControlledAccounts() ([]*coreauth.Auth, error)
	SetControlledMembership(context.Context, string, string, uint64, bool) (*coreauth.Auth, error)
	CommitControlledAuthorization(context.Context, string, string, uint64, *codex.CodexTokenStorage) (*coreauth.Auth, error)
	ConfirmControlledAuthorization(context.Context, string, string) (*coreauth.Auth, error)
	RetireControlledAccount(context.Context, string, string, uint64) (*coreauth.Auth, error)
}

type accountView struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	Authorization string    `json:"authorization"`
	Included      bool      `json:"included"`
	Availability  string    `json:"availability"`
	Revision      uint64    `json:"revision"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type accountAttempt struct {
	ID        string    `json:"id"`
	Target    string    `json:"targetId"`
	Expected  uint64    `json:"expectedRevision"`
	State     string    `json:"state"`
	AccountID string    `json:"accountId,omitempty"`
	Failure   string    `json:"failure,omitempty"`
	Expires   time.Time `json:"expiresAt"`
	Code      string    `json:"-"`
	URL       string    `json:"-"`
	cancel    context.CancelFunc
}

type accountController struct {
	mu             sync.Mutex
	dir, authDir   string
	parent         context.Context
	service        accountRuntime
	login          deviceLogin
	attempts       map[string]*accountAttempt
	loaded, closed bool
	observer       *routingobs.Observer
}

func newAccountController(cfg *config.Config) *accountController {
	return &accountController{authDir: cfg.AuthDir, dir: filepath.Join(cfg.AuthDir, ".submind-account-operations"), login: newEnrollmentController(cfg).login, attempts: make(map[string]*accountAttempt)}
}

func (c *accountController) bindService(ctx context.Context, service *cliproxy.Service) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.parent, c.service = ctx, service
}
func (c *accountController) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for _, a := range c.attempts {
		if a.cancel != nil {
			a.cancel()
		}
		a.Code = ""
	}
}

func publicAccountID(value *coreauth.Auth) string {
	identity, _ := value.Metadata["account_id"].(string)
	if identity == "" || len(identity) > 256 {
		return ""
	}
	digest := sha256.Sum256([]byte("submind-proxy-account-v1:" + identity))
	return hex.EncodeToString(digest[:])
}

func projectAccount(value *coreauth.Auth) (accountView, error) {
	id := publicAccountID(value)
	revision, err := coreauth.AccountRevision(value)
	if err != nil || id == "" {
		return accountView{}, coreauth.ErrAccountUnavailable
	}
	email, _ := value.Metadata["email"].(string)
	if len(email) > 320 || strings.ContainsAny(email, "\r\n\t") {
		email = ""
	}
	authorization := "authorized"
	accessToken, accessOK := value.Metadata["access_token"].(string)
	refreshToken, refreshOK := value.Metadata["refresh_token"].(string)
	if !accessOK || accessToken == "" || !refreshOK || refreshToken == "" {
		authorization = "unknown"
	}
	if coreauth.AccountRequiresReauthorization(value) {
		authorization = "reauthorization_required"
	}
	availability := "eligible"
	if !coreauth.AccountIncluded(value) {
		availability = "not_included"
	} else if authorization != "authorized" {
		availability = authorization
	} else if value.Quota.Exceeded {
		availability = "quota_limited"
	} else if value.Unavailable {
		availability = "cooldown"
	}
	updated := value.UpdatedAt
	if updated.IsZero() {
		updated = value.CreatedAt
	}
	return accountView{ID: id, Email: email, Authorization: authorization, Included: coreauth.AccountIncluded(value), Availability: availability, Revision: revision, UpdatedAt: updated}, nil
}

func (c *accountController) accounts() ([]*coreauth.Auth, error) {
	if c.closed || c.service == nil || c.parent == nil || c.parent.Err() != nil {
		return nil, coreauth.ErrAccountUnavailable
	}
	return c.service.ControlledAccounts()
}

func findAccount(values []*coreauth.Auth, id string, retired bool) *coreauth.Auth {
	var found *coreauth.Auth
	for _, a := range values {
		if a.Provider != "codex" || coreauth.IsPluginVirtualAuth(a) || a.Attributes["runtime_only"] == "true" || !retired && a.Metadata[coreauth.AccountRetiredKey] == true || publicAccountID(a) != id {
			continue
		}
		if found != nil {
			return nil
		}
		found = a
	}
	return found
}

func (c *accountController) save(a *accountAttempt) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return codex.SaveControlReceipt(filepath.Join(c.dir, a.ID+".receipt"), append(raw, '\n'))
}

// Called under c.mu only after the service loaded its authoritative token store.
func (c *accountController) load(values []*coreauth.Auth) error {
	if c.loaded {
		return nil
	}
	if err := os.Mkdir(c.dir, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(c.dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !controlAuthDirOwner(info) {
		return coreauth.ErrAccountUnavailable
	}
	entries, err := os.ReadDir(c.dir)
	if err != nil || len(entries) > 1024 {
		return coreauth.ErrAccountUnavailable
	}
	for _, entry := range entries {
		name := entry.Name()
		fileInfo, err := entry.Info()
		if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != 0600 || !controlAuthDirOwner(fileInfo) || fileInfo.Size() > 4096 {
			return coreauth.ErrAccountUnavailable
		}
		// Preserve an owned atomic-writer temporary file left by process death.
		// It is not a published receipt and cannot authorize or cancel anything.
		if len(name) == 70 && name[0] == '.' && isLowerHex(name[1:33]) && name[33:46] == ".receipt.tmp-" && isLowerHex(name[46:]) {
			continue
		}
		if !strings.HasSuffix(name, ".receipt") || len(name) != 40 || !isLowerHex(name[:32]) {
			return coreauth.ErrAccountUnavailable
		}
		raw, err := os.ReadFile(filepath.Join(c.dir, name))
		var a accountAttempt
		if err != nil || json.Unmarshal(raw, &a) != nil || a.ID != name[:32] {
			return coreauth.ErrAccountUnavailable
		}
		c.attempts[a.ID] = &a
		if a.State == "pending" || a.State == "awaiting_authorization" {
			a.State = "expired"
			a.Failure = "service_restarted"
			if err := c.save(&a); err != nil {
				return err
			}
		}
		if a.State == "committing" || a.State == "commit_uncertain" {
			if err := c.reconcile(&a, values); err != nil && !errors.Is(err, coreauth.ErrAccountUncertain) {
				return err
			}
		}
	}
	c.loaded = true
	return nil
}

func (c *accountController) reconcile(a *accountAttempt, values []*coreauth.Auth) error {
	var value *coreauth.Auth
	for _, candidate := range values {
		if candidate.Provider == "codex" && candidate.Metadata[coreauth.AccountOperationKey] == a.ID {
			if value != nil {
				return coreauth.ErrAccountConflict
			}
			value = candidate
		}
	}
	if value == nil {
		// Absence from the loaded runtime is not proof that a prior commit did
		// not happen. Keep this attempt fenced without blocking other accounts.
		a.State = "commit_uncertain"
		a.Failure = ""
		if err := c.save(a); err != nil {
			return err
		}
		return coreauth.ErrAccountUncertain
	}
	confirmed, err := c.service.ConfirmControlledAuthorization(c.parent, value.ID, a.ID)
	if err != nil {
		return err
	}
	a.AccountID = publicAccountID(confirmed)
	a.State = "completed"
	a.Failure = ""
	return c.save(a)
}

func (c *accountController) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeEnrollmentError(w, 400, "invalid_request")
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	values, err := c.accounts()
	if err != nil || c.load(values) != nil {
		writeEnrollmentError(w, 503, "unavailable")
		return
	}
	path := r.URL.Path
	if (path == routingobs.ControlAccountsPath || path == routingobs.ControlAccountsPath+"/observations") && r.Method == http.MethodGet {
		// A browser reload may lose its transient operation handle. Reconcile only
		// our recorded commits against positive credential evidence; missing
		// evidence stays fenced without hiding unrelated inventory.
		for _, attempt := range c.attempts {
			if attempt.State == "committing" || attempt.State == "commit_uncertain" {
				_ = c.reconcile(attempt, values)
			}
		}
		if path == routingobs.ControlAccountsPath+"/observations" {
			c.observeAccounts(w, values)
			return
		}
		rows := make([]accountView, 0)
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
			rows = append(rows, row)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
		_ = json.NewEncoder(w).Encode(struct {
			Accounts []accountView `json:"accounts"`
		}{rows})
		return
	}
	if path == routingobs.ControlAccountAuthorizationsPath && r.Method == http.MethodPost {
		c.startAccount(w, r, values)
		return
	}
	if strings.HasPrefix(path, routingobs.ControlAccountAuthorizationsPath+"/") {
		id := strings.TrimPrefix(path, routingobs.ControlAccountAuthorizationsPath+"/")
		if len(id) != 32 || !isLowerHex(id) {
			writeEnrollmentError(w, 404, "not_found")
			return
		}
		a := c.attempts[id]
		if r.Method == http.MethodDelete {
			if a == nil {
				a = &accountAttempt{ID: id, State: "cancelled", Expires: time.Now()}
				if len(c.attempts) >= 1024 || c.save(a) != nil {
					writeEnrollmentError(w, 503, "unavailable")
					return
				}
				c.attempts[id] = a
			}
			if a.State == "committing" || a.State == "commit_uncertain" {
				writeEnrollmentError(w, 409, "commit_uncertain")
				return
			}
			if a.State == "pending" || a.State == "awaiting_authorization" {
				copy := *a
				copy.State = "cancelled"
				if c.save(&copy) != nil {
					writeEnrollmentError(w, 503, "unavailable")
					return
				}
				a.State = "cancelled"
				a.Code = ""
				if a.cancel != nil {
					a.cancel()
				}
			}
			w.WriteHeader(204)
			return
		}
		if r.Method != http.MethodGet {
			writeEnrollmentError(w, 405, "method_not_allowed")
			return
		}
		if a == nil {
			writeEnrollmentError(w, 404, "not_found")
			return
		}
		if a.State == "committing" || a.State == "commit_uncertain" {
			if c.reconcile(a, values) != nil {
				writeEnrollmentError(w, 503, "unavailable")
				return
			}
		}
		c.replyAttempt(w, a)
		return
	}
	if strings.HasPrefix(path, routingobs.ControlAccountsPath+"/") && r.Method == http.MethodPost {
		parts := strings.Split(strings.TrimPrefix(path, routingobs.ControlAccountsPath+"/"), "/")
		if len(parts) != 2 || len(parts[0]) != 64 || !isLowerHex(parts[0]) {
			writeEnrollmentError(w, 404, "not_found")
			return
		}
		var request struct {
			OperationID string  `json:"operationId"`
			Expected    *uint64 `json:"expectedRevision"`
			Included    *bool   `json:"included,omitempty"`
		}
		if r.Header.Get("Content-Type") != "application/json" || !readPrivateControlJSON(r.Body, &request) || len(request.OperationID) != 32 || !isLowerHex(request.OperationID) || request.Expected == nil || *request.Expected >= coreauth.MaxAccountRevision || parts[1] != "membership" && parts[1] != "retire" || parts[1] == "membership" && request.Included == nil || parts[1] == "retire" && request.Included != nil {
			writeEnrollmentError(w, 400, "invalid_request")
			return
		}
		current := findAccount(values, parts[0], parts[1] == "retire")
		if current == nil {
			writeEnrollmentError(w, 404, "not_found")
			return
		}
		for _, a := range c.attempts {
			if (a.Target == parts[0] || a.AccountID == parts[0]) && (a.State == "pending" || a.State == "awaiting_authorization" || a.State == "committing" || a.State == "commit_uncertain") {
				writeEnrollmentError(w, 409, "authorization_in_progress")
				return
			}
		}
		var result *coreauth.Auth
		if parts[1] == "membership" {
			result, err = c.service.SetControlledMembership(c.parent, current.ID, request.OperationID, *request.Expected, *request.Included)
		} else {
			result, err = c.service.RetireControlledAccount(c.parent, current.ID, request.OperationID, *request.Expected)
		}
		if err != nil {
			c.accountError(w, err)
			return
		}
		row, err := projectAccount(result)
		if err != nil {
			c.accountError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(row)
		return
	}
	writeEnrollmentError(w, 404, "not_found")
}

func (c *accountController) startAccount(w http.ResponseWriter, r *http.Request, values []*coreauth.Auth) {
	var request struct {
		ID       string  `json:"attemptId"`
		Target   *string `json:"targetId"`
		Expected *uint64 `json:"expectedRevision"`
	}
	if r.Header.Get("Content-Type") != "application/json" || !readPrivateControlJSON(r.Body, &request) || len(request.ID) != 32 || !isLowerHex(request.ID) || request.Target == nil || request.Expected == nil || *request.Target != "" && (len(*request.Target) != 64 || !isLowerHex(*request.Target)) || *request.Expected >= coreauth.MaxAccountRevision || *request.Target == "" && *request.Expected != 0 {
		writeEnrollmentError(w, 400, "invalid_request")
		return
	}
	target, expected := *request.Target, *request.Expected
	if existing := c.attempts[request.ID]; existing != nil {
		if existing.Target != target || existing.Expected != expected || existing.State == "cancelled" {
			writeEnrollmentError(w, 409, "operation_conflict")
			return
		}
		w.WriteHeader(202)
		c.replyAttempt(w, existing)
		return
	}
	if target != "" {
		current := findAccount(values, target, false)
		if current == nil {
			writeEnrollmentError(w, 404, "not_found")
			return
		}
		revision, err := coreauth.AccountRevision(current)
		if err != nil || revision != expected {
			writeEnrollmentError(w, 409, "revision_conflict")
			return
		}
	}
	active := 0
	for _, a := range c.attempts {
		if a.State == "pending" || a.State == "awaiting_authorization" || a.State == "committing" || a.State == "commit_uncertain" {
			active++
			if target != "" && a.Target == target {
				writeEnrollmentError(w, 409, "authorization_in_progress")
				return
			}
		}
	}
	if active >= 8 || len(c.attempts) >= 1024 {
		writeEnrollmentError(w, 503, "unavailable")
		return
	}
	a := &accountAttempt{ID: request.ID, Target: target, Expected: expected, State: "pending", Expires: time.Now().Add(15 * time.Minute)}
	if c.save(a) != nil {
		writeEnrollmentError(w, 503, "unavailable")
		return
	}
	ctx, cancel := context.WithDeadline(c.parent, a.Expires)
	a.cancel = cancel
	c.attempts[a.ID] = a
	go c.authorize(ctx, a)
	w.WriteHeader(202)
	c.replyAttempt(w, a)
}

func (c *accountController) authorize(ctx context.Context, a *accountAttempt) {
	defer a.cancel()
	storage, err := c.login(ctx, func(url, code string) error {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.closed || ctx.Err() != nil || a.State != "pending" || url != "https://auth.openai.com/codex/device" || !validChallenge(code) {
			return errors.New("challenge rejected")
		}
		copy := *a
		copy.State = "awaiting_authorization"
		if err := c.save(&copy); err != nil {
			return err
		}
		a.State, a.Code, a.URL = copy.State, code, url
		return nil
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || a.State == "cancelled" {
		return
	}
	a.Code = ""
	a.URL = ""
	if err != nil || storage == nil || ctx.Err() != nil || a.State != "awaiting_authorization" {
		a.State = "failed"
		a.Failure = "authorization_failed"
		if ctx.Err() != nil {
			a.State = "expired"
			a.Failure = "authorization_expired"
		}
		_ = c.save(a)
		return
	}
	values, err := c.accounts()
	if err != nil {
		a.State = "failed"
		a.Failure = "unavailable"
		_ = c.save(a)
		return
	}
	target := ""
	if a.Target != "" {
		current := findAccount(values, a.Target, false)
		if current == nil {
			a.State = "failed"
			a.Failure = "revision_conflict"
			_ = c.save(a)
			return
		}
		target = current.ID
	}
	a.State = "committing"
	if c.save(a) != nil {
		a.State = "commit_uncertain"
		return
	}
	result, err := c.service.CommitControlledAuthorization(c.parent, target, a.ID, a.Expected, storage)
	if err != nil {
		if errors.Is(err, coreauth.ErrAccountUncertain) {
			a.State = "commit_uncertain"
		} else {
			a.State = "failed"
			a.Failure = "authorization_conflict"
			if !errors.Is(err, coreauth.ErrAccountConflict) {
				a.Failure = "authorization_failed"
			}
			if errors.Is(err, coreauth.ErrAccountIdentityMismatch) {
				a.Failure = "identity_mismatch"
			}
		}
		_ = c.save(a)
		return
	}
	a.AccountID = publicAccountID(result)
	a.State = "completed"
	if c.save(a) != nil {
		a.State = "commit_uncertain"
	}
}

func (c *accountController) replyAttempt(w http.ResponseWriter, a *accountAttempt) {
	result := struct {
		ID        string    `json:"id"`
		State     string    `json:"state"`
		AccountID string    `json:"accountId,omitempty"`
		Failure   string    `json:"failure,omitempty"`
		Expires   time.Time `json:"expiresAt"`
		URL       string    `json:"verificationUrl,omitempty"`
		Code      string    `json:"code,omitempty"`
	}{ID: a.ID, State: a.State, AccountID: a.AccountID, Failure: a.Failure, Expires: a.Expires}
	if a.State == "awaiting_authorization" && a.Expires.After(time.Now()) {
		result.URL, result.Code = a.URL, a.Code
	}
	_ = json.NewEncoder(w).Encode(result)
}

func (c *accountController) accountError(w http.ResponseWriter, err error) {
	if errors.Is(err, coreauth.ErrAccountConflict) {
		writeEnrollmentError(w, 409, "revision_conflict")
	} else if errors.Is(err, coreauth.ErrAccountUncertain) {
		writeEnrollmentError(w, 503, "commit_uncertain")
	} else {
		writeEnrollmentError(w, 503, "unavailable")
	}
}

// Keep the interface assertion at compile time; HTTP handlers never acquire or
// expose a raw token store or the broad management API.
var _ accountRuntime = (*cliproxy.Service)(nil)
