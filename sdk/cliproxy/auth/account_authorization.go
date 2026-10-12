package auth

import (
	"context"
	"crypto/subtle"
	"strconv"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
)

// A fresh account must never replace an unexpectedly existing file. Subsequent
// refreshes use the normal atomic writer, not this creation-only adapter.
type newAccountStorage struct{ *codex.CodexTokenStorage }

func (s *newAccountStorage) SaveTokenToFile(path string) error { return s.SaveNewTokenToFile(path) }

// ConfirmAccountAuthorization re-saves an observed token publication after an
// uncertain acknowledgement without running OAuth or replacing credentials.
func (m *Manager) ConfirmAccountAuthorization(ctx context.Context, id, operation string) (*Auth, error) {
	m.mu.Lock()
	current := m.auths[id]
	if m.store == nil || shouldSkipPersist(ctx) || !controlledAccount(current) || current.Metadata[AccountOperationKey] != operation || current.Metadata[accountActionKey] != "authorization" {
		m.mu.Unlock()
		return nil, ErrAccountConflict
	}
	next := current.Clone()
	next.Storage = &codex.CodexTokenStorage{}
	return m.publishControlledAccountLocked(ctx, next)
}

// CommitAccountAuthorization receives credentials only from the private device
// worker. Existing-target replacements require the same identity and revision.
// New logins start excluded; retiring and reauthorizing reuses one credential owner.
func (m *Manager) CommitAccountAuthorization(ctx context.Context, target, operation string, expected uint64, storage *codex.CodexTokenStorage) (*Auth, error) {
	if operation == "" || len(operation) > 128 || expected >= MaxAccountRevision || target == "" && expected != 0 || shouldSkipPersist(ctx) || storage == nil || storage.AccountID == "" || len(storage.AccountID) > 256 || len(storage.Metadata) != 0 || storage.AccessToken == "" || storage.RefreshToken == "" || storage.IDToken == "" || len(storage.AccessToken) > 16<<10 || len(storage.RefreshToken) > 16<<10 || len(storage.IDToken) > 16<<10 {
		return nil, ErrAccountUnavailable
	}
	claims, err := codex.ParseJWTToken(storage.IDToken)
	if err != nil || claims == nil || subtle.ConstantTimeCompare([]byte(claims.GetAccountID()), []byte(storage.AccountID)) != 1 {
		return nil, ErrAccountConflict
	}
	m.mu.Lock()
	if m.store == nil {
		m.mu.Unlock()
		return nil, ErrAccountUnavailable
	}
	if target != "" {
		selected := m.auths[target]
		if !controlledAccount(selected) || selected.Metadata["account_id"] != storage.AccountID {
			m.mu.Unlock()
			return nil, ErrAccountIdentityMismatch
		}
	}
	var current *Auth
	for _, value := range m.auths {
		if controlledAccount(value) && value.Metadata["account_id"] == storage.AccountID {
			if current != nil {
				m.mu.Unlock()
				return nil, ErrAccountConflict
			}
			current = value
		}
	}
	if target != "" && (current == nil || current.ID != target || current.Metadata[AccountRetiredKey] == true) {
		m.mu.Unlock()
		return nil, ErrAccountConflict
	}
	if target == "" && current != nil && current.Metadata[AccountRetiredKey] != true {
		// A completed new-account attempt can be reconciled without minting a
		// second credential family. All other duplicate logins are refused.
		if current.Metadata[AccountOperationKey] == operation && current.Metadata[accountActionKey] == "authorization" {
			next := current.Clone()
			next.Storage = &codex.CodexTokenStorage{}
			return m.publishControlledAccountLocked(ctx, next)
		}
		m.mu.Unlock()
		return nil, ErrAccountConflict
	}
	revision := uint64(0)
	if current != nil {
		revision, err = AccountRevision(current)
		if err != nil {
			m.mu.Unlock()
			return nil, err
		}
		if current.Metadata[AccountOperationKey] == operation && current.Metadata[accountActionKey] == "authorization" && revision == expected+1 && current.Metadata[accountExpectedKey] == strconv.FormatUint(expected, 10) {
			next := current.Clone()
			next.Storage = &codex.CodexTokenStorage{}
			return m.publishControlledAccountLocked(ctx, next)
		}
		if target != "" && revision != expected {
			m.mu.Unlock()
			return nil, ErrAccountConflict
		}
	}
	now := time.Now()
	next := &Auth{ID: "codex-account-" + codex.AccountIDHash(storage.AccountID) + ".json", Provider: "codex", Disabled: true, Status: StatusDisabled, Metadata: map[string]any{}, CreatedAt: now, UpdatedAt: now, RegistrationEpoch: 1, Generation: 1}
	if current != nil {
		next = current.Clone()
		next.RegistrationEpoch = max(current.RegistrationEpoch, m.authEpochs[current.ID]) + 1
		next.Generation++
		next.Disabled = !AccountIncluded(current) || target == ""
	} else {
		next.FileName = next.ID
	}
	if revision >= MaxAccountRevision {
		m.mu.Unlock()
		return nil, ErrAccountConflict
	}
	next.Metadata["access_token"], next.Metadata["refresh_token"], next.Metadata["id_token"] = storage.AccessToken, storage.RefreshToken, storage.IDToken
	next.Metadata["account_id"], next.Metadata["email"], next.Metadata["type"] = storage.AccountID, storage.Email, "codex"
	next.Metadata["expired"], next.Metadata["last_refresh"] = storage.Expire, storage.LastRefresh
	next.Metadata["disabled"] = next.Disabled
	next.Metadata[AccountIncludedKey] = !next.Disabled
	next.Metadata[AccountAuthorizationKey] = false
	next.Metadata[AccountRetiredKey] = false
	next.Metadata[AccountRevisionKey] = strconv.FormatUint(revision+1, 10)
	next.Metadata[AccountOperationKey], next.Metadata[accountExpectedKey], next.Metadata[accountActionKey] = operation, strconv.FormatUint(expected, 10), "authorization"
	next.LastError = nil
	next.Unavailable = false
	next.StatusMessage = ""
	next.ModelStates = nil
	next.NextRetryAfter = time.Time{}
	next.NextRefreshAfter = time.Time{}
	next.Quota = QuotaState{}
	next.Status = StatusActive
	if next.Disabled {
		next.Status = StatusDisabled
	}
	next.UpdatedAt = now
	next.Storage = &codex.CodexTokenStorage{}
	if current == nil {
		next.Storage = &newAccountStorage{CodexTokenStorage: &codex.CodexTokenStorage{}}
	}
	result, saveErr := m.publishControlledAccountLocked(WithAuthCreationIntent(ctx), next)
	// Creation-only is a publication boundary, not the future refresh serializer.
	if result != nil {
		m.mu.Lock()
		if latest := m.auths[result.ID]; latest != nil && latest.RegistrationEpoch == result.RegistrationEpoch {
			latest.Storage = &codex.CodexTokenStorage{}
		}
		m.mu.Unlock()
	}
	return result, saveErr
}

// RetireAccount keeps a durable tombstone and private history instead of deleting
// a file and allowing a late refresh to recreate a competing credential owner.
func (m *Manager) RetireAccount(ctx context.Context, id, operation string, expected uint64) (*Auth, error) {
	if operation == "" || len(operation) > 128 || expected >= MaxAccountRevision || shouldSkipPersist(ctx) {
		return nil, ErrAccountConflict
	}
	m.mu.Lock()
	current := m.auths[id]
	if !controlledAccount(current) || m.store == nil {
		m.mu.Unlock()
		return nil, ErrAccountUnavailable
	}
	revision, err := AccountRevision(current)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	if current.Metadata[AccountOperationKey] == operation && current.Metadata[accountActionKey] == "retire" && current.Metadata[AccountRetiredKey] == true && revision == expected+1 && current.Metadata[accountExpectedKey] == strconv.FormatUint(expected, 10) {
		next := current.Clone()
		next.Storage = &codex.CodexTokenStorage{}
		return m.publishControlledAccountLocked(ctx, next)
	}
	if revision != expected || current.Metadata[AccountRetiredKey] == true {
		m.mu.Unlock()
		return nil, ErrAccountConflict
	}
	next := current.Clone()
	next.Disabled = true
	next.Status = StatusDisabled
	next.Generation++
	next.RegistrationEpoch = max(current.RegistrationEpoch, m.authEpochs[id]) + 1
	next.UpdatedAt = time.Now()
	next.Metadata["disabled"], next.Metadata[AccountRetiredKey] = true, true
	next.Metadata[AccountIncludedKey] = false
	next.Metadata[AccountRevisionKey] = strconv.FormatUint(revision+1, 10)
	next.Metadata[AccountOperationKey], next.Metadata[accountExpectedKey], next.Metadata[accountActionKey] = operation, strconv.FormatUint(expected, 10), "retire"
	next.Storage = &codex.CodexTokenStorage{}
	return m.publishControlledAccountLocked(ctx, next)
}
