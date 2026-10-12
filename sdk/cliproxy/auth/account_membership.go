package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
)

const (
	AccountRevisionKey      = "submind_membership_revision"
	AccountOperationKey     = "submind_membership_operation"
	accountExpectedKey      = "submind_membership_expected"
	accountActionKey        = "submind_account_action"
	AccountRetiredKey       = "submind_account_retired"
	AccountIncludedKey      = "submind_account_included"
	AccountAuthorizationKey = "submind_account_reauthorization_required"
	MaxAccountRevision      = uint64(1<<53 - 1)
)

var (
	ErrAccountConflict         = errors.New("account revision or operation conflict")
	ErrAccountUncertain        = errors.New("account publication durability is uncertain")
	ErrAccountUnavailable      = errors.New("persistent Codex account unavailable")
	ErrAccountIdentityMismatch = errors.New("authorization identity does not match selected account")
)

// AccountRevision is the durable account-control revision, independent of the
// runtime registration epoch and token refresh generation.
func AccountRevision(value *Auth) (uint64, error) {
	if value == nil || value.Metadata == nil {
		return 0, ErrAccountUnavailable
	}
	if raw, exists := value.Metadata[AccountIncludedKey]; exists {
		if _, ok := raw.(bool); !ok {
			return 0, ErrAccountConflict
		}
	}
	if raw, exists := value.Metadata[AccountAuthorizationKey]; exists {
		if _, ok := raw.(bool); !ok {
			return 0, ErrAccountConflict
		}
	}
	raw, exists := value.Metadata[AccountRevisionKey]
	if !exists {
		return 0, nil
	}
	text, ok := raw.(string)
	revision, err := strconv.ParseUint(text, 10, 64)
	if !ok || err != nil || revision > MaxAccountRevision || strconv.FormatUint(revision, 10) != text {
		return 0, ErrAccountConflict
	}
	return revision, nil
}

// Membership is desired state, not a promise that currently invalid credentials
// or quota permit routing. A terminal refresh may disable execution separately.
func AccountIncluded(value *Auth) bool {
	if value == nil {
		return false
	}
	if included, ok := value.Metadata[AccountIncludedKey].(bool); ok {
		return included
	}
	return !value.Disabled
}

// AccountRequiresReauthorization retains a terminal credential failure across
// reload and subsequent membership changes. Inclusion never repairs credentials.
func AccountRequiresReauthorization(value *Auth) bool {
	if value == nil {
		return false
	}
	if value.Metadata[AccountAuthorizationKey] == true || value.Disabled && AccountIncluded(value) {
		return true
	}
	return value.Disabled && value.LastError != nil && (value.LastError.HTTPStatus == 401 || value.LastError.HTTPStatus == 403)
}

// SetAccountMembership changes desired routing membership, preserving the latest
// credentials. The receipt is saved atomically before installing runtime state.
// Replaying the current operation re-saves it before acknowledging durability.
func (m *Manager) SetAccountMembership(ctx context.Context, id, operation string, expected uint64, included bool) (*Auth, error) {
	if operation == "" || len(operation) > 128 || strings.TrimSpace(operation) != operation || shouldSkipPersist(ctx) || expected >= MaxAccountRevision {
		return nil, ErrAccountConflict
	}
	m.mu.Lock()
	current := m.auths[id]
	if !controlledAccount(current) || current.Metadata[AccountRetiredKey] == true || m.store == nil {
		m.mu.Unlock()
		return nil, ErrAccountUnavailable
	}
	revision, err := AccountRevision(current)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	replay := current.Metadata[AccountOperationKey] == operation
	if replay {
		if revision != expected+1 || current.Metadata[accountExpectedKey] != strconv.FormatUint(expected, 10) || AccountIncluded(current) != included || current.Metadata[accountActionKey] != "membership" {
			m.mu.Unlock()
			return nil, ErrAccountConflict
		}
	} else if revision != expected {
		m.mu.Unlock()
		return nil, ErrAccountConflict
	}
	next := current.Clone()
	next.Disabled = !included
	reauthorizationRequired := AccountRequiresReauthorization(current)
	if included && reauthorizationRequired {
		next.Disabled = true
	}
	next.Status = StatusActive
	if next.Disabled {
		next.Status = StatusDisabled
	}
	next.Metadata["disabled"] = next.Disabled
	next.Metadata[AccountIncludedKey] = included
	next.Metadata[AccountAuthorizationKey] = reauthorizationRequired
	if !replay {
		next.Metadata[AccountRevisionKey] = strconv.FormatUint(revision+1, 10)
		next.Metadata[AccountOperationKey] = operation
		next.Metadata[accountExpectedKey] = strconv.FormatUint(expected, 10)
		next.Metadata[accountActionKey] = "membership"
	}
	next.Generation++
	next.UpdatedAt = time.Now()
	// Disk-loaded records have no Storage serializer. Explicitly select the
	// existing atomic Codex writer, retaining every current metadata field.
	next.Storage = &codex.CodexTokenStorage{}
	return m.publishControlledAccountLocked(ctx, next)
}

func controlledAccount(value *Auth) bool {
	return value != nil && value.Provider == "codex" && value.Metadata != nil && !IsPluginVirtualAuth(value) && value.Attributes["runtime_only"] != "true"
}

// The caller holds m.mu. This function always releases it, including errors.
func (m *Manager) publishControlledAccountLocked(ctx context.Context, next *Auth) (*Auth, error) {
	lockValue, _ := m.persistLocks.LoadOrStore(next.ID, &authPersistLock{})
	pLock := lockValue.(*authPersistLock)
	pLock.mu.Lock()
	if next.RegistrationEpoch < pLock.lastEpoch || next.RegistrationEpoch == pLock.lastEpoch && next.Generation < pLock.lastGeneration {
		pLock.mu.Unlock()
		m.mu.Unlock()
		return nil, ErrAccountConflict
	}
	path, saveErr := m.store.Save(ctx, next)
	visible := false
	if saveErr != nil {
		if store, ok := m.store.(interface{ SaveErrorCommitted(error) bool }); ok {
			visible = store.SaveErrorCommitted(saveErr)
		}
		if !visible {
			pLock.mu.Unlock()
			m.mu.Unlock()
			return nil, fmt.Errorf("persist account membership: %w", saveErr)
		}
	} else if path == "" {
		pLock.mu.Unlock()
		m.mu.Unlock()
		return nil, ErrAccountUnavailable
	}
	pLock.lastEpoch, pLock.lastGeneration = next.RegistrationEpoch, next.Generation
	previous := m.auths[next.ID]
	m.auths[next.ID] = next.Clone()
	if m.authEpochs == nil {
		m.authEpochs = make(map[string]uint64)
	}
	m.authEpochs[next.ID] = next.RegistrationEpoch
	if previous == nil || previous.RegistrationEpoch != next.RegistrationEpoch {
		m.advanceAuthMembershipGenerationLocked()
	}
	pLock.mu.Unlock()
	m.mu.Unlock()
	if m.scheduler != nil {
		m.scheduler.upsertAuth(next.Clone())
	}
	m.queueRefreshReschedule(next.ID)
	m.hook.OnAuthUpdated(ctx, next.Clone())
	if visible {
		return nil, ErrAccountUncertain
	}
	return next.Clone(), nil
}
