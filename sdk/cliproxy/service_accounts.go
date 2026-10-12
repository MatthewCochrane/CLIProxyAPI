package cliproxy

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// ControlledAccounts is an in-process private adapter, never a public token API.
// The HTTP controller projects only explicitly allowed metadata from these clones.
func (s *Service) ControlledAccounts() ([]*coreauth.Auth, error) {
	if s == nil || s.coreManager == nil || !s.accountControlReady.Load() {
		return nil, coreauth.ErrAccountUnavailable
	}
	return s.coreManager.List(), nil
}

func (s *Service) ControlledUsageCredential(ctx context.Context, id string, epoch uint64, failedToken string) (*coreauth.Auth, error) {
	if _, err := s.ControlledAccounts(); err != nil {
		return nil, err
	}
	return s.coreManager.UsageCredential(ctx, id, epoch, failedToken)
}

func (s *Service) SetControlledMembership(ctx context.Context, id, operation string, expected uint64, included bool) (*coreauth.Auth, error) {
	if _, err := s.ControlledAccounts(); err != nil {
		return nil, err
	}
	s.authUpdateMu.Lock()
	defer s.authUpdateMu.Unlock()
	value, err := s.coreManager.SetAccountMembership(ctx, id, operation, expected, included)
	if current, ok := s.coreManager.GetByID(id); ok {
		s.completeModelRegistrationForAuth(ctx, current)
	}
	return value, err
}

func (s *Service) CommitControlledAuthorization(ctx context.Context, target, operation string, expected uint64, storage *codex.CodexTokenStorage) (*coreauth.Auth, error) {
	if _, err := s.ControlledAccounts(); err != nil {
		return nil, err
	}
	s.authUpdateMu.Lock()
	defer s.authUpdateMu.Unlock()
	value, err := s.coreManager.CommitAccountAuthorization(ctx, target, operation, expected, storage)
	if value != nil {
		s.ensureExecutorsForAuthWithContext(ctx, value, false)
		s.completeModelRegistrationForAuth(ctx, value)
	}
	return value, err
}

func (s *Service) RetireControlledAccount(ctx context.Context, id, operation string, expected uint64) (*coreauth.Auth, error) {
	if _, err := s.ControlledAccounts(); err != nil {
		return nil, err
	}
	s.authUpdateMu.Lock()
	defer s.authUpdateMu.Unlock()
	value, err := s.coreManager.RetireAccount(ctx, id, operation, expected)
	if current, ok := s.coreManager.GetByID(id); ok {
		s.completeModelRegistrationForAuth(ctx, current)
	}
	return value, err
}

func (s *Service) ConfirmControlledAuthorization(ctx context.Context, id, operation string) (*coreauth.Auth, error) {
	if _, err := s.ControlledAccounts(); err != nil {
		return nil, err
	}
	s.authUpdateMu.Lock()
	defer s.authUpdateMu.Unlock()
	value, err := s.coreManager.ConfirmAccountAuthorization(ctx, id, operation)
	if value != nil {
		s.ensureExecutorsForAuthWithContext(ctx, value, false)
		s.completeModelRegistrationForAuth(ctx, value)
	}
	return value, err
}
