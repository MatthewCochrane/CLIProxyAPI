package auth

import (
	"context"
	"time"
)

// UsageCredential uses the existing serialized, durable credential lifecycle;
// membership is not changed and excluded credentials are never made selectable.
func (m *Manager) UsageCredential(ctx context.Context, id string, epoch uint64, failedToken string) (*Auth, error) {
	a, ok := m.GetByID(id)
	if !ok || a.Provider != "codex" || a.RegistrationEpoch != epoch || a.Metadata[AccountRetiredKey] == true || AccountRequiresReauthorization(a) {
		return nil, ErrAccountUnavailable
	}
	if failedToken == "" && a.HasValidAccessToken(time.Now()) {
		return a, nil
	}
	if failedToken == "" {
		failedToken = authAccessToken(a)
	}
	updated, err := m.refreshAuthForRequest(ctx, id, failedToken)
	if err != nil || updated == nil || updated.RegistrationEpoch != epoch {
		return nil, ErrAccountUnavailable
	}
	return updated, nil
}
