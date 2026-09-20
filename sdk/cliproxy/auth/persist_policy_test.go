package auth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

type countingStore struct {
	saveCount         atomic.Int32
	remainingFailures atomic.Int32
	saveErr           atomic.Pointer[error]
}

func (s *countingStore) List(context.Context) ([]*Auth, error) { return nil, nil }

func (s *countingStore) Save(context.Context, *Auth) (string, error) {
	s.saveCount.Add(1)
	if errPointer := s.saveErr.Load(); errPointer != nil {
		remaining := s.remainingFailures.Load()
		if remaining < 0 || remaining > 0 && s.remainingFailures.CompareAndSwap(remaining, remaining-1) {
			return "", *errPointer
		}
	}
	return "", nil
}

func (s *countingStore) Delete(context.Context, string) error { return nil }

func (s *countingStore) SaveErrorCommitted(err error) bool {
	var committed interface{ CommitVisible() bool }
	return errors.As(err, &committed) && committed.CommitVisible()
}

func (s *countingStore) failSaves(err error) {
	s.saveErr.Store(&err)
	s.remainingFailures.Store(-1)
}

func (s *countingStore) failNextSaves(count int32, err error) {
	s.saveErr.Store(&err)
	s.remainingFailures.Store(count)
}

func (s *countingStore) allowSaves() {
	s.saveErr.Store(nil)
	s.remainingFailures.Store(0)
}

type committedPersistenceError struct{}

func (committedPersistenceError) Error() string       { return "commit durability uncertain" }
func (committedPersistenceError) CommitVisible() bool { return true }

type nonAuthoritativeStore struct {
	inner *countingStore
}

func (s *nonAuthoritativeStore) List(ctx context.Context) ([]*Auth, error) {
	return s.inner.List(ctx)
}

func (s *nonAuthoritativeStore) Save(ctx context.Context, auth *Auth) (string, error) {
	return s.inner.Save(ctx, auth)
}

func (s *nonAuthoritativeStore) Delete(ctx context.Context, id string) error {
	return s.inner.Delete(ctx, id)
}

func TestWithSkipPersist_DisablesUpdatePersistence(t *testing.T) {
	store := &countingStore{}
	mgr := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "auth-1",
		Provider: "antigravity",
		Metadata: map[string]any{"type": "antigravity"},
	}

	if _, err := mgr.Register(WithSkipPersist(context.Background()), auth); err != nil {
		t.Fatalf("Register(skipPersist) returned error: %v", err)
	}
	if got := store.saveCount.Load(); got != 0 {
		t.Fatalf("expected 0 Save calls, got %d", got)
	}

	if _, err := mgr.Update(context.Background(), auth); err != nil {
		t.Fatalf("Update returned error: %v", err)
	}
	if got := store.saveCount.Load(); got != 1 {
		t.Fatalf("expected 1 Save call, got %d", got)
	}

	ctxSkip := WithSkipPersist(context.Background())
	if _, err := mgr.Update(ctxSkip, auth); err != nil {
		t.Fatalf("Update(skipPersist) returned error: %v", err)
	}
	if got := store.saveCount.Load(); got != 1 {
		t.Fatalf("expected Save call count to remain 1, got %d", got)
	}
}

func TestWithSkipPersist_DisablesRegisterPersistence(t *testing.T) {
	store := &countingStore{}
	mgr := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "auth-1",
		Provider: "antigravity",
		Metadata: map[string]any{"type": "antigravity"},
	}

	if _, err := mgr.Register(WithSkipPersist(context.Background()), auth); err != nil {
		t.Fatalf("Register(skipPersist) returned error: %v", err)
	}
	if got := store.saveCount.Load(); got != 0 {
		t.Fatalf("expected 0 Save calls, got %d", got)
	}
}

func TestPersist_SkipsConfigAPIKeyAuth(t *testing.T) {
	store := &countingStore{}
	mgr := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "codex:apikey:abc",
		Provider: "codex",
		Attributes: map[string]string{
			"api_key": "secret",
			"source":  "config:codex[abc]",
		},
		Metadata: map[string]any{"disable_cooling": true},
	}
	if _, err := mgr.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if got := store.saveCount.Load(); got != 0 {
		t.Fatalf("expected 0 Save calls for config api key, got %d", got)
	}
	mgr.MarkResult(context.Background(), Result{AuthID: auth.ID, Provider: "codex", Model: "gpt-5", Success: true})
	if got := store.saveCount.Load(); got != 0 {
		t.Fatalf("expected MarkResult to skip persist for config api key, got %d Save calls", got)
	}
}

func TestUpdateRefreshedCodexAuthPersistsBeforeInstall(t *testing.T) {
	store := &countingStore{}
	mgr := NewManager(store, nil, nil)
	registered, err := mgr.Register(context.Background(), &Auth{
		ID:       "codex-auth",
		Provider: "codex",
		Metadata: map[string]any{
			"access_token":  "old-access",
			"refresh_token": "old-refresh",
		},
	})
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	updated := registered.Clone()
	updated.Metadata["access_token"] = "new-access"
	updated.Metadata["refresh_token"] = "new-refresh"
	persistErr := errors.New("injected persistence failure")
	store.failSaves(persistErr)
	if _, err = mgr.UpdateRefreshedAuth(context.Background(), registered, updated); !errors.Is(err, persistErr) {
		t.Fatalf("UpdateRefreshedAuth error = %v, want persistence failure", err)
	}
	current, ok := mgr.GetByID(registered.ID)
	if !ok {
		t.Fatal("registered auth disappeared")
	}
	if got := current.Metadata["refresh_token"]; got != "old-refresh" {
		t.Fatalf("in-memory refresh token = %v, want old token after failed persistence", got)
	}

	store.allowSaves()
	saved, err := mgr.UpdateRefreshedAuth(context.Background(), registered, updated)
	if err != nil {
		t.Fatalf("UpdateRefreshedAuth retry returned error: %v", err)
	}
	if got := saved.Metadata["refresh_token"]; got != "new-refresh" {
		t.Fatalf("saved refresh token = %v, want rotated token", got)
	}
}

func TestUpdateRefreshedCodexAuthInstallsVisibleCommitAndReportsWarning(t *testing.T) {
	store := &countingStore{}
	mgr := NewManager(store, nil, nil)
	registered, err := mgr.Register(context.Background(), &Auth{
		ID:       "codex-auth",
		Provider: "codex",
		Metadata: map[string]any{"refresh_token": "old-refresh"},
	})
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	updated := registered.Clone()
	updated.Metadata["refresh_token"] = "new-refresh"
	store.failSaves(committedPersistenceError{})

	saved, err := mgr.UpdateRefreshedAuth(context.Background(), registered, updated)
	if err == nil || saved == nil {
		t.Fatalf("UpdateRefreshedAuth = (%v, %v), want installed auth plus warning", saved, err)
	}
	current, ok := mgr.GetByID(registered.ID)
	if !ok || current.Metadata["refresh_token"] != "new-refresh" {
		t.Fatalf("visible committed token was not installed: %#v", current)
	}
}

func TestUpdateRefreshedCodexAuthDoesNotTrustVisibleCommitFromUnknownStore(t *testing.T) {
	inner := &countingStore{}
	store := &nonAuthoritativeStore{inner: inner}
	mgr := NewManager(store, nil, nil)
	registered, err := mgr.Register(context.Background(), &Auth{
		ID:       "codex-auth",
		Provider: "codex",
		Metadata: map[string]any{"refresh_token": "old-refresh"},
	})
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	updated := registered.Clone()
	updated.Metadata["refresh_token"] = "new-refresh"
	inner.failSaves(committedPersistenceError{})

	if saved, errUpdate := mgr.UpdateRefreshedAuth(context.Background(), registered, updated); errUpdate == nil || saved != nil {
		t.Fatalf("UpdateRefreshedAuth = (%v, %v), want untrusted-store failure", saved, errUpdate)
	}
	current, ok := mgr.GetByID(registered.ID)
	if !ok || current.Metadata["refresh_token"] != "old-refresh" {
		t.Fatalf("untrusted visible commit was installed: %#v", current)
	}
}

func TestPersistRefreshedAuthRetriesSameRotatedCredential(t *testing.T) {
	store := &countingStore{}
	mgr := NewManager(store, nil, nil)
	registered, err := mgr.Register(context.Background(), &Auth{
		ID:       "codex-auth",
		Provider: "codex",
		Metadata: map[string]any{"refresh_token": "old-refresh"},
	})
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	updated := registered.Clone()
	updated.Metadata["refresh_token"] = "new-refresh"
	store.failNextSaves(2, errors.New("transient persistence failure"))
	before := store.saveCount.Load()

	saved, err := mgr.persistRefreshedAuth(context.Background(), registered, updated)
	if err != nil {
		t.Fatalf("persistRefreshedAuth returned error: %v", err)
	}
	if got := store.saveCount.Load() - before; got != 3 {
		t.Fatalf("Save calls = %d, want 3", got)
	}
	if got := saved.Metadata["refresh_token"]; got != "new-refresh" {
		t.Fatalf("saved refresh token = %v, want rotated token", got)
	}
}
