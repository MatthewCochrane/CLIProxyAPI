package access

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// Manager coordinates authentication providers.
type Manager struct {
	mu                     sync.RWMutex
	providers              []Provider
	environmentKeyVerifier func(string) (string, bool)
	sharedInferenceDigests [][32]byte
	sharedForbiddenDigests [][32]byte
	sharedInferenceEnabled bool
}

// SetSharedInferenceKeys explicitly admits configured shared inference keys.
// It never delegates to permissive plugin providers or admits managed-prefix
// keys through this path. Empty configuration removes shared access.
func (m *Manager) SetSharedInferenceKeys(keys []string, forbidden ...string) error {
	if m == nil {
		return fmt.Errorf("shared inference admission is unavailable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	blocked := append([][32]byte(nil), m.sharedForbiddenDigests...)
	for _, key := range forbidden {
		if key != "" {
			blocked = append(blocked, sha256.Sum256([]byte(key)))
		}
	}
	digests := make([][32]byte, 0, len(keys))
	for _, key := range keys {
		if len(key) < 16 || len(key) > 4096 || strings.Contains(key, EnvironmentKeyPrefix) {
			return fmt.Errorf("invalid shared inference credential configuration")
		}
		for _, char := range key {
			if char < 33 || char > 126 {
				return fmt.Errorf("invalid shared inference credential configuration")
			}
		}
		digest := sha256.Sum256([]byte(key))
		for _, deny := range blocked {
			if subtle.ConstantTimeCompare(digest[:], deny[:]) == 1 {
				return fmt.Errorf("shared inference and control credentials must be independent")
			}
		}
		digests = append(digests, digest)
	}
	m.sharedInferenceDigests = digests
	m.sharedForbiddenDigests = blocked
	m.sharedInferenceEnabled = true
	return nil
}

// SetEnvironmentKeyVerifier installs the dedicated inference-only credential
// authority. A managed-key prefix never falls through to legacy providers,
// including after revocation or when no providers are configured.
func (m *Manager) SetEnvironmentKeyVerifier(verify func(string) (string, bool)) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.environmentKeyVerifier = verify
	m.mu.Unlock()
}

func (m *Manager) EnvironmentKeysEnabled() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.environmentKeyVerifier != nil
}

// NewManager constructs an empty manager.
func NewManager() *Manager {
	return &Manager{}
}

// SetProviders replaces the active provider list.
func (m *Manager) SetProviders(providers []Provider) {
	if m == nil {
		return
	}
	cloned := make([]Provider, len(providers))
	copy(cloned, providers)
	m.mu.Lock()
	m.providers = cloned
	m.mu.Unlock()
}

// Providers returns a snapshot of the active providers.
func (m *Manager) Providers() []Provider {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	snapshot := make([]Provider, len(m.providers))
	copy(snapshot, m.providers)
	return snapshot
}

// Authenticate evaluates providers until one succeeds.
func (m *Manager) Authenticate(ctx context.Context, r *http.Request) (*Result, *AuthError) {
	if m == nil {
		return nil, nil
	}
	m.mu.RLock()
	providers := append([]Provider(nil), m.providers...)
	verify := m.environmentKeyVerifier
	shared := append([][32]byte(nil), m.sharedInferenceDigests...)
	sharedEnabled := m.sharedInferenceEnabled
	m.mu.RUnlock()
	if r != nil {
		authorization := r.Header.Get("Authorization")
		other := append([]string(nil), r.Header.Values("X-Api-Key")...)
		other = append(other, r.Header.Values("X-Goog-Api-Key")...)
		if r.URL != nil {
			other = append(other, r.URL.Query()["key"]...)
			other = append(other, r.URL.Query()["auth_token"]...)
		}
		managed := false
		for _, value := range r.Header.Values("Authorization") {
			managed = managed || strings.Contains(value, EnvironmentKeyPrefix)
		}
		for _, value := range other {
			managed = managed || strings.Contains(value, EnvironmentKeyPrefix)
		}
		if managed {
			const bearer = "Bearer "
			if len(r.Header.Values("Authorization")) != 1 || len(authorization) < len(bearer) || !strings.EqualFold(authorization[:len(bearer)], bearer) ||
				!ValidEnvironmentKey(authorization[len(bearer):]) || verify == nil {
				return nil, NewInvalidCredentialError()
			}
			for _, value := range other {
				if value != "" {
					return nil, NewInvalidCredentialError()
				}
			}
			if principal, ok := verify(authorization[len(bearer):]); ok && principal != "" {
				return &Result{Provider: "managed-inference-key", Principal: principal}, nil
			}
			return nil, NewInvalidCredentialError()
		}
		if len(shared) > 0 {
			const bearer = "Bearer "
			if len(r.Header.Values("Authorization")) != 1 || len(authorization) < len(bearer) || !strings.EqualFold(authorization[:len(bearer)], bearer) {
				return nil, NewInvalidCredentialError()
			}
			for _, value := range other {
				if value != "" {
					return nil, NewInvalidCredentialError()
				}
			}
			digest := sha256.Sum256([]byte(authorization[len(bearer):]))
			matched := 0
			for _, expected := range shared {
				matched |= subtle.ConstantTimeCompare(digest[:], expected[:])
			}
			if matched == 1 {
				return &Result{Provider: "shared-inference-key", Principal: "shared-pool"}, nil
			}
			return nil, NewInvalidCredentialError()
		}
	}
	// Dedicated environment admission denies legacy/plugin fallback. Only the
	// separately configured shared snapshot above can coexist; a revoked managed
	// credential can never be interpreted as a shared or plugin credential.
	if verify != nil || sharedEnabled {
		return nil, NewNoCredentialsError()
	}
	if len(providers) == 0 {
		return nil, nil
	}

	var (
		missing bool
		invalid bool
	)

	for _, provider := range providers {
		if provider == nil {
			continue
		}
		res, authErr := provider.Authenticate(ctx, r)
		if authErr == nil {
			return res, nil
		}
		if IsAuthErrorCode(authErr, AuthErrorCodeNotHandled) {
			continue
		}
		if IsAuthErrorCode(authErr, AuthErrorCodeNoCredentials) {
			missing = true
			continue
		}
		if IsAuthErrorCode(authErr, AuthErrorCodeInvalidCredential) {
			invalid = true
			continue
		}
		return nil, authErr
	}

	if invalid {
		return nil, NewInvalidCredentialError()
	}
	if missing {
		return nil, NewNoCredentialsError()
	}
	return nil, NewNoCredentialsError()
}
