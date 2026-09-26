// Package codex provides authentication and token management functionality
// for OpenAI's Codex AI services. It handles OAuth2 token storage, serialization,
// and retrieval for maintaining authenticated sessions with the Codex API.
package codex

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
)

// CodexTokenStorage stores OAuth2 token information for OpenAI Codex API authentication.
// It maintains compatibility with the existing auth system while adding Codex-specific fields
// for managing access tokens, refresh tokens, and user account information.
type CodexTokenStorage struct {
	// IDToken is the JWT ID token containing user claims and identity information.
	IDToken string `json:"id_token"`
	// AccessToken is the OAuth2 access token used for authenticating API requests.
	AccessToken string `json:"access_token"`
	// RefreshToken is used to obtain new access tokens when the current one expires.
	RefreshToken string `json:"refresh_token"`
	// AccountID is the OpenAI account identifier associated with this token.
	AccountID string `json:"account_id"`
	// LastRefresh is the timestamp of the last token refresh operation.
	LastRefresh string `json:"last_refresh"`
	// Email is the OpenAI account email address associated with this token.
	Email string `json:"email"`
	// Type indicates the authentication provider type, always "codex" for this storage.
	Type string `json:"type"`
	// Expire is the timestamp when the current access token expires.
	Expire string `json:"expired"`

	// Metadata holds arbitrary key-value pairs injected via hooks.
	// It is not exported to JSON directly to allow flattening during serialization.
	Metadata map[string]any `json:"-"`
}

// ErrCodexAccountExists is a fixed identity-free duplicate-admission signal.
var ErrCodexAccountExists = errors.New("codex account already exists")

// SetMetadata allows external callers to inject metadata into the storage before saving.
func (ts *CodexTokenStorage) SetMetadata(meta map[string]any) {
	ts.Metadata = meta
}

// SaveTokenToFile serializes the Codex token storage to a JSON file.
// The destination's parent directory must already exist.
// It merges any injected metadata into the top-level JSON object.
//
// Parameters:
//   - authFilePath: The full path where the token file should be saved
//
// Returns:
//   - error: An error if the operation fails, nil otherwise
func (ts *CodexTokenStorage) SaveTokenToFile(authFilePath string) error {
	return ts.saveTokenToFile(authFilePath, false)
}

// SaveNewTokenToFile publishes a fresh Codex credential only if the
// destination did not already exist at the atomic commit point.
func (ts *CodexTokenStorage) SaveNewTokenToFile(authFilePath string) error {
	return ts.saveTokenToFile(authFilePath, true)
}

func (ts *CodexTokenStorage) saveTokenToFile(authFilePath string, createOnly bool) error {
	raw, err := ts.encodeTokenFile(authFilePath)
	if err != nil {
		return err
	}
	if createOnly {
		return persistNewTokenFile(authFilePath, raw)
	}
	return persistTokenFile(authFilePath, raw)
}

// SaveNewAccountTokenToDir admits a fresh provider-owned credential only when
// its ID-token identity matches the expected account and no credential for
// that identity already exists in the private auth directory. Its generated
// filename contains no email, path, or raw provider account ID.
func (ts *CodexTokenStorage) SaveNewAccountTokenToDir(dir, expectedAccountID string) (string, error) {
	if len(expectedAccountID) == 0 || len(expectedAccountID) > 256 || strings.TrimSpace(expectedAccountID) != expectedAccountID || strings.ContainsAny(expectedAccountID, "\r\n\t") ||
		len(ts.AccountID) == 0 || len(ts.AccountID) > 256 || subtle.ConstantTimeCompare([]byte(ts.AccountID), []byte(expectedAccountID)) != 1 {
		return "", fmt.Errorf("codex account identity mismatch")
	}
	// Metadata is merged over the typed credential fields by the general save
	// path. A private fresh enrollment must not permit it to override identity
	// or token material after the exact identity check.
	if len(ts.Metadata) != 0 || ts.AccessToken == "" || ts.RefreshToken == "" || ts.IDToken == "" ||
		len(ts.AccessToken) > 16<<10 || len(ts.RefreshToken) > 16<<10 || len(ts.IDToken) > 16<<10 {
		return "", fmt.Errorf("codex enrollment credential is unavailable")
	}
	claims, err := ParseJWTToken(ts.IDToken)
	if err != nil || claims == nil || subtle.ConstantTimeCompare([]byte(claims.GetAccountID()), []byte(expectedAccountID)) != 1 {
		return "", fmt.Errorf("codex account identity mismatch")
	}
	if !filepath.IsAbs(dir) || strings.TrimSpace(dir) != dir {
		return "", fmt.Errorf("codex account directory is unavailable")
	}
	path := filepath.Join(dir, "codex-account-"+AccountIDHash(expectedAccountID)+".json")
	raw, err := ts.encodeTokenFile(path)
	if err != nil {
		return "", err
	}
	return path, persistNewAccountTokenFile(path, raw, expectedAccountID)
}

func (ts *CodexTokenStorage) encodeTokenFile(authFilePath string) ([]byte, error) {
	ts.Type = "codex"
	if strings.TrimSpace(authFilePath) == "" {
		return nil, fmt.Errorf("failed to save token file: path is empty")
	}

	// Merge metadata using helper
	data, errMerge := misc.MergeMetadata(ts, ts.Metadata)
	if errMerge != nil {
		return nil, fmt.Errorf("failed to merge metadata: %w", errMerge)
	}

	raw, errMarshal := json.MarshalIndent(data, "", "  ")
	if errMarshal != nil {
		return nil, fmt.Errorf("failed to encode token file: %w", errMarshal)
	}
	raw = append(raw, '\n')
	return raw, nil
}
