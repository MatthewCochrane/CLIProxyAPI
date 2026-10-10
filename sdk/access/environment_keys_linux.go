//go:build linux

package access

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	EnvironmentKeyPrefix = "pcx-env-v1-"
	environmentKeyFile   = "environment-keys-v1.json"
	maxKeyStoreBytes     = 65536
	maxEnvironmentKeys   = 256
)

var (
	ErrEnvironmentKeyConflict    = errors.New("environment key conflict")
	ErrEnvironmentKeyUnavailable = errors.New("environment key store unavailable")
	ErrEnvironmentKeyUncertain   = errors.New("environment key commit durability uncertain")
)

type environmentKeyRecord struct {
	Environment string `json:"environment"`
	Digest      string `json:"digest"`
	Revision    uint64 `json:"revision"`
	Revoked     bool   `json:"revoked"`
}

type environmentKeyFileData struct {
	Version int                    `json:"version"`
	Keys    []environmentKeyRecord `json:"keys"`
}

// EnvironmentKeyStore holds only digests and revision fences. The service is the
// sole writer of its private directory; an external writer must not share it.
// Reads go to the authoritative file rather than a cache, including after an
// uncertain post-rename directory sync or a process restart.
type EnvironmentKeyStore struct {
	mu      sync.Mutex
	fd      int
	syncDir func(int) error
}

func ValidEnvironmentID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for i := range value {
		ch := value[i]
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

// ValidEnvironmentKey admits only a canonical 256-bit, environment-specific
// bearer. The future Submind issuer must generate its 32 bytes with crypto/rand.
func ValidEnvironmentKey(key string) bool {
	if !strings.HasPrefix(key, EnvironmentKeyPrefix) || len(key) != len(EnvironmentKeyPrefix)+43 {
		return false
	}
	encoded := strings.TrimPrefix(key, EnvironmentKeyPrefix)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == encoded
}

// NewEnvironmentKeyStore requires a preprovisioned, current-user-owned 0700
// directory. It never creates the trust root or follows symlink ancestors.
func NewEnvironmentKeyStore(dir string) (*EnvironmentKeyStore, error) {
	if !filepath.IsAbs(dir) {
		return nil, ErrEnvironmentKeyUnavailable
	}
	for path := filepath.Clean(dir); ; path = filepath.Dir(path) {
		entry, err := os.Lstat(path)
		if err != nil || entry.Mode()&os.ModeSymlink != 0 {
			return nil, ErrEnvironmentKeyUnavailable
		}
		if filepath.Dir(path) == path {
			break
		}
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrEnvironmentKeyUnavailable
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0777 != 0700 {
		_ = unix.Close(fd)
		return nil, ErrEnvironmentKeyUnavailable
	}
	store := &EnvironmentKeyStore{fd: fd, syncDir: unix.Fsync}
	if _, err = store.read(); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return store, nil
}

// Close follows inference-server shutdown. It cannot race an in-flight read.
func (s *EnvironmentKeyStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		return nil
	}
	err := unix.Close(s.fd)
	s.fd = -1
	return err
}

func (s *EnvironmentKeyStore) read() (environmentKeyFileData, error) {
	result := environmentKeyFileData{Version: 1}
	if s == nil || s.fd < 0 {
		return result, ErrEnvironmentKeyUnavailable
	}
	// A crash before rename can leave a private temp containing key-store
	// metadata. Do not infer an empty or complete authority from ambiguous
	// files, and never clean them up automatically.
	listingFD, err := unix.Openat(s.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return result, ErrEnvironmentKeyUnavailable
	}
	listing := os.NewFile(uintptr(listingFD), "environment-key-store")
	entries, err := listing.ReadDir(maxEnvironmentKeys + 2)
	_ = listing.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 1 {
		return result, ErrEnvironmentKeyUnavailable
	}
	for _, entry := range entries {
		if entry.Name() != environmentKeyFile {
			return result, ErrEnvironmentKeyUnavailable
		}
	}
	fd, err := unix.Openat(s.fd, environmentKeyFile, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return result, nil
	}
	if err != nil {
		return result, ErrEnvironmentKeyUnavailable
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0777 != 0600 || stat.Nlink != 1 || stat.Size > maxKeyStoreBytes {
		_ = unix.Close(fd)
		return result, ErrEnvironmentKeyUnavailable
	}
	file := os.NewFile(uintptr(fd), environmentKeyFile)
	// The descriptor is owned by file after NewFile; do not close it twice.
	defer func() { _ = file.Close() }()
	body, err := io.ReadAll(io.LimitReader(file, maxKeyStoreBytes+1))
	if err != nil || len(body) > maxKeyStoreBytes {
		return result, ErrEnvironmentKeyUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	result = environmentKeyFileData{}
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.Version != 1 || result.Keys == nil || len(result.Keys) > maxEnvironmentKeys {
		return result, ErrEnvironmentKeyUnavailable
	}
	canonical, err := json.Marshal(result)
	if err != nil || !bytes.Equal(canonical, body) {
		return result, ErrEnvironmentKeyUnavailable
	}
	seenEnv := make(map[string]environmentKeyRecord)
	seenDigest := make(map[string]bool)
	for _, row := range result.Keys {
		decoded, digestErr := hex.DecodeString(row.Digest)
		if !ValidEnvironmentID(row.Environment) || len(row.Digest) != 64 || digestErr != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != row.Digest || row.Revision == 0 || seenDigest[row.Digest] {
			return result, ErrEnvironmentKeyUnavailable
		}
		if prior, exists := seenEnv[row.Environment]; exists {
			// Revoke advances the revision in the existing row. Compare the next
			// row's issuance revision, not its later retirement revision: a valid
			// issue/revoke/reissue/revoke history is [2 revoked, 4 revoked].
			issuedRevision := row.Revision
			if row.Revoked {
				issuedRevision--
			}
			if !prior.Revoked || prior.Revision == ^uint64(0) || issuedRevision != prior.Revision+1 {
				return result, ErrEnvironmentKeyUnavailable
			}
		}
		seenEnv[row.Environment], seenDigest[row.Digest] = row, true
	}
	return result, nil
}

// Inspect returns only an environment's durable state, never its key or digest.
func (s *EnvironmentKeyStore) Inspect(environment string) (uint64, bool, bool, error) {
	if !ValidEnvironmentID(environment) {
		return 0, false, false, ErrEnvironmentKeyUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.read()
	if err != nil {
		return 0, false, false, err
	}
	for i := len(data.Keys) - 1; i >= 0; i-- {
		row := data.Keys[i]
		if row.Environment == environment {
			return row.Revision, !row.Revoked, true, nil
		}
	}
	return 0, false, false, nil
}

// InspectDigest proves that the *current* revision belongs to the caller's
// exact high-entropy key without returning its digest or key. A caller must
// require a match before recovering or revoking an ambiguous issue attempt.
func (s *EnvironmentKeyStore) InspectDigest(environment, digest string) (uint64, bool, bool, bool, error) {
	if !ValidEnvironmentID(environment) || len(digest) != 64 {
		return 0, false, false, false, ErrEnvironmentKeyUnavailable
	}
	requested, err := hex.DecodeString(digest)
	if err != nil || hex.EncodeToString(requested) != digest {
		return 0, false, false, false, ErrEnvironmentKeyUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.read()
	if err != nil {
		return 0, false, false, false, err
	}
	for i := len(data.Keys) - 1; i >= 0; i-- {
		row := data.Keys[i]
		if row.Environment == environment {
			stored, _ := hex.DecodeString(row.Digest)
			return row.Revision, !row.Revoked, true, subtle.ConstantTimeCompare(stored, requested) == 1, nil
		}
	}
	return 0, false, false, false, nil
}

// Verify consults the durable authority for every request. Storage uncertainty
// or corruption always denies inference, including when no other keys exist.
func (s *EnvironmentKeyStore) Verify(key string) (string, bool) {
	if !ValidEnvironmentKey(key) {
		return "", false
	}
	digest := sha256.Sum256([]byte(key))
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.read()
	if err != nil {
		return "", false
	}
	for _, row := range data.Keys {
		stored, _ := hex.DecodeString(row.Digest) // read() validated it.
		if subtle.ConstantTimeCompare(stored, digest[:]) == 1 && !row.Revoked {
			return "managed-env-" + hex.EncodeToString(digest[:16]), true
		}
	}
	return "", false
}

// Issue records a Submind-generated key exactly once for its environment.
// A revoked environment can receive a new generation; every prior digest is
// retained as a tombstone so no key can ever move to another environment.
func (s *EnvironmentKeyStore) Issue(environment, key string) (uint64, error) {
	if !ValidEnvironmentID(environment) || !ValidEnvironmentKey(key) {
		return 0, ErrEnvironmentKeyUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.read()
	if err != nil {
		return 0, err
	}
	digest := sha256.Sum256([]byte(key))
	hexDigest := hex.EncodeToString(digest[:])
	revision := uint64(1)
	for _, row := range data.Keys {
		if row.Digest == hexDigest {
			return 0, ErrEnvironmentKeyConflict
		}
		if row.Environment == environment {
			if !row.Revoked || row.Revision == ^uint64(0) {
				return 0, ErrEnvironmentKeyConflict
			}
			revision = row.Revision + 1
		}
	}
	if len(data.Keys) == maxEnvironmentKeys {
		return 0, ErrEnvironmentKeyUnavailable
	}
	data.Keys = append(data.Keys, environmentKeyRecord{Environment: environment, Digest: hexDigest, Revision: revision})
	return revision, s.write(data)
}

// Revoke requires the exact observed generation and never alters another key.
func (s *EnvironmentKeyStore) Revoke(environment string, revision uint64) error {
	if !ValidEnvironmentID(environment) || revision == 0 {
		return ErrEnvironmentKeyUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.read()
	if err != nil {
		return err
	}
	for i := len(data.Keys) - 1; i >= 0; i-- {
		row := &data.Keys[i]
		if row.Environment == environment {
			if row.Revoked || row.Revision != revision || row.Revision == ^uint64(0) {
				return ErrEnvironmentKeyConflict
			}
			row.Revoked = true
			row.Revision++
			return s.write(data)
		}
	}
	return ErrEnvironmentKeyConflict
}

func (s *EnvironmentKeyStore) write(data environmentKeyFileData) error {
	body, err := json.Marshal(data)
	if err != nil || len(body) > maxKeyStoreBytes {
		return ErrEnvironmentKeyUnavailable
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return ErrEnvironmentKeyUnavailable
	}
	temporary := ".environment-keys-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(s.fd, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrEnvironmentKeyUnavailable
	}
	defer unix.Unlinkat(s.fd, temporary, 0)
	file := os.NewFile(uintptr(fd), temporary)
	if _, err = file.Write(body); err != nil {
		_ = file.Close()
		return ErrEnvironmentKeyUnavailable
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return ErrEnvironmentKeyUnavailable
	}
	if err = file.Close(); err != nil {
		return ErrEnvironmentKeyUnavailable
	}
	if err = unix.Renameat(s.fd, temporary, s.fd, environmentKeyFile); err != nil {
		return ErrEnvironmentKeyUnavailable
	}
	if err = s.syncDir(s.fd); err != nil {
		return ErrEnvironmentKeyUncertain
	}
	return nil
}

// GenerateEnvironmentKey is for the eventual sole-owner Submind issuer. The
// proxy's HTTP issue route accepts but never generates or returns this secret.
func GenerateEnvironmentKey() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate environment key: %w", ErrEnvironmentKeyUnavailable)
	}
	return EnvironmentKeyPrefix + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
