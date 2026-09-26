//go:build !linux

package access

import "errors"

const EnvironmentKeyPrefix = "pcx-env-v1-"

var (
	ErrEnvironmentKeyConflict    = errors.New("environment key conflict")
	ErrEnvironmentKeyUnavailable = errors.New("environment key store unavailable")
	ErrEnvironmentKeyUncertain   = errors.New("environment key commit durability uncertain")
)

type EnvironmentKeyStore struct{}

func ValidEnvironmentID(string) bool  { return false }
func ValidEnvironmentKey(string) bool { return false }
func NewEnvironmentKeyStore(string) (*EnvironmentKeyStore, error) {
	return nil, ErrEnvironmentKeyUnavailable
}
func (s *EnvironmentKeyStore) Close() error { return nil }
func (s *EnvironmentKeyStore) Inspect(string) (uint64, bool, bool, error) {
	return 0, false, false, ErrEnvironmentKeyUnavailable
}
func (s *EnvironmentKeyStore) InspectDigest(string, string) (uint64, bool, bool, bool, error) {
	return 0, false, false, false, ErrEnvironmentKeyUnavailable
}
func (s *EnvironmentKeyStore) Verify(string) (string, bool) { return "", false }
func (s *EnvironmentKeyStore) Issue(string, string) (uint64, error) {
	return 0, ErrEnvironmentKeyUnavailable
}
func (s *EnvironmentKeyStore) Revoke(string, uint64) error { return ErrEnvironmentKeyUnavailable }
func GenerateEnvironmentKey() (string, error)              { return "", ErrEnvironmentKeyUnavailable }
