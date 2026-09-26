package cliproxy

import (
	"fmt"

	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
)

// BindEnvironmentKeyStore installs a separate durable inference admission
// source; ordinary access-provider reloads cannot replace its verifier.
func (s *Service) BindEnvironmentKeyStore(store *sdkaccess.EnvironmentKeyStore) error {
	if s == nil || s.accessManager == nil || store == nil {
		return fmt.Errorf("private inference-key admission is unavailable")
	}
	s.accessManager.SetEnvironmentKeyVerifier(store.Verify)
	return nil
}

// PinControlAuthDir binds private enrollment and inference-key admission to the service's
// current auth directory. A later configuration reload that changes that
// directory is rejected as a whole rather than silently stranding credentials
// in a path the auth watcher no longer owns.
func (s *Service) PinControlAuthDir(dir string) error {
	if s == nil || dir == "" {
		return fmt.Errorf("private enrollment auth directory is unavailable")
	}
	s.configUpdateMu.Lock()
	defer s.configUpdateMu.Unlock()
	s.cfgMu.RLock()
	current := s.cfg
	s.cfgMu.RUnlock()
	if current == nil || current.AuthDir != dir || s.controlAuthDir != "" && s.controlAuthDir != dir {
		return fmt.Errorf("private enrollment auth directory changed")
	}
	s.controlAuthDir = dir
	return nil
}
