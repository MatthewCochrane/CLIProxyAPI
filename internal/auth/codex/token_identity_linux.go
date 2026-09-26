//go:build linux

package codex

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// checkTokenAccountUnique examines every JSON credential through the already
// admitted parent descriptor. An unreadable/unsafe file cannot be skipped:
// it may contain the same account under an older email/plan-derived filename.
// The process-local tokenDirectoryMu serializes this scan with all Codex token
// saves in this process. The service's private auth directory is single-owner.
func checkTokenAccountUnique(parentFD int, accountID string) error {
	// A dup shares the parent's directory offset and would silently skip files
	// on a later admission. Open a new description of the same pinned directory.
	dupFD, err := unix.Openat(parentFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("codex credential inventory is unavailable")
	}
	dir := os.NewFile(uintptr(dupFD), "private-codex-credentials")
	if dir == nil {
		_ = unix.Close(dupFD)
		return fmt.Errorf("codex credential inventory is unavailable")
	}
	defer dir.Close()
	count := 0
	total := 0
	for {
		names, err := dir.Readdirnames(64)
		if err != nil && err != io.EOF {
			return fmt.Errorf("codex credential inventory is unavailable")
		}
		total += len(names)
		if total > 1024 {
			return fmt.Errorf("codex credential inventory is unavailable")
		}
		for _, name := range names {
			if !strings.HasSuffix(strings.ToLower(name), ".json") {
				// A crashed writer can leave a private temporary credential
				// whose contents may already hold a newly issued refresh token.
				// Require explicit owner reconciliation instead of authorizing
				// another token family past unknown persistent state.
				return fmt.Errorf("codex credential inventory is unavailable")
			}
			count++
			if count > 256 {
				return fmt.Errorf("codex credential inventory is unavailable")
			}
			fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			if err != nil {
				return fmt.Errorf("codex credential inventory is unavailable")
			}
			file := os.NewFile(uintptr(fd), "private-codex-credential")
			if file == nil {
				_ = unix.Close(fd)
				return fmt.Errorf("codex credential inventory is unavailable")
			}
			var stat unix.Stat_t
			err = unix.Fstat(fd, &stat)
			if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o077 != 0 || stat.Nlink != 1 || stat.Size < 1 || stat.Size > 64<<10 {
				_ = file.Close()
				return fmt.Errorf("codex credential inventory is unavailable")
			}
			raw, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
			_ = file.Close()
			if err != nil || len(raw) == 0 || len(raw) > 64<<10 {
				return fmt.Errorf("codex credential inventory is unavailable")
			}
			var metadata struct {
				Type      string `json:"type"`
				AccountID string `json:"account_id"`
				IDToken   string `json:"id_token"`
			}
			if json.Unmarshal(raw, &metadata) != nil {
				return fmt.Errorf("codex credential inventory is unavailable")
			}
			if metadata.Type == "codex" {
				claims, errClaim := ParseJWTToken(metadata.IDToken)
				if metadata.AccountID == "" || errClaim != nil || claims == nil || claims.GetAccountID() != metadata.AccountID {
					return fmt.Errorf("codex credential inventory is unavailable")
				}
				if metadata.AccountID == accountID {
					return ErrCodexAccountExists
				}
			}
		}
		if err == io.EOF {
			break
		}
	}
	return nil
}

// CheckAccountNotPresentInDir prevents an OAuth attempt from rotating a
// credential family that the proxy already owns. The commit repeats this check
// under the same in-process lock immediately before atomic publication.
func CheckAccountNotPresentInDir(dir, accountID string) error {
	if !filepath.IsAbs(dir) || accountID == "" || len(accountID) > 256 {
		return fmt.Errorf("codex credential inventory is unavailable")
	}
	tokenDirectoryMu.Lock()
	defer tokenDirectoryMu.Unlock()
	fd, err := openTokenParent(dir)
	if err != nil {
		return fmt.Errorf("codex credential inventory is unavailable")
	}
	defer unix.Close(fd)
	if validateTokenParent(fd) != nil {
		return fmt.Errorf("codex credential inventory is unavailable")
	}
	return checkTokenAccountUnique(fd, accountID)
}

// AccountPresentInDir returns only whether the exact stable account identity
// is present. Unsafe or incomplete inventory is never treated as absence.
func AccountPresentInDir(dir, accountID string) (bool, error) {
	err := CheckAccountNotPresentInDir(dir, accountID)
	if err == nil {
		return false, nil
	}
	if errors.Is(err, ErrCodexAccountExists) {
		return true, nil
	}
	return false, err
}
