//go:build linux

package codex

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var syncTokenParent = unix.Fsync

// ErrTokenCommitDurabilityUncertain means the replacement is visible but its
// directory entry could not be proven durable across a host crash.
var ErrTokenCommitDurabilityUncertain = errors.New("Codex token file was replaced but durability is uncertain")

func persistTokenFile(path string, raw []byte) error {
	path = filepath.Clean(path)
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) || strings.ContainsRune(name, filepath.Separator) {
		return fmt.Errorf("failed to save token file: invalid destination")
	}

	parentFD, errOpen := openTokenParent(filepath.Dir(path))
	if errOpen != nil {
		return fmt.Errorf("failed to open token directory: %w", errOpen)
	}
	defer unix.Close(parentFD)

	if errValidate := validateTokenParent(parentFD); errValidate != nil {
		return errValidate
	}
	if errValidate := validateTokenDestination(parentFD, name); errValidate != nil {
		return errValidate
	}

	tempName, tempFD, errTemp := createTokenTemp(parentFD, name)
	if errTemp != nil {
		return fmt.Errorf("failed to create temporary token file: %w", errTemp)
	}
	committed := false
	defer func() {
		if !committed {
			_ = unix.Unlinkat(parentFD, tempName, 0)
		}
	}()

	file := os.NewFile(uintptr(tempFD), tempName)
	if file == nil {
		_ = unix.Close(tempFD)
		return fmt.Errorf("failed to create temporary token file handle")
	}
	if _, errWrite := file.Write(raw); errWrite != nil {
		_ = file.Close()
		return fmt.Errorf("failed to write token file: %w", errWrite)
	}
	if errSync := file.Sync(); errSync != nil {
		_ = file.Close()
		return fmt.Errorf("failed to sync token file: %w", errSync)
	}
	if errClose := file.Close(); errClose != nil {
		return fmt.Errorf("failed to close token file: %w", errClose)
	}
	if errRename := unix.Renameat(parentFD, tempName, parentFD, name); errRename != nil {
		return fmt.Errorf("failed to replace token file: %w", errRename)
	}
	committed = true

	// Rename is the visible commit point. Return a distinct error after it so the
	// caller does not mistake uncertain durability for a pre-commit failure.
	if errSync := syncTokenParent(parentFD); errSync != nil {
		return ErrTokenCommitDurabilityUncertain
	}
	return nil
}

func openTokenParent(path string) (int, error) {
	path = filepath.Clean(path)
	start := "."
	if filepath.IsAbs(path) {
		start = string(filepath.Separator)
	}
	fd, errOpen := unix.Open(start, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errOpen != nil {
		return -1, errOpen
	}
	for _, component := range strings.Split(path, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		if component == ".." {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("parent traversal is not allowed")
		}
		next, errNext := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if errNext != nil {
			return -1, errNext
		}
		fd = next
	}
	return fd, nil
}

func validateTokenParent(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("failed to inspect token directory: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o077 != 0 {
		return fmt.Errorf("failed to save token file: parent directory must be private and owned by the current user")
	}
	return nil
}

func validateTokenDestination(parentFD int, name string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to inspect token file: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o077 != 0 || stat.Nlink != 1 {
		return fmt.Errorf("failed to save token file: destination must be a private, owned, single-link regular file")
	}
	return nil
}

func createTokenTemp(parentFD int, destination string) (string, int, error) {
	for range 128 {
		var suffix [12]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return "", -1, err
		}
		name := "." + destination + ".tmp-" + hex.EncodeToString(suffix[:])
		fd, errOpen := unix.Openat(parentFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if errors.Is(errOpen, unix.EEXIST) {
			continue
		}
		if errOpen != nil {
			return "", -1, errOpen
		}
		var stat unix.Stat_t
		if errStat := unix.Fstat(fd, &stat); errStat != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(parentFD, name, 0)
			if errStat != nil {
				return "", -1, errStat
			}
			return "", -1, fmt.Errorf("temporary token file failed safety checks")
		}
		return name, fd, nil
	}
	return "", -1, fmt.Errorf("temporary token file name collision limit reached")
}
