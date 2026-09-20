//go:build linux

package cliproxy

import (
	"os"
	"syscall"
)

func authDirOwnedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}
