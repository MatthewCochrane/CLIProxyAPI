//go:build linux

package cmd

import (
	"os"
	"syscall"
)

func controlAuthDirOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
