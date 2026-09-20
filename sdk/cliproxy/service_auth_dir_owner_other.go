//go:build !linux

package cliproxy

import "os"

func authDirOwnedByCurrentUser(os.FileInfo) bool {
	return true
}
