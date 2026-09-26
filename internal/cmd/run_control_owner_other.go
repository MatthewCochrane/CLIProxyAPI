//go:build !linux

package cmd

import "os"

func controlAuthDirOwner(os.FileInfo) bool { return false }
