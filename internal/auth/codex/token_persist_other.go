//go:build !linux

package codex

import "fmt"

func persistTokenFile(_ string, _ []byte) error {
	return fmt.Errorf("secure Codex token persistence is only supported on Linux")
}
