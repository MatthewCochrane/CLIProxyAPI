//go:build !linux

package codex

import (
	"errors"
	"fmt"
)

var ErrTokenCommitDurabilityUncertain = errors.New("Codex token file is visible but durability is uncertain")

func CheckAccountNotPresentInDir(_, _ string) error {
	return fmt.Errorf("secure Codex token persistence is only supported on Linux")
}

func AccountPresentInDir(_, _ string) (bool, error) {
	return false, fmt.Errorf("secure Codex token persistence is only supported on Linux")
}

func persistTokenFile(_ string, _ []byte) error {
	return fmt.Errorf("secure Codex token persistence is only supported on Linux")
}

func persistNewTokenFile(_ string, _ []byte) error {
	return fmt.Errorf("secure Codex token persistence is only supported on Linux")
}

func persistNewAccountTokenFile(_ string, _ []byte, _ string) error {
	return fmt.Errorf("secure Codex token persistence is only supported on Linux")
}
