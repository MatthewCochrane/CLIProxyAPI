package codex

// SaveControlReceipt reuses the private atomic file publication used by Codex
// tokens. The caller supplies bounded, token-free operation metadata in a
// separately named directory; receipts are not auth JSON files.
func SaveControlReceipt(path string, raw []byte) error {
	return persistTokenFile(path, raw)
}
