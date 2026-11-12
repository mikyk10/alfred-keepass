//go:build !darwin || !cgo

package cmd

// Without cgo the lock state cannot be queried without prompting, so the
// keychain is reported as unlocked and security(1) prompts on first read.
func keychainFileLocked(kc string) (bool, error) {
	return false, nil
}

// unlockKeychainFile triggers the unlock dialog by reading the item.
func unlockKeychainFile(kc string) error {
	_, err := readKeychainItem(kc, keychainService)
	return err
}
