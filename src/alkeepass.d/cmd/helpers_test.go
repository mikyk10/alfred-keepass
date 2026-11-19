package cmd

import (
	"os"
	"testing"

	"github.com/pkg/errors"
	"github.com/tobischo/gokeepasslib/v3"
)

// useWorkflow configures the workflow for the database at dbPath, with the
// variables in env, and makes the keychain unlocked and holding passwd. It
// returns the number of times the password is read from the keychain.
func useWorkflow(t *testing.T, dbPath, passwd string, env map[string]string) *int {
	for _, v := range []string{keyFileVariable, yubikeySlotVariable, keyCacheMinutesVariable,
		forgetOnSleepVariable, forgetOnScreenLockVariable, "keepassxc_cache_seconds"} {
		t.Setenv(v, "")
	}
	t.Setenv(dbPathVariable, dbPath)
	for k, v := range env {
		t.Setenv(k, v)
	}

	reads := 0
	origRead, origLocked, origUnlock := readKeychain, keychainLocked, unlockKeychain
	readKeychain = func() (string, error) {
		reads++
		return passwd, nil
	}
	keychainLocked = func() (bool, error) { return false, nil }
	// Tests that make the keychain locked and expect to be asked to unlock
	// it replace this.
	unlockKeychain = func() error {
		if locked, _ := keychainLocked(); locked {
			return errors.New("the test did not expect to be asked to unlock the keychain")
		}
		return nil
	}
	t.Cleanup(func() { readKeychain, keychainLocked, unlockKeychain = origRead, origLocked, origUnlock })
	return &reads
}

// openDatabase opens the database at kbdxpath with cred and the YubiKey
// slot, as openConfiguredDatabase does once it has the credentials.
func openDatabase(kbdxpath string, cred *gokeepasslib.DBCredentials, yubikeySlot int) (*gokeepasslib.Database, error) {
	data, err := os.ReadFile(kbdxpath)
	if err != nil {
		return nil, err
	}
	header, err := decodeHeader(data)
	if err != nil {
		return nil, err
	}
	if yubikeySlot != 0 {
		if cred, err = addChallengeResponse(cred, header.Header, yubikeySlot); err != nil {
			return nil, err
		}
	}
	return decodeDatabase(data, header, cred)
}

func search(kbdxpath string, cred *gokeepasslib.DBCredentials, yubikeySlot int, query []string) (*AlfredJSON, error) {
	db, err := openDatabase(kbdxpath, cred, yubikeySlot)
	if err != nil {
		return nil, err
	}
	return searchDatabase(db, query), nil
}

func get(kbdxpath string, cred *gokeepasslib.DBCredentials, yubikeySlot int, entryPath string) (*AlfredJSON, error) {
	db, err := openDatabase(kbdxpath, cred, yubikeySlot)
	if err != nil {
		return nil, err
	}
	return entryDetails(db, entryPath)
}

func openEntry(kbdxpath, keyfilepath, passwd string, yubikeySlot int, entryPath string) (*gokeepasslib.Database, *gokeepasslib.Entry, error) {
	cred, err := buildCredentials(passwd, keyfilepath, yubikeySlot)
	if err != nil {
		return nil, nil, err
	}
	db, err := openDatabase(kbdxpath, cred, yubikeySlot)
	if err != nil {
		return nil, nil, err
	}
	entry, err := findEntry(db, entryPath)
	if err != nil {
		return nil, nil, err
	}
	return db, &entry.Entry, nil
}
