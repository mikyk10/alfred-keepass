package cmd

import (
	"path/filepath"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/tobischo/gokeepasslib/v3"
)

// A search never asks to unlock the keychain, which would close Alfred's
// window, while the actions do.
func TestOpenConfiguredEntryUnlocksKeychain(t *testing.T) {
	reads := useWorkflow(t, filepath.Join("testdata", "actions.kdbx"), "Abc12345", nil)
	locked := true
	keychainLocked = func() (bool, error) { return locked, nil }
	unlocks := 0
	unlockErr := error(nil)
	orig := unlockKeychain
	unlockKeychain = func() error {
		unlocks++
		if unlockErr == nil {
			locked = false
		}
		return unlockErr
	}
	t.Cleanup(func() { unlockKeychain = orig })

	alf := runSearch([]string{"Example"})
	assert.Equal(t, "locked", alf.Items[0].Uid)
	assert.Equal(t, 0, unlocks)
	assert.Equal(t, 0, *reads)

	unlockErr = errors.New("unlocking the keychain was cancelled")
	_, _, err := openConfiguredEntry("Example")
	assert.ErrorContains(t, err, "cancelled")
	assert.Equal(t, 1, unlocks)
	assert.Equal(t, 0, *reads, "nothing is read from the locked keychain")

	unlockErr = nil
	_, entry, err := openConfiguredEntry("Example")
	if assert.NoError(t, err) {
		assert.Equal(t, "Example", entry.GetTitle())
	}
	assert.Equal(t, 2, unlocks)
	assert.Equal(t, 1, *reads)
}

// Unlike no password at all, an empty password is part of the composite key.
// KeePassXC tries both when no password is entered; so does the workflow when
// none is stored.
func TestEmptyPassword(t *testing.T) {
	emptyPassword := gokeepasslib.NewPasswordCredentials("").Passphrase

	t.Run("alone", func(t *testing.T) {
		useWorkflow(t, writeTestDatabase(t, emptyPassword, nil), "", nil)
		alf := runSearch([]string{"Entry1"})
		assert.Equal(t, "Entry1", alf.Items[0].Title)
	})

	t.Run("with a YubiKey", func(t *testing.T) {
		yubikey := &fakeYubiKey{secrets: map[int][]byte{2: testSecret}}
		useReaders(t, fakeReaders{"YubiKey": yubikey})
		useWorkflow(t, writeTestDatabase(t, emptyPassword, testSecret), "", map[string]string{yubikeySlotVariable: "2"})
		alf := runSearch([]string{"Entry1"})
		assert.Equal(t, "Entry1", alf.Items[0].Title)
		assert.Equal(t, 1, yubikey.challenges, "the YubiKey is asked once")
	})

	t.Run("no password and a YubiKey", func(t *testing.T) {
		useReaders(t, fakeReaders{"YubiKey": &fakeYubiKey{secrets: map[int][]byte{2: testSecret}}})
		useWorkflow(t, writeTestDatabase(t, nil, testSecret), "", map[string]string{yubikeySlotVariable: "2"})
		alf := runSearch([]string{"Entry1"})
		assert.Equal(t, "Entry1", alf.Items[0].Title)
	})

	t.Run("a stored password is not replaced by an empty one", func(t *testing.T) {
		useWorkflow(t, writeTestDatabase(t, emptyPassword, nil), "wrong", nil)
		alf := runSearch([]string{"Entry1"})
		assert.Contains(t, alf.Items[0].Title, "Wrong password")
	})

	t.Run("a database that needs a password", func(t *testing.T) {
		useWorkflow(t, writeYubiKeyDatabase(t, "Abc12345", nil), "", nil)
		alf := runSearch([]string{"Entry1"})
		assert.Contains(t, alf.Items[0].Title, "run `kp:setpass`")
	})
}
