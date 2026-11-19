package cmd

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tobischo/gokeepasslib/v3"
)

// TestOpenArgon2id verifies that a KDBX 4 database using the Argon2id KDF can be
// opened. Upstream gokeepasslib only handles Argon2d and derived a wrong key for
// Argon2id, failing with "HMAC-SHA256 of header mismatching". The fixture was
// cross-checked with keepassxc-cli.
func TestOpenArgon2id(t *testing.T) {
	dbPath := filepath.Join("testdata", "argon2id.kdbx")

	db, err := openDatabase(dbPath, gokeepasslib.NewPasswordCredentials("Abc12345"), 0)
	if assert.NoError(t, err) {
		entry := db.Content.Root.Groups[0].Entries[0]
		assert.Equal(t, "Entry1", entry.GetTitle())
		assert.Equal(t, "secret1", entry.GetPassword())
	}

	_, err = openDatabase(dbPath, gokeepasslib.NewPasswordCredentials("wrong"), 0)
	assert.Error(t, err)
}

// TestOpenErrors verifies that a missing database file, a wrong password and a
// missing entry surface as errors instead of panicking on a nil reader.
func TestOpenErrors(t *testing.T) {
	good := gokeepasslib.NewPasswordCredentials("Abc12345")
	dbPath := filepath.Join("testdata", "test.kdbx")

	t.Run("missing database file", func(t *testing.T) {
		db, err := openDatabase(filepath.Join("testdata", "does-not-exist.kdbx"), good, 0)
		assert.Error(t, err)
		assert.Nil(t, db)
	})

	t.Run("search on missing database file", func(t *testing.T) {
		alf, err := search(filepath.Join("testdata", "does-not-exist.kdbx"), good, 0, []string{"Entry1"})
		assert.Error(t, err)
		assert.Nil(t, alf)
	})

	t.Run("search with wrong password", func(t *testing.T) {
		alf, err := search(dbPath, gokeepasslib.NewPasswordCredentials("wrong"), 0, []string{"Entry1"})
		assert.Error(t, err)
		assert.Nil(t, alf)
	})

	t.Run("get on missing entry", func(t *testing.T) {
		alf, err := get(dbPath, good, 0, "NoSuchEntry")
		assert.Error(t, err)
		assert.Nil(t, alf)
	})

	t.Run("get succeeds for an existing entry", func(t *testing.T) {
		alf, err := get(dbPath, good, 0, "Entry1")
		assert.NoError(t, err)
		assert.NotNil(t, alf)
		assert.Equal(t, "← Back", alf.Items[0].Title)
	})
}
