package cmd

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tobischo/gokeepasslib/v3"
)

// TestOpenErrors verifies that a missing database file, a wrong password and a
// missing entry surface as errors instead of panicking on a nil reader.
func TestOpenErrors(t *testing.T) {
	good := gokeepasslib.NewPasswordCredentials("Abc12345")
	dbPath := filepath.Join("testdata", "test.kdbx")

	t.Run("missing database file", func(t *testing.T) {
		db, err := openDatabase(filepath.Join("testdata", "does-not-exist.kdbx"), good)
		assert.Error(t, err)
		assert.Nil(t, db)
	})

	t.Run("search on missing database file", func(t *testing.T) {
		alf, err := search(filepath.Join("testdata", "does-not-exist.kdbx"), good, []string{"Entry1"})
		assert.Error(t, err)
		assert.Nil(t, alf)
	})

	t.Run("search with wrong password", func(t *testing.T) {
		alf, err := search(dbPath, gokeepasslib.NewPasswordCredentials("wrong"), []string{"Entry1"})
		assert.Error(t, err)
		assert.Nil(t, alf)
	})

	t.Run("get on missing entry", func(t *testing.T) {
		alf, err := get(dbPath, good, "NoSuchEntry")
		assert.Error(t, err)
		assert.Nil(t, alf)
	})

	t.Run("get succeeds for an existing entry", func(t *testing.T) {
		alf, err := get(dbPath, good, "Entry1")
		assert.NoError(t, err)
		assert.NotNil(t, alf)
		assert.Equal(t, "← Back", alf.Items[0].Title)
	})
}
