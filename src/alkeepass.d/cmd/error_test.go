package cmd

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestErrorJSON(t *testing.T) {
	alf := errorJSON(errors.New("boom"))
	assert.Len(t, alf.Items, 1)
	assert.Contains(t, alf.Items[0].Title, "boom")
	assert.Empty(t, alf.Items[0].Arg) // non-actionable
}

// TestRunSearchAndGetReportErrors checks that failures become an Alfred error
// item instead of panicking, while the happy paths still return real results.
func TestRunSearchAndGetReportErrors(t *testing.T) {
	dbPath := filepath.Join("testdata", "test.kdbx")

	t.Run("missing credentials", func(t *testing.T) {
		useWorkflow(t, dbPath, "", nil)
		alf := runSearch([]string{"Entry1"})
		assert.Len(t, alf.Items, 1)
		assert.True(t, strings.HasPrefix(alf.Items[0].Title, "⚠️"))
		assert.Nil(t, alf.Cache) // errors are not cached
	})

	t.Run("missing database", func(t *testing.T) {
		useWorkflow(t, filepath.Join("testdata", "nope.kdbx"), "Abc12345", nil)
		alf := runSearch([]string{"Entry1"})
		assert.Len(t, alf.Items, 1)
		assert.True(t, strings.HasPrefix(alf.Items[0].Title, "⚠️"))
		assert.Nil(t, alf.Cache) // errors are not cached
	})

	t.Run("invalid configuration", func(t *testing.T) {
		useWorkflow(t, dbPath, "Abc12345", map[string]string{yubikeySlotVariable: "3"})
		alf := runSearch([]string{"Entry1"})
		assert.Len(t, alf.Items, 1)
		assert.True(t, strings.HasPrefix(alf.Items[0].Title, "⚠️ invalid YubiKey slot"))
	})

	t.Run("search happy path", func(t *testing.T) {
		useWorkflow(t, dbPath, "Abc12345", nil)
		alf := runSearch([]string{"Entry1"})
		assert.Equal(t, "Entry1", alf.Items[0].Title)
		assert.NotNil(t, alf.Cache)
		assert.Equal(t, 5, alf.Cache.Seconds)
		assert.True(t, alf.Cache.LooseReload)
	})

	t.Run("locked keychain", func(t *testing.T) {
		useWorkflow(t, dbPath, "Abc12345", nil)
		keychainLocked = func() (bool, error) { return true, nil }
		alf := runSearch([]string{"Entry1", "#work"})
		assert.Equal(t, "locked", alf.Items[0].Uid)
		assert.Equal(t, "Entry1 #work", alf.Items[0].Arg)
		alf = runGet([]string{"Entry1"})
		assert.Equal(t, "locked", alf.Items[0].Uid)
		assert.Equal(t, "back", alf.Items[0].Arg)
	})

	t.Run("get with no argument", func(t *testing.T) {
		useWorkflow(t, dbPath, "Abc12345", nil)
		alf := runGet(nil)
		assert.Len(t, alf.Items, 1)
		assert.True(t, strings.HasPrefix(alf.Items[0].Title, "⚠️"))
	})

	t.Run("get missing entry", func(t *testing.T) {
		useWorkflow(t, dbPath, "Abc12345", nil)
		alf := runGet([]string{"NoSuchEntry"})
		assert.Len(t, alf.Items, 1)
		assert.True(t, strings.HasPrefix(alf.Items[0].Title, "⚠️"))
	})

	t.Run("get happy path", func(t *testing.T) {
		useWorkflow(t, dbPath, "Abc12345", nil)
		alf := runGet([]string{"Entry1"})
		assert.Equal(t, "← Back", alf.Items[0].Title)
	})
}
