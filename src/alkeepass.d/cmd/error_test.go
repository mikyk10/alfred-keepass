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
		alf := runSearch(dbPath, "", "", []string{"Entry1"})
		assert.Len(t, alf.Items, 1)
		assert.True(t, strings.HasPrefix(alf.Items[0].Title, "⚠️"))
	})

	t.Run("missing database", func(t *testing.T) {
		alf := runSearch(filepath.Join("testdata", "nope.kdbx"), "", "Abc12345", []string{"Entry1"})
		assert.Len(t, alf.Items, 1)
		assert.True(t, strings.HasPrefix(alf.Items[0].Title, "⚠️"))
	})

	t.Run("search happy path", func(t *testing.T) {
		alf := runSearch(dbPath, "", "Abc12345", []string{"Entry1"})
		assert.Equal(t, "Entry1", alf.Items[0].Title)
	})

	t.Run("get missing entry", func(t *testing.T) {
		alf := runGet(dbPath, "", "Abc12345", "NoSuchEntry")
		assert.Len(t, alf.Items, 1)
		assert.True(t, strings.HasPrefix(alf.Items[0].Title, "⚠️"))
	})

	t.Run("get happy path", func(t *testing.T) {
		alf := runGet(dbPath, "", "Abc12345", "Entry1")
		assert.Equal(t, "← Back", alf.Items[0].Title)
	})
}
