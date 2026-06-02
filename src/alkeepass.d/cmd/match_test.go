package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/text/unicode/norm"
)

func TestMatchesQuery(t *testing.T) {
	// "ガジェット" contains characters that differ between NFC (precomposed)
	// and NFD (base + combining dakuten), which is exactly the macOS case.
	nfc := norm.NFC.String("ガジェット")
	nfd := norm.NFD.String("ガジェット")
	assert.NotEqual(t, nfc, nfd, "fixture must actually differ between NFC and NFD")

	t.Run("NFD query matches NFC path", func(t *testing.T) {
		assert.True(t, matchesQuery(nfc, []string{nfd}))
	})

	t.Run("NFC query matches NFD path", func(t *testing.T) {
		assert.True(t, matchesQuery(nfd, []string{nfc}))
	})

	t.Run("case insensitive", func(t *testing.T) {
		assert.True(t, matchesQuery("MyEntry", []string{"myentry"}))
	})

	t.Run("all terms must match", func(t *testing.T) {
		assert.True(t, matchesQuery("group/My Entry", []string{"group", "entry"}))
		assert.False(t, matchesQuery("group/My Entry", []string{"group", "missing"}))
	})

	t.Run("empty query matches anything", func(t *testing.T) {
		assert.True(t, matchesQuery("anything", nil))
	})
}
