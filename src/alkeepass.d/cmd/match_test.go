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

func TestSplitQuery(t *testing.T) {
	t.Run("plain terms go to path terms", func(t *testing.T) {
		path, tag := splitQuery([]string{"gmail", "work"})
		assert.Equal(t, []string{"gmail", "work"}, path)
		assert.Empty(t, tag)
	})

	t.Run("hashed terms go to tag terms with the # stripped", func(t *testing.T) {
		path, tag := splitQuery([]string{"#work"})
		assert.Empty(t, path)
		assert.Equal(t, []string{"work"}, tag)
	})

	t.Run("path and tag terms are split apart", func(t *testing.T) {
		path, tag := splitQuery([]string{"gmail", "#work", "#mail"})
		assert.Equal(t, []string{"gmail"}, path)
		assert.Equal(t, []string{"work", "mail"}, tag)
	})

	t.Run("a bare # carries no term and is ignored", func(t *testing.T) {
		path, tag := splitQuery([]string{"gmail", "#"})
		assert.Equal(t, []string{"gmail"}, path)
		assert.Empty(t, tag)
	})
}

func TestQueryTerms(t *testing.T) {
	t.Run("single quoted argument is split on whitespace", func(t *testing.T) {
		// Alfred passes the whole query as one argument (e.g. `search "gmail #work"`).
		assert.Equal(t, []string{"gmail", "#work"}, queryTerms([]string{"gmail #work"}))
	})

	t.Run("already word-split argv is preserved", func(t *testing.T) {
		assert.Equal(t, []string{"gmail", "#work"}, queryTerms([]string{"gmail", "#work"}))
	})

	t.Run("surrounding and repeated whitespace is collapsed", func(t *testing.T) {
		assert.Equal(t, []string{"a", "b"}, queryTerms([]string{"  a   b  "}))
	})

	t.Run("empty query yields no terms", func(t *testing.T) {
		assert.Empty(t, queryTerms([]string{""}))
		assert.Empty(t, queryTerms(nil))
	})
}

func TestMatchesTags(t *testing.T) {
	// Tag filtering reuses matchesQuery against the entry's raw Tags string,
	// so it is partial and case-insensitive just like path matching.
	const tags = "Work;Mail"

	t.Run("partial, case-insensitive tag match", func(t *testing.T) {
		assert.True(t, matchesQuery(tags, []string{"work"}))
		assert.True(t, matchesQuery(tags, []string{"wor"}))
		assert.True(t, matchesQuery(tags, []string{"MAIL"}))
	})

	t.Run("non-matching tag is rejected", func(t *testing.T) {
		assert.False(t, matchesQuery(tags, []string{"personal"}))
	})

	t.Run("an entry without tags never matches a tag term", func(t *testing.T) {
		assert.False(t, matchesQuery("", []string{"work"}))
	})
}
