package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestParseCacheSeconds(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"", 5},           // empty -> default
		{"abc", 5},        // invalid -> default
		{"30", 30},        // valid passthrough
		{"1", 5},          // below min -> clamped to 5
		{"0", 5},          // below min -> clamped to 5
		{"-10", 5},        // negative -> clamped to 5
		{"999999", 86400}, // above max -> clamped to 86400
	}
	for _, c := range cases {
		assert.Equal(t, c.want, parseCacheSeconds(c.raw), "raw=%q", c.raw)
	}
}

func TestCacheSerialization(t *testing.T) {
	t.Run("cache is emitted when set", func(t *testing.T) {
		alf := &AlfredJSON{Cache: &AlfredCache{Seconds: 5, LooseReload: true}}
		b, err := json.Marshal(alf)
		assert.NoError(t, err)
		assert.Contains(t, string(b), `"cache":{"seconds":5,"loosereload":true}`)
	})

	t.Run("cache is omitted when nil", func(t *testing.T) {
		b, err := json.Marshal(errorJSON(errors.New("boom")))
		assert.NoError(t, err)
		assert.False(t, strings.Contains(string(b), "cache"), "error output must not carry a cache key")
	})
}
