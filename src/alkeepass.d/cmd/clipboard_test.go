package cmd

import (
	"os"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

// TestMain keeps every test away from the real clipboard; tests that need
// one install a fake.
func TestMain(m *testing.M) {
	writeClipboard = func(string) error { return errors.New("tests must not write to the real clipboard") }
	readClipboard = func() (string, error) { return "", errors.New("tests must not read the real clipboard") }
	os.Exit(m.Run())
}

// fakeClipboard stands in for the clipboard and records what was written.
type fakeClipboard struct {
	content string
	writes  []string
}

func useFakeClipboard(t *testing.T) *fakeClipboard {
	f := &fakeClipboard{content: "copied before"}
	write, read := writeClipboard, readClipboard
	writeClipboard = func(text string) error {
		f.content = text
		f.writes = append(f.writes, text)
		return nil
	}
	readClipboard = func() (string, error) { return f.content, nil }
	t.Cleanup(func() { writeClipboard, readClipboard = write, read })
	return f
}

func TestClipValue(t *testing.T) {
	t.Run("without a timeout the value stays", func(t *testing.T) {
		f := useFakeClipboard(t)
		assert.NoError(t, clipValue("secret", 0))
		assert.Equal(t, []string{"secret"}, f.writes)
		assert.Equal(t, "secret", f.content)
	})

	t.Run("the value is cleared after the timeout", func(t *testing.T) {
		f := useFakeClipboard(t)
		start := time.Now()
		assert.NoError(t, clipValue("123456", 20*time.Millisecond))
		assert.GreaterOrEqual(t, time.Since(start), 20*time.Millisecond, "cleared before the timeout")
		assert.Equal(t, []string{"123456", ""}, f.writes)
		assert.Equal(t, "", f.content)
	})

	t.Run("something copied in the meantime is kept", func(t *testing.T) {
		f := useFakeClipboard(t)
		readClipboard = func() (string, error) {
			f.content = "copied by the user" // while clipValue was waiting
			return f.content, nil
		}
		assert.NoError(t, clipValue("123456", time.Millisecond))
		assert.Equal(t, []string{"123456"}, f.writes)
		assert.Equal(t, "copied by the user", f.content)
	})

	t.Run("an empty value is not cleared", func(t *testing.T) {
		f := useFakeClipboard(t)
		readClipboard = func() (string, error) { return "", errors.New("must not be read") }
		assert.NoError(t, clipValue("", time.Millisecond))
		assert.Equal(t, []string{""}, f.writes)
	})

	t.Run("a failed copy is reported", func(t *testing.T) {
		useFakeClipboard(t)
		writeClipboard = func(string) error { return errors.New("pbcopy failed") }
		assert.ErrorContains(t, clipValue("123456", time.Millisecond), "pbcopy failed")
	})

	t.Run("a failed read is reported and nothing is cleared", func(t *testing.T) {
		f := useFakeClipboard(t)
		readClipboard = func() (string, error) { return "", errors.New("pbpaste failed") }
		assert.ErrorContains(t, clipValue("123456", time.Millisecond), "pbpaste failed")
		assert.Equal(t, []string{"123456"}, f.writes)
	})
}
