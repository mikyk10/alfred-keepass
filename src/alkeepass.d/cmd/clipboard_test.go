package cmd

import (
	"os"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

// TestMain keeps every test away from the real clipboard and from starting
// the clearing process; tests that need them install fakes.
func TestMain(m *testing.M) {
	writeClipboard = func(string) error { return errors.New("tests must not write to the real clipboard") }
	readClipboard = func() (string, error) { return "", errors.New("tests must not read the real clipboard") }
	startClipboardClear = func(string, time.Duration) error {
		return errors.New("tests must not start a process to clear the clipboard")
	}
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

// clearStart records a clearing that clipValue started.
type clearStart struct {
	digest  string
	timeout time.Duration
}

func useFakeClear(t *testing.T) *[]clearStart {
	var started []clearStart
	start := startClipboardClear
	startClipboardClear = func(digest string, timeout time.Duration) error {
		started = append(started, clearStart{digest, timeout})
		return nil
	}
	t.Cleanup(func() { startClipboardClear = start })
	return &started
}

func TestClipValue(t *testing.T) {
	t.Run("without a timeout the value stays", func(t *testing.T) {
		f := useFakeClipboard(t)
		started := useFakeClear(t)
		assert.NoError(t, clipValue("secret", 0))
		assert.Equal(t, []string{"secret"}, f.writes)
		assert.Equal(t, "secret", f.content)
		assert.Empty(t, *started)
	})

	t.Run("with a timeout the clearing is left to the background", func(t *testing.T) {
		f := useFakeClipboard(t)
		started := useFakeClear(t)
		// Returning at all shows that clipValue does not wait for the hour.
		assert.NoError(t, clipValue("123456", time.Hour))
		assert.Equal(t, []string{"123456"}, f.writes)
		assert.Equal(t, "123456", f.content)
		assert.Equal(t, []clearStart{{clipboardDigest("123456"), time.Hour}}, *started)
	})

	t.Run("an empty value is not cleared", func(t *testing.T) {
		f := useFakeClipboard(t)
		started := useFakeClear(t)
		assert.NoError(t, clipValue("", time.Hour))
		assert.Equal(t, []string{""}, f.writes)
		assert.Empty(t, *started)
	})

	t.Run("a failed copy is reported and nothing is cleared", func(t *testing.T) {
		useFakeClipboard(t)
		started := useFakeClear(t)
		writeClipboard = func(string) error { return errors.New("pbcopy failed") }
		assert.ErrorContains(t, clipValue("123456", time.Hour), "pbcopy failed")
		assert.Empty(t, *started)
	})

	t.Run("a failure to start the clearing is reported", func(t *testing.T) {
		useFakeClipboard(t)
		useFakeClear(t) // restores startClipboardClear afterwards
		startClipboardClear = func(string, time.Duration) error { return errors.New("no process") }
		assert.ErrorContains(t, clipValue("123456", time.Hour), "no process")
	})
}

func TestClearClipboardAfter(t *testing.T) {
	digest := clipboardDigest("123456")

	t.Run("the value is cleared after the timeout", func(t *testing.T) {
		f := useFakeClipboard(t)
		f.content = "123456"
		start := time.Now()
		assert.NoError(t, clearClipboardAfter(digest, 20*time.Millisecond))
		assert.GreaterOrEqual(t, time.Since(start), 20*time.Millisecond, "cleared before the timeout")
		assert.Equal(t, []string{""}, f.writes)
		assert.Equal(t, "", f.content)
	})

	t.Run("something copied in the meantime is kept", func(t *testing.T) {
		f := useFakeClipboard(t)
		f.content = "copied by the user"
		assert.NoError(t, clearClipboardAfter(digest, time.Millisecond))
		assert.Empty(t, f.writes)
		assert.Equal(t, "copied by the user", f.content)
	})

	t.Run("a failed read is reported and nothing is cleared", func(t *testing.T) {
		f := useFakeClipboard(t)
		readClipboard = func() (string, error) { return "", errors.New("pbpaste failed") }
		assert.ErrorContains(t, clearClipboardAfter(digest, time.Millisecond), "pbpaste failed")
		assert.Empty(t, f.writes)
	})
}
