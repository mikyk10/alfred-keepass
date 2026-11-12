package cmd

import (
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const (
	pbcopyPath  = "/usr/bin/pbcopy"
	pbpastePath = "/usr/bin/pbpaste"
)

// writeClipboard replaces the clipboard content with text. It is a variable
// so tests can replace it and never touch the real clipboard.
var writeClipboard = func(text string) error {
	cmd := exec.Command(pbcopyPath)
	cmd.Env = clipboardEnv()
	cmd.Stdin = strings.NewReader(text)
	cmd.Stderr = os.Stderr
	return errors.Wrap(cmd.Run(), "could not copy to the clipboard")
}

// readClipboard returns the text in the clipboard, which is "" when it holds
// no text. It is a variable so tests can replace it.
var readClipboard = func() (string, error) {
	cmd := exec.Command(pbpastePath)
	cmd.Env = clipboardEnv()
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	return string(out), errors.Wrap(err, "could not read the clipboard")
}

// clipboardEnv makes pbcopy(1) and pbpaste(1) use UTF-8. They take the
// encoding from the locale, which is not necessarily set when Alfred runs the
// workflow.
func clipboardEnv() []string {
	return append(os.Environ(), "LC_ALL=en_US.UTF-8")
}

// clipValue copies value to the clipboard. With a positive timeout it then
// waits and clears the clipboard, as keepassxc-cli does, but only if the
// clipboard still holds value, so that anything copied in the meantime is
// kept. An empty value is never cleared: the clipboard also reads as empty
// while it holds e.g. an image.
func clipValue(value string, timeout time.Duration) error {
	if err := writeClipboard(value); err != nil {
		return err
	}
	if timeout <= 0 || value == "" {
		return nil
	}
	time.Sleep(timeout)
	current, err := readClipboard()
	if err != nil {
		return err
	}
	if current != value {
		return nil
	}
	return writeClipboard("")
}
