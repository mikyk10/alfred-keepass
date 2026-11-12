package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
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

// clipValue copies value to the clipboard. With a positive timeout the
// clipboard is cleared after it, as keepassxc-cli does, but only if it still
// holds value, so that anything copied in the meantime is kept. The clearing
// runs in a background process, so clip returns right after copying and
// Alfred can confirm the copy without waiting for the timeout. An empty value
// is never cleared: the clipboard also reads as empty while it holds e.g. an
// image.
func clipValue(value string, timeout time.Duration) error {
	if err := writeClipboard(value); err != nil {
		return err
	}
	if timeout <= 0 || value == "" {
		return nil
	}
	return startClipboardClear(clipboardDigest(value), timeout)
}

// clipboardDigest identifies a copied value, so that the clearing process
// can recognize it without being given the value itself.
func clipboardDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// startClipboardClear runs `alkeepass clear-clipboard` detached from this
// process, in its own session so that it outlives the Alfred action. The
// digest goes through stdin, since the arguments and environment of a process
// can be read by other processes. It is a variable so tests can replace it
// and never start a process.
var startClipboardClear = func(digest string, timeout time.Duration) error {
	exe, err := os.Executable()
	if err != nil {
		return errors.Wrap(err, "could not start clearing the clipboard")
	}
	cmd := exec.Command(exe, clearClipboardCmd.Name(), timeout.String())
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return errors.Wrap(err, "could not start clearing the clipboard")
	}
	if err := cmd.Start(); err != nil {
		return errors.Wrap(err, "could not start clearing the clipboard")
	}
	_, err = io.WriteString(stdin, digest)
	stdin.Close()
	cmd.Process.Release()
	return errors.Wrap(err, "could not start clearing the clipboard")
}

// clearClipboardAfter waits for timeout and then clears the clipboard if it
// still holds the value with the given digest.
func clearClipboardAfter(digest string, timeout time.Duration) error {
	time.Sleep(timeout)
	current, err := readClipboard()
	if err != nil {
		return err
	}
	if clipboardDigest(current) != digest {
		return nil
	}
	return writeClipboard("")
}
