package cmd

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// The master password is kept as a generic password item in a keychain
// dedicated to this workflow instead of the workflow configuration, which
// Alfred stores in plain text (and often syncs to iCloud). The dedicated
// keychain locks itself after a short idle period and on sleep, so the
// password can only be read while the user has recently unlocked it.
const (
	keychainService = "alfred-keepass"
	keychainAccount = "alfred-keepass"
	keychainFile    = "alfred-keepass.keychain-db"
	securityPath    = "/usr/bin/security"

	// idle seconds after which the dedicated keychain locks itself
	keychainLockSeconds = 300

	// exit status of security(1) for errSecItemNotFound
	securityItemNotFound = 44
)

var passwordCmd = &cobra.Command{
	Use:   "password",
	Short: "Print the master password stored in the keychain",
	Run:   passwordMain,
}

var setPasswordCmd = &cobra.Command{
	Use:   "set-password",
	Short: "Store the master password read from stdin in the keychain",
	Run:   setPasswordMain,
}

var unlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Ask the user to unlock the keychain holding the master password",
	Run:   unlockMain,
}

// keychainLocked reports whether the dedicated keychain exists and is locked,
// without prompting. Script Filters check it before reading the password:
// an unlock dialog shown while Alfred's window is open closes the window and
// loses the results. It is a variable so tests can replace it.
var keychainLocked = func() (bool, error) {
	kc, err := keychainPath()
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(kc); os.IsNotExist(err) {
		return false, nil
	}
	return keychainFileLocked(kc)
}

// unlockKeychain asks the user to unlock the dedicated keychain if it is
// locked, and returns once it has been answered.
func unlockKeychain() error {
	locked, err := keychainLocked()
	if err != nil || !locked {
		return err
	}
	kc, err := keychainPath()
	if err != nil {
		return err
	}
	return unlockKeychainFile(kc)
}

// keychainPath returns the location of the dedicated keychain.
func keychainPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.WithStack(err)
	}
	return filepath.Join(home, "Library", "Keychains", keychainFile), nil
}

// readKeychain returns the stored master password, or "" when no item has
// been registered. Any other failure (e.g. the user cancelled the unlock
// dialog) is returned as an error. It is a variable so tests can replace it.
var readKeychain = func() (string, error) {
	kc, err := keychainPath()
	if err != nil {
		return "", err
	}
	return readKeychainItem(kc, keychainService)
}

// readKeychainItem reads the item for service from the keychain file kc.
// A missing keychain or item reads as "". When the keychain is locked,
// security(1) asks the user to unlock it.
func readKeychainItem(kc, service string) (string, error) {
	if _, err := os.Stat(kc); os.IsNotExist(err) {
		return "", nil
	}

	// -g writes the password to stderr; unlike -w it marks non-printable
	// (e.g. non-ASCII) passwords as hex so they can be decoded unambiguously.
	var stderr bytes.Buffer
	cmd := exec.Command(securityPath, "find-generic-password", "-s", service, "-g", kc)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == securityItemNotFound {
			return "", nil
		}
		return "", errors.Errorf("could not read the master password from the keychain: %s", strings.TrimSpace(stderr.String()))
	}
	return parseSecurityPassword(stderr.String())
}

// parseSecurityPassword extracts the password from the "password: ..." line
// that `security find-generic-password -g` prints. The value is either a
// quoted string, or a hex dump (0x...) followed by a quoted rendering when
// the data is not plain printable text.
func parseSecurityPassword(out string) (string, error) {
	const prefix = "password: "
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		v := strings.TrimPrefix(line, prefix)
		if strings.HasPrefix(v, "0x") {
			h := strings.TrimPrefix(v, "0x")
			if i := strings.IndexByte(h, ' '); i >= 0 {
				h = h[:i]
			}
			b, err := hex.DecodeString(h)
			if err != nil {
				return "", errors.WithStack(err)
			}
			return string(b), nil
		}
		if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
			return v[1 : len(v)-1], nil
		}
		return v, nil
	}
	return "", errors.New("could not read the master password from the keychain: unexpected output")
}

// writeKeychain stores passwd in the dedicated keychain, creating the
// keychain first if needed, and removes the item that earlier versions kept
// in the login keychain.
func writeKeychain(passwd string) error {
	kc, err := keychainPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(kc); os.IsNotExist(err) {
		// -P lets macOS ask the user for the new keychain's password, so it
		// never passes through this process.
		if err := runSecurity("create-keychain", "-P", kc); err != nil {
			return err
		}
		if err := removeFromSearchList(kc); err != nil {
			return err
		}
	}
	// (Re)apply the lock policy: lock on sleep and after the idle timeout.
	if err := runSecurity("set-keychain-settings", "-l", "-u", "-t", strconv.Itoa(keychainLockSeconds), kc); err != nil {
		return err
	}
	if err := writeKeychainItem(kc, keychainService, passwd); err != nil {
		return err
	}
	removeLegacyItem(filepath.Join(filepath.Dir(kc), "login.keychain-db"))
	return nil
}

// writeKeychainItem stores passwd for service in the keychain file kc,
// replacing any existing item. The command is fed to `security -i` on stdin
// with the password hex-encoded (-X), so the password neither appears in the
// process list nor needs any quoting.
func writeKeychainItem(kc, service, passwd string) error {
	if strings.ContainsAny(kc, " \t\"'\\") {
		return errors.Errorf("unsupported keychain path: %s", kc)
	}
	line := fmt.Sprintf("add-generic-password -U -s %s -a %s -X %s %s\n",
		service, keychainAccount, hex.EncodeToString([]byte(passwd)), kc)

	var out bytes.Buffer
	cmd := exec.Command(securityPath, "-i")
	cmd.Stdin = strings.NewReader(line)
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return errors.Errorf("could not store the master password in the keychain: %s", strings.TrimSpace(out.String()))
	}
	// security -i keeps going after a failed command, so its exit status is
	// not enough; check that the item can actually be read back.
	got, err := readKeychainItem(kc, service)
	if err != nil {
		return err
	}
	if got != passwd {
		return errors.Errorf("could not store the master password in the keychain: %s", strings.TrimSpace(out.String()))
	}
	return nil
}

// removeFromSearchList drops kc from the user's keychain search list, which
// create-keychain adds it to. Otherwise other apps searching all keychains
// would keep prompting to unlock it whenever it is locked.
func removeFromSearchList(kc string) error {
	out, err := exec.Command(securityPath, "list-keychains", "-d", "user").Output()
	if err != nil {
		return errors.WithStack(err)
	}
	target := resolvePath(kc)
	args := []string{"list-keychains", "-d", "user", "-s"}
	for _, p := range parseKeychainList(string(out)) {
		if resolvePath(p) != target {
			args = append(args, p)
		}
	}
	return runSecurity(args...)
}

// resolvePath resolves symlinks (e.g. /var -> /private/var) so paths can be
// compared as security(1) reports them; it falls back to path as given.
func resolvePath(path string) string {
	if p, err := filepath.EvalSymlinks(path); err == nil {
		return p
	}
	return path
}

// parseKeychainList parses the quoted, one-per-line output of
// `security list-keychains`.
func parseKeychainList(out string) []string {
	var list []string
	for _, line := range strings.Split(out, "\n") {
		if p := strings.Trim(strings.TrimSpace(line), `"`); p != "" {
			list = append(list, p)
		}
	}
	return list
}

// removeLegacyItem deletes the item that earlier versions stored in the login
// keychain, where any process could read it while the user is logged in.
// A missing item is not an error.
func removeLegacyItem(login string) {
	exec.Command(securityPath, "delete-generic-password", "-s", keychainService, login).Run()
}

func runSecurity(args ...string) error {
	out, err := exec.Command(securityPath, args...).CombinedOutput()
	if err != nil {
		return errors.Errorf("security %s failed: %s", args[0], strings.TrimSpace(string(out)))
	}
	return nil
}

func unlockMain(cmd *cobra.Command, args []string) {
	if err := unlockKeychain(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func passwordMain(cmd *cobra.Command, args []string) {
	// Unlock first so that the dialog has been answered before the
	// password is read, rather than leaving security(1) to prompt mid-read.
	if err := unlockKeychain(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	passwd, err := readKeychain()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(passwd)
}

func setPasswordMain(cmd *cobra.Command, args []string) {
	passwd, err := bufio.NewReader(os.Stdin).ReadString('\n')
	passwd = strings.TrimRight(passwd, "\r\n")
	if passwd == "" {
		if err != nil && err != io.EOF {
			fmt.Fprintln(os.Stderr, err)
		} else {
			fmt.Fprintln(os.Stderr, "empty password; nothing stored")
		}
		os.Exit(1)
	}
	if err := writeKeychain(passwd); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
