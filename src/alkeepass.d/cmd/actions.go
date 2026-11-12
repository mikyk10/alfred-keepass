package cmd

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/tobischo/gokeepasslib/v3"
)

// The commands below back the workflow's copy, open and export actions. They
// follow the keepassxc-cli commands that those actions used to run, without
// the database argument: like search, they open the configured database with
// the master password from the keychain and the configured key file.

var clipCmd = &cobra.Command{
	Use:   "clip [flags] entry [timeout]",
	Short: "Copy an attribute or the TOTP of an entry to the clipboard",
	Long: `Copy an attribute or the TOTP of an entry to the clipboard. After timeout
seconds (default 10, 0 to never clear) the clipboard is cleared in the
background if it still holds the copied value.`,
	Args: cobra.RangeArgs(1, 2),
	Run:  clipMain,
}

var showCmd = &cobra.Command{
	Use:   "show [flags] entry",
	Short: "Print an attribute or the TOTP of an entry",
	Args:  cobra.ExactArgs(1),
	Run:   showMain,
}

var attachmentExportCmd = &cobra.Command{
	Use:   "attachment-export entry attachment file",
	Short: "Save an attachment of an entry to a file",
	Args:  cobra.ExactArgs(3),
	Run:   attachmentExportMain,
}

// clearClipboardCmd is started by clip to clear the clipboard in the
// background. It reads the digest of the copied value from stdin.
var clearClipboardCmd = &cobra.Command{
	Use:    "clear-clipboard timeout",
	Short:  "Clear the clipboard after timeout if it still holds the copied value",
	Hidden: true,
	Args:   cobra.ExactArgs(1),
	Run:    clearClipboardMain,
}

// defaultClipTimeout is how long a copied value stays in the clipboard when
// clip is given no timeout, as in keepassxc-cli.
const defaultClipTimeout = 10 * time.Second

func init() {
	for _, c := range []*cobra.Command{clipCmd, showCmd} {
		c.Flags().StringP("attribute", "a", "password",
			"attribute to use; matched case-insensitively if there is no exact match")
		c.Flags().BoolP("totp", "t", false, "use the current TOTP instead of an attribute")
	}
}

func clipMain(cmd *cobra.Command, args []string) {
	timeout := defaultClipTimeout
	if len(args) == 2 {
		s, err := strconv.Atoi(args[1])
		if err != nil || s < 0 {
			exitOnError(errors.Errorf("invalid timeout: %s", args[1]))
		}
		timeout = time.Duration(s) * time.Second
	}
	value, err := selectedValue(cmd, args[0])
	exitOnError(err)
	exitOnError(clipValue(value, timeout))
}

func showMain(cmd *cobra.Command, args []string) {
	value, err := selectedValue(cmd, args[0])
	exitOnError(err)
	fmt.Println(value)
}

func attachmentExportMain(cmd *cobra.Command, args []string) {
	db, entry, err := openConfiguredEntry(args[0])
	exitOnError(err)
	exitOnError(exportAttachment(db, entry, args[1], args[2]))
}

func clearClipboardMain(cmd *cobra.Command, args []string) {
	timeout, err := time.ParseDuration(args[0])
	exitOnError(errors.WithStack(err))
	digest, err := io.ReadAll(os.Stdin)
	exitOnError(errors.WithStack(err))
	exitOnError(clearClipboardAfter(string(digest), timeout))
}

// exitOnError reports err on stderr and exits non-zero. The actions run after
// Alfred's window has closed, so there is no Alfred item to show it in.
func exitOnError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// selectedValue returns the value that the --attribute or --totp flag of cmd
// selects in the entry at entryPath.
func selectedValue(cmd *cobra.Command, entryPath string) (string, error) {
	attr, _ := cmd.Flags().GetString("attribute")
	useTOTP, _ := cmd.Flags().GetBool("totp")
	if useTOTP && cmd.Flags().Changed("attribute") {
		return "", errors.New("specify either --attribute or --totp, not both")
	}

	_, entry, err := openConfiguredEntry(entryPath)
	if err != nil {
		return "", err
	}
	if useTOTP {
		return entryTOTP(entry, time.Now())
	}
	return findAttribute(entry, attr)
}

// openConfiguredEntry opens the configured database and returns the entry at
// entryPath. Like `password`, it unlocks the keychain first so that the
// dialog has been answered before the master password is read.
func openConfiguredEntry(entryPath string) (*gokeepasslib.Database, *gokeepasslib.Entry, error) {
	if err := unlockKeychain(); err != nil {
		return nil, nil, err
	}
	passwd, err := readKeychain()
	if err != nil {
		return nil, nil, err
	}
	return openEntry(os.Getenv("keepassxc_db_path"), os.Getenv("keepassxc_keyfile_path"), passwd, entryPath)
}

// openEntry opens the database at kbdxpath with the same credentials as
// search and returns it with the entry at entryPath, the path that search
// results carry.
func openEntry(kbdxpath, keyfilepath, passwd, entryPath string) (*gokeepasslib.Database, *gokeepasslib.Entry, error) {
	cred, err := buildCredentials(passwd, keyfilepath)
	if err != nil {
		return nil, nil, err
	}
	db, err := openDatabase(kbdxpath, cred)
	if err != nil {
		return nil, nil, err
	}

	result := []KPEntry{}
	scan(&db.Content.Root.Groups, []string{}, nil, &result)
	entry := getEntry(result, entryPath)
	if entry == nil {
		return nil, nil, errors.Errorf("entry not found: %s", entryPath)
	}
	return db, &entry.Entry, nil
}

// standardAttributes are the attributes every KeePassXC entry has, even when
// the database does not store them because they are empty.
var standardAttributes = []string{"Title", "UserName", "Password", "URL", "Notes"}

// findAttribute returns the value of the attribute name of entry. Like
// keepassxc-cli it prefers an exact match and otherwise matches the name
// case-insensitively, so that e.g. "password" finds "Password", and it reads
// a missing standard attribute as empty.
func findAttribute(entry *gokeepasslib.Entry, name string) (string, error) {
	// TODO: resolve placeholders such as {USERNAME} and field references
	// ({REF:...}) as keepassxc-cli does; values are returned as stored.
	if v := entry.Get(name); v != nil {
		return v.Value.Content, nil
	}
	var keys, values []string
	for _, v := range entry.Values {
		if strings.EqualFold(v.Key, name) {
			keys = append(keys, v.Key)
			values = append(values, v.Value.Content)
		}
	}
	switch len(keys) {
	case 0:
		for _, k := range standardAttributes {
			if strings.EqualFold(k, name) {
				return "", nil
			}
		}
		return "", errors.Errorf("unknown attribute: %s", name)
	case 1:
		return values[0], nil
	default:
		return "", errors.Errorf("attribute %s is ambiguous, it matches %s", name, strings.Join(keys, ", "))
	}
}

// exportAttachment writes the attachment called name of entry to path,
// replacing the file if it exists, as keepassxc-cli does.
func exportAttachment(db *gokeepasslib.Database, entry *gokeepasslib.Entry, name, path string) error {
	for _, ref := range entry.Binaries {
		if ref.Name != name {
			continue
		}
		bin := db.FindBinary(ref.Value.ID)
		if bin == nil {
			return errors.Errorf("attachment has no data: %s", name)
		}
		data, err := bin.GetContentBytes()
		if err != nil {
			return errors.WithStack(err)
		}
		return errors.WithStack(os.WriteFile(path, data, 0666))
	}
	return errors.Errorf("attachment not found: %s", name)
}
