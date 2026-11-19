package cmd

import (
	"encoding/json"
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
// the master password from the keychain and the configured key file. The
// entry is given by its UUID, as search results pass it on, or by its path.

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
	addValueFlags(clipCmd)
	addValueFlags(showCmd)
	showCmd.Flags().Bool("alfred", false,
		"print the value or the error as the JSON output of an Alfred Run Script action, the error in the variable kp_error, and exit 0")
}

// addValueFlags adds the flags that select the value of an entry to c.
func addValueFlags(c *cobra.Command) {
	c.Flags().StringP("attribute", "a", "password",
		"attribute to use; matched case-insensitively if there is no exact match")
	c.Flags().BoolP("totp", "t", false, "use the current TOTP instead of an attribute")
	c.Flags().Bool("prepend-totp", false,
		"put the current TOTP in front of the attribute, for sites that take both in one field")
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
	if alfred, _ := cmd.Flags().GetBool("alfred"); alfred {
		os.Stdout.Write(alfredOutput(value, err))
		return
	}
	exitOnError(err)
	fmt.Println(value)
}

// alfredOutput returns the JSON output of an Alfred Run Script action that
// passes on value, or, if err is set, an empty argument. The variable
// kp_error holds the error, if any, so that the workflow can tell the user
// instead of carrying on.
func alfredOutput(value string, err error) []byte {
	var out struct {
		Workflow struct {
			Arg       string            `json:"arg"`
			Variables map[string]string `json:"variables"`
		} `json:"alfredworkflow"`
	}
	out.Workflow.Arg = value
	out.Workflow.Variables = map[string]string{"kp_error": ""}
	if err != nil {
		out.Workflow.Arg = ""
		out.Workflow.Variables["kp_error"] = err.Error()
	}
	b, _ := json.Marshal(out)
	return b
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

// selectedValue returns the value that the flags added by addValueFlags to
// cmd select in the entry that ref refers to.
func selectedValue(cmd *cobra.Command, ref string) (string, error) {
	attr, _ := cmd.Flags().GetString("attribute")
	useTOTP, _ := cmd.Flags().GetBool("totp")
	prependTOTP, _ := cmd.Flags().GetBool("prepend-totp")
	if useTOTP && (cmd.Flags().Changed("attribute") || prependTOTP) {
		return "", errors.New("--totp takes neither --attribute nor --prepend-totp")
	}

	_, entry, err := openConfiguredEntry(ref)
	if err != nil {
		return "", err
	}
	if useTOTP {
		return entryTOTP(entry, time.Now())
	}
	value, err := findAttribute(entry, attr)
	if err != nil || !prependTOTP {
		return value, err
	}
	// The TOTP comes last, so that it is as fresh as it can be.
	otp, err := entryTOTP(entry, time.Now())
	if err != nil {
		return "", err
	}
	return otp + value, nil
}

// openConfiguredEntry opens the configured database and returns the entry
// that ref refers to (see findEntry). If the master password is needed, it
// asks the user to unlock the keychain first, as `password` does.
func openConfiguredEntry(ref string) (*gokeepasslib.Database, *gokeepasslib.Entry, error) {
	db, err := openConfiguredDatabase(true)
	if err != nil {
		return nil, nil, err
	}
	entry, err := findEntry(db, ref)
	if err != nil {
		return nil, nil, err
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
// replacing the file if it exists, as keepassxc-cli does. The workflow saves
// the attachment under its name in ~/Downloads, so a name that is not a plain
// file name is refused: the database could otherwise make it write anywhere,
// e.g. over ~/.zshrc with "../.zshrc".
func exportAttachment(db *gokeepasslib.Database, entry *gokeepasslib.Entry, name, path string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return errors.Errorf("refusing to save an attachment named %q, which is not a plain file name", name)
	}
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
