package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/tobischo/gokeepasslib/v3"
	"golang.org/x/text/unicode/norm"
)

// buildCredentials assembles KeePass credentials from a master password
// and/or a key file path. It propagates the error returned by the key file
// based constructors (e.g. a missing or unreadable key file) instead of
// discarding it, and returns an error when neither is configured.
func buildCredentials(passwd, keyfilepath string) (*gokeepasslib.DBCredentials, error) {
	switch {
	case passwd != "" && keyfilepath != "":
		return gokeepasslib.NewPasswordAndKeyCredentials(passwd, keyfilepath)
	case passwd != "":
		return gokeepasslib.NewPasswordCredentials(passwd), nil
	case keyfilepath != "":
		return gokeepasslib.NewKeyCredentials(keyfilepath)
	default:
		return nil, errors.New("either `keepassxc_master_password` or `keepassxc_keyfile_path` must be configured")
	}
}

type KPEntry struct {
	Path  []string
	Entry gokeepasslib.Entry
}

var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Look for KeePass Entry",
	Run:   searchMain,
}

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get Entry",
	Run:   getMain,
}

func searchMain(cmd *cobra.Command, args []string) {
	alf := runSearch(
		os.Getenv("keepassxc_db_path"),
		os.Getenv("keepassxc_keyfile_path"),
		strings.TrimSpace(os.Getenv("keepassxc_master_password")),
		args,
		parseCacheSeconds(os.Getenv("keepassxc_cache_seconds")),
	)
	s, _ := json.Marshal(alf)
	fmt.Println(string(s))
}

// parseCacheSeconds reads the result-cache window from its raw env value and
// clamps it to Alfred's allowed range. An empty or invalid value yields the
// default window.
func parseCacheSeconds(raw string) int {
	const def, min, max = 5, 5, 86400
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

// errorJSON renders err as a single, non-actionable Alfred item so the user
// sees what went wrong (e.g. a missing database or a wrong password) instead
// of the workflow silently breaking on an unparseable panic stack trace.
func errorJSON(err error) *AlfredJSON {
	alf := &AlfredJSON{}
	alf.Items = append(alf.Items, AlfredJSONItem{
		Uid:      "error",
		Title:    "⚠️ " + err.Error(),
		Subtitle: "alfred-keepass could not complete the request",
	})
	return alf
}

// runSearch resolves credentials, runs the search and converts any error into
// an Alfred error item. On success the result carries a cache window so Alfred
// can avoid re-decrypting the database for repeated identical queries; errors
// are never cached.
func runSearch(kbdxpath, keyfilepath, passwd string, query []string, cacheSeconds int) *AlfredJSON {
	cred, err := buildCredentials(passwd, keyfilepath)
	if err != nil {
		return errorJSON(err)
	}

	alf, err := search(kbdxpath, cred, query)
	if err != nil {
		return errorJSON(err)
	}
	alf.Cache = &AlfredCache{Seconds: cacheSeconds, LooseReload: true}
	return alf
}

// openDatabase opens and decodes the KeePass database at kbdxpath. The error
// from os.Open (e.g. a missing or unreadable database file) is no longer
// discarded so the caller can report it instead of crashing on a nil reader.
func openDatabase(kbdxpath string, cred *gokeepasslib.DBCredentials) (*gokeepasslib.Database, error) {
	file, err := os.Open(kbdxpath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer file.Close()

	return openKbdx(file, cred)
}

func search(kbdxpath string, cred *gokeepasslib.DBCredentials, query []string) (*AlfredJSON, error) {
	db, err := openDatabase(kbdxpath, cred)
	if err != nil {
		return nil, err
	}

	root := db.Content.Root
	result := []KPEntry{}
	scan(&root.Groups, []string{}, query, &result) // start recursive scan
	alf := readEntries(result, query)              // search
	alf.Variables.Query = strings.Join(query, " ")

	return alf, nil
}

func getMain(cmd *cobra.Command, args []string) {
	alf := runGet(
		os.Getenv("keepassxc_db_path"),
		os.Getenv("keepassxc_keyfile_path"),
		strings.TrimSpace(os.Getenv("keepassxc_master_password")),
		args,
	)
	s, _ := json.Marshal(alf)
	fmt.Println(string(s))
}

// runGet resolves credentials, builds the entry detail view and converts any
// error into an Alfred error item. The entry path is taken from the first
// argument; a missing argument is reported instead of panicking on args[0].
func runGet(kbdxpath, keyfilepath, passwd string, args []string) *AlfredJSON {
	if len(args) == 0 {
		return errorJSON(errors.New("no entry path given"))
	}

	cred, err := buildCredentials(passwd, keyfilepath)
	if err != nil {
		return errorJSON(err)
	}

	alf, err := get(kbdxpath, cred, args[0])
	if err != nil {
		return errorJSON(err)
	}
	return alf
}

// get builds the detail view for a single entry identified by entryPath.
// It returns an error when the database cannot be opened or the entry does
// not exist, rather than panicking.
func get(kbdxpath string, cred *gokeepasslib.DBCredentials, entryPath string) (*AlfredJSON, error) {
	db, err := openDatabase(kbdxpath, cred)
	if err != nil {
		return nil, err
	}

	root := db.Content.Root
	result := []KPEntry{}
	scan(&root.Groups, []string{}, nil, &result) // start recursive scan

	entry := getEntry(result, entryPath)
	if entry == nil {
		return nil, errors.Errorf("entry not found: %s", entryPath)
	}

	alf := &AlfredJSON{}
	alf.Items = append(alf.Items, AlfredJSONItem{
		Uid:      "0",
		Title:    "← Back",
		Subtitle: "Back to search",
		Arg:      "back",
	})
	if entry.Entry.GetContent("UserName") != "" {
		alf.Items = append(alf.Items, AlfredJSONItem{
			Uid:      "2",
			Title:    "👤 UserName",
			Subtitle: entry.Entry.GetContent("UserName"),
			Arg:      "username",
		})
	}
	if entry.Entry.GetContent("Password") != "" {
		alf.Items = append(alf.Items, AlfredJSONItem{
			Uid:      "3",
			Title:    "*️⃣ Password",
			Subtitle: "*****",
			Arg:      "password",
		})
	}
	if entry.Entry.GetContent("URL") != "" {
		alf.Items = append(alf.Items, AlfredJSONItem{
			Uid:      "4",
			Title:    "🌏 URL",
			Subtitle: entry.Entry.GetContent("URL"),
			Arg:      "url",
		})
	}
	if entry.Entry.GetContent("Notes") != "" {
		alf.Items = append(alf.Items, AlfredJSONItem{
			Uid:      "5",
			Title:    "📄 Notes",
			Subtitle: entry.Entry.GetContent("Notes"),
			Arg:      "notes",
		})
	}
	if entry.Entry.GetContent("otp") != "" {
		alf.Items = append(alf.Items, AlfredJSONItem{
			Uid:      "6",
			Title:    "🔐 TOTP",
			Subtitle: "Generate TOTP token",
			Arg:      "otp",
		})
		alf.Items = append(alf.Items, AlfredJSONItem{
			Uid:      "7",
			Title:    "🔐#️⃣ TOTP+Password",
			Subtitle: "Generate TOTP token + Password combined",
			Arg:      "otppass",
		})
	}
	for i, item := range entry.Entry.Values {
		switch item.Key {
		case "Title":
			fallthrough
		case "UserName":
			fallthrough
		case "Password":
			fallthrough
		case "URL":
			fallthrough
		case "Notes":
			fallthrough
		case "otp":
			continue
		default:
			alf.Items = append(alf.Items, AlfredJSONItem{
				Uid:      strconv.Itoa(i + 6),
				Title:    "☁️ " + item.Key,
				Subtitle: entry.Entry.GetContent(item.Key),
				Arg:      item.Key,
			})
		}
	}

	for i, item := range entry.Entry.Binaries {
		alf.Items = append(alf.Items, AlfredJSONItem{
			Uid:       strconv.Itoa(i + 100),
			Title:     fmt.Sprintf("📁 Attached File (%d)", i+1),
			Subtitle:  item.Name,
			Arg:       "_file",
			Variables: map[string]string{"filename": item.Name},
		})
	}

	return alf, nil
}

// readEntries scans all entries in []KPEntry for filtered result
func getEntry(kpe []KPEntry, path string) *KPEntry {
	for i, entry := range kpe {
		entryPath := strings.Join(kpe[i].Path[1:], "/") // remove the top-level (root) group from path
		if entryPath != path {
			continue
		}
		return &entry
	}
	return nil
}

// readEntries scans all entries in []KPEntry for filtered result
func readEntries(kpe []KPEntry, query []string) *AlfredJSON {
	alf := AlfredJSON{}
	for i, entry := range kpe {
		uuid, _ := entry.Entry.UUID.MarshalText()
		path := strings.Join(kpe[i].Path[1:], "/") // remove the top-level (root) group from path

		if !matchesQuery(path, query) {
			continue
		}

		item := AlfredJSONItem{
			Uid:      string(uuid),
			Title:    entry.Entry.GetTitle(),
			Subtitle: path,

			Mods: AlfredMods{
				Cmd:      AlfredModItem{Arg: path, Icon: &AlfredIcon{Path: "./icon-na.png"}},
				Alt:      AlfredModItem{Arg: path, Icon: &AlfredIcon{Path: "./icon-na.png"}},
				AltShift: AlfredModItem{Arg: path, Icon: &AlfredIcon{Path: "./icon-na.png"}},
				CmdAlt:   AlfredModItem{Arg: path, Icon: &AlfredIcon{Path: "./icon-na.png"}},
				Ctrl:     AlfredModItem{Arg: path, Valid: true},
			},

			Arg: path,
		}

		if entry.Entry.Times.Expires.Bool &&
			entry.Entry.Times.ExpiryTime != nil &&
			entry.Entry.Times.ExpiryTime.Time.Before(time.Now()) {
			item.Title = "🚫(Expired) " + item.Title
		}

		if entry.Entry.GetContent("UserName") != "" {
			item.Mods.Cmd.Valid = true
			item.Mods.Cmd.Icon = nil
		}
		if entry.Entry.GetContent("URL") != "" {
			item.Mods.Alt.Valid = true
			item.Mods.AltShift.Valid = true
			item.Mods.Alt.Icon = nil
			item.Mods.AltShift.Icon = nil
		}
		if entry.Entry.GetContent("Notes") != "" {
			item.Mods.CmdAlt.Icon = nil
			item.Mods.CmdAlt.Valid = true
		}

		alf.Items = append(alf.Items, item)
	}

	return &alf
}

// matchesQuery reports whether path contains every query term. Comparison is
// case-insensitive and both sides are normalized to Unicode NFC first, so a
// query typed in NFD (as macOS often produces) still matches an entry name
// stored in NFC, and vice versa.
func matchesQuery(path string, query []string) bool {
	p := norm.NFC.String(strings.ToLower(path))
	for _, q := range query {
		if !strings.Contains(p, norm.NFC.String(strings.ToLower(q))) {
			return false
		}
	}
	return true
}

// scan recursively reads KeePass groups and build an one dimensional slice for later search.
func scan(groups *[]gokeepasslib.Group, path []string, args []string, result *[]KPEntry) {
	for _, grp := range *groups {

		dup1 := make([]string, len(path))
		copy(dup1, path)
		dup1 = append(dup1, grp.Name)
		scan(&grp.Groups, dup1, args, result)

		if len(dup1) >= 2 {
			switch dup1[1] {
			case "Backup":
				fallthrough
			case "Recycle Bin":
				continue
			}
		}

		for _, ent := range grp.Entries {
			vd := ent.Get("Title")

			dup2 := make([]string, len(dup1))
			copy(dup2, dup1)
			dup2 = append(dup2, vd.Value.Content)

			*result = append(*result, KPEntry{
				Path:  dup2,
				Entry: ent,
			})
		}
	}
}
