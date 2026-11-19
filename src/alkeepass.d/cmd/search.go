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
// discarding it. A YubiKey slot alone yields empty credentials, which
// addChallengeResponse completes with the YubiKey's response, and nothing at
// all an empty password, the only key a database can then have.
func buildCredentials(passwd, keyfilepath string, yubikeySlot int) (*gokeepasslib.DBCredentials, error) {
	switch {
	case passwd != "" && keyfilepath != "":
		return gokeepasslib.NewPasswordAndKeyCredentials(passwd, keyfilepath)
	case passwd != "":
		return gokeepasslib.NewPasswordCredentials(passwd), nil
	case keyfilepath != "":
		return gokeepasslib.NewKeyCredentials(keyfilepath)
	case yubikeySlot != 0:
		return &gokeepasslib.DBCredentials{}, nil
	default:
		return gokeepasslib.NewPasswordCredentials(""), nil
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
	s, _ := json.Marshal(runSearch(queryTerms(args)))
	fmt.Println(string(s))
}

// queryTerms splits the search arguments into individual terms on whitespace.
// Alfred passes the typed query as a single quoted argument (so that a "#tag"
// term is not eaten by the shell as a comment), so the whitespace splitting
// that the shell used to do is done here instead. It also tolerates already
// word-split argv, making the binary callable both ways.
func queryTerms(args []string) []string {
	return strings.Fields(strings.Join(args, " "))
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

// unlockAction is the kp_action value that routes an item's Enter to the
// workflow's unlock step instead of the copy actions.
const unlockAction = "unlock"

// lockedJSON renders the item shown instead of results while the keychain is
// locked. Its Enter carries arg (and kp_action, when set) to the next node;
// the modifier actions are disabled so they cannot copy anything.
func lockedJSON(arg, action string) *AlfredJSON {
	item := AlfredJSONItem{
		Uid:      "locked",
		Title:    "🔒 The keychain is locked",
		Subtitle: "Press Enter to unlock it, then search again",
		Arg:      arg,
	}
	if action != "" {
		item.Variables = map[string]string{"kp_action": action}
	} else {
		item.Subtitle = "Press Enter to go back to the search and unlock it there"
	}
	return &AlfredJSON{Items: []AlfredJSONItem{item}}
}

// runSearch opens the configured database, runs the search and converts any
// error into an Alfred error item, or into the locked item while the keychain
// is locked. On success the result carries a cache window so Alfred can avoid
// re-decrypting the database for repeated identical queries; errors are never
// cached.
func runSearch(query []string) *AlfredJSON {
	db, err := openConfiguredDatabase(false)
	switch {
	case errors.Is(err, errKeychainLocked):
		return lockedJSON(strings.Join(query, " "), unlockAction)
	case err != nil:
		return errorJSON(err)
	}
	alf := searchDatabase(db, query)
	alf.Cache = &AlfredCache{
		Seconds:     parseCacheSeconds(os.Getenv("keepassxc_cache_seconds")),
		LooseReload: true,
	}
	return alf
}

// searchDatabase lists the entries of db that match query.
func searchDatabase(db *gokeepasslib.Database, query []string) *AlfredJSON {
	result := []KPEntry{}
	scan(&db.Content.Root.Groups, []string{}, query, &result) // start recursive scan
	alf := readEntries(result, query)                         // search
	alf.Variables.Query = strings.Join(query, " ")
	return alf
}

func getMain(cmd *cobra.Command, args []string) {
	s, _ := json.Marshal(runGet(args))
	fmt.Println(string(s))
}

// runGet opens the configured database, builds the entry detail view and
// converts any error into an Alfred error item, or into the locked item while
// the keychain is locked. The entry path is taken from the first argument; a
// missing argument is reported instead of panicking on args[0].
func runGet(args []string) *AlfredJSON {
	if len(args) == 0 {
		return errorJSON(errors.New("no entry path given"))
	}
	db, err := openConfiguredDatabase(false)
	switch {
	case errors.Is(err, errKeychainLocked):
		return lockedJSON("back", "")
	case err != nil:
		return errorJSON(err)
	}
	alf, err := entryDetails(db, args[0])
	if err != nil {
		return errorJSON(err)
	}
	return alf
}

// entryDetails builds the detail view for the entry of db that ref refers to
// (see findEntry). It returns an error when there is no such entry.
func entryDetails(db *gokeepasslib.Database, ref string) (*AlfredJSON, error) {
	entry, err := findEntry(db, ref)
	if err != nil {
		return nil, err
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

// findEntry returns the entry of db that ref refers to: its UUID, which
// search results pass on, or its path, which then has to be unique.
func findEntry(db *gokeepasslib.Database, ref string) (*KPEntry, error) {
	entries := []KPEntry{}
	scan(&db.Content.Root.Groups, []string{}, nil, &entries)
	var found []KPEntry
	for _, entry := range entries {
		if entryRef(entry.Entry) == ref {
			return &entry, nil
		}
		if entryPath(entry) == ref {
			found = append(found, entry)
		}
	}
	switch len(found) {
	case 0:
		return nil, errors.Errorf("entry not found: %s", ref)
	case 1:
		return &found[0], nil
	}
	return nil, errors.Errorf("%d entries have the path %s: pick one in the search results instead", len(found), ref)
}

// entryRef returns what search results pass on to refer to entry: its UUID,
// which unlike its path is unique.
func entryRef(entry gokeepasslib.Entry) string {
	uuid, _ := entry.UUID.MarshalText()
	return string(uuid)
}

// entryPath returns the path of entry, i.e. its groups and title, without the
// top-level (root) group.
func entryPath(entry KPEntry) string {
	return strings.Join(entry.Path[1:], "/")
}

// readEntries scans all entries in []KPEntry for filtered result
func readEntries(kpe []KPEntry, query []string) *AlfredJSON {
	// Initialize Items to a non-nil slice so a query that matches nothing (which
	// is common for tag filters) marshals to "items": [] rather than null.
	alf := AlfredJSON{Items: []AlfredJSONItem{}}
	pathTerms, tagTerms := splitQuery(query)
	for _, entry := range kpe {
		ref := entryRef(entry.Entry)
		path := entryPath(entry)

		// Path terms filter on the entry path; "#" terms filter on its tags.
		if !matchesQuery(path, pathTerms) || !matchesQuery(entry.Entry.Tags, tagTerms) {
			continue
		}

		item := AlfredJSONItem{
			Uid:      ref,
			Title:    entry.Entry.GetTitle(),
			Subtitle: path,

			Mods: AlfredMods{
				Cmd:       AlfredModItem{Arg: ref, Icon: &AlfredIcon{Path: "./icon-na.png"}},
				Alt:       AlfredModItem{Arg: ref, Icon: &AlfredIcon{Path: "./icon-na.png"}},
				AltShift:  AlfredModItem{Arg: ref, Icon: &AlfredIcon{Path: "./icon-na.png"}},
				CmdAlt:    AlfredModItem{Arg: ref, Icon: &AlfredIcon{Path: "./icon-na.png"}},
				Ctrl:      AlfredModItem{Arg: ref, Valid: true},
				CtrlShift: AlfredModItem{Arg: ref, Icon: &AlfredIcon{Path: "./icon-na.png"}},
			},

			Arg: ref,
			// what Cmd+C copies and Cmd+L shows, instead of the UUID
			Text: &AlfredText{Copy: path, LargeType: path},
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
		if entry.Entry.GetContent("otp") != "" {
			item.Mods.CtrlShift.Icon = nil
			item.Mods.CtrlShift.Valid = true
			item.Mods.CtrlShift.Subtitle = "Copy TOTP token"
		}

		alf.Items = append(alf.Items, item)
	}

	return &alf
}

// splitQuery separates raw query terms into path terms and tag terms. A term
// prefixed with "#" filters on the entry's tags (the "#" is stripped before
// matching); a bare "#" carries no term and is ignored. Every other term
// filters on the entry path.
func splitQuery(query []string) (pathTerms, tagTerms []string) {
	for _, q := range query {
		if strings.HasPrefix(q, "#") {
			if t := strings.TrimPrefix(q, "#"); t != "" {
				tagTerms = append(tagTerms, t)
			}
			continue
		}
		pathTerms = append(pathTerms, q)
	}
	return pathTerms, tagTerms
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
