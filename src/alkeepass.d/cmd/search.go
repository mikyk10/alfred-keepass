package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tobischo/gokeepasslib/v3"
	"golang.org/x/text/unicode/norm"
)

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
	kbdxpath := os.Getenv("keepassxc_db_path")
	keyfilepath := os.Getenv("keepassxc_keyfile_path")
	passwd := strings.TrimSpace(os.Getenv("keepassxc_master_password"))

	var cred *gokeepasslib.DBCredentials

	if passwd != "" {
		if keyfilepath != "" {
			// password and keyfile
			cred, _ = gokeepasslib.NewPasswordAndKeyCredentials(passwd, keyfilepath)
		} else {
			// password only
			cred = gokeepasslib.NewPasswordCredentials(passwd)
		}
	} else {
		if keyfilepath != "" {
			// keyfile only
			cred, _ = gokeepasslib.NewKeyCredentials(keyfilepath)
		} else {
			// all blank
			panic("Your must either configure `keepassxc_master_password` or `keepassxc_keyfile_path`")
		}
	}

	alf := search(kbdxpath, cred, args)
	s, _ := json.Marshal(alf)
	fmt.Println(string(s))
}

func search(kbdxpath string, cred *gokeepasslib.DBCredentials, query []string) *AlfredJSON {
	file, _ := os.Open(kbdxpath)
	defer file.Close()

	db, err := openKbdx(file, cred)
	if err != nil {
		panic(err)
	}

	root := db.Content.Root
	result := []KPEntry{}
	scan(root.Groups, []string{}, query, &result) // start recursive scan
	alf := readEntries(result, query)             // search
	alf.Variables.Query = strings.Join(query, " ")

	return alf
}

func getMain(cmd *cobra.Command, args []string) {
	kbdxpath := os.Getenv("keepassxc_db_path")
	keyfilepath := os.Getenv("keepassxc_keyfile_path")
	passwd := strings.TrimSpace(os.Getenv("keepassxc_master_password"))

	var cred *gokeepasslib.DBCredentials

	if passwd != "" {
		if keyfilepath != "" {
			// password and keyfile
			cred, _ = gokeepasslib.NewPasswordAndKeyCredentials(passwd, keyfilepath)
		} else {
			// password only
			cred = gokeepasslib.NewPasswordCredentials(passwd)
		}
	} else {
		if keyfilepath != "" {
			// keyfile only
			cred, _ = gokeepasslib.NewKeyCredentials(keyfilepath)
		} else {
			// all blank
			panic("Your must either configure `keepassxc_master_password` or `keepassxc_keyfile_path`")
		}
	}

	file, _ := os.Open(kbdxpath)
	defer file.Close()

	db, err := openKbdx(file, cred)
	if err != nil {
		panic(err)
	}

	path := args[0]
	root := db.Content.Root
	result := []KPEntry{}
	scan(root.Groups, []string{}, args, &result) // start recursive scan
	alf := AlfredJSON{}                          // search

	entry := getEntry(result, path)
	if entry == nil {
		panic("entry is nil")
	}
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

	s, _ := json.Marshal(alf)
	fmt.Println(string(s))
}

// readEntries scans all entries in []KPEntry for filtered result
func getEntry(kpe []KPEntry, path string) *KPEntry {
	for i, entry := range kpe {
		entryPath := strings.Join(kpe[i].Path, "/")[5:] // remove "Root/" from path
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
		path := strings.Join(kpe[i].Path, "/")[5:] // remove "Root/" from path

		var item AlfredJSONItem
		for j := range query {
			// Convert NFD normalized query string to NFC and compare 2 strings with lower case.
			if !strings.Contains(strings.ToLower(path), norm.NFC.String(strings.ToLower(query[j]))) {
				goto cont
			}
		}

		item = AlfredJSONItem{
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

	cont:
	}

	return &alf
}

// scan recursively reads KeePass groups and build an one dimensional slice for later search.
func scan(groups []gokeepasslib.Group, path []string, args []string, result *[]KPEntry) {
	for i := range groups {
		dup1 := make([]string, len(path))
		copy(dup1, path)
		dup1 = append(dup1, groups[i].Name)
		scan(groups[i].Groups, dup1, args, result)

		if len(dup1) >= 2 {
			switch dup1[1] {
			case "backup":
				fallthrough
			case "recycle bin":
				return
			}
		}

		for j := range groups[i].Entries {
			vd := groups[i].Entries[j].Get("Title")

			dup2 := make([]string, len(dup1))
			copy(dup2, dup1)
			dup2 = append(dup2, vd.Value.Content)

			*result = append(*result, KPEntry{
				Path:  dup2,
				Entry: groups[i].Entries[j],
			})
		}
	}
}
