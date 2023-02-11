package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tobischo/gokeepasslib"
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

func searchMain(cmd *cobra.Command, args []string) {
	if v, err := cmd.Flags().GetBool("alfred"); err == nil && !v {
		panic("Must specify --alfred option.")
	}

	kbdxpath := viper.GetString("kdbx_path")
	encType := viper.GetString("encryption.type")
	var cred *gokeepasslib.DBCredentials
	switch encType {
	case "none":
	case "password":
		cred = gokeepasslib.NewPasswordCredentials(strings.TrimSpace(viper.GetString("encryption.secret")))
	case "key":
		cred, _ = gokeepasslib.NewKeyCredentials("")
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

	// Note: This is a simplified example and the groups and entries will depend on the specific file.
	// bound checking for the slices is recommended to avoid panics.
	root := db.Content.Root
	result := []KPEntry{}
	scan(root.Groups, []string{}, query, &result)
	alf := readEntries(result, query)

	return alf
}

func readEntries(kpe []KPEntry, query []string) *AlfredJSON {
	alf := AlfredJSON{}
	for i, item := range kpe {
		uuid, _ := item.Entry.UUID.MarshalText()
		path := strings.Join(kpe[i].Path, " > ")
		for j := range query {
			// AlfredからNFDで正規化された文字列が渡されるのでComposeし、英小文字に統一
			if !strings.Contains(path, norm.NFC.String(strings.ToLower(query[j]))) {
				goto cont
			}
		}

		alf.Items = append(alf.Items, AlfredJSONItem{
			Uid:      string(uuid),
			Title:    item.Entry.GetTitle(),
			Subtitle: path,

			Mods: AlfredMods{
				Alt: AlfredModItem{
					Arg:      item.Entry.GetContent("URL"),
					Subtitle: item.Entry.GetContent("URL"),
					Valid:    true,
				},
				Cmd: AlfredModItem{
					Arg:      item.Entry.GetContent("UserName"),
					Subtitle: item.Entry.GetContent("UserName"),
					Valid:    true,
				},
			},
			Arg: item.Entry.GetPassword(),
		})

	cont:
	}

	return &alf
}

func scan(g []gokeepasslib.Group, path []string, args []string, result *[]KPEntry) {
	for i := range g {
		dup1 := make([]string, len(path))
		copy(dup1, path)
		dup1 = append(dup1, strings.ToLower(g[i].Name))
		scan(g[i].Groups, dup1, args, result)

		if len(dup1) >= 2 {
			switch dup1[1] {
			case "backup":
				fallthrough
			case "recycle bin":
				return
			}
		}

		for j := range g[i].Entries {
			vd := g[i].Entries[j].Get("Title")

			dup2 := make([]string, len(dup1))
			copy(dup2, dup1)
			dup2 = append(dup2, strings.ToLower(vd.Value.Content))

			*result = append(*result, KPEntry{
				Path:  dup2,
				Entry: g[i].Entries[j],
			})
		}
	}
}
