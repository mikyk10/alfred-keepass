package cmd

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tobischo/gokeepasslib/v3"
	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

func TestKBDX(t *testing.T) {
	var alf *AlfredJSON
	var err error

	cred := gokeepasslib.NewPasswordCredentials("Abc12345")

	// Entry1 lives directly under the top-level group and has UserName, URL and Notes.
	alf, err = search(filepath.Join("testdata", "test.kdbx"), cred, 0, []string{"Entry1"})
	assert.NoError(t, err)
	assert.Equal(t, "Entry1", alf.Items[0].Title)
	// The top-level "Root" group must be stripped from the path (issue #1).
	assert.Equal(t, "Entry1", alf.Items[0].Subtitle)
	// The actions get the UUID of the entry, which unlike its path is unique.
	assert.Len(t, alf.Items[0].Uid, 24)
	assert.Equal(t, alf.Items[0].Uid, alf.Items[0].Arg)
	assert.Equal(t, alf.Items[0].Uid, alf.Items[0].Mods.Cmd.Arg)
	assert.Equal(t, alf.Items[0].Uid, alf.Items[0].Mods.Alt.Arg)
	assert.Equal(t, &AlfredText{Copy: "Entry1", LargeType: "Entry1"}, alf.Items[0].Text)
	assert.True(t, alf.Items[0].Mods.Cmd.Valid)    // UserName present
	assert.True(t, alf.Items[0].Mods.Alt.Valid)    // URL present
	assert.True(t, alf.Items[0].Mods.CmdAlt.Valid) // Notes present
	assert.NotEmpty(t, alf.Items[0].Uid)

	// Entry2 has UserName and URL but no Notes.
	alf, err = search(filepath.Join("testdata", "test.kdbx"), cred, 0, []string{"Entry2"})
	assert.NoError(t, err)
	assert.Equal(t, "Entry2", alf.Items[0].Title)
	assert.Equal(t, "Entry2", alf.Items[0].Subtitle)
	assert.Equal(t, alf.Items[0].Uid, alf.Items[0].Arg)
	assert.Equal(t, alf.Items[0].Uid, alf.Items[0].Mods.Cmd.Arg)
	assert.Equal(t, alf.Items[0].Uid, alf.Items[0].Mods.Alt.Arg)
	assert.True(t, alf.Items[0].Mods.Cmd.Valid)     // UserName present
	assert.True(t, alf.Items[0].Mods.Alt.Valid)     // URL present
	assert.False(t, alf.Items[0].Mods.CmdAlt.Valid) // no Notes
	assert.NotEmpty(t, alf.Items[0].Uid)
}

func TestCtrlShiftTOTPMod(t *testing.T) {
	withOTP := gokeepasslib.NewEntry()
	withOTP.Values = append(withOTP.Values,
		gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "WithOTP"}},
		gokeepasslib.ValueData{Key: "otp", Value: gokeepasslib.V{Content: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"}},
	)
	withoutOTP := gokeepasslib.NewEntry()
	withoutOTP.Values = append(withoutOTP.Values,
		gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "NoOTP"}},
	)

	alf := readEntries([]KPEntry{
		{Path: []string{"Root", "WithOTP"}, Entry: withOTP},
		{Path: []string{"Root", "NoOTP"}, Entry: withoutOTP},
	}, nil)

	assert.Len(t, alf.Items, 2)
	assert.True(t, alf.Items[0].Mods.CtrlShift.Valid) // TOTP present
	assert.Equal(t, entryRef(withOTP), alf.Items[0].Mods.CtrlShift.Arg)
	assert.Nil(t, alf.Items[0].Mods.CtrlShift.Icon)
	assert.False(t, alf.Items[1].Mods.CtrlShift.Valid) // no TOTP
	assert.Equal(t, entryRef(withoutOTP), alf.Items[1].Mods.CtrlShift.Arg)
}

func TestFindEntry(t *testing.T) {
	newEntry := func(title string) gokeepasslib.Entry {
		e := gokeepasslib.NewEntry()
		e.Values = append(e.Values, gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: title}})
		return e
	}
	first, second, other := newEntry("Google"), newEntry("Google"), newEntry("Google")
	group := gokeepasslib.NewGroup()
	group.Name = "Personal"
	group.Entries = []gokeepasslib.Entry{first, second}
	work := gokeepasslib.NewGroup()
	work.Name = "Work"
	work.Entries = []gokeepasslib.Entry{other}
	root := gokeepasslib.NewGroup()
	root.Name = "Root"
	root.Groups = []gokeepasslib.Group{group, work}
	db := gokeepasslib.NewDatabase()
	db.Content.Root = &gokeepasslib.RootData{Groups: []gokeepasslib.Group{root}}

	t.Run("by UUID", func(t *testing.T) {
		for _, e := range []gokeepasslib.Entry{first, second, other} {
			found, err := findEntry(db, entryRef(e))
			if assert.NoError(t, err) {
				assert.Equal(t, e.UUID, found.Entry.UUID)
			}
		}
	})

	t.Run("by a unique path", func(t *testing.T) {
		found, err := findEntry(db, "Work/Google")
		if assert.NoError(t, err) {
			assert.Equal(t, other.UUID, found.Entry.UUID)
		}
	})

	t.Run("a path that is not unique", func(t *testing.T) {
		_, err := findEntry(db, "Personal/Google")
		assert.ErrorContains(t, err, "2 entries have the path Personal/Google")
	})

	t.Run("no such entry", func(t *testing.T) {
		_, err := findEntry(db, "Personal/Gmail")
		assert.ErrorContains(t, err, "entry not found")
	})
}

func TestEntryDetailsMaskProtectedValues(t *testing.T) {
	entry := gokeepasslib.NewEntry()
	for _, v := range []struct {
		key, value string
		protected  bool
	}{
		{"Title", "Example", false},
		{"UserName", "alice", false},
		{"Password", "secret", true},
		{"Notes", "protected notes", true},
		{"Recovery Code", "1234-5678", true},
		{"Email", "alice@example.com", false},
	} {
		entry.Values = append(entry.Values, gokeepasslib.ValueData{
			Key:   v.key,
			Value: gokeepasslib.V{Content: v.value, Protected: w.NewBoolWrapper(v.protected)},
		})
	}
	root := gokeepasslib.NewGroup()
	root.Name = "Root"
	root.Entries = []gokeepasslib.Entry{entry}
	db := gokeepasslib.NewDatabase()
	db.Content.Root = &gokeepasslib.RootData{Groups: []gokeepasslib.Group{root}}

	alf, err := entryDetails(db, entryRef(entry))
	if !assert.NoError(t, err) {
		return
	}
	shown := map[string]string{}
	for _, item := range alf.Items {
		shown[item.Arg] = item.Subtitle
	}
	assert.Equal(t, "alice", shown["username"])
	assert.Equal(t, "*****", shown["password"])
	assert.Equal(t, "*****", shown["notes"])
	assert.Equal(t, "*****", shown["Recovery Code"])
	assert.Equal(t, "alice@example.com", shown["Email"])

	t.Run("protection survives opening the database", func(t *testing.T) {
		useWorkflow(t, filepath.Join("testdata", "actions.kdbx"), "Abc12345", nil)
		for _, item := range runGet([]string{"Example"}).Items {
			if item.Arg == "Recovery Code" {
				assert.Equal(t, "*****", item.Subtitle)
				return
			}
		}
		t.Error("no Recovery Code item")
	})
}
