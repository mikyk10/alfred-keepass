package cmd

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tobischo/gokeepasslib/v3"
)

func TestKBDX(t *testing.T) {
	var alf *AlfredJSON
	var err error

	cred := gokeepasslib.NewPasswordCredentials("Abc12345")

	// Entry1 lives directly under the top-level group and has UserName, URL and Notes.
	alf, err = search(filepath.Join("testdata", "test.kdbx"), cred, []string{"Entry1"})
	assert.NoError(t, err)
	assert.Equal(t, "Entry1", alf.Items[0].Title)
	// The top-level "Root" group must be stripped from the path (issue #1).
	assert.Equal(t, "Entry1", alf.Items[0].Subtitle)
	assert.Equal(t, "Entry1", alf.Items[0].Arg)
	assert.Equal(t, "Entry1", alf.Items[0].Mods.Cmd.Arg)
	assert.Equal(t, "Entry1", alf.Items[0].Mods.Alt.Arg)
	assert.True(t, alf.Items[0].Mods.Cmd.Valid)    // UserName present
	assert.True(t, alf.Items[0].Mods.Alt.Valid)    // URL present
	assert.True(t, alf.Items[0].Mods.CmdAlt.Valid) // Notes present
	assert.NotEmpty(t, alf.Items[0].Uid)

	// Entry2 has UserName and URL but no Notes.
	alf, err = search(filepath.Join("testdata", "test.kdbx"), cred, []string{"Entry2"})
	assert.NoError(t, err)
	assert.Equal(t, "Entry2", alf.Items[0].Title)
	assert.Equal(t, "Entry2", alf.Items[0].Subtitle)
	assert.Equal(t, "Entry2", alf.Items[0].Arg)
	assert.Equal(t, "Entry2", alf.Items[0].Mods.Cmd.Arg)
	assert.Equal(t, "Entry2", alf.Items[0].Mods.Alt.Arg)
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
	assert.Equal(t, "WithOTP", alf.Items[0].Mods.CtrlShift.Arg)
	assert.Nil(t, alf.Items[0].Mods.CtrlShift.Icon)
	assert.False(t, alf.Items[1].Mods.CtrlShift.Valid) // no TOTP
	assert.Equal(t, "NoOTP", alf.Items[1].Mods.CtrlShift.Arg)
}
