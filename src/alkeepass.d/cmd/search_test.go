package cmd

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tobischo/gokeepasslib/v3"
)

func TestKBDX(t *testing.T) {
	var alf *AlfredJSON

	cred := gokeepasslib.NewPasswordCredentials("Abc12345")

	// Entry1 lives directly under the top-level group and has UserName, URL and Notes.
	alf = search(filepath.Join("testdata", "test.kdbx"), cred, []string{"Entry1"})
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
	alf = search(filepath.Join("testdata", "test.kdbx"), cred, []string{"Entry2"})
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
