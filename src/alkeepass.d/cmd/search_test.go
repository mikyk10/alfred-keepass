package cmd

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tobischo/gokeepasslib"
)

func TestKBDX(t *testing.T) {
	var alf *AlfredJSON

	cred := gokeepasslib.NewPasswordCredentials("Abc12345")

	alf = search(filepath.Join("testdata", "test.kdbx"), cred, []string{"Entry1"})
	assert.Equal(t, "Entry1", alf.Items[0].Title)
	assert.Equal(t, "Abc12345", alf.Items[0].Arg)
	assert.Equal(t, "root > entry1", alf.Items[0].Subtitle)
	assert.Equal(t, "https://test.test/Entry1", alf.Items[0].Mods.Alt.Arg)
	assert.Equal(t, "https://test.test/Entry1", alf.Items[0].Mods.Alt.Subtitle)
	assert.Equal(t, "username", alf.Items[0].Mods.Cmd.Arg)
	assert.Equal(t, "username", alf.Items[0].Mods.Cmd.Subtitle)
	assert.NotEmpty(t, alf.Items[0].Uid)

	alf = search(filepath.Join("testdata", "test.kdbx"), cred, []string{"Entry2"})
	assert.Equal(t, "Entry2", alf.Items[0].Title)
	assert.Equal(t, "Passwd", alf.Items[0].Arg)
	assert.Equal(t, "root > entry2", alf.Items[0].Subtitle)
	assert.Equal(t, "https://test.test/Entry2", alf.Items[0].Mods.Alt.Arg)
	assert.Equal(t, "https://test.test/Entry2", alf.Items[0].Mods.Alt.Subtitle)
	assert.Equal(t, "Entry2-User", alf.Items[0].Mods.Cmd.Arg)
	assert.Equal(t, "Entry2-User", alf.Items[0].Mods.Cmd.Subtitle)
	assert.NotEmpty(t, alf.Items[0].Uid)
}
