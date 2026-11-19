package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tobischo/gokeepasslib/v3"
)

func TestBuildCredentials(t *testing.T) {
	// A raw 32-byte key file is accepted by gokeepasslib as-is.
	keyfile := filepath.Join(t.TempDir(), "test.key")
	if err := os.WriteFile(keyfile, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}

	t.Run("password only", func(t *testing.T) {
		cred, err := buildCredentials("Abc12345", "", 0)
		assert.NoError(t, err)
		assert.NotNil(t, cred)
		assert.NotEmpty(t, cred.Passphrase)
	})

	t.Run("keyfile only", func(t *testing.T) {
		cred, err := buildCredentials("", keyfile, 0)
		assert.NoError(t, err)
		assert.NotNil(t, cred)
		assert.NotEmpty(t, cred.Key)
	})

	t.Run("password and keyfile", func(t *testing.T) {
		cred, err := buildCredentials("Abc12345", keyfile, 0)
		assert.NoError(t, err)
		assert.NotNil(t, cred)
		assert.NotEmpty(t, cred.Passphrase)
		assert.NotEmpty(t, cred.Key)
	})

	t.Run("nothing configured is an empty password", func(t *testing.T) {
		cred, err := buildCredentials("", "", 0)
		assert.NoError(t, err)
		assert.Equal(t, gokeepasslib.NewPasswordCredentials(""), cred)
	})

	t.Run("missing keyfile error is propagated", func(t *testing.T) {
		cred, err := buildCredentials("", filepath.Join(t.TempDir(), "does-not-exist.key"), 0)
		assert.Error(t, err)
		assert.Nil(t, cred)
	})
}
