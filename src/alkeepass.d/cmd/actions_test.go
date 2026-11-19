package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tobischo/gokeepasslib/v3"
)

// testdata/actions.kdbx is a KDBX 4 database (password "Abc12345") built with
// gokeepasslib. Its "Example" entry has the standard attributes, an otp
// attribute, a "Recovery Code" attribute and the attachments hello.txt,
// token.txt and bytes.bin; the "TOTP" group holds entries with other TOTP
// settings. keepassxc-cli shows and exports the same values.

func TestFindAttribute(t *testing.T) {
	entry := gokeepasslib.NewEntry()
	for _, kv := range [][2]string{
		{"Title", "Example"},
		{"Password", "secret"},
		{"URL", "https://example.com"},
		{"Recovery Code", "1234-5678"},
		{"Email", "alice@example.com"},
		{"EMAIL", "ALICE@EXAMPLE.COM"},
		{"Empty", ""},
	} {
		entry.Values = append(entry.Values, gokeepasslib.ValueData{Key: kv[0], Value: gokeepasslib.V{Content: kv[1]}})
	}
	find := func(name string) (string, error) { return findAttribute(&entry, name) }

	t.Run("exact match", func(t *testing.T) {
		v, err := find("Recovery Code")
		assert.NoError(t, err)
		assert.Equal(t, "1234-5678", v)
	})

	t.Run("the workflow's lowercase names match case-insensitively", func(t *testing.T) {
		for name, want := range map[string]string{"password": "secret", "url": "https://example.com", "title": "Example"} {
			v, err := find(name)
			assert.NoError(t, err, name)
			assert.Equal(t, want, v, name)
		}
	})

	t.Run("an exact match wins over case-insensitive ones", func(t *testing.T) {
		v, err := find("EMAIL")
		assert.NoError(t, err)
		assert.Equal(t, "ALICE@EXAMPLE.COM", v)
	})

	t.Run("an ambiguous name is an error", func(t *testing.T) {
		_, err := find("email")
		assert.ErrorContains(t, err, "ambiguous")
	})

	t.Run("an unknown name is an error", func(t *testing.T) {
		_, err := find("Security Question")
		assert.ErrorContains(t, err, "unknown attribute")
	})

	t.Run("an empty value is found", func(t *testing.T) {
		v, err := find("Empty")
		assert.NoError(t, err)
		assert.Equal(t, "", v)
	})

	t.Run("a missing standard attribute reads as empty, as in keepassxc-cli", func(t *testing.T) {
		for _, name := range []string{"Notes", "username"} {
			v, err := find(name)
			assert.NoError(t, err, name)
			assert.Equal(t, "", v, name)
		}
	})
}

func TestOpenEntry(t *testing.T) {
	dbPath := filepath.Join("testdata", "actions.kdbx")

	t.Run("top-level entry", func(t *testing.T) {
		_, entry, err := openEntry(dbPath, "", "Abc12345", 0, "Example")
		if assert.NoError(t, err) {
			v, err := findAttribute(entry, "password")
			assert.NoError(t, err)
			assert.Equal(t, "Abc12345!", v) // protected values are unlocked
		}
	})

	t.Run("entry in a group", func(t *testing.T) {
		_, entry, err := openEntry(dbPath, "", "Abc12345", 0, "TOTP/SHA256")
		if assert.NoError(t, err) {
			assert.Equal(t, "SHA256", entry.GetTitle())
		}
	})

	t.Run("the path does not include the root group", func(t *testing.T) {
		_, _, err := openEntry(dbPath, "", "Abc12345", 0, "Root/Example")
		assert.ErrorContains(t, err, "entry not found")
	})

	t.Run("wrong password", func(t *testing.T) {
		_, _, err := openEntry(dbPath, "", "wrong", 0, "Example")
		assert.Error(t, err)
	})

	t.Run("a configured key file is used", func(t *testing.T) {
		// The fixture has no key file, so adding one makes the key wrong.
		keyfile := filepath.Join(t.TempDir(), "test.key")
		if err := os.WriteFile(keyfile, make([]byte, 32), 0600); err != nil {
			t.Fatal(err)
		}
		_, _, err := openEntry(dbPath, keyfile, "Abc12345", 0, "Example")
		assert.Error(t, err)
	})

	t.Run("no credentials", func(t *testing.T) {
		_, _, err := openEntry(dbPath, "", "", 0, "Example")
		assert.ErrorContains(t, err, "Wrong password")
	})
}

func TestExportAttachment(t *testing.T) {
	db, entry, err := openEntry(filepath.Join("testdata", "actions.kdbx"), "", "Abc12345", 0, "Example")
	if !assert.NoError(t, err) {
		return
	}
	allBytes := make([]byte, 256)
	for i := range allBytes {
		allBytes[i] = byte(i)
	}
	dir := t.TempDir()

	for name, want := range map[string][]byte{
		"hello.txt": []byte("Hello, KeePass!\n"),
		// valid base64, which Binary.GetContentBytes would decode to "Abc12345"
		"token.txt": []byte("QWJjMTIzNDU="),
		"bytes.bin": allBytes,
	} {
		path := filepath.Join(dir, name)
		if assert.NoError(t, exportAttachment(db, entry, name, path), name) {
			got, err := os.ReadFile(path)
			assert.NoError(t, err, name)
			assert.Equal(t, want, got, name)
		}
	}

	t.Run("an existing file is replaced", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hello.txt")
		if err := os.WriteFile(path, []byte("a longer file that is already there\n"), 0600); err != nil {
			t.Fatal(err)
		}
		assert.NoError(t, exportAttachment(db, entry, "hello.txt", path))
		got, _ := os.ReadFile(path)
		assert.Equal(t, "Hello, KeePass!\n", string(got))
	})

	t.Run("a name that is not a plain file name is refused", func(t *testing.T) {
		db := gokeepasslib.NewDatabase()
		entry := gokeepasslib.NewEntry()
		dir := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(dir, "Downloads"), 0700))
		for _, name := range []string{"../escaped.txt", "a/b.txt", "..", ".", "", "nul\x00.txt"} {
			entry.Binaries = append(entry.Binaries, db.AddBinary([]byte("data")).CreateReference(name))
			// as the workflow builds the path, from a directory and the name
			path := filepath.Join(dir, "Downloads") + "/" + name
			assert.ErrorContains(t, exportAttachment(db, &entry, name, path), "not a plain file name", "%q", name)
		}
		assert.NoFileExists(t, filepath.Join(dir, "escaped.txt"))
	})

	t.Run("a missing attachment is an error and writes nothing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.txt")
		assert.ErrorContains(t, exportAttachment(db, entry, "missing.txt", path), "attachment not found")
		assert.NoFileExists(t, path)
	})

	t.Run("KDBX 3.1 attachments are decoded", func(t *testing.T) {
		// KDBX 3.1 keeps attachments base64-encoded and compressed in the
		// metadata.
		db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion3())
		entry := gokeepasslib.NewEntry()
		entry.Binaries = append(entry.Binaries, db.AddBinary([]byte("QWJjMTIzNDU=")).CreateReference("token.txt"))
		path := filepath.Join(t.TempDir(), "token.txt")
		if assert.NoError(t, exportAttachment(db, &entry, "token.txt", path)) {
			got, _ := os.ReadFile(path)
			assert.Equal(t, "QWJjMTIzNDU=", string(got))
		}
	})
}

func TestSelectedValue(t *testing.T) {
	dbPath := filepath.Join("testdata", "actions.kdbx")
	useWorkflow(t, dbPath, "Abc12345", nil)
	_, example, err := openEntry(dbPath, "", "Abc12345", 0, "Example")
	require.NoError(t, err)
	value := func(flags ...string) (string, error) {
		cmd := &cobra.Command{}
		addValueFlags(cmd)
		require.NoError(t, cmd.ParseFlags(flags))
		return selectedValue(cmd, "Example")
	}
	// totps returns the TOTPs of the Example entry from before to now.
	totps := func(before time.Time) []string {
		var codes []string
		for _, at := range []time.Time{before, time.Now()} {
			code, err := entryTOTP(example, at)
			require.NoError(t, err)
			codes = append(codes, code)
		}
		return codes
	}

	t.Run("the password by default", func(t *testing.T) {
		v, err := value()
		assert.NoError(t, err)
		assert.Equal(t, "Abc12345!", v)
	})

	t.Run("the TOTP", func(t *testing.T) {
		before := time.Now()
		v, err := value("--totp")
		assert.NoError(t, err)
		assert.Contains(t, totps(before), v)
	})

	t.Run("the TOTP in front of the password", func(t *testing.T) {
		before := time.Now()
		v, err := value("--prepend-totp")
		require.NoError(t, err)
		otp, ok := strings.CutSuffix(v, "Abc12345!")
		require.True(t, ok, v)
		assert.Contains(t, totps(before), otp)
	})

	t.Run("--totp takes no other flag", func(t *testing.T) {
		_, err := value("--totp", "--prepend-totp")
		assert.ErrorContains(t, err, "--totp takes")
		_, err = value("--totp", "-a", "URL")
		assert.ErrorContains(t, err, "--totp takes")
	})
}

func TestAlfredOutput(t *testing.T) {
	assert.JSONEq(t, `{"alfredworkflow": {"arg": "a\"b\\c", "variables": {"kp_error": ""}}}`,
		string(alfredOutput(`a"b\c`, nil)))
	assert.JSONEq(t, `{"alfredworkflow": {"arg": "", "variables": {"kp_error": "the YubiKey was not touched in time"}}}`,
		string(alfredOutput("", errors.New("the YubiKey was not touched in time"))))
}
