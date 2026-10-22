package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSecurityPassword(t *testing.T) {
	t.Run("quoted printable password", func(t *testing.T) {
		p, err := parseSecurityPassword("password: \"Abc 123\"\n")
		assert.NoError(t, err)
		assert.Equal(t, "Abc 123", p)
	})

	t.Run("quotes inside the password are kept", func(t *testing.T) {
		p, err := parseSecurityPassword(`password: "a"b"` + "\n")
		assert.NoError(t, err)
		assert.Equal(t, `a"b`, p)
	})

	t.Run("hex encoded non-ASCII password", func(t *testing.T) {
		// "pä" in UTF-8
		p, err := parseSecurityPassword("password: 0x70C3A4  \"p\\303\\244\"\n")
		assert.NoError(t, err)
		assert.Equal(t, "pä", p)
	})

	t.Run("password line among other output", func(t *testing.T) {
		p, err := parseSecurityPassword("keychain: \"login.keychain-db\"\npassword: \"x\"\n")
		assert.NoError(t, err)
		assert.Equal(t, "x", p)
	})

	t.Run("no password line", func(t *testing.T) {
		_, err := parseSecurityPassword("something else\n")
		assert.Error(t, err)
	})
}

func TestParseKeychainList(t *testing.T) {
	out := "    \"/Users/u/Library/Keychains/login.keychain-db\"\n    \"/Users/u/Library/Keychains/alfred-keepass.keychain-db\"\n"
	assert.Equal(t, []string{
		"/Users/u/Library/Keychains/login.keychain-db",
		"/Users/u/Library/Keychains/alfred-keepass.keychain-db",
	}, parseKeychainList(out))
	assert.Empty(t, parseKeychainList(""))
}

// TestKeychainRoundTrip uses the real security(1), so it only runs when
// ALKEEPASS_KEYCHAIN_TEST=1. It works on a throwaway keychain, leaving the
// login keychain and the workflow's own keychain untouched.
func TestKeychainRoundTrip(t *testing.T) {
	if os.Getenv("ALKEEPASS_KEYCHAIN_TEST") != "1" {
		t.Skip("set ALKEEPASS_KEYCHAIN_TEST=1 to run against a temporary keychain")
	}
	const service = "alfred-keepass-test"
	kc := filepath.Join(t.TempDir(), "test.keychain-db")

	p, err := readKeychainItem(kc, service)
	assert.NoError(t, err)
	assert.Equal(t, "", p, "a missing keychain reads as empty")

	if err := runSecurity("create-keychain", "-p", "test", kc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { exec.Command(securityPath, "delete-keychain", kc).Run() })
	assert.NoError(t, removeFromSearchList(kc))
	out, _ := exec.Command(securityPath, "list-keychains", "-d", "user").Output()
	for _, p := range parseKeychainList(string(out)) {
		assert.NotEqual(t, resolvePath(kc), resolvePath(p))
	}

	p, err = readKeychainItem(kc, service)
	assert.NoError(t, err)
	assert.Equal(t, "", p, "a missing item reads as empty")

	for _, passwd := range []string{"Abc12345", `a"b\c d`, "日本語 pass", "-U -s x"} {
		assert.NoError(t, writeKeychainItem(kc, service, passwd))
		got, err := readKeychainItem(kc, service)
		assert.NoError(t, err)
		assert.Equal(t, passwd, got)
	}
}
