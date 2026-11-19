package cmd

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tobischo/gokeepasslib/v3"
)

// fakeYubiKey emulates the OTP application of a YubiKey whose slots hold
// the given HMAC-SHA1 secrets.
type fakeYubiKey struct {
	secrets map[int][]byte
	sw      uint16 // if set, the status word every HMAC command fails with
	chunk   int    // if set, response data is returned in parts of this size
	resets  int    // number of HMAC commands failing because of a card reset
	// if set, called for every HMAC command, as while the user touches it
	onChallenge func()

	challenges int // number of HMAC commands answered
	selected   bool
	pending    []byte
}

func (k *fakeYubiKey) transmit(apdu []byte) ([]byte, error) {
	switch {
	case apdu[1] == insSelect:
		k.selected = bytes.Equal(apdu[5:], otpAID)
		if !k.selected {
			return statusWord(0x6A82), nil
		}
		return append([]byte{5, 7, 2}, statusWord(swOK)...), nil
	case apdu[1] == insGetResponse:
		return k.nextPart(), nil
	case apdu[1] == insOTP && k.selected:
		if k.resets > 0 {
			k.resets--
			k.selected = false
			return nil, errCardReset
		}
		if k.sw != 0 {
			return statusWord(k.sw), nil
		}
		slot := map[byte]int{0x30: 1, 0x38: 2}[apdu[2]]
		secret, ok := k.secrets[slot]
		if !ok {
			// a slot not set up for challenge-response answers no data
			return statusWord(swOK), nil
		}
		if k.onChallenge != nil {
			k.onChallenge()
		}
		k.challenges++
		k.pending = yubikeyHMAC(secret, apdu[5:])
		return k.nextPart(), nil
	}
	return statusWord(0x6D00), nil
}

// nextPart returns the pending response data, or the next part of it
// followed by 61xx when it is returned in parts.
func (k *fakeYubiKey) nextPart() []byte {
	if k.chunk == 0 || len(k.pending) <= k.chunk {
		part := append(k.pending, statusWord(swOK)...)
		k.pending = nil
		return part
	}
	part := append([]byte{}, k.pending[:k.chunk]...)
	k.pending = k.pending[k.chunk:]
	return append(part, swMoreDataPending, byte(len(k.pending)))
}

func (k *fakeYubiKey) close() { k.selected = false }

// yubikeyHMAC computes the response of a slot configured for variable length
// challenges: it takes the trailing bytes equal to the last one of the 64
// byte challenge as padding.
func yubikeyHMAC(secret, challenge []byte) []byte {
	n := len(challenge)
	for n > 0 && challenge[n-1] == challenge[len(challenge)-1] {
		n--
	}
	mac := hmac.New(sha1.New, secret)
	mac.Write(challenge[:n])
	return mac.Sum(nil)
}

func statusWord(sw uint16) []byte {
	return binary.BigEndian.AppendUint16(nil, sw)
}

// otherCard is a smart card without the OTP application.
type otherCard struct{}

func (otherCard) transmit([]byte) ([]byte, error) { return statusWord(0x6A82), nil }
func (otherCard) close()                          {}

// fakeReaders maps reader names to their cards; nil is an empty reader.
type fakeReaders map[string]smartCard

func (r fakeReaders) list() ([]string, error) {
	var names []string
	for name := range r {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (r fakeReaders) connect(reader string) (smartCard, error) {
	if r[reader] == nil {
		return nil, errNoCard
	}
	return r[reader], nil
}

func (r fakeReaders) close() {}

// useReaders makes challengeYubiKey see readers instead of the real ones.
func useReaders(t *testing.T, readers cardReaders) {
	orig := openCardReaders
	openCardReaders = func() (cardReaders, error) { return readers, nil }
	t.Cleanup(func() { openCardReaders = orig })
}

// resettingReaders are readers whose card is reset by another process while
// connecting to it, the given number of times.
type resettingReaders struct {
	fakeReaders
	resets int
}

func (r *resettingReaders) connect(reader string) (smartCard, error) {
	if r.resets > 0 {
		r.resets--
		return nil, errCardReset
	}
	return r.fakeReaders.connect(reader)
}

var testSecret = []byte("0123456789abcdefghij")

func TestHMACAPDU(t *testing.T) {
	t.Run("challenge is padded to 64 bytes like KeePassXC does", func(t *testing.T) {
		apdu, err := hmacAPDU(2, bytes.Repeat([]byte{0xAB}, 32))
		require.NoError(t, err)
		assert.Equal(t, []byte{0x00, 0x01, 0x38, 0x00, 64}, apdu[:5])
		assert.Equal(t, bytes.Repeat([]byte{0xAB}, 32), apdu[5:37])
		assert.Equal(t, bytes.Repeat([]byte{32}, 32), apdu[37:])
	})

	t.Run("64 byte challenge is sent as is", func(t *testing.T) {
		challenge := bytes.Repeat([]byte{0xCD}, 64)
		apdu, err := hmacAPDU(1, challenge)
		require.NoError(t, err)
		assert.Equal(t, byte(0x30), apdu[2])
		assert.Equal(t, challenge, apdu[5:])
	})

	t.Run("invalid input", func(t *testing.T) {
		_, err := hmacAPDU(3, []byte{1})
		assert.Error(t, err)
		_, err = hmacAPDU(1, make([]byte, 65))
		assert.Error(t, err)
	})
}

func TestChallengeYubiKey(t *testing.T) {
	challenge := bytes.Repeat([]byte{0x5A}, 32)
	mac := hmac.New(sha1.New, testSecret)
	mac.Write(challenge)
	want := mac.Sum(nil)

	t.Run("skips empty readers and other cards", func(t *testing.T) {
		useReaders(t, fakeReaders{
			"A NFC reader":    nil,
			"B other card":    otherCard{},
			"C YubiKey":       &fakeYubiKey{secrets: map[int][]byte{2: testSecret}},
			"D unused reader": nil,
		})
		got, err := challengeYubiKey(2, challenge)
		assert.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("response returned in parts", func(t *testing.T) {
		useReaders(t, fakeReaders{"YubiKey": &fakeYubiKey{secrets: map[int][]byte{1: testSecret}, chunk: 8}})
		got, err := challengeYubiKey(1, challenge)
		assert.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("connects again after a card reset", func(t *testing.T) {
		useReaders(t, fakeReaders{"YubiKey": &fakeYubiKey{secrets: map[int][]byte{1: testSecret}, resets: 1}})
		got, err := challengeYubiKey(1, challenge)
		assert.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("connects again after a card reset while connecting", func(t *testing.T) {
		readers := &resettingReaders{fakeReaders{"YubiKey": &fakeYubiKey{secrets: map[int][]byte{1: testSecret}}}, 1}
		useReaders(t, readers)
		got, err := challengeYubiKey(1, challenge)
		assert.NoError(t, err)
		assert.Equal(t, want, got)

		readers.resets = 2
		_, err = challengeYubiKey(1, challenge)
		assert.ErrorIs(t, err, errCardReset, "but only once")
	})

	t.Run("no YubiKey", func(t *testing.T) {
		useReaders(t, fakeReaders{"NFC reader": nil, "other card": otherCard{}})
		_, err := challengeYubiKey(1, challenge)
		assert.ErrorIs(t, err, errNoYubiKey)

		useReaders(t, fakeReaders{})
		_, err = challengeYubiKey(1, challenge)
		assert.ErrorIs(t, err, errNoYubiKey)
	})

	t.Run("slot without challenge-response", func(t *testing.T) {
		useReaders(t, fakeReaders{"YubiKey": &fakeYubiKey{secrets: map[int][]byte{2: testSecret}}})
		_, err := challengeYubiKey(1, challenge)
		assert.ErrorContains(t, err, "slot 1 is not configured")
	})

	t.Run("not touched in time", func(t *testing.T) {
		useReaders(t, fakeReaders{"YubiKey": &fakeYubiKey{sw: swNotTouched}})
		_, err := challengeYubiKey(1, challenge)
		assert.ErrorContains(t, err, "not touched")
	})

	t.Run("other failure", func(t *testing.T) {
		useReaders(t, fakeReaders{"YubiKey": &fakeYubiKey{sw: 0x6F00}})
		_, err := challengeYubiKey(1, challenge)
		assert.ErrorContains(t, err, "6F00")
	})
}

// writeYubiKeyDatabase writes a KDBX 4 database holding an entry "Entry1",
// protected like KeePassXC protects it with password (if not empty) and the
// challenge-response of a YubiKey slot programmed with secret.
func writeYubiKeyDatabase(t *testing.T, password string, secret []byte) string {
	var passphrase []byte
	if password != "" {
		passphrase = gokeepasslib.NewPasswordCredentials(password).Passphrase
	}
	return writeTestDatabase(t, passphrase, secret)
}

// writeTestDatabase writes a KDBX 4 database holding an entry "Entry1",
// protected with passphrase (a hashed password, if not nil) and, if secret is
// not nil, the challenge-response of a YubiKey slot programmed with it.
func writeTestDatabase(t *testing.T, passphrase, secret []byte) string {
	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion4())
	db.Credentials = &gokeepasslib.DBCredentials{Passphrase: passphrase}

	if secret != nil {
		// The challenge is the seed of the key derivation, and the composite
		// key is SHA-256(SHA-256(password) || SHA-256(response)).
		params := db.Header.FileHeaders.KdfParameters
		for i := range params.Salt {
			params.Salt[i] = byte(0xA0 + i)
		}
		mac := hmac.New(sha1.New, secret)
		mac.Write(params.Salt[:])
		response := sha256.Sum256(mac.Sum(nil))
		db.Credentials.Windows = response[:]
	}

	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "Entry1"}})
	root := gokeepasslib.NewGroup()
	root.Name = "Root"
	root.Entries = append(root.Entries, entry)
	db.Content.Root = &gokeepasslib.RootData{Groups: []gokeepasslib.Group{root}}
	require.NoError(t, db.LockProtectedEntries())

	var buf bytes.Buffer
	require.NoError(t, gokeepasslib.NewEncoder(&buf).Encode(db))
	path := filepath.Join(t.TempDir(), "yubikey.kdbx")
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0600))
	return path
}

func TestOpenDatabaseWithYubiKey(t *testing.T) {
	dbPath := writeYubiKeyDatabase(t, "Abc12345", testSecret)
	password := gokeepasslib.NewPasswordCredentials("Abc12345")

	t.Run("password and YubiKey", func(t *testing.T) {
		useReaders(t, fakeReaders{"YubiKey": &fakeYubiKey{secrets: map[int][]byte{2: testSecret}}})
		db, err := openDatabase(dbPath, password, 2)
		if assert.NoError(t, err) {
			assert.Equal(t, "Entry1", db.Content.Root.Groups[0].Entries[0].GetTitle())
		}
		assert.Nil(t, password.Windows, "the given credentials are left unchanged")
	})

	t.Run("YubiKey with another secret", func(t *testing.T) {
		useReaders(t, fakeReaders{"YubiKey": &fakeYubiKey{secrets: map[int][]byte{2: []byte("another secret")}}})
		_, err := openDatabase(dbPath, password, 2)
		assert.Error(t, err)
	})

	t.Run("password alone", func(t *testing.T) {
		useReaders(t, fakeReaders{})
		_, err := openDatabase(dbPath, password, 0)
		assert.Error(t, err)
	})

	t.Run("no YubiKey", func(t *testing.T) {
		useReaders(t, fakeReaders{})
		useWorkflow(t, dbPath, "Abc12345", map[string]string{yubikeySlotVariable: "2"})
		alf := runSearch([]string{"Entry1"})
		assert.Len(t, alf.Items, 1)
		assert.True(t, strings.HasPrefix(alf.Items[0].Title, "⚠️ no YubiKey found"), alf.Items[0].Title)
	})

	t.Run("search, get and entries", func(t *testing.T) {
		useReaders(t, fakeReaders{"YubiKey": &fakeYubiKey{secrets: map[int][]byte{2: testSecret}}})
		useWorkflow(t, dbPath, "Abc12345", map[string]string{yubikeySlotVariable: "2"})
		alf := runSearch([]string{"Entry1"})
		assert.Equal(t, "Entry1", alf.Items[0].Title)
		alf = runGet([]string{"Entry1"})
		assert.Equal(t, "← Back", alf.Items[0].Title)
		_, entry, err := openEntry(dbPath, "", "Abc12345", 2, "Entry1")
		if assert.NoError(t, err) {
			assert.Equal(t, "Entry1", entry.GetTitle())
		}
	})

	t.Run("no master password in the keychain", func(t *testing.T) {
		useReaders(t, fakeReaders{"YubiKey": &fakeYubiKey{secrets: map[int][]byte{2: testSecret}}})
		useWorkflow(t, dbPath, "", map[string]string{yubikeySlotVariable: "2"})
		alf := runSearch([]string{"Entry1"})
		assert.Len(t, alf.Items, 1)
		assert.Contains(t, alf.Items[0].Title, "run `kp:setpass`")
	})

	t.Run("YubiKey only", func(t *testing.T) {
		dbPath := writeYubiKeyDatabase(t, "", testSecret)
		useReaders(t, fakeReaders{"YubiKey": &fakeYubiKey{secrets: map[int][]byte{1: testSecret}}})
		useWorkflow(t, dbPath, "", map[string]string{yubikeySlotVariable: "1"})
		alf := runSearch([]string{"Entry1"})
		assert.Equal(t, "Entry1", alf.Items[0].Title)
	})

	t.Run("KDBX 3.1 is reported as unsupported", func(t *testing.T) {
		useReaders(t, fakeReaders{"YubiKey": &fakeYubiKey{secrets: map[int][]byte{1: testSecret}}})
		_, err := openDatabase(filepath.Join("testdata", "test.kdbx"), password, 1)
		assert.ErrorContains(t, err, "only supported for KDBX 4")
	})
}
