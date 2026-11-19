package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/tobischo/gokeepasslib/v3"
)

// errKeychainLocked is returned by openConfiguredDatabase when the master
// password is needed while the keychain is locked and may not be unlocked.
var errKeychainLocked = errors.New("the keychain is locked")

// openConfiguredDatabase opens the database set in the workflow
// configuration. If the key agent holds the derived key of the database, the
// database is opened with it, without the keychain, the YubiKey or the key
// derivation. Otherwise it is opened with the master password from the
// keychain, the key file and the YubiKey, and the derived key is handed to
// the key agent if the configuration says so. Unless prompt is set, a locked
// keychain yields errKeychainLocked instead of asking to unlock it: the
// dialog would close Alfred's window and lose the results.
func openConfiguredDatabase(prompt bool) (*gokeepasslib.Database, error) {
	// A key derived from here on is not cached if kp:lock is run meanwhile.
	started := time.Now()
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(cfg.dbPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	header, err := decodeHeader(data)
	if err != nil {
		return nil, err
	}

	cache := cfg.keyCache
	if cache.TTL > 0 && !keyAgentSupported {
		fmt.Fprintln(os.Stderr, "the key cache is off: this build of alkeepass cannot run the key agent, which needs macOS and cgo")
		cache.TTL = 0
	}
	var fingerprint string
	if cache.TTL > 0 {
		fingerprint = keyFingerprint(cfg.dbPath, header.Header)
		if key := cachedKey(fingerprint, cache); key != nil {
			db, err := openKbdx(bytes.NewReader(data), &gokeepasslib.DBCredentials{TransformedKey: key})
			if err == nil {
				return db, nil
			}
			// e.g. the credentials changed but the key derivation did not
			forgetCachedKey()
		}
	} else {
		// so that turning the cache off takes effect at once
		forgetCachedKey()
	}

	passwd, err := masterPassword(prompt)
	if err != nil {
		return nil, err
	}
	cred, err := buildCredentials(passwd, cfg.keyFile, cfg.yubikeySlot)
	if err != nil {
		return nil, err
	}
	if cfg.yubikeySlot != 0 {
		if cred, err = addChallengeResponse(cred, header.Header, cfg.yubikeySlot); err != nil {
			return nil, err
		}
	}
	db, err := decodeDatabase(data, header, cred)
	if err != nil && cred.Passphrase == nil {
		// Unlike no password, an empty one is part of the key. KeePassXC
		// retries with it too when no password is entered.
		withEmpty := *cred
		withEmpty.Passphrase = gokeepasslib.NewPasswordCredentials("").Passphrase
		if retried, retryErr := decodeDatabase(data, header, &withEmpty); retryErr == nil {
			db, err = retried, nil
		}
	}
	if err != nil {
		if passwd == "" {
			// A database may have no master password, or an empty one, so a
			// missing one is only reported now.
			return nil, fmt.Errorf("%w (no master password in the keychain: run `kp:setpass` in Alfred if the database has one)", err)
		}
		return nil, err
	}
	if cache.TTL > 0 {
		if err := cacheKey(fingerprint, db.Credentials.TransformedKey, cache, started); err != nil {
			// The database is open; only the next one will be slower.
			fmt.Fprintln(os.Stderr, "could not cache the key:", err)
		}
	}
	return db, nil
}

// masterPassword reads the master password from the keychain. With prompt it
// first asks the user to unlock the keychain if needed, so that the dialog has
// been answered before the password is read; without, a locked keychain
// yields errKeychainLocked.
func masterPassword(prompt bool) (string, error) {
	if prompt {
		if err := unlockKeychain(); err != nil {
			return "", err
		}
	} else if locked, err := keychainLocked(); err == nil && locked {
		return "", errKeychainLocked
	}
	return readKeychain()
}

// decodeHeader returns a database holding just the header of the database in
// data. Decoding without credentials reads the header (and checks its hash in
// KDBX 4) and stops before the key derivation, which needs them.
func decodeHeader(data []byte) (*gokeepasslib.Database, error) {
	db := gokeepasslib.NewDatabase()
	db.Credentials = nil
	err := gokeepasslib.NewDecoder(bytes.NewReader(data)).Decode(db)
	var missing gokeepasslib.ErrRequiredAttributeMissing
	if !errors.As(err, &missing) {
		if err == nil {
			err = errors.New("the database could be read without credentials")
		}
		return nil, errors.WithStack(err)
	}
	return db, nil
}

// decodeDatabase decodes the database in data, whose header decodeHeader
// returned, with cred. The key is derived up front, so that the credentials
// of the returned database carry it as their TransformedKey.
func decodeDatabase(data []byte, header *gokeepasslib.Database, cred *gokeepasslib.DBCredentials) (*gokeepasslib.Database, error) {
	header.Credentials = cred
	key, err := header.TransformedKey()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return openKbdx(bytes.NewReader(data), &gokeepasslib.DBCredentials{TransformedKey: key})
}

func openKbdx(rd io.Reader, credentials *gokeepasslib.DBCredentials) (*gokeepasslib.Database, error) {

	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials

	err := gokeepasslib.NewDecoder(rd).Decode(db)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	err = db.UnlockProtectedEntries()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return db, nil
}
