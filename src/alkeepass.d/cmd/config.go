package cmd

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// Alfred passes the workflow configuration in these environment variables.
const (
	dbPathVariable             = "keepassxc_db_path"
	keyFileVariable            = "keepassxc_keyfile_path"
	yubikeySlotVariable        = "keepassxc_yubikey_slot"
	keyCacheMinutesVariable    = "keepassxc_key_cache_minutes"
	forgetOnSleepVariable      = "keepassxc_key_cache_forget_on_sleep"
	forgetOnScreenLockVariable = "keepassxc_key_cache_forget_on_screen_lock"
)

// maxKeyCacheMinutes is the longest time the derived key can be cached.
const maxKeyCacheMinutes = 24 * 60

type workflowConfig struct {
	dbPath      string
	keyFile     string
	yubikeySlot int // 0 when no YubiKey is used
	keyCache    keyCacheSettings
}

// keyCacheSettings say how long the key agent keeps the derived key. They go
// with every request for the key, so that a change of the configuration
// applies to a key cached before.
type keyCacheSettings struct {
	TTL                time.Duration `json:"ttl"` // 0 when the key is not cached
	ForgetOnSleep      bool          `json:"forget_on_sleep"`
	ForgetOnScreenLock bool          `json:"forget_on_screen_lock"`
}

// loadConfig reads and checks the workflow configuration.
func loadConfig() (workflowConfig, error) {
	slot, err := parseYubiKeySlot(os.Getenv(yubikeySlotVariable))
	if err != nil {
		return workflowConfig{}, err
	}
	minutes, err := parseKeyCacheMinutes(os.Getenv(keyCacheMinutesVariable))
	if err != nil {
		return workflowConfig{}, err
	}
	return workflowConfig{
		dbPath:      os.Getenv(dbPathVariable),
		keyFile:     os.Getenv(keyFileVariable),
		yubikeySlot: slot,
		keyCache: keyCacheSettings{
			TTL:                time.Duration(minutes) * time.Minute,
			ForgetOnSleep:      parseCheckbox(os.Getenv(forgetOnSleepVariable)),
			ForgetOnScreenLock: parseCheckbox(os.Getenv(forgetOnScreenLockVariable)),
		},
	}, nil
}

func parseYubiKeySlot(raw string) (int, error) {
	switch strings.TrimSpace(raw) {
	case "", "0":
		return 0, nil
	case "1":
		return 1, nil
	case "2":
		return 2, nil
	}
	return 0, errors.Errorf("invalid YubiKey slot %q: choose 1 or 2", raw)
}

// parseKeyCacheMinutes reads the key cache time; empty means 0 (off).
func parseKeyCacheMinutes(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > maxKeyCacheMinutes {
		return 0, errors.Errorf("invalid key cache time %q: give the minutes from 0 (off) to %d", raw, maxKeyCacheMinutes)
	}
	return n, nil
}

// parseCheckbox reads a checkbox, which Alfred passes as 1 or 0. It is on
// unless turned off, the default of the checkboxes this is used for.
func parseCheckbox(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "0", "false", "no":
		return false
	}
	return true
}
