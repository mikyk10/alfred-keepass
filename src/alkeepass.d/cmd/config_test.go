package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		useWorkflow(t, "db.kdbx", "", nil)
		cfg, err := loadConfig()
		assert.NoError(t, err)
		assert.Equal(t, "db.kdbx", cfg.dbPath)
		assert.Equal(t, 0, cfg.yubikeySlot)
		assert.Equal(t, keyCacheSettings{ForgetOnSleep: true, ForgetOnScreenLock: true}, cfg.keyCache)
	})

	t.Run("everything set", func(t *testing.T) {
		useWorkflow(t, "db.kdbx", "", map[string]string{
			keyFileVariable:            "db.key",
			yubikeySlotVariable:        "2",
			keyCacheMinutesVariable:    "15",
			forgetOnSleepVariable:      "0",
			forgetOnScreenLockVariable: "1",
		})
		cfg, err := loadConfig()
		assert.NoError(t, err)
		assert.Equal(t, workflowConfig{
			dbPath:      "db.kdbx",
			keyFile:     "db.key",
			yubikeySlot: 2,
			keyCache:    keyCacheSettings{TTL: 15 * time.Minute, ForgetOnScreenLock: true},
		}, cfg)
	})

	for name, env := range map[string]map[string]string{
		"invalid slot":          {yubikeySlotVariable: "3"},
		"invalid cache time":    {keyCacheMinutesVariable: "ten"},
		"negative cache time":   {keyCacheMinutesVariable: "-1"},
		"cache time too long":   {keyCacheMinutesVariable: "1441"},
		"fractional cache time": {keyCacheMinutesVariable: "1.5"},
	} {
		t.Run(name, func(t *testing.T) {
			useWorkflow(t, "db.kdbx", "", env)
			_, err := loadConfig()
			assert.Error(t, err)
		})
	}
}

func TestParseYubiKeySlot(t *testing.T) {
	for raw, want := range map[string]int{"": 0, "0": 0, "1": 1, "2": 2, " 2 ": 2} {
		slot, err := parseYubiKeySlot(raw)
		assert.NoError(t, err, raw)
		assert.Equal(t, want, slot, raw)
	}
	for _, raw := range []string{"3", "slot 1", "-1"} {
		_, err := parseYubiKeySlot(raw)
		assert.Error(t, err, raw)
	}
}

func TestParseCheckbox(t *testing.T) {
	for raw, want := range map[string]bool{"": true, "1": true, "true": true, "0": false, "false": false, " 0 ": false} {
		assert.Equal(t, want, parseCheckbox(raw), raw)
	}
}
