package cmd

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLockedJSON(t *testing.T) {
	t.Run("search item routes Enter to the unlock step", func(t *testing.T) {
		alf := lockedJSON("gmail #work", unlockAction)
		assert.Len(t, alf.Items, 1)
		item := alf.Items[0]
		assert.Equal(t, "gmail #work", item.Arg)
		assert.Equal(t, map[string]string{"kp_action": "unlock"}, item.Variables)
	})

	t.Run("detail item goes back without the unlock variable", func(t *testing.T) {
		item := lockedJSON("back", "").Items[0]
		assert.Equal(t, "back", item.Arg)
		assert.Nil(t, item.Variables)
	})

	t.Run("modifier actions are disabled", func(t *testing.T) {
		b, err := json.Marshal(lockedJSON("q", unlockAction))
		assert.NoError(t, err)
		var out struct {
			Items []struct {
				Mods map[string]struct {
					Valid bool `json:"valid"`
				} `json:"mods"`
			} `json:"items"`
		}
		assert.NoError(t, json.Unmarshal(b, &out))
		assert.NotEmpty(t, out.Items[0].Mods)
		for k, m := range out.Items[0].Mods {
			assert.False(t, m.Valid, k)
		}
	})
}
