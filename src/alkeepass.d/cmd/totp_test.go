package cmd

import (
	"encoding/base32"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tobischo/gokeepasslib/v3"
)

// The seeds of the RFC 6238 test vectors
var rfc6238Seeds = map[string]string{
	"SHA1":   "12345678901234567890",
	"SHA256": "12345678901234567890123456789012",
	"SHA512": "1234567890123456789012345678901234567890123456789012345678901234",
}

// TestTOTPRFC6238 checks the test vectors of RFC 6238, Appendix B (8 digits,
// 30 second period), going through an otpauth URI as the otp attribute holds.
func TestTOTPRFC6238(t *testing.T) {
	vectors := []struct {
		unix int64
		want map[string]string
	}{
		{59, map[string]string{"SHA1": "94287082", "SHA256": "46119246", "SHA512": "90693936"}},
		{1111111109, map[string]string{"SHA1": "07081804", "SHA256": "68084774", "SHA512": "25091201"}},
		{1111111111, map[string]string{"SHA1": "14050471", "SHA256": "67062674", "SHA512": "99943326"}},
		{1234567890, map[string]string{"SHA1": "89005924", "SHA256": "91819424", "SHA512": "93441116"}},
		{2000000000, map[string]string{"SHA1": "69279037", "SHA256": "90698825", "SHA512": "38618901"}},
		{20000000000, map[string]string{"SHA1": "65353130", "SHA256": "77737706", "SHA512": "47863826"}},
	}
	for alg, seed := range rfc6238Seeds {
		otp, err := parseOTPAuth("otpauth://totp/RFC6238?algorithm=" + alg + "&digits=8&secret=" +
			base32.StdEncoding.EncodeToString([]byte(seed)))
		if !assert.NoError(t, err, alg) {
			continue
		}
		for _, v := range vectors {
			assert.Equal(t, v.want[alg], otp.code(time.Unix(v.unix, 0)), "%s at %d", alg, v.unix)
		}
	}
}

func TestParseOTPAuth(t *testing.T) {
	sha1Secret := base32.StdEncoding.EncodeToString([]byte(rfc6238Seeds["SHA1"]))
	sha512Secret := base32.StdEncoding.EncodeToString([]byte(rfc6238Seeds["SHA512"]))
	at59 := time.Unix(59, 0)

	t.Run("defaults are SHA1, 6 digits and 30 seconds", func(t *testing.T) {
		otp, err := parseOTPAuth("otpauth://totp/Example:alice@example.com?secret=" + sha1Secret + "&issuer=Example")
		if assert.NoError(t, err) {
			assert.Equal(t, 6, otp.digits)
			assert.Equal(t, int64(30), otp.period)
			assert.Equal(t, "287082", otp.code(at59)) // the SHA1 vector 94287082, truncated
		}
	})

	t.Run("algorithm, digits and period are read", func(t *testing.T) {
		otp, err := parseOTPAuth("otpauth://totp/x?secret=" + sha512Secret + "&algorithm=sha512&digits=8&period=60")
		if assert.NoError(t, err) {
			assert.Equal(t, 8, otp.digits)
			assert.Equal(t, int64(60), otp.period)
			// time 60 is counter 1 with a 60 second period, as time 59 is with 30
			assert.Equal(t, "90693936", otp.code(time.Unix(60, 0)))
		}
	})

	t.Run("lowercase secret without padding", func(t *testing.T) {
		padded := base32.StdEncoding.EncodeToString([]byte(rfc6238Seeds["SHA256"]))
		assert.True(t, strings.HasSuffix(padded, "="), "fixture must actually need padding")
		unpadded := strings.ToLower(strings.TrimRight(padded, "="))
		otp, err := parseOTPAuth("otpauth://totp/x?algorithm=SHA256&digits=8&secret=" + unpadded)
		if assert.NoError(t, err) {
			assert.Equal(t, "46119246", otp.code(at59))
		}
	})

	t.Run("spaces and dashes in the secret", func(t *testing.T) {
		for _, s := range []string{
			"GEZDGNBV%20GY3TQOJQ%20GEZDGNBV%20GY3TQOJQ",
			"GEZDGNBV+GY3TQOJQ+GEZDGNBV+GY3TQOJQ",
			"GEZDGNBV-GY3TQOJQ-GEZDGNBV-GY3TQOJQ",
		} {
			otp, err := parseOTPAuth("otpauth://totp/x?secret=" + s)
			if assert.NoError(t, err, s) {
				assert.Equal(t, "287082", otp.code(at59), s)
			}
		}
	})

	t.Run("unsupported or invalid settings are rejected", func(t *testing.T) {
		cases := []struct{ name, uri, want string }{
			{"KeeOtp settings", "key=" + sha1Secret + "&size=6&step=30", "otpauth"},
			{"unparsable URI", "otpauth://totp/100%:x?secret=" + sha1Secret, "otpauth"},
			{"HOTP", "otpauth://hotp/x?secret=" + sha1Secret + "&counter=1", "hotp"},
			{"Steam", "otpauth://totp/Steam:x?secret=" + sha1Secret + "&encoder=steam", "steam"},
			{"no secret", "otpauth://totp/x?issuer=x", "no secret"},
			{"invalid base32", "otpauth://totp/x?secret=" + sha1Secret + "1", "base32"},
			{"unsupported algorithm", "otpauth://totp/x?secret=" + sha1Secret + "&algorithm=MD5", "MD5"},
			{"zero digits", "otpauth://totp/x?secret=" + sha1Secret + "&digits=0", "digits"},
			{"too many digits", "otpauth://totp/x?secret=" + sha1Secret + "&digits=11", "digits"},
			{"non-numeric digits", "otpauth://totp/x?secret=" + sha1Secret + "&digits=six", "digits"},
			{"zero period", "otpauth://totp/x?secret=" + sha1Secret + "&period=0", "period"},
			{"negative period", "otpauth://totp/x?secret=" + sha1Secret + "&period=-30", "period"},
		}
		for _, c := range cases {
			_, err := parseOTPAuth(c.uri)
			if assert.Error(t, err, c.name) {
				assert.Contains(t, err.Error(), c.want, c.name)
				assert.NotContains(t, err.Error(), sha1Secret, "%s: the error must not reveal the secret", c.name)
			}
		}
	})
}

// TestEntryTOTP generates the TOTP of the fixture entries. The expected codes
// are what keepassxc-cli 2.8.0 (`show --totp`) printed for the same otp
// attributes at the same moments.
func TestEntryTOTP(t *testing.T) {
	dbPath := filepath.Join("testdata", "actions.kdbx")
	cases := []struct {
		entry string
		unix  int64
		want  string
	}{
		{"Example", 1794447102, "744530"},
		{"Example", 1794447226, "652194"},
		{"TOTP/SHA256", 1794447102, "03726057"},
		{"TOTP/SHA256", 1794447226, "33811154"},
		{"TOTP/SHA512", 1794447102, "75368728"},
		{"TOTP/SHA512", 1794447226, "68368044"},
		{"TOTP/Lowercase", 1794447102, "6635832"},
		{"TOTP/Lowercase", 1794447226, "7307936"},
	}
	for _, c := range cases {
		_, entry, err := openEntry(dbPath, "", "Abc12345", 0, c.entry)
		if assert.NoError(t, err, c.entry) {
			code, err := entryTOTP(entry, time.Unix(c.unix, 0))
			assert.NoError(t, err, c.entry)
			assert.Equal(t, c.want, code, "%s at %d", c.entry, c.unix)
		}
	}

	t.Run("Steam is rejected", func(t *testing.T) {
		_, entry, err := openEntry(dbPath, "", "Abc12345", 0, "TOTP/Steam")
		if assert.NoError(t, err) {
			_, err := entryTOTP(entry, time.Now())
			assert.ErrorContains(t, err, "steam")
		}
	})

	t.Run("an entry without otp attribute", func(t *testing.T) {
		entry := gokeepasslib.NewEntry()
		_, err := entryTOTP(&entry, time.Now())
		assert.ErrorContains(t, err, "no TOTP")
	})
}
