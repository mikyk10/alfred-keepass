package cmd

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/tobischo/gokeepasslib/v3"
)

// totp holds the parameters of a time-based one-time password (RFC 6238).
type totp struct {
	secret []byte
	hash   func() hash.Hash
	digits int
	period int64 // seconds
}

// entryTOTP returns the TOTP of entry at the time now. It is generated from
// the otpauth:// URI that KeePassXC keeps in the otp attribute, which is also
// what the detail view checks before offering the TOTP.
func entryTOTP(entry *gokeepasslib.Entry, now time.Time) (string, error) {
	uri := entry.GetContent("otp")
	if uri == "" {
		return "", errors.New("the entry has no TOTP")
	}
	t, err := parseOTPAuth(uri)
	if err != nil {
		return "", err
	}
	return t.code(now), nil
}

// parseOTPAuth parses an otpauth://totp/ URI. It reads the secret, algorithm,
// digits and period parameters, defaulting to SHA1, 6 digits and 30 seconds.
// Other formats (e.g. HOTP, Steam or KeeOtp's key=... settings) are rejected.
// Errors never quote the URI, since it contains the secret.
func parseOTPAuth(uri string) (*totp, error) {
	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil || u.Scheme != "otpauth" {
		return nil, errors.New("unsupported TOTP format: the otp attribute is not an otpauth:// URI")
	}
	if !strings.EqualFold(u.Host, "totp") {
		return nil, errors.Errorf("unsupported OTP type %q: only TOTP is supported", u.Host)
	}
	q := u.Query()
	if enc := q.Get("encoder"); enc != "" {
		return nil, errors.Errorf("unsupported TOTP encoder %q", enc)
	}

	// Lowercase, missing padding and the spaces or dashes that some sites
	// group the secret with are tolerated, as in KeePassXC.
	s := strings.NewReplacer(" ", "", "-", "").Replace(q.Get("secret"))
	s = strings.TrimRight(strings.ToUpper(s), "=")
	if s == "" {
		return nil, errors.New("the otpauth URI has no secret")
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		return nil, errors.New("the TOTP secret is not valid base32")
	}
	t := &totp{secret: secret, hash: sha1.New, digits: 6, period: 30}

	switch alg := q.Get("algorithm"); strings.ToUpper(alg) {
	case "", "SHA1":
	case "SHA256":
		t.hash = sha256.New
	case "SHA512":
		t.hash = sha512.New
	default:
		return nil, errors.Errorf("unsupported TOTP algorithm %q", alg)
	}
	if v := q.Get("digits"); v != "" {
		// The truncated value has 31 bits, so more than 10 digits only pads.
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 10 {
			return nil, errors.Errorf("unsupported number of TOTP digits %q", v)
		}
		t.digits = n
	}
	if v := q.Get("period"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			return nil, errors.Errorf("invalid TOTP period %q", v)
		}
		t.period = n
	}
	return t, nil
}

// code returns the one-time password for the time at (RFC 6238 with T0 = 0,
// using the HOTP truncation of RFC 4226).
func (t *totp) code(at time.Time) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/t.period))
	mac := hmac.New(t.hash, t.secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:]) & 0x7fffffff
	mod := uint64(1)
	for i := 0; i < t.digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", t.digits, uint64(value)%mod)
}
