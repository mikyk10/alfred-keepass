package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/pkg/errors"
	"github.com/tobischo/gokeepasslib/v3"
)

// A database can additionally be protected by the HMAC-SHA1
// challenge-response of a YubiKey, as KeePassXC offers it. The YubiKey is
// reached through PC/SC, i.e. its smart card (CCID) interface over USB or an
// NFC reader, where its OTP application answers the challenge with the secret
// programmed into slot 1 or 2.

const (
	// maximum size of a challenge, and the size the YubiKey always receives
	hmacChallengeSize = 64
	// size of an HMAC-SHA1 response
	hmacResponseSize = 20

	insSelect      = 0xA4
	insGetResponse = 0xC0
	insOTP         = 0x01 // the OTP application's command for its slots

	swOK              = 0x9000
	swNotTouched      = 0x6985 // conditions of use not satisfied: no touch in time
	swMoreDataPending = 0x61   // SW1 telling the rest is fetched with GET RESPONSE
)

// AID of the YubiKey OTP application
var otpAID = []byte{0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01}

// slotCommands are the OTP application's HMAC-SHA1 commands for slots 1 and 2.
var slotCommands = map[int]byte{1: 0x30, 2: 0x38}

var (
	// errNoYubiKey is returned when no reader holds a YubiKey.
	errNoYubiKey = errors.New("no YubiKey found: insert it (or hold it on the NFC reader) and try again")
	// errNoCard is returned by cardReaders.connect for a reader without a card.
	errNoCard = errors.New("no card in the reader")
	// errCardReset is returned by smartCard.transmit when another process
	// reset the card, which then has to be connected to again.
	errCardReset = errors.New("the card was reset")
	// errNotYubiKey is returned when a card has no OTP application.
	errNotYubiKey = errors.New("not a YubiKey")
)

// cardReaders is a session with the PC/SC service.
type cardReaders interface {
	// list returns the names of the readers.
	list() ([]string, error)
	// connect connects to the card in reader for exclusive use until it is
	// closed. It returns errNoCard when the reader is empty.
	connect(reader string) (smartCard, error)
	close()
}

// smartCard is a card connected through cardReaders.
type smartCard interface {
	// transmit sends a command APDU and returns the response APDU, i.e. the
	// response data followed by the status word.
	transmit(apdu []byte) ([]byte, error)
	close()
}

// openCardReaders starts a session with the PC/SC service. It is a variable
// so tests can replace it.
var openCardReaders = openPCSC

// addChallengeResponse returns a copy of cred completed with the response of
// the YubiKey slot to the challenge of the database with header, as KeePassXC
// computes it for a KDBX 4 database: the challenge is the seed of the key
// derivation function, and the SHA-256 of the response is the last component
// of the composite key, after the password and the key file. gokeepasslib
// hashes its Windows user account component in that position, so the
// response is passed in there.
func addChallengeResponse(cred *gokeepasslib.DBCredentials, header *gokeepasslib.DBHeader, slot int) (*gokeepasslib.DBCredentials, error) {
	challenge, err := databaseChallenge(header)
	if err != nil {
		return nil, err
	}
	response, err := challengeYubiKey(slot, challenge)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(response)
	c := *cred
	c.Windows = sum[:]
	return &c, nil
}

// databaseChallenge returns the challenge for the database with header: the
// seed of its key derivation function.
func databaseChallenge(header *gokeepasslib.DBHeader) ([]byte, error) {
	// KeePassXC challenges a KDBX 3.1 database with its master seed and adds
	// the response to the final key, which gokeepasslib has no place for.
	if !header.IsKdbx4() {
		return nil, errors.New("YubiKey challenge-response is only supported for KDBX 4 databases")
	}
	params := header.FileHeaders.KdfParameters
	if params == nil || params.RawData == nil {
		return nil, errors.New("the database header has no key derivation parameters")
	}
	seed := params.RawData.Get("S")
	if seed == nil || len(seed.Value) == 0 || len(seed.Value) > hmacChallengeSize {
		return nil, errors.New("the database header has no usable key derivation seed")
	}
	return seed.Value, nil
}

// challengeYubiKey returns the HMAC-SHA1 response of the given slot of the
// first YubiKey that answers the challenge.
func challengeYubiKey(slot int, challenge []byte) ([]byte, error) {
	apdu, err := hmacAPDU(slot, challenge)
	if err != nil {
		return nil, err
	}
	readers, err := openCardReaders()
	if err != nil {
		return nil, err
	}
	defer readers.close()

	names, err := readers.list()
	if err != nil {
		return nil, err
	}
	// Report what went wrong with the last YubiKey (or reader) tried.
	failure := errNoYubiKey
	for _, name := range names {
		response, err := challengeReader(readers, name, apdu, slot)
		switch {
		case err == nil:
			return response, nil
		case errors.Is(err, errNoCard), errors.Is(err, errNotYubiKey):
		default:
			failure = err
		}
	}
	return nil, failure
}

// challengeReader sends the challenge to the card in reader, connecting to
// it again (once) if another process resets it meanwhile.
func challengeReader(readers cardReaders, reader string, apdu []byte, slot int) ([]byte, error) {
	var err error
	for range 2 {
		var card smartCard
		var response []byte
		if card, err = readers.connect(reader); err == nil {
			response, err = challengeCard(card, apdu, slot)
			card.close()
		}
		if !errors.Is(err, errCardReset) {
			return response, err
		}
	}
	return nil, err
}

// challengeCard selects the OTP application of card and sends it apdu, the
// HMAC-SHA1 challenge for slot.
func challengeCard(card smartCard, apdu []byte, slot int) ([]byte, error) {
	selectAPDU := append([]byte{0x00, insSelect, 0x04, 0x00, byte(len(otpAID))}, otpAID...)
	if _, sw, err := exchange(card, selectAPDU); err != nil {
		return nil, err
	} else if sw != swOK {
		return nil, errNotYubiKey
	}

	response, sw, err := exchange(card, apdu)
	switch {
	case err != nil:
		return nil, err
	case sw == swNotTouched:
		return nil, errors.New("the YubiKey was not touched in time")
	case sw == swOK && len(response) == hmacResponseSize:
		return response, nil
	case sw == swOK:
		// The slot answers, but not with an HMAC-SHA1 response.
		return nil, errors.Errorf("YubiKey slot %d is not configured for HMAC-SHA1 challenge-response", slot)
	default:
		return nil, errors.Errorf("YubiKey challenge-response failed (status %04X)", sw)
	}
}

// hmacAPDU builds the command asking for the HMAC-SHA1 response of slot to
// challenge. Like KeePassXC it pads the challenge to 64 bytes with PKCS #7
// padding; a slot configured for variable length challenges (the default)
// ignores the padding.
func hmacAPDU(slot int, challenge []byte) ([]byte, error) {
	cmd, ok := slotCommands[slot]
	if !ok {
		return nil, errors.Errorf("invalid YubiKey slot %d", slot)
	}
	if len(challenge) > hmacChallengeSize {
		return nil, errors.Errorf("challenge of %d bytes is too long", len(challenge))
	}
	pad := hmacChallengeSize - len(challenge)
	apdu := append([]byte{0x00, insOTP, cmd, 0x00, hmacChallengeSize}, challenge...)
	return append(apdu, bytes.Repeat([]byte{byte(pad)}, pad)...), nil
}

// exchange transmits apdu to card and returns the response data and status
// word, fetching data the card holds back with GET RESPONSE.
func exchange(card smartCard, apdu []byte) ([]byte, uint16, error) {
	var data []byte
	for range 16 {
		response, err := card.transmit(apdu)
		if err != nil {
			return nil, 0, err
		}
		if len(response) < 2 {
			return nil, 0, errors.New("incomplete response from the smart card")
		}
		n := len(response) - 2
		data = append(data, response[:n]...)
		sw := binary.BigEndian.Uint16(response[n:])
		if sw>>8 != swMoreDataPending {
			return data, sw, nil
		}
		apdu = []byte{0x00, insGetResponse, 0x00, 0x00, byte(sw)}
	}
	return nil, 0, errors.New("too many response parts from the smart card")
}
