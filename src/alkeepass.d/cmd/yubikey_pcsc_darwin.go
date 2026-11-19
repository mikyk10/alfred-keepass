//go:build darwin && cgo

package cmd

/*
#cgo LDFLAGS: -framework PCSC
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#include <stdlib.h>

// kpTransmit sends an APDU with the protocol control information of the
// protocol the card was connected with.
static int32_t kpTransmit(SCARDHANDLE card, uint32_t protocol,
		const unsigned char *send, uint32_t sendLength,
		unsigned char *recv, uint32_t *recvLength) {
	const SCARD_IO_REQUEST *pci = protocol == SCARD_PROTOCOL_T0 ? SCARD_PCI_T0 : SCARD_PCI_T1;
	return SCardTransmit(card, pci, send, sendLength, NULL, recv, recvLength);
}
*/
import "C"

import (
	"strings"
	"unsafe"

	"github.com/pkg/errors"
)

type pcscReaders struct {
	ctx C.SCARDCONTEXT
}

type pcscCard struct {
	handle   C.SCARDHANDLE
	protocol C.uint32_t
}

func openPCSC() (cardReaders, error) {
	var ctx C.SCARDCONTEXT
	if rv := C.SCardEstablishContext(C.SCARD_SCOPE_SYSTEM, nil, nil, &ctx); rv != C.SCARD_S_SUCCESS {
		return nil, pcscError(rv, "")
	}
	return &pcscReaders{ctx: ctx}, nil
}

func (r *pcscReaders) list() ([]string, error) {
	var size C.uint32_t
	rv := C.SCardListReaders(r.ctx, nil, nil, &size)
	if uint32(rv) == C.SCARD_E_NO_READERS_AVAILABLE || (rv == C.SCARD_S_SUCCESS && size == 0) {
		return nil, nil
	}
	if rv != C.SCARD_S_SUCCESS {
		return nil, pcscError(rv, "")
	}
	buf := make([]byte, size)
	if rv := C.SCardListReaders(r.ctx, nil, (*C.char)(unsafe.Pointer(&buf[0])), &size); rv != C.SCARD_S_SUCCESS {
		return nil, pcscError(rv, "")
	}
	// The names are NUL-terminated, followed by an empty name.
	var names []string
	for _, name := range strings.Split(string(buf[:size]), "\x00") {
		if name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

func (r *pcscReaders) connect(reader string) (smartCard, error) {
	name := C.CString(reader)
	defer C.free(unsafe.Pointer(name))

	var card pcscCard
	rv := C.SCardConnect(r.ctx, name, C.SCARD_SHARE_SHARED,
		C.SCARD_PROTOCOL_T0|C.SCARD_PROTOCOL_T1, &card.handle, &card.protocol)
	if rv != C.SCARD_S_SUCCESS {
		return nil, pcscError(rv, reader)
	}
	// Keep other processes (e.g. the system's smart card token driver) from
	// selecting another application between our commands.
	if rv := C.SCardBeginTransaction(card.handle); rv != C.SCARD_S_SUCCESS {
		C.SCardDisconnect(card.handle, C.SCARD_LEAVE_CARD)
		return nil, pcscError(rv, reader)
	}
	return &card, nil
}

func (r *pcscReaders) close() {
	C.SCardReleaseContext(r.ctx)
}

func (c *pcscCard) transmit(apdu []byte) ([]byte, error) {
	if len(apdu) == 0 {
		return nil, errors.New("empty command APDU")
	}
	// up to 256 bytes of data and the status word
	buf := make([]byte, 258)
	size := C.uint32_t(len(buf))
	rv := C.kpTransmit(c.handle, c.protocol,
		(*C.uchar)(unsafe.Pointer(&apdu[0])), C.uint32_t(len(apdu)),
		(*C.uchar)(unsafe.Pointer(&buf[0])), &size)
	if rv != C.SCARD_S_SUCCESS {
		return nil, pcscError(rv, "")
	}
	return buf[:size], nil
}

func (c *pcscCard) close() {
	C.SCardEndTransaction(c.handle, C.SCARD_LEAVE_CARD)
	C.SCardDisconnect(c.handle, C.SCARD_LEAVE_CARD)
}

// pcscError converts a PC/SC result into an error, using the sentinel errors
// that challengeYubiKey handles where one applies.
func pcscError(rv C.int32_t, reader string) error {
	switch uint32(rv) {
	case C.SCARD_E_NO_SMARTCARD, C.SCARD_W_REMOVED_CARD, C.SCARD_W_UNPOWERED_CARD, C.SCARD_W_UNRESPONSIVE_CARD:
		return errNoCard
	case C.SCARD_W_RESET_CARD:
		return errCardReset
	case C.SCARD_E_NO_SERVICE, C.SCARD_E_SERVICE_STOPPED, C.SCARD_E_NO_READERS_AVAILABLE:
		// macOS only runs the service while a reader is attached.
		return errNoYubiKey
	case C.SCARD_E_SHARING_VIOLATION:
		return errors.Errorf("the card in %s is in use by another application (such as gpg-agent)", reader)
	}
	return errors.Errorf("smart card communication failed (PC/SC error 0x%08X)", uint32(rv))
}
