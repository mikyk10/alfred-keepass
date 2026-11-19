//go:build !darwin || !cgo

package cmd

import "github.com/pkg/errors"

// The YubiKey is reached through the PCSC framework of macOS.
func openPCSC() (cardReaders, error) {
	return nil, errors.New("YubiKey challenge-response is only supported on macOS")
}
