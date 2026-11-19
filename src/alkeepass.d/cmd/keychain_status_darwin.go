//go:build darwin && cgo

package cmd

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <stdlib.h>

// kpKeychainUnlocked reports in *unlocked whether the keychain file at path
// is unlocked. It never prompts the user.
static OSStatus kpKeychainUnlocked(const char *path, int *unlocked) {
	SecKeychainRef kc = NULL;
	OSStatus st = SecKeychainOpen(path, &kc);
	if (st != errSecSuccess) return st;
	SecKeychainStatus s = 0;
	st = SecKeychainGetStatus(kc, &s);
	CFRelease(kc);
	if (st != errSecSuccess) return st;
	*unlocked = (s & kSecUnlockStateStatus) != 0;
	return errSecSuccess;
}

// kpKeychainUnlock shows the standard macOS dialog asking for the password
// of the keychain file at path and waits for the user to answer it.
static OSStatus kpKeychainUnlock(const char *path) {
	SecKeychainRef kc = NULL;
	OSStatus st = SecKeychainOpen(path, &kc);
	if (st != errSecSuccess) return st;
	st = SecKeychainUnlock(kc, 0, NULL, false);
	CFRelease(kc);
	return st;
}
*/
import "C"

import (
	"unsafe"

	"github.com/pkg/errors"
)

func keychainFileLocked(kc string) (bool, error) {
	p := C.CString(kc)
	defer C.free(unsafe.Pointer(p))
	var unlocked C.int
	if st := C.kpKeychainUnlocked(p, &unlocked); st != C.errSecSuccess {
		return false, errors.Errorf("could not check whether the keychain is locked (OSStatus %d)", int(st))
	}
	return unlocked == 0, nil
}

func unlockKeychainFile(kc string) error {
	p := C.CString(kc)
	defer C.free(unsafe.Pointer(p))
	switch st := C.kpKeychainUnlock(p); st {
	case C.errSecSuccess:
	case C.errSecUserCanceled:
		return errors.New("unlocking the keychain was cancelled")
	default:
		return errors.Errorf("the keychain was not unlocked (OSStatus %d)", int(st))
	}
	return nil
}
