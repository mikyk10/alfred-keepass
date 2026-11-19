//go:build darwin && cgo

package cmd

/*
#cgo LDFLAGS: -framework CoreGraphics -framework CoreFoundation
#include <CoreGraphics/CoreGraphics.h>
#include <time.h>
#include <unistd.h>

// kpScreenLocked reports whether the screen of the user's login session is
// locked.
static int kpScreenLocked(void) {
	CFDictionaryRef session = CGSessionCopyCurrentDictionary();
	if (session == NULL) return 0;
	CFTypeRef locked = CFDictionaryGetValue(session, CFSTR("CGSSessionScreenIsLocked"));
	int result = locked != NULL && CFGetTypeID(locked) == CFBooleanGetTypeID() &&
		CFBooleanGetValue((CFBooleanRef)locked);
	CFRelease(session);
	return result;
}
*/
import "C"

import (
	"net"
	"os"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// keyAgentSupported tells whether this build can run the key agent.
const keyAgentSupported = true

// awakeTime returns how long the Mac has been awake since it started:
// CLOCK_UPTIME_RAW does not advance while it sleeps.
func awakeTime() time.Duration {
	return time.Duration(C.clock_gettime_nsec_np(C.CLOCK_UPTIME_RAW))
}

// userTempDir returns the user's private temporary directory, which macOS
// gives each user (in /var/folders) whether or not TMPDIR is set.
func userTempDir() string {
	var buf [1024]C.char
	n := C.confstr(C._CS_DARWIN_USER_TEMP_DIR, &buf[0], C.size_t(len(buf)))
	if n > 0 && n <= C.size_t(len(buf)) {
		return C.GoString(&buf[0])
	}
	return os.TempDir()
}

func screenLocked() bool {
	return C.kpScreenLocked() != 0
}

// peerUID returns the user ID of the process at the other end of conn.
func peerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, errors.WithStack(err)
	}
	var cred *unix.Xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, errors.WithStack(err)
	}
	if credErr != nil {
		return 0, errors.WithStack(credErr)
	}
	return int(cred.Uid), nil
}
