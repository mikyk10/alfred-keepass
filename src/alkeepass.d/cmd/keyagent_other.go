//go:build !darwin || !cgo

package cmd

import (
	"net"
	"os"
	"time"

	"github.com/pkg/errors"
)

// keyAgentSupported tells whether this build can run the key agent: it needs
// cgo on macOS to check who connects to it.
const keyAgentSupported = false

var processStart = time.Now()

// awakeTime is only used by the key agent.
func awakeTime() time.Duration {
	return time.Since(processStart)
}

func userTempDir() string {
	return os.TempDir()
}

func screenLocked() bool {
	return false
}

// Without a way to check who connects, the key agent serves nobody.
func peerUID(conn *net.UnixConn) (int, error) {
	return 0, errors.New("the key agent is only supported on macOS")
}
