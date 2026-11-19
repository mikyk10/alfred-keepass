package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/tobischo/gokeepasslib/v3"
)

// The derived key of the database can be kept for a while by a key agent:
// a background process holding it in memory only, which other runs of the
// workflow ask for it through a Unix socket. The agent exits, wiping the key,
// when the configured time is up, when the Mac has slept or its screen is
// locked (if so configured), or when told to forget the key.

var keyAgentCmd = &cobra.Command{
	Use:    "key-agent",
	Short:  "Hold a derived key, read from stdin, for other runs of the workflow",
	Hidden: true,
	Args:   cobra.NoArgs,
	Run:    keyAgentMain,
}

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Forget the cached derived key and lock the keychain holding the master password",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		exitOnError(lock())
	},
}

// lock makes the next run of the workflow ask the user again: it wipes the
// derived key the agent holds, keeps runs of the workflow that started before
// from caching the key they derive, and locks the keychain, from which the
// master password would otherwise be read without asking.
func lock() error {
	// Recorded before the key is forgotten: see keyAgent.put.
	err := recordLock(time.Now())
	if forgetErr := forgetCachedKey(); err == nil {
		err = forgetErr
	}
	if lockErr := lockKeychain(); err == nil {
		err = lockErr
	}
	return err
}

const (
	agentGet    = "get"
	agentPut    = "put"
	agentForget = "forget"

	// how often the agent checks whether to keep the key
	agentCheckInterval = 2 * time.Second
	// The Mac counts as having slept between two checks when the wall clock
	// moved on by this much more than the time it was awake.
	agentSleepThreshold = 5 * time.Second
	// time allowed for a request and its response
	agentTimeout = 2 * time.Second

	// files in the directory of the socket
	agentLockFile = "agent.lock" // locked by the running agent
	lockTimeFile  = "locked"     // when kp:lock was last run
)

// agentStartTimeout is how long a starting agent waits for a running one to
// answer or exit. It is a variable so tests can shorten it.
var agentStartTimeout = 3 * time.Second

// agentRequest is what a run of the workflow sends the agent. A put request
// is also what the agent reads from stdin when started.
type agentRequest struct {
	Op          string `json:"op"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Key         []byte `json:"key,omitempty"`
	// For get and put: the configuration, which may have changed since the
	// key was put.
	Settings keyCacheSettings `json:"settings"`
	// For put: when the run of the workflow that derived the key started.
	Since time.Time `json:"since"`
}

type agentResponse struct {
	Key []byte `json:"key,omitempty"`
}

// keyFingerprint identifies the derived key of the database at path. The key
// depends on the credentials and on the key derivation parameters in header;
// a key cached for other credentials fails to open the database and is then
// replaced.
func keyFingerprint(path string, header *gokeepasslib.DBHeader) string {
	h := sha256.New()
	field := func(b []byte) {
		binary.Write(h, binary.BigEndian, uint32(len(b)))
		h.Write(b)
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	field([]byte(path))
	fh := header.FileHeaders
	if header.IsKdbx4() && fh.KdfParameters != nil && fh.KdfParameters.RawData != nil {
		for _, item := range fh.KdfParameters.RawData.Items {
			field([]byte{item.Type})
			field(item.Name)
			field(item.Value)
		}
	} else {
		field(fh.TransformSeed)
		field(binary.BigEndian.AppendUint64(nil, fh.TransformRounds))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// agentSocket returns the path of the agent's socket. It is a variable so
// tests can use their own.
var agentSocket = func() string {
	return filepath.Join(userTempDir(), "alfred-keepass", "agent.sock")
}

// agentFile returns the path of the file called name in the directory of the
// agent's socket.
func agentFile(name string) string {
	return filepath.Join(filepath.Dir(agentSocket()), name)
}

// startKeyAgent starts the key agent with the put request req. It is a
// variable so tests can run the agent in process.
var startKeyAgent = func(req agentRequest) error {
	exe, err := os.Executable()
	if err != nil {
		return errors.WithStack(err)
	}
	// Like the clipboard clearing, the agent runs detached in its own
	// session, and the key goes through stdin, since the arguments and the
	// environment of a process can be read by other processes.
	cmd := exec.Command(exe, keyAgentCmd.Name())
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return errors.WithStack(err)
	}
	if err := cmd.Start(); err != nil {
		return errors.WithStack(err)
	}
	err = json.NewEncoder(stdin).Encode(req)
	stdin.Close()
	cmd.Process.Release()
	return errors.WithStack(err)
}

// cachedKey returns the derived key the agent holds for fingerprint, or nil.
// The agent keeps the key according to settings from now on.
func cachedKey(fingerprint string, settings keyCacheSettings) []byte {
	resp, err := askAgent(agentRequest{Op: agentGet, Fingerprint: fingerprint, Settings: settings})
	if err != nil {
		return nil
	}
	return resp.Key
}

// cacheKey hands key to the agent, starting one if none is running. since is
// when the run of the workflow that derived the key started: the key is not
// taken if kp:lock has been run since.
func cacheKey(fingerprint string, key []byte, settings keyCacheSettings, since time.Time) error {
	req := agentRequest{
		Op:          agentPut,
		Fingerprint: fingerprint,
		Key:         key,
		Settings:    settings,
		Since:       since,
	}
	if _, err := askAgent(req); err == nil {
		return nil
	}
	return startKeyAgent(req)
}

// forgetCachedKey makes a running agent wipe its key and exit.
func forgetCachedKey() error {
	_, err := askAgent(agentRequest{Op: agentForget})
	if errors.Is(err, errNoAgent) {
		return nil
	}
	return err
}

var errNoAgent = errors.New("no key agent is running")

// askAgent sends req to the agent and returns its response.
func askAgent(req agentRequest) (agentResponse, error) {
	var resp agentResponse
	path := agentSocket()
	if err := checkAgentDir(filepath.Dir(path)); err != nil {
		return resp, errNoAgent
	}
	conn, err := net.DialTimeout("unix", path, agentTimeout)
	if err != nil {
		return resp, errNoAgent
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(agentTimeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return resp, errors.WithStack(err)
	}
	err = json.NewDecoder(conn).Decode(&resp)
	return resp, errors.WithStack(err)
}

// makeAgentDir creates dir, which holds the socket, if needed, and checks it
// with checkAgentDir.
func makeAgentDir(dir string) error {
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return errors.WithStack(err)
	}
	return checkAgentDir(dir)
}

// checkAgentDir makes sure that dir, which holds the socket, is a directory
// (not a symbolic link) that only the user can access.
func checkAgentDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return errors.WithStack(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm() != 0700 || !ok || int(st.Uid) != os.Getuid() {
		return errors.Errorf("unsafe key agent directory: %s", dir)
	}
	return nil
}

// recordLock records that kp:lock was run at t.
func recordLock(t time.Time) error {
	path := agentFile(lockTimeFile)
	dir := filepath.Dir(path)
	if err := makeAgentDir(dir); err != nil {
		return err
	}
	// Written to a new file that is then renamed, so that the agent never
	// reads it half written.
	f, err := os.CreateTemp(dir, lockTimeFile+".*")
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = f.WriteString(t.Format(time.RFC3339Nano))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return errors.WithStack(err)
}

// lockedSince reports whether kp:lock has been run at or after t.
func lockedSince(t time.Time) bool {
	b, err := os.ReadFile(agentFile(lockTimeFile))
	if err != nil {
		return false
	}
	locked, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(b)))
	return err == nil && !locked.Before(t)
}

func keyAgentMain(cmd *cobra.Command, args []string) {
	var req agentRequest
	exitOnError(errors.WithStack(json.NewDecoder(os.Stdin).Decode(&req)))
	defer clear(req.Key)
	ln, release, err := listenAgent(agentSocket(), req)
	exitOnError(err)
	if ln == nil {
		return // another agent took the key
	}
	defer release()
	agent := newKeyAgent(systemClock{}, screenLocked, lockedSince)
	// Only now that the agent listens, so that kp:lock either has been
	// recorded already or reaches the agent: see keyAgent.put.
	agent.put(req)
	clear(req.Key)
	serveKeyAgent(ln, agent, agentCheckInterval)
}

var errAgentRunning = errors.New("another key agent is running")

// listenAgent makes this process the key agent and returns the listener on
// the socket at path, and a function that lets go of the agent lock once the
// listener is closed. The running agent holds the lock, so that there is
// never more than one, and only it creates or removes the socket. If another
// agent is running, listenAgent hands it req instead and returns no listener.
func listenAgent(path string, req agentRequest) (*net.UnixListener, func(), error) {
	dir := filepath.Dir(path)
	if err := makeAgentDir(dir); err != nil {
		return nil, nil, err
	}
	deadline := time.Now().Add(agentStartTimeout)
	for {
		lock, err := lockAgent(filepath.Join(dir, agentLockFile))
		if err == nil {
			// Without a running agent, a socket at path was left behind by
			// one that did not exit cleanly.
			os.Remove(path)
			ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				lock.Close()
				return nil, nil, errors.WithStack(err)
			}
			return ln, func() { lock.Close() }, nil
		}
		if !errors.Is(err, errAgentRunning) {
			return nil, nil, err
		}
		if _, err := askAgent(req); err == nil {
			return nil, nil, nil
		}
		// The running agent is busy, or exiting.
		if time.Now().After(deadline) {
			return nil, nil, errors.New("another key agent is running but does not answer")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// lockAgent takes the agent lock at path, which is released when the
// returned file is closed or the process exits. It returns errAgentRunning
// if another agent holds the lock.
func lockAgent(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errAgentRunning
		}
		return nil, errors.WithStack(err)
	}
	return f, nil
}

// serveKeyAgent answers requests on ln until agent no longer holds a key.
func serveKeyAgent(ln *net.UnixListener, agent *keyAgent, checkInterval time.Duration) {
	// Closing the listener removes the socket.
	stop := sync.OnceFunc(func() { ln.Close() })
	defer stop()

	done := make(chan struct{})
	defer close(done)
	conns := make(chan *net.UnixConn)
	go func() {
		defer close(conns)
		for {
			conn, err := ln.AcceptUnix()
			if err != nil {
				return
			}
			select {
			case conns <- conn:
			case <-done:
				conn.Close()
				return
			}
		}
	}()

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for agent.check() {
		select {
		case <-ticker.C:
		case conn, ok := <-conns:
			if !ok {
				agent.wipe()
				return
			}
			resp := agent.request(conn)
			if !agent.holding() {
				// Stop listening before replying, so that the next run of
				// the workflow does not find the socket of an exiting agent.
				stop()
			}
			if resp != nil {
				json.NewEncoder(conn).Encode(resp)
				clear(resp.Key)
			}
			conn.Close()
		}
	}
}

// agentClock tells the agent the time: the wall clock, and how long the Mac
// has been awake, which does not advance while it sleeps.
type agentClock interface {
	wall() time.Time
	awake() time.Duration
}

type systemClock struct{}

func (systemClock) wall() time.Time      { return time.Now().Round(0) }
func (systemClock) awake() time.Duration { return awakeTime() }

// keyAgent holds a derived key and decides when to forget it.
type keyAgent struct {
	mu           sync.Mutex
	entry        agentRequest // the put request with the key, if any
	storedWall   time.Time    // when the key was put
	storedAwake  time.Duration
	lastWall     time.Time // when the agent last checked
	lastAwake    time.Duration
	clock        agentClock
	screenLocked func() bool
	lockedSince  func(time.Time) bool
}

func newKeyAgent(clock agentClock, screenLocked func() bool, lockedSince func(time.Time) bool) *keyAgent {
	return &keyAgent{
		clock:        clock,
		screenLocked: screenLocked,
		lockedSince:  lockedSince,
		lastWall:     clock.wall(),
		lastAwake:    clock.awake(),
	}
}

// put replaces the key with the one of req, unless kp:lock has been run since
// the run of the workflow that derived it started. kp:lock records when it
// is run before it tells the agent to forget the key, so a key put before the
// record is wiped by that, and one put after is refused.
func (a *keyAgent) put(req agentRequest) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.wipeLocked()
	if a.lockedSince(req.Since) {
		return
	}
	req.Key = bytes.Clone(req.Key)
	a.entry = req
	a.storedWall, a.storedAwake = a.clock.wall(), a.clock.awake()
}

// get returns a copy of the key if it is held for the fingerprint of req,
// which it is kept for according to the settings of req from now on.
func (a *keyAgent) get(req agentRequest) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.entry.Key != nil {
		if a.entry.Fingerprint != req.Fingerprint {
			// The key is of no more use: the database was saved with a new
			// key derivation seed, or another one is opened.
			a.wipeLocked()
		} else {
			a.entry.Settings = req.Settings
		}
	}
	if !a.checkLocked() {
		return nil
	}
	return bytes.Clone(a.entry.Key)
}

// check wipes the key if it is to be forgotten by now, and reports whether
// a key is still held.
func (a *keyAgent) check() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.checkLocked()
}

func (a *keyAgent) checkLocked() bool {
	wall, awake := a.clock.wall(), a.clock.awake()
	// While the Mac sleeps, only the wall clock moves on.
	slept := wall.Sub(a.lastWall)-(awake-a.lastAwake) > agentSleepThreshold
	a.lastWall, a.lastAwake = wall, awake
	if a.entry.Key == nil {
		return false
	}
	s := a.entry.Settings
	// The time is up by either clock, so that neither sleeping nor setting
	// the wall clock back extends it.
	expired := wall.Sub(a.storedWall) >= s.TTL || awake-a.storedAwake >= s.TTL
	if expired || s.ForgetOnSleep && slept || s.ForgetOnScreenLock && a.screenLocked() {
		a.wipeLocked()
	}
	return a.entry.Key != nil
}

func (a *keyAgent) holding() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.entry.Key != nil
}

func (a *keyAgent) wipe() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.wipeLocked()
}

func (a *keyAgent) wipeLocked() {
	clear(a.entry.Key)
	a.entry = agentRequest{}
}

// request reads the request on conn and carries it out. It returns the
// response, or nil for a request that is not answered: one that cannot be
// read, or that comes from a process of another user.
func (a *keyAgent) request(conn *net.UnixConn) *agentResponse {
	conn.SetDeadline(time.Now().Add(agentTimeout))
	if uid, err := peerUID(conn); err != nil || uid != os.Getuid() {
		return nil
	}
	var req agentRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return nil
	}
	defer clear(req.Key)
	var resp agentResponse
	switch req.Op {
	case agentGet:
		resp.Key = a.get(req)
	case agentPut:
		a.put(req)
	case agentForget:
		a.wipe()
	}
	return &resp
}
