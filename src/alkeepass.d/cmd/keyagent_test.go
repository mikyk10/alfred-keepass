package cmd

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tobischo/gokeepasslib/v3"
)

func readHeader(t *testing.T, path string) *gokeepasslib.DBHeader {
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	db, err := decodeHeader(data)
	require.NoError(t, err)
	return db.Header
}

func TestKeyFingerprint(t *testing.T) {
	t.Run("KDBX 4", func(t *testing.T) {
		path := filepath.Join("testdata", "actions.kdbx")
		header := readHeader(t, path)
		fp := keyFingerprint(path, header)

		assert.Equal(t, fp, keyFingerprint(path, readHeader(t, path)))
		abs, err := filepath.Abs(path)
		require.NoError(t, err)
		assert.Equal(t, fp, keyFingerprint(abs, header), "same file")
		assert.NotEqual(t, fp, keyFingerprint("other.kdbx", header), "other file")

		header.FileHeaders.MasterSeed[0] ^= 1
		assert.Equal(t, fp, keyFingerprint(path, header), "the master seed changes on every save")
		header.FileHeaders.KdfParameters.RawData.Get("S").Value[0] ^= 1
		assert.NotEqual(t, fp, keyFingerprint(path, header), "other key derivation seed")
	})

	t.Run("KDBX 3.1", func(t *testing.T) {
		path := filepath.Join("testdata", "test.kdbx")
		header := readHeader(t, path)
		fp := keyFingerprint(path, header)
		header.FileHeaders.TransformRounds++
		assert.NotEqual(t, fp, keyFingerprint(path, header))
	})
}

// fakeClock is a clock that tests move on.
type fakeClock struct {
	w  time.Time
	up time.Duration
}

func (c *fakeClock) wall() time.Time      { return c.w }
func (c *fakeClock) awake() time.Duration { return c.up }

// sleep moves the wall clock on by d, as while the Mac sleeps.
func (c *fakeClock) sleep(d time.Duration) { c.w = c.w.Add(d) }

func TestKeyAgentForgets(t *testing.T) {
	key := []byte("derived key")
	newAgent := func(settings keyCacheSettings) (*keyAgent, *fakeClock, *bool) {
		clock := &fakeClock{w: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC), up: time.Hour}
		locked := new(bool)
		agent := newKeyAgent(clock, func() bool { return *locked }, func(time.Time) bool { return false })
		agent.put(agentRequest{Fingerprint: "fp", Key: key, Settings: settings})
		return agent, clock, locked
	}
	// wait moves the clock on by d while the Mac is awake, with the agent's
	// regular checks.
	wait := func(agent *keyAgent, clock *fakeClock, d time.Duration) bool {
		for passed := time.Duration(0); passed < d; passed += agentCheckInterval {
			clock.w = clock.w.Add(agentCheckInterval)
			clock.up += agentCheckInterval
			agent.check()
		}
		return agent.holding()
	}
	get := func(agent *keyAgent, fingerprint string, settings keyCacheSettings) []byte {
		return agent.get(agentRequest{Fingerprint: fingerprint, Settings: settings})
	}

	t.Run("after the configured time", func(t *testing.T) {
		settings := keyCacheSettings{TTL: time.Minute, ForgetOnSleep: true}
		agent, clock, _ := newAgent(settings)
		assert.True(t, wait(agent, clock, 58*time.Second))
		assert.Equal(t, key, get(agent, "fp", settings))
		held := agent.entry.Key
		assert.False(t, wait(agent, clock, 2*time.Second))
		assert.Nil(t, get(agent, "fp", settings))
		assert.Equal(t, make([]byte, len(key)), held, "the key is overwritten")
	})

	t.Run("the time asleep counts", func(t *testing.T) {
		agent, clock, _ := newAgent(keyCacheSettings{TTL: time.Minute})
		clock.sleep(time.Minute)
		assert.False(t, agent.check())
	})

	t.Run("setting the clock back does not extend the time", func(t *testing.T) {
		agent, clock, _ := newAgent(keyCacheSettings{TTL: time.Minute})
		clock.w = clock.w.Add(-time.Hour)
		assert.False(t, wait(agent, clock, time.Minute))
	})

	t.Run("when the Mac slept", func(t *testing.T) {
		agent, clock, _ := newAgent(keyCacheSettings{TTL: time.Hour, ForgetOnSleep: true})
		assert.True(t, wait(agent, clock, 10*time.Second))
		clock.sleep(10 * time.Second) // shorter than the time between checks would be awake
		assert.False(t, agent.check())
	})

	t.Run("a sleep is noticed by the next request", func(t *testing.T) {
		settings := keyCacheSettings{TTL: time.Hour, ForgetOnSleep: true}
		agent, clock, _ := newAgent(settings)
		clock.sleep(time.Minute)
		assert.Nil(t, get(agent, "fp", settings))
	})

	t.Run("sleep is ignored unless configured", func(t *testing.T) {
		agent, clock, _ := newAgent(keyCacheSettings{TTL: time.Hour})
		clock.sleep(time.Minute)
		assert.True(t, agent.check())
	})

	t.Run("when the screen locks", func(t *testing.T) {
		agent, clock, locked := newAgent(keyCacheSettings{TTL: time.Hour, ForgetOnScreenLock: true})
		assert.True(t, wait(agent, clock, 10*time.Second))
		*locked = true
		assert.False(t, wait(agent, clock, agentCheckInterval))
	})

	t.Run("screen lock is ignored unless configured", func(t *testing.T) {
		agent, clock, locked := newAgent(keyCacheSettings{TTL: time.Hour})
		*locked = true
		assert.True(t, wait(agent, clock, 10*time.Second))
	})

	t.Run("a request applies the current settings", func(t *testing.T) {
		agent, clock, _ := newAgent(keyCacheSettings{TTL: time.Hour})
		assert.True(t, wait(agent, clock, 2*time.Minute))
		assert.Nil(t, get(agent, "fp", keyCacheSettings{TTL: time.Minute}), "the time is shortened")

		agent, clock, _ = newAgent(keyCacheSettings{TTL: time.Hour})
		assert.Equal(t, key, get(agent, "fp", keyCacheSettings{TTL: time.Hour, ForgetOnSleep: true}))
		clock.sleep(time.Minute)
		assert.False(t, agent.check(), "forgetting on sleep is turned on")
	})

	t.Run("a request for another database wipes the key", func(t *testing.T) {
		settings := keyCacheSettings{TTL: time.Hour}
		agent, _, _ := newAgent(settings)
		held := agent.entry.Key
		assert.Nil(t, get(agent, "other", settings))
		assert.False(t, agent.holding())
		assert.Equal(t, make([]byte, len(key)), held, "the key is overwritten")
	})

	t.Run("a new key replaces the old one", func(t *testing.T) {
		settings := keyCacheSettings{TTL: time.Minute}
		agent, clock, _ := newAgent(settings)
		held := agent.entry.Key
		assert.True(t, wait(agent, clock, 50*time.Second))
		agent.put(agentRequest{Fingerprint: "fp2", Key: []byte("new key"), Settings: settings})
		assert.Equal(t, make([]byte, len(key)), held, "the old key is overwritten")
		assert.True(t, wait(agent, clock, 50*time.Second), "the time starts again")
		assert.Equal(t, []byte("new key"), get(agent, "fp2", settings))
	})

	t.Run("a key derived before kp:lock is refused", func(t *testing.T) {
		lockTime := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
		clock := &fakeClock{w: lockTime}
		agent := newKeyAgent(clock, func() bool { return false }, func(since time.Time) bool { return !lockTime.Before(since) })
		settings := keyCacheSettings{TTL: time.Hour}
		agent.put(agentRequest{Fingerprint: "fp", Key: key, Settings: settings, Since: lockTime.Add(time.Second)})
		held := agent.entry.Key
		require.True(t, agent.holding())

		agent.put(agentRequest{Fingerprint: "fp2", Key: []byte("new key"), Settings: settings, Since: lockTime.Add(-time.Second)})
		assert.False(t, agent.holding())
		assert.Equal(t, make([]byte, len(key)), held, "the key held before is overwritten too")
	})
}

// useInProcessAgent makes cacheKey start the key agent in this process
// instead of as a process of its own, and returns how many were started.
func useInProcessAgent(t *testing.T) *int {
	if !keyAgentSupported {
		t.Skip("this build cannot run the key agent")
	}
	started := 0
	var wg sync.WaitGroup
	orig := startKeyAgent
	startKeyAgent = func(req agentRequest) error {
		ln, release, err := listenAgent(agentSocket(), req)
		if err != nil || ln == nil {
			return err
		}
		started++
		agent := newKeyAgent(systemClock{}, func() bool { return false }, lockedSince)
		agent.put(req)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer release()
			serveKeyAgent(ln, agent, 10*time.Millisecond)
		}()
		return nil
	}
	t.Cleanup(func() {
		forgetCachedKey()
		wg.Wait()
		startKeyAgent = orig
	})
	return &started
}

// agentGone reports whether no agent is listening any more.
func agentGone() bool {
	_, err := os.Stat(agentSocket())
	return os.IsNotExist(err)
}

func TestKeyAgentSocket(t *testing.T) {
	started := useInProcessAgent(t)
	settings := keyCacheSettings{TTL: time.Minute}

	assert.Nil(t, cachedKey("fp", settings), "no agent is running")
	assert.NoError(t, forgetCachedKey(), "nothing to forget")

	require.NoError(t, cacheKey("fp", []byte("key 1"), settings, time.Now()))
	assert.Equal(t, 1, *started)
	assert.Equal(t, []byte("key 1"), cachedKey("fp", settings))

	require.NoError(t, cacheKey("fp2", []byte("key 2"), settings, time.Now()))
	assert.Equal(t, 1, *started, "the running agent takes the new key")
	assert.Equal(t, []byte("key 2"), cachedKey("fp2", settings))

	assert.Nil(t, cachedKey("fp", settings))
	assert.True(t, agentGone(), "a key for another database is of no more use")

	require.NoError(t, cacheKey("fp", []byte("key 3"), settings, time.Now()))
	assert.Equal(t, 2, *started, "started once the exiting agent is gone")
	assert.Equal(t, []byte("key 3"), cachedKey("fp", settings))

	require.NoError(t, forgetCachedKey())
	assert.True(t, agentGone(), "the agent stops listening before it replies")
	assert.Nil(t, cachedKey("fp", settings))

	require.NoError(t, cacheKey("fp", []byte("key 4"), settings, time.Now()))
	assert.Nil(t, cachedKey("fp", keyCacheSettings{TTL: time.Nanosecond}), "the current settings apply")
	assert.True(t, agentGone())
}

func TestKeyAgentSingleInstance(t *testing.T) {
	useInProcessAgent(t)
	settings := keyCacheSettings{TTL: time.Minute}
	timeout := agentStartTimeout
	agentStartTimeout = 200 * time.Millisecond
	t.Cleanup(func() { agentStartTimeout = timeout })

	t.Run("an agent started meanwhile hands its key to the running one", func(t *testing.T) {
		require.NoError(t, cacheKey("fp", []byte("key 1"), settings, time.Now()))
		ln, _, err := listenAgent(agentSocket(), agentRequest{
			Op: agentPut, Fingerprint: "fp2", Key: []byte("key 2"), Settings: settings, Since: time.Now(),
		})
		require.NoError(t, err)
		assert.Nil(t, ln)
		assert.Equal(t, []byte("key 2"), cachedKey("fp2", settings))
		require.NoError(t, forgetCachedKey())
	})

	t.Run("an agent that does not answer is not replaced", func(t *testing.T) {
		// Wait for the agent of the last test to let go of the lock.
		var lock *os.File
		require.Eventually(t, func() bool {
			var err error
			lock, err = lockAgent(agentFile(agentLockFile))
			return err == nil
		}, 2*time.Second, 10*time.Millisecond)
		defer lock.Close()
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: agentSocket(), Net: "unix"})
		require.NoError(t, err)
		defer ln.Close()
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				conn.Close()
			}
		}()
		socket, err := os.Stat(agentSocket())
		require.NoError(t, err)

		err = cacheKey("fp", []byte("key"), settings, time.Now())
		assert.ErrorContains(t, err, "does not answer")
		current, err := os.Stat(agentSocket())
		if assert.NoError(t, err) {
			assert.True(t, os.SameFile(socket, current), "the socket is left alone")
		}
	})

	t.Run("a socket left behind is replaced", func(t *testing.T) {
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: agentSocket(), Net: "unix"})
		require.NoError(t, err)
		ln.SetUnlinkOnClose(false)
		ln.Close()
		require.False(t, agentGone())

		require.NoError(t, cacheKey("fp", []byte("key"), settings, time.Now()))
		assert.Equal(t, []byte("key"), cachedKey("fp", settings))
	})
}

func TestLock(t *testing.T) {
	useInProcessAgent(t)
	settings := keyCacheSettings{TTL: time.Minute}
	locks := 0
	lockErr := error(nil)
	orig := lockKeychain
	lockKeychain = func() error {
		locks++
		return lockErr
	}
	t.Cleanup(func() { lockKeychain = orig })

	require.NoError(t, cacheKey("fp", []byte("key"), settings, time.Now()))
	assert.NoError(t, lock())
	assert.True(t, agentGone(), "the cached key is forgotten")
	assert.Equal(t, 1, locks, "the keychain is locked")

	assert.NoError(t, lock(), "nothing cached")
	assert.Equal(t, 2, locks, "the keychain is locked all the same")

	lockErr = errors.New("cannot lock")
	assert.ErrorContains(t, lock(), "cannot lock")
	lockErr = nil

	t.Run("a key derived before is not cached", func(t *testing.T) {
		since := time.Now()
		require.NoError(t, lock())
		require.NoError(t, cacheKey("fp", []byte("key"), settings, since))
		assert.Nil(t, cachedKey("fp", settings), "by an agent started afterwards")

		require.NoError(t, cacheKey("fp", []byte("key"), settings, time.Now()))
		since = time.Now()
		require.NoError(t, recordLock(time.Now()))
		require.NoError(t, cacheKey("fp2", []byte("key 2"), settings, since))
		assert.Nil(t, cachedKey("fp2", settings), "by a running agent")
		assert.True(t, agentGone(), "which forgets the key it held")

		time.Sleep(time.Millisecond)
		require.NoError(t, cacheKey("fp", []byte("key"), settings, time.Now()))
		assert.Equal(t, []byte("key"), cachedKey("fp", settings), "a key derived afterwards is cached")
	})
}

func TestKeyAgentExpires(t *testing.T) {
	useInProcessAgent(t)
	settings := keyCacheSettings{TTL: 100 * time.Millisecond}
	require.NoError(t, cacheKey("fp", []byte("key"), settings, time.Now()))
	assert.Equal(t, []byte("key"), cachedKey("fp", settings))
	assert.Eventually(t, agentGone, 2*time.Second, 10*time.Millisecond)
	assert.Nil(t, cachedKey("fp", settings))
}

func TestKeyAgentUnsafeDirectory(t *testing.T) {
	dir := filepath.Dir(agentSocket())
	require.NoError(t, os.MkdirAll(dir, 0700))
	require.NoError(t, os.Chmod(dir, 0755))
	t.Cleanup(func() { os.Chmod(dir, 0700) })

	_, _, err := listenAgent(agentSocket(), agentRequest{Op: agentPut})
	assert.ErrorContains(t, err, "unsafe key agent directory")
	_, err = askAgent(agentRequest{Op: agentGet})
	assert.ErrorIs(t, err, errNoAgent)
	assert.ErrorContains(t, recordLock(time.Now()), "unsafe key agent directory")
}

func TestOpenConfiguredDatabaseCachesKey(t *testing.T) {
	started := useInProcessAgent(t)
	dbPath := writeYubiKeyDatabase(t, "Abc12345", testSecret)
	yubikey := &fakeYubiKey{secrets: map[int][]byte{2: testSecret}}
	useReaders(t, fakeReaders{"YubiKey": yubikey})
	reads := useWorkflow(t, dbPath, "Abc12345", map[string]string{
		yubikeySlotVariable:     "2",
		keyCacheMinutesVariable: "5",
	})

	alf := runSearch([]string{"Entry1"})
	assert.Equal(t, "Entry1", alf.Items[0].Title)
	assert.Equal(t, 1, *reads)
	assert.Equal(t, 1, yubikey.challenges)
	assert.Equal(t, 1, *started)

	// The cached key opens the database without the keychain or the
	// YubiKey, even while the keychain is locked.
	keychainLocked = func() (bool, error) { return true, nil }
	alf = runSearch([]string{"Entry1"})
	assert.Equal(t, "Entry1", alf.Items[0].Title)
	_, entry, err := openConfiguredEntry("Entry1")
	if assert.NoError(t, err) {
		assert.Equal(t, "Entry1", entry.GetTitle())
	}
	assert.Equal(t, 1, *reads)
	assert.Equal(t, 1, yubikey.challenges)

	// kp:lock
	require.NoError(t, forgetCachedKey())
	alf = runSearch([]string{"Entry1"})
	assert.Equal(t, "locked", alf.Items[0].Uid)

	keychainLocked = func() (bool, error) { return false, nil }
	alf = runSearch([]string{"Entry1"})
	assert.Equal(t, "Entry1", alf.Items[0].Title)
	assert.Equal(t, 2, *reads)
	assert.Equal(t, 2, yubikey.challenges)
	assert.Equal(t, 2, *started)
}

// A run of the workflow waiting for the YubiKey when kp:lock is run does not
// cache the key it derives.
func TestOpenConfiguredDatabaseLockedMeanwhile(t *testing.T) {
	useInProcessAgent(t)
	orig := lockKeychain
	lockKeychain = func() error { return nil }
	t.Cleanup(func() { lockKeychain = orig })
	dbPath := writeYubiKeyDatabase(t, "Abc12345", testSecret)
	yubikey := &fakeYubiKey{secrets: map[int][]byte{2: testSecret}}
	yubikey.onChallenge = func() { require.NoError(t, lock()) }
	useReaders(t, fakeReaders{"YubiKey": yubikey})
	useWorkflow(t, dbPath, "Abc12345", map[string]string{
		yubikeySlotVariable:     "2",
		keyCacheMinutesVariable: "5",
	})

	alf := runSearch([]string{"Entry1"})
	assert.Equal(t, "Entry1", alf.Items[0].Title, "the database is open all the same")
	assert.Nil(t, cachedKey(keyFingerprint(dbPath, readHeader(t, dbPath)), keyCacheSettings{TTL: 5 * time.Minute}))

	yubikey.onChallenge = nil
	runSearch([]string{"Entry1"})
	runSearch([]string{"Entry1"})
	assert.Equal(t, 2, yubikey.challenges, "a run started afterwards caches the key")
}

func TestOpenConfiguredDatabaseReplacesStaleKey(t *testing.T) {
	useInProcessAgent(t)
	dbPath := filepath.Join("testdata", "actions.kdbx")
	reads := useWorkflow(t, dbPath, "Abc12345", map[string]string{keyCacheMinutesVariable: "5"})
	fp := keyFingerprint(dbPath, readHeader(t, dbPath))
	settings := keyCacheSettings{TTL: 5 * time.Minute, ForgetOnSleep: true, ForgetOnScreenLock: true}
	require.NoError(t, cacheKey(fp, make([]byte, 32), settings, time.Now()))

	db, err := openConfiguredDatabase(false)
	require.NoError(t, err)
	assert.Equal(t, 1, *reads, "opened with the master password instead")
	assert.Equal(t, db.Credentials.TransformedKey, cachedKey(fp, settings))
}

func TestOpenConfiguredDatabaseWithoutCache(t *testing.T) {
	started := useInProcessAgent(t)
	dbPath := filepath.Join("testdata", "actions.kdbx")
	fp := keyFingerprint(dbPath, readHeader(t, dbPath))
	require.NoError(t, cacheKey(fp, []byte("cached before"), keyCacheSettings{TTL: time.Minute}, time.Now()))
	reads := useWorkflow(t, dbPath, "Abc12345", map[string]string{keyCacheMinutesVariable: "0"})

	for range 2 {
		_, err := openConfiguredDatabase(false)
		require.NoError(t, err)
	}
	assert.Equal(t, 2, *reads)
	assert.Equal(t, 1, *started, "no agent is started")
	assert.True(t, agentGone(), "turning the cache off forgets the cached key")
}
