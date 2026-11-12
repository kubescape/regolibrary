package gitregostore

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	opapolicy "github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const waitForServer = 5 * time.Second

// releaseBodies is the minimal, valid content of every unverified release artifact.
var releaseBodies = map[string]string{
	"frameworks":            `[{"name":"new-fw"}]`,
	"security_frameworks":   `[]`,
	"controls":              `[{"name":"new-control"}]`,
	"rules":                 `[{"name":"new-rule"}]`,
	"attack_tracks":         `[]`,
	"FWName_CID_CName":      "a,b\n1,2\n",
	"ControlID_RuleName":    "a,b\n1,2\n",
	"default_config_inputs": `{}`,
	"exceptions":            `[]`,
}

// releaseServer serves a release without checksums (404 on checksums.txt, so the unverified path is used).
// Paths in hang block until the client aborts the request; the name of every such request that ended is
// reported on terminated, so tests can prove that the underlying request really terminated.
type releaseServer struct {
	*httptest.Server
	terminated chan string

	mu       sync.Mutex
	hang     map[string]bool
	extra    map[string]string
	requests []string
}

func newReleaseServer(t *testing.T, hang ...string) *releaseServer {
	t.Helper()

	rs := &releaseServer{
		hang:       map[string]bool{},
		extra:      map[string]string{},
		terminated: make(chan string, 64),
	}
	for _, h := range hang {
		rs.hang[h] = true
	}
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")

		rs.mu.Lock()
		rs.requests = append(rs.requests, name)
		hang := rs.hang[name]
		body, ok := rs.extra[name]
		rs.mu.Unlock()

		if hang {
			<-r.Context().Done() // only returns once the client aborted the request
			rs.terminated <- name
			return
		}
		if !ok {
			body, ok = releaseBodies[name]
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(rs.Close)
	return rs
}

func (rs *releaseServer) requested(name string) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, r := range rs.requests {
		if r == name {
			return true
		}
	}
	return false
}

func (rs *releaseServer) stopHanging() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.hang = map[string]bool{}
}

func (rs *releaseServer) store() *GitRegoStore {
	return &GitRegoStore{
		URL:                 rs.URL,
		httpClient:          rs.Client(),
		StripFilesExtension: true,
	}
}

func (rs *releaseServer) waitTerminated(t *testing.T, name string) {
	t.Helper()
	select {
	case got := <-rs.terminated:
		assert.Equal(t, name, got)
	case <-time.After(waitForServer):
		t.Fatalf("server-side request for %q was not terminated", name)
	}
}

// oldStore returns a store that already holds data from an earlier, successful pull.
func (rs *releaseServer) oldStore() *GitRegoStore {
	gs := rs.store()
	gs.Frameworks = []opapolicy.Framework{{}}
	gs.Frameworks[0].Name = "old-fw"
	gs.Controls = []opapolicy.Control{{}}
	gs.Controls[0].Name = "old-control"
	gs.Rules = []opapolicy.PolicyRule{{}}
	gs.Rules[0].Name = "old-rule"
	return gs
}

func assertStoreUntouched(t *testing.T, gs *GitRegoStore) {
	t.Helper()
	require.Len(t, gs.Frameworks, 1)
	assert.Equal(t, "old-fw", gs.Frameworks[0].Name)
	require.Len(t, gs.Controls, 1)
	assert.Equal(t, "old-control", gs.Controls[0].Name)
	require.Len(t, gs.Rules, 1)
	assert.Equal(t, "old-rule", gs.Rules[0].Name)
	assert.Empty(t, gs.AttackTracks)
	assert.Empty(t, gs.SystemPostureExceptionPolicies)
}

func TestSetRegoObjectsWithContextSuccess(t *testing.T) {
	rs := newReleaseServer(t)
	gs := rs.store()

	require.NoError(t, gs.SetRegoObjectsWithContext(context.Background()))

	require.Len(t, gs.Frameworks, 1)
	assert.Equal(t, "new-fw", gs.Frameworks[0].Name)
	require.Len(t, gs.Controls, 1)
	assert.Equal(t, "new-control", gs.Controls[0].Name)
	require.Len(t, gs.Rules, 1)
	assert.Equal(t, "new-rule", gs.Rules[0].Name)
	assert.True(t, rs.requested("checksums.txt"), "checksums must be attempted first")
}

func TestSetRegoObjectsLegacyEntryPointStillWorks(t *testing.T) {
	rs := newReleaseServer(t)
	gs := rs.store()

	require.NoError(t, gs.SetRegoObjects())
	require.Len(t, gs.Rules, 1)
}

// A server that accepts the TCP connection but never answers must not block the download forever.
func TestDownloadTimesOutWhenServerNeverResponds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	connClosed := make(chan struct{})
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			if _, readErr := conn.Read(buf); readErr != nil { // fails once the client closes the connection
				close(connClosed)
				return
			}
		}
	}()

	gs := &GitRegoStore{
		URL:                 "http://" + ln.Addr().String(),
		httpClient:          &http.Client{},
		StripFilesExtension: true,
		requestTimeout:      200 * time.Millisecond,
	}

	start := time.Now()
	err = gs.SetRegoObjectsWithContext(context.Background())
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, elapsed, waitForServer)
	assert.Empty(t, gs.Frameworks)

	select {
	case <-connClosed:
	case <-time.After(waitForServer):
		t.Fatal("the client never closed the connection: the underlying request was not terminated")
	}
}

func TestDownloadCancelledWhileInProgress(t *testing.T) {
	rs := newReleaseServer(t, "controls")
	gs := rs.oldStore()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- gs.SetRegoObjectsWithContext(ctx) }()

	// wait for the hanging request to reach the server, then cancel
	require.Eventually(t, func() bool { return rs.requested("controls") }, waitForServer, 5*time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
		assert.NotErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(waitForServer):
		t.Fatal("SetRegoObjectsWithContext did not return after cancellation")
	}

	rs.waitTerminated(t, "controls")
	assertStoreUntouched(t, gs)
}

// The caller's (shorter) deadline must win over the default per-request timeout.
func TestCallerDeadlineIsRespected(t *testing.T) {
	rs := newReleaseServer(t, "rules")
	gs := rs.oldStore()
	require.Zero(t, gs.requestTimeout, "the default per-request timeout must be in effect")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := gs.SetRegoObjectsWithContext(ctx)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, elapsed, waitForServer)

	rs.waitTerminated(t, "rules")
	assertStoreUntouched(t, gs)
}

// Artifacts downloaded before the failure must not be published.
func TestNoPartialDataPublishedOnFailure(t *testing.T) {
	// security_frameworks is fetched last, after every other artifact was already downloaded.
	rs := newReleaseServer(t, "security_frameworks")
	gs := rs.oldStore()
	gs.requestTimeout = 200 * time.Millisecond

	err := gs.SetRegoObjectsWithContext(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	rs.waitTerminated(t, "security_frameworks")
	assert.True(t, rs.requested("rules"), "other artifacts were downloaded before the failure")
	assertStoreUntouched(t, gs)

	// a store that never loaded anything stays empty as well
	fresh := rs.store()
	fresh.requestTimeout = 200 * time.Millisecond
	require.Error(t, fresh.SetRegoObjectsWithContext(context.Background()))
	rs.waitTerminated(t, "security_frameworks")
	assert.Empty(t, fresh.Frameworks)
	assert.Empty(t, fresh.Controls)
	assert.Empty(t, fresh.Rules)
}

// After a cancelled download the store can be refreshed again, and the unverified fallback
// (checksums.txt answering 404) keeps working.
func TestRetryAfterCancelledDownload(t *testing.T) {
	rs := newReleaseServer(t, "rules")
	gs := rs.oldStore()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, gs.SetRegoObjectsWithContext(ctx), context.DeadlineExceeded)
	rs.waitTerminated(t, "rules")
	assertStoreUntouched(t, gs)

	rs.stopHanging()

	require.NoError(t, gs.SetRegoObjectsWithContext(context.Background()))
	require.Len(t, gs.Rules, 1)
	assert.Equal(t, "new-rule", gs.Rules[0].Name)
	assert.Equal(t, "new-fw", gs.Frameworks[0].Name)
}

// A timeout while fetching the checksums must fail closed instead of falling back to unverified artifacts.
func TestTimeoutOnChecksumsDoesNotFallBackToUnverified(t *testing.T) {
	rs := newReleaseServer(t, "checksums.txt")
	gs := rs.store()
	gs.requestTimeout = 200 * time.Millisecond

	err := gs.SetRegoObjectsWithContext(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	rs.waitTerminated(t, "checksums.txt")
	assert.False(t, rs.requested("frameworks"), "artifacts must not be downloaded without verified checksums")
	assert.Empty(t, gs.Frameworks)
}

// A missing signature stays a checksum verification failure, but a timeout while fetching it must stay
// recognizable as a timeout.
func TestTimeoutOnChecksumSignatureKeepsContextError(t *testing.T) {
	rs := newReleaseServer(t, checksumsSignatureFileName)
	rs.extra[checksumsFileName] = "irrelevant"
	gs := rs.store()
	gs.requestTimeout = 200 * time.Millisecond

	_, err := gs.getReleaseChecksums(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.NotErrorIs(t, err, errHTTPNotFound)
	rs.waitTerminated(t, checksumsSignatureFileName)
}

func TestHttpGetterWithContextCancellation(t *testing.T) {
	rs := newReleaseServer(t, "rules")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := HttpGetterWithContext(ctx, rs.Client(), rs.URL+"/rules")
		errCh <- err
	}()

	require.Eventually(t, func() bool { return rs.requested("rules") }, waitForServer, 5*time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(waitForServer):
		t.Fatal("HttpGetterWithContext did not return after cancellation")
	}
	rs.waitTerminated(t, "rules")
}

func TestHttpGetterStillReturnsBodyAndNotFound(t *testing.T) {
	rs := newReleaseServer(t)

	body, err := HttpGetter(rs.Client(), rs.URL+"/rules")
	require.NoError(t, err)
	assert.Equal(t, releaseBodies["rules"], body)

	_, err = HttpGetter(rs.Client(), rs.URL+"/missing")
	assert.ErrorIs(t, err, errHTTPNotFound)
}

func TestWatchReleaseStopsWhenContextIsDone(t *testing.T) {
	gs := &GitRegoStore{Watch: true, FrequencyPullFromGitMinutes: 1}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		gs.watchRelease(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(waitForServer):
		t.Fatal("watchRelease goroutine leaked after context cancellation")
	}
}

func TestPlainFailureIsNotReportedAsCancellation(t *testing.T) {
	rs := newReleaseServer(t)
	gs := rs.store()
	gs.URL = rs.URL + "/does-not-exist"

	err := gs.SetRegoObjectsWithContext(context.Background())
	require.Error(t, err)
	assert.False(t, errors.Is(err, context.Canceled))
	assert.False(t, errors.Is(err, context.DeadlineExceeded))
}
