package gitregostore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	commonpb "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekorpb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

func Test_isControlID(t *testing.T) {
	tests := []struct {
		name string
		c    string
		want bool
	}{
		{
			name: "C-XXXX format 00",
			c:    "C-0000",
			want: true,
		},
		{
			name: "C-XXXX format 01",
			c:    "c-0000",
			want: true,
		},
		{
			name: "C-XXXX format 02",
			c:    "c-1234",
			want: true,
		},
		{
			name: "C-XXXX format 03",
			c:    "C-1234",
			want: true,
		},
		{
			name: "C-XXXX format 04",
			c:    "C-1234",
			want: true,
		},
		{
			name: "C-XXXX format 05",
			c:    "C1234",
			want: false,
		},
		{
			name: "NAME-[vVERSION]-NUMBER.[NUMBER.][NUMBER.]... format 00",
			c:    "C-12345",
			want: true,
		},
		{
			name: "NAME-[vVERSION]-NUMBER.[NUMBER.][NUMBER.]... format 01",
			c:    "C-123",
			want: true,
		},
		{
			name: "NAME-[vVERSION]-NUMBER.[NUMBER.][NUMBER.]... format 02",
			c:    "CC-1234",
			want: true,
		},
		{
			name: "NAME-[vVERSION]-NUMBER.[NUMBER.][NUMBER.]... format 03",
			c:    "CIS-v1.6.1-4.1.3",
			want: true,
		},
		{
			name: "NAME-[vVERSION]-NUMBER.[NUMBER.][NUMBER.]... format 04",
			c:    "CIS-vv1.6.1-4.1.3",
			want: false,
		},
		{
			name: "NAME-[vVERSION]-NUMBER.[NUMBER.][NUMBER.]... format 05",
			c:    "CIS-v1.6.1-v4.1.3",
			want: false,
		},
		{
			name: "NAME-[vVERSION]-NUMBER.[NUMBER.][NUMBER.]... format 06",
			c:    "CIS-v1.6.1 4.1.3",
			want: false,
		},
		{
			name: "NAME-[vVERSION]-NUMBER.[NUMBER.][NUMBER.]... format 07",
			c:    "CIS-CIS-v1.6.1-4.1.3",
			want: false,
		},
		{
			name: "NAME-[vVERSION]-NUMBER.[NUMBER.][NUMBER.]... format 08",
			c:    "CiS-v1.6.1-4.1.3",
			want: false,
		},
		{
			name: "control name 00",
			c:    "control-name-minuses",
			want: false,
		},
		{
			name: "control name 01",
			c:    "control name spaces",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isControlID(tt.c); got != tt.want {
				t.Errorf("isControlID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewGitRegoStore(t *testing.T) {
	type fields struct {
		BaseUrl    string
		Owner      string
		Repository string
		Branch     string
		Path       string
		Tag        string
	}
	tests := []struct {
		name      string
		fields    fields
		wantedURL string
	}{
		{
			name: "Check Dev gitregostore",
			fields: fields{
				BaseUrl:    "https://raw.githubusercontent.com",
				Owner:      "kubescape",
				Repository: "regolibrary-dev",
				Branch:     "main",
				Path:       "releaseDev",
				Tag:        "",
			},
			wantedURL: "https://raw.githubusercontent.com/kubescape/regolibrary-dev/main/releaseDev",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			gs := NewGitRegoStore(tt.fields.BaseUrl, tt.fields.Owner, tt.fields.Repository, tt.fields.Path, tt.fields.Tag, tt.fields.Branch, 5)
			if gs.URL != tt.wantedURL {
				t.Errorf("setURL() = %v, want %v", gs.URL, tt.wantedURL)
			}
			gs.SetRegoObjects()
			gs_tests(t, gs)

		})
	}
}

func TestSetFramework(t *testing.T) {
	gs := &GitRegoStore{}

	// Successful test case
	input := `{"name": "framework1"}`
	err := gs.setFramework(input)
	if err != nil {
		t.Errorf("Expected nil error, but got: %v", err)
	}
	if len(gs.Frameworks) != 1 {
		t.Errorf("Expected 1 framework, but got: %d", len(gs.Frameworks))
	}

	// Error test case
	input = `invalid JSON`
	expectedErr := errors.New("invalid character 'i' looking for beginning of value")
	err = gs.setFramework(input)
	if err == nil || err.Error() != expectedErr.Error() {
		t.Errorf("Expected error '%v', but got: %v", expectedErr, err)
	}
	if len(gs.Frameworks) != 1 {
		t.Errorf("Expected 1 framework, but got: %d", len(gs.Frameworks))
	}
}

func TestSetAttackTrack(t *testing.T) {
	store := &GitRegoStore{}
	// Successful test case
	respStr := `{"name": "attack_track_name"}`
	err := store.setAttackTrack(respStr)
	if err != nil {
		t.Errorf("Error setting attack track: %v", err)
	}
	if len(store.AttackTracks) != 1 {
		t.Errorf("Attack track not added to store")
	}

	// Error test case
	respStr = `invalid JSON`
	expectedErr := errors.New("invalid character 'i' looking for beginning of value")
	err = store.setAttackTrack(respStr)
	if err == nil || err.Error() != expectedErr.Error() {
		t.Errorf("Expected error '%v', but got: %v", expectedErr, err)
	}
	if len(store.AttackTracks) != 1 {
		t.Errorf("Expected 1 attack track, but got: %d", len(store.AttackTracks))
	}
}

func TestSetSystemPostureExceptionPolicy(t *testing.T) {
	store := &GitRegoStore{}
	// Successful test case
	respStr := `[{"name": "policy1"}, {"name": "policy2"}]`
	err := store.setSystemPostureExceptionPolicy(respStr)
	if err != nil {
		t.Errorf("Error setting system posture exception policy: %v", err)
	}
	if len(store.SystemPostureExceptionPolicies) != 2 {
		t.Errorf("System posture exception policies not added to store")
	}

	// Error test case
	respStr = `invalid JSON`
	expectedErr := errors.New("invalid character 'i' looking for beginning of value")
	err = store.setSystemPostureExceptionPolicy(respStr)
	if err == nil || err.Error() != expectedErr.Error() {
		t.Errorf("Expected error '%v', but got: %v", expectedErr, err)
	}
	if len(store.SystemPostureExceptionPolicies) != 2 {
		t.Errorf("Expected 2 system posture exception policies, but got: %d", len(store.SystemPostureExceptionPolicies))
	}
}

func TestSetControl(t *testing.T) {
	store := &GitRegoStore{}
	// Successful test case
	respStr := `{"name": "control_name"}`
	err := store.setControl(respStr)
	if err != nil {
		t.Errorf("Error setting control: %v", err)
	}
	if len(store.Controls) != 1 {
		t.Errorf("Control not added to store")
	}

	// Error test case
	respStr = `invalid JSON`
	expectedErr := errors.New("invalid character 'i' looking for beginning of value")
	err = store.setControl(respStr)
	if err == nil || err.Error() != expectedErr.Error() {
		t.Errorf("Expected error '%v', but got: %v", expectedErr, err)
	}
	if len(store.Controls) != 1 {
		t.Errorf("Expected 1 control, but got: %d", len(store.Controls))
	}
}

func TestVersionHasSecurityFrameworks(t *testing.T) {
	testCases := []struct {
		tag           string
		expectedValue bool
	}{
		{"download/v1.0.202", false},     // Expected: false, because tag < earliestTagWithSecurityFrameworks
		{"download/v1.0.1", false},       // Expected: false, because tag < earliestTagWithSecurityFrameworks
		{"download/v1.1.1", true},        // Expected: true, because tag > earliestTagWithSecurityFrameworks
		{"download/v1.0.283", true},      // Expected: true, because tag > earliestTagWithSecurityFrameworks
		{"download/v1.0.283-rc.0", true}, // Expected: true, because tag > earliestTagWithSecurityFrameworks
		{"download/v1.0.283-rc.2", true}, // Expected: true, because tag > earliestTagWithSecurityFrameworks
		{"download/v1.0.282-rc.0", true}, // Expected: true, because tag = earliestTagWithSecurityFrameworks
		{"download/v2.0.202", true},      // Expected: true, because tag > earliestTagWithSecurityFrameworks
		{"download/v2.0.202-rc.0", true}, // Expected: true, because tag > earliestTagWithSecurityFrameworks
		{"latest/download", true},        // Expected: true, because !hasNumbers(gs.Tag) is true
		{"/", true},                      // Expected: true, because !hasNumbers(gs.Tag) is true
		{"", true},                       // Expected: true, because !hasNumbers(gs.Tag) is true
	}

	for _, tc := range testCases {
		gs := &GitRegoStore{
			Tag: tc.tag,
		}

		actualValue := gs.versionHasSecurityFrameworks()

		if actualValue != tc.expectedValue {
			t.Errorf("For tag '%s', expected %t, but got %t", tc.tag, tc.expectedValue, actualValue)
		}
	}
}

func TestHasNumbers(t *testing.T) {
	testCases := []struct {
		input          string
		expectedResult bool
	}{
		{"download/v1.0.202", true},      // Expected: true, because input contains numbers
		{"download/v1.0.283-rc.0", true}, // Expected: true, because input contains numbers
		{"abc", false},                   // Expected: false, because input does not contain numbers
		{"123", true},                    // Expected: true, because input contains numbers
		{"!@#$%", false},                 // Expected: false, because input does not contain numbers
		{"", false},                      // Expected: false, because input is empty
		{"123abc!@#", true},              // Expected: true, because input contains numbers
		{"12 34", true},                  // Expected: true, because input contains numbers
		{" 56 ", true},                   // Expected: true, because input contains numbers
		{"", false},                      // Expected: false, because input is empty
		{"/", false},                     // Expected: false, because input does not contain numbers
		{"", false},                      // Expected: false, because input does not contain numbers
		{"latest/download", false},       // Expected: false, because input does not contain numbers

	}

	for _, tc := range testCases {
		actualResult := hasNumbers(tc.input)

		if actualResult != tc.expectedResult {
			t.Errorf("For input '%s', expected %t, but got %t", tc.input, tc.expectedResult, actualResult)
		}
	}
}

func TestSetControls(t *testing.T) {
	store := &GitRegoStore{}
	// Successful test case
	respStr := `[{"name": "control1"}, {"name": "control2"}]`
	err := store.setControls(respStr)
	if err != nil {
		t.Errorf("Error setting controls: %v", err)
	}
	if len(store.Controls) != 2 {
		t.Errorf("Controls not added to store")
	}
	if len(store.AttackTrackControls) != 0 {
		t.Errorf("Attack track controls not added to store")
	}

	// Error test case
	respStr = `invalid JSON`
	expectedErr := errors.New("invalid character 'i' looking for beginning of value")
	err = store.setControls(respStr)
	if err == nil || err.Error() != expectedErr.Error() {
		t.Errorf("Expected error '%v', but got: %v", expectedErr, err)
	}
	if len(store.Controls) != 2 {
		t.Errorf("Expected 2 controls, but got: %d", len(store.Controls))
	}

	//
	respStr = `[{"name":"TEST","attributes":{"controlTypeTags":["security","compliance"],"attackTracks":[{"attackTrack": "container","categories": ["Execution","Initial access"]},{"attackTrack": "network","categories": ["Eavesdropping","Spoofing"]}]},"description":"","remediation":"","rulesNames":["CVE-2022-0185"],"id":"C-0079","long_description":"","test":"","controlID":"C-0079","baseScore":4,"example":""}]`
	err = store.setControls(respStr)
	if err != nil {
		t.Errorf("Error setting controls: %v", err)
	}
	if len(store.Controls) != 1 {
		t.Errorf("Controls not added to store")
	}
	if len(store.AttackTrackControls) != 1 {
		t.Errorf("Attack track controls not added to store")
	}
}

func TestSetAttackTracks(t *testing.T) {
	store := &GitRegoStore{}
	// Successful test case
	respStr := `[{"name": "attack_track1"}, {"name": "attack_track2"}]`
	err := store.setAttackTracks(respStr)
	if err != nil {
		t.Errorf("Error setting attack tracks: %v", err)
	}
	if len(store.AttackTracks) != 2 {
		t.Errorf("Attack tracks added to store")
	}

	// Error test case
	respStr = `invalid JSON`
	expectedErr := errors.New("invalid character 'i' looking for beginning of value")
	err = store.setAttackTracks(respStr)
	if err == nil || err.Error() != expectedErr.Error() {
		t.Errorf("Expected error '%v', but got: %v", expectedErr, err)
	}
	if len(store.AttackTracks) != 2 {
		t.Errorf("Expected 2 attack tracks, but got: %d", len(store.AttackTracks))
	}
}

func TestParseChecksums(t *testing.T) {
	validHash := sha256.Sum256([]byte("artifact-content"))
	validDigest := hex.EncodeToString(validHash[:])

	tests := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{
			name:    "valid manifest",
			input:   fmt.Sprintf("%s frameworks\n%s rules\n", validDigest, validDigest),
			wantLen: 2,
		},
		{
			name:    "blank lines are ignored",
			input:   fmt.Sprintf("\n%s frameworks\n\n%s rules\n", validDigest, validDigest),
			wantLen: 2,
		},
		{
			name:    "invalid field count",
			input:   fmt.Sprintf("%s frameworks extra\n", validDigest),
			wantErr: true,
		},
		{
			name:    "invalid digest length",
			input:   "abcd frameworks\n",
			wantErr: true,
		},
		{
			name:    "invalid digest encoding",
			input:   fmt.Sprintf("%s frameworks\n", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
			wantErr: true,
		},
		{
			name:    "duplicate artifact",
			input:   fmt.Sprintf("%s frameworks\n%s frameworks\n", validDigest, validDigest),
			wantErr: true,
		},
		{
			name:    "empty manifest",
			input:   "\n\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseChecksums(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(got) != tt.wantLen {
				t.Fatalf("got %d checksums, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestVerifyChecksum(t *testing.T) {
	content := "artifact-content"
	hash := sha256.Sum256([]byte(content))
	validDigest := hex.EncodeToString(hash[:])

	tests := []struct {
		name           string
		expectedDigest string
		wantErr        bool
	}{
		{
			name:           "matching checksum",
			expectedDigest: validDigest,
		},
		{
			name:           "uppercase checksum",
			expectedDigest: strings.ToUpper(validDigest),
		},
		{
			name: "mismatching checksum",
			expectedDigest: func() string {
				h := sha256.Sum256([]byte("tampered"))
				return hex.EncodeToString(h[:])
			}(),
			wantErr: true,
		},
		{
			name:           "invalid checksum",
			expectedDigest: "invalid",
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyChecksum(content, tt.expectedDigest)

			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestHTTPRespToStringNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}

	_, err = HTTPRespToString(resp)
	if !errors.Is(err, errHTTPNotFound) {
		t.Fatalf("got error %v, want errHTTPNotFound", err)
	}
}

func TestGetVerifiedReleaseArtifact(t *testing.T) {
	content := "verified artifact"
	hash := sha256.Sum256([]byte(content))
	digest := hex.EncodeToString(hash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/frameworks" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(content))
	}))
	defer server.Close()

	gs := &GitRegoStore{
		URL:                 server.URL,
		httpClient:          http.DefaultClient,
		StripFilesExtension: true,
	}

	checksums := map[string]string{
		"frameworks": digest,
	}

	got, err := gs.getVerifiedReleaseArtifact("frameworks.json", checksums)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != content {
		t.Fatalf("got %q, want %q", got, content)
	}
}

func TestGetVerifiedReleaseArtifactChecksumMismatch(t *testing.T) {
	content := "tampered artifact"
	expectedContent := "original artifact"
	hash := sha256.Sum256([]byte(expectedContent))
	digest := hex.EncodeToString(hash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(content))
	}))
	defer server.Close()

	gs := &GitRegoStore{
		URL:                 server.URL,
		httpClient:          http.DefaultClient,
		StripFilesExtension: true,
	}

	checksums := map[string]string{
		"frameworks": digest,
	}

	_, err := gs.getVerifiedReleaseArtifact("frameworks.json", checksums)
	if err == nil {
		t.Fatal("expected checksum mismatch error, got nil")
	}

	if !errors.Is(err, ErrChecksumVerification) {
		t.Fatalf("expected checksum verification error, got %v", err)
	}
}

func TestGetVerifiedReleaseArtifactMissingChecksum(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("artifact should not be downloaded when checksum is missing")
	}))
	defer server.Close()

	gs := &GitRegoStore{
		URL:        server.URL,
		httpClient: http.DefaultClient,
	}

	_, err := gs.getVerifiedReleaseArtifact(
		"frameworks.json",
		map[string]string{},
	)
	if err == nil {
		t.Fatal("expected missing checksum error, got nil")
	}

	if !errors.Is(err, ErrChecksumVerification) {
		t.Fatalf("expected checksum verification error, got %v", err)
	}
}

func TestGetReleaseChecksumsMissingSignature(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + checksumsFileName:
			_, _ = w.Write([]byte("not-a-valid-checksum-entry"))
		case "/" + checksumsSignatureFileName:
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	gs := &GitRegoStore{
		URL:        server.URL,
		httpClient: http.DefaultClient,
	}

	_, err := gs.getReleaseChecksums()
	if err == nil {
		t.Fatal("expected missing signature error, got nil")
	}

	if !errors.Is(err, ErrChecksumVerification) {
		t.Fatalf("expected checksum verification error, got %v", err)
	}
}

func TestGetReleaseChecksumsInvalidSignatureBundle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + checksumsFileName:
			_, _ = w.Write([]byte("not-a-valid-checksum-entry"))
		case "/" + checksumsSignatureFileName:
			_, _ = w.Write([]byte("not-valid-json"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	gs := &GitRegoStore{
		URL:        server.URL,
		httpClient: http.DefaultClient,
	}

	_, err := gs.getReleaseChecksums()
	if err == nil {
		t.Fatal("expected invalid signature bundle error, got nil")
	}

	if !errors.Is(err, ErrChecksumVerification) {
		t.Fatalf("expected checksum verification error, got %v", err)
	}
}

func TestGetReleaseChecksumsMissingSignatureBundleIsVerificationFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + checksumsFileName:
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("sha256  artifact.tar.gz\\n"))

		case "/" + checksumsSignatureFileName:
			http.NotFound(w, r)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	gs := &GitRegoStore{
		URL:        server.URL,
		httpClient: server.Client(),
	}

	_, err := gs.getReleaseChecksums()
	if err == nil {
		t.Fatal("expected checksum verification error")
	}

	if !errors.Is(err, ErrChecksumVerification) {
		t.Fatalf("expected ErrChecksumVerification, got %v", err)
	}

	if errors.Is(err, errHTTPNotFound) {
		t.Fatalf(
			"missing signature bundle must not expose errHTTPNotFound: %v",
			err,
		)
	}
}

func TestFetchTrustedRootRetriesAfterFailureAndCachesSuccess(t *testing.T) {
	trustedRootCache.mu.Lock()
	trustedRootCache.material = nil
	trustedRootCache.ok = false
	trustedRootCache.mu.Unlock()

	originalFetcher := fetchTrustedRootFromSigstore

	defer func() {
		fetchTrustedRootFromSigstore = originalFetcher

		trustedRootCache.mu.Lock()
		trustedRootCache.material = nil
		trustedRootCache.ok = false
		trustedRootCache.mu.Unlock()
	}()

	var calls int

	fetchTrustedRootFromSigstore = func(_ *tuf.Options) (*root.TrustedRoot, error) {
		calls++

		if calls == 1 {
			return nil, errors.New("temporary TUF failure")
		}

		return &root.TrustedRoot{}, nil
	}

	_, err := fetchTrustedRoot()
	if err == nil {
		t.Fatal("expected first trusted-root fetch to fail")
	}

	if calls != 1 {
		t.Fatalf("expected 1 fetch call, got %d", calls)
	}

	_, err = fetchTrustedRoot()
	if err != nil {
		t.Fatalf("expected retry to succeed, got %v", err)
	}

	if calls != 2 {
		t.Fatalf(
			"expected failed fetch not to be cached; got %d calls",
			calls,
		)
	}

	_, err = fetchTrustedRoot()
	if err != nil {
		t.Fatalf("expected cached trusted root, got %v", err)
	}

	if calls != 2 {
		t.Fatalf(
			"expected successful trusted root to be cached; got %d calls",
			calls,
		)
	}
}

func TestFetchTrustedRootWithReadOnlyHome(t *testing.T) {
	trustedRootCache.mu.Lock()
	trustedRootCache.material = nil
	trustedRootCache.ok = false
	trustedRootCache.mu.Unlock()

	originalFetcher := fetchTrustedRootFromSigstore
	originalHome := os.Getenv("HOME")

	defer func() {
		fetchTrustedRootFromSigstore = originalFetcher

		if err := os.Setenv("HOME", originalHome); err != nil {
			t.Fatalf("failed to restore HOME: %v", err)
		}

		trustedRootCache.mu.Lock()
		trustedRootCache.material = nil
		trustedRootCache.ok = false
		trustedRootCache.mu.Unlock()
	}()

	home, err := os.MkdirTemp("", "sigstore-readonly-home-*")
	if err != nil {
		t.Fatalf("failed to create temporary HOME: %v", err)
	}

	defer func() {
		if err := os.Chmod(home, 0o700); err != nil {
			t.Errorf("failed to restore HOME permissions: %v", err)
		}

		if err := os.RemoveAll(home); err != nil {
			t.Errorf("failed to remove temporary HOME: %v", err)
		}
	}()

	if err := os.Chmod(home, 0o500); err != nil {
		t.Fatalf("failed to make HOME read-only: %v", err)
	}

	if err := os.Setenv("HOME", home); err != nil {
		t.Fatalf("failed to set HOME: %v", err)
	}

	var called bool

	fetchTrustedRootFromSigstore = func(opts *tuf.Options) (*root.TrustedRoot, error) {
		called = true

		if !opts.DisableLocalCache {
			t.Fatal("expected local TUF cache to be disabled")
		}

		return &root.TrustedRoot{}, nil
	}

	_, err = fetchTrustedRoot()
	if err != nil {
		t.Fatalf("expected trusted-root fetch to succeed with read-only HOME: %v", err)
	}

	if !called {
		t.Fatal("expected trusted-root fetcher to be called")
	}
}

func TestVerifyChecksumManifestSignatureJSONBundle(t *testing.T) {
	manifest := []byte("sha256  artifact.tar.gz\n")
	identity := "https://github.com/kubescape/regolibrary/.github/workflows/create-release-v2.yaml@refs/tags/v1.2.3-rc.1"
	issuer := "https://token.actions.githubusercontent.com"

	virtualSigstore, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("failed to create virtual Sigstore: %v", err)
	}

	entity, err := virtualSigstore.SignAtTime(
		identity,
		issuer,
		manifest,
		time.Now(),
	)
	if err != nil {
		t.Fatalf("failed to sign manifest: %v", err)
	}

	verificationContent, err := entity.VerificationContent()
	if err != nil {
		t.Fatalf("failed to get verification content: %v", err)
	}

	certificate, ok := verificationContent.(*bundle.Certificate)
	if !ok {
		t.Fatalf("expected certificate verification content, got %T", verificationContent)
	}

	signatureContent, err := entity.SignatureContent()
	if err != nil {
		t.Fatalf("failed to get signature content: %v", err)
	}

	messageSignature, ok := signatureContent.(*bundle.MessageSignature)
	if !ok {
		t.Fatalf("expected message signature content, got %T", signatureContent)
	}

	timestamps, err := entity.Timestamps()
	if err != nil {
		t.Fatalf("failed to get timestamps: %v", err)
	}

	tlogEntries, err := entity.TlogEntries()
	if err != nil {
		t.Fatalf("failed to get transparency log entries: %v", err)
	}

	protoEntries := make([]*rekorpb.TransparencyLogEntry, 0, len(tlogEntries))
	rekorLogID, err := virtualSigstore.RekorLogID()
	if err != nil {
		t.Fatalf("failed to get Rekor log ID: %v", err)
	}

	for _, entry := range tlogEntries {
		protoEntry := entry.TransparencyLogEntry()

		inclusionProof, err := virtualSigstore.GetInclusionProof(
			protoEntry.CanonicalizedBody,
		)
		if err != nil {
			t.Fatalf("failed to generate inclusion proof: %v", err)
		}

		hashes := make([][]byte, 0, len(inclusionProof.Hashes))
		for _, hash := range inclusionProof.Hashes {
			decodedHash, err := hex.DecodeString(hash)
			if err != nil {
				t.Fatalf("failed to decode inclusion proof hash: %v", err)
			}
			hashes = append(hashes, decodedHash)
		}

		rootHash, err := hex.DecodeString(*inclusionProof.RootHash)
		if err != nil {
			t.Fatalf("failed to decode inclusion proof root hash: %v", err)
		}

		protoEntry.KindVersion = &rekorpb.KindVersion{
			Kind:    "hashedrekord",
			Version: "0.0.1",
		}

		signedEntryTimestamp, err := virtualSigstore.RekorSignPayload(
			tlog.RekorPayload{
				Body:           protoEntry.CanonicalizedBody,
				IntegratedTime: protoEntry.IntegratedTime,
				LogIndex:       protoEntry.LogIndex,
				LogID:          rekorLogID,
			},
		)
		if err != nil {
			t.Fatalf("failed to generate Rekor signed entry timestamp: %v", err)
		}

		protoEntry.InclusionPromise = &rekorpb.InclusionPromise{
			SignedEntryTimestamp: signedEntryTimestamp,
		}

		protoEntry.InclusionProof = &rekorpb.InclusionProof{
			LogIndex: *inclusionProof.LogIndex,
			RootHash: rootHash,
			TreeSize: *inclusionProof.TreeSize,
			Hashes:   hashes,
			Checkpoint: &rekorpb.Checkpoint{
				Envelope: *inclusionProof.Checkpoint,
			},
		}

		protoEntries = append(protoEntries, protoEntry)
	}

	protoTimestamps := make([]*commonpb.RFC3161SignedTimestamp, 0, len(timestamps))
	for _, timestamp := range timestamps {
		protoTimestamps = append(protoTimestamps, &commonpb.RFC3161SignedTimestamp{
			SignedTimestamp: timestamp,
		})
	}

	protoBundle := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &commonpb.X509Certificate{
					RawBytes: certificate.Certificate().Raw,
				},
			},
			TlogEntries: protoEntries,
			TimestampVerificationData: &protobundle.TimestampVerificationData{
				Rfc3161Timestamps: protoTimestamps,
			},
		},
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &commonpb.MessageSignature{
				MessageDigest: &commonpb.HashOutput{
					Algorithm: commonpb.HashAlgorithm_SHA2_256,
					Digest:    messageSignature.Digest(),
				},
				Signature: messageSignature.Signature(),
			},
		},
	}

	sigstoreBundle, err := bundle.NewBundle(protoBundle)
	if err != nil {
		t.Fatalf("failed to construct Sigstore bundle: %v", err)
	}

	jsonBundle, err := sigstoreBundle.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal Sigstore bundle: %v", err)
	}

	var decodedBundle bundle.Bundle
	if err := decodedBundle.UnmarshalJSON(jsonBundle); err != nil {
		t.Fatalf("failed to unmarshal Sigstore bundle: %v", err)
	}

	if err := verifyChecksumManifestSignatureWithTrustedMaterial(
		manifest,
		&decodedBundle,
		virtualSigstore,
	); err != nil {
		t.Fatalf("expected JSON round-trip signature to verify, got: %v", err)
	}
}

func TestVerifyChecksumManifestSignatureWithTrustedMaterial(t *testing.T) {
	manifest := []byte("sha256  artifact.tar.gz\n")
	identity := "https://github.com/kubescape/regolibrary/.github/workflows/create-release-v2.yaml@refs/tags/v1.2.3-rc.1"
	issuer := "https://token.actions.githubusercontent.com"

	virtualSigstore, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("failed to create virtual Sigstore: %v", err)
	}

	entity, err := virtualSigstore.Sign(identity, issuer, manifest)
	if err != nil {
		t.Fatalf("failed to sign manifest: %v", err)
	}

	if err := verifyChecksumManifestSignatureWithTrustedMaterial(
		manifest,
		entity,
		virtualSigstore,
	); err != nil {
		t.Fatalf("expected valid signature to verify, got: %v", err)
	}
}

func TestVerifyChecksumManifestSignatureWithTrustedMaterialRejectsTamperedManifest(t *testing.T) {
	manifest := []byte("sha256  artifact.tar.gz\n")
	tamperedManifest := []byte("sha256  modified.tar.gz\n")
	identity := "https://github.com/kubescape/regolibrary/.github/workflows/create-release-v2.yaml@refs/tags/v1.2.3-rc.1"
	issuer := "https://token.actions.githubusercontent.com"

	virtualSigstore, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("failed to create virtual Sigstore: %v", err)
	}

	entity, err := virtualSigstore.Sign(identity, issuer, manifest)
	if err != nil {
		t.Fatalf("failed to sign manifest: %v", err)
	}

	err = verifyChecksumManifestSignatureWithTrustedMaterial(
		tamperedManifest,
		entity,
		virtualSigstore,
	)
	if err == nil {
		t.Fatal("expected tampered manifest to fail verification")
	}
}

func TestVerifyChecksumManifestSignatureWithTrustedMaterialRejectsWrongIdentity(t *testing.T) {
	manifest := []byte("sha256  artifact.tar.gz\n")
	identity := "https://github.com/example/other/.github/workflows/release.yaml@refs/tags/v1.2.3-rc.1"
	issuer := "https://token.actions.githubusercontent.com"

	virtualSigstore, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("failed to create virtual Sigstore: %v", err)
	}

	entity, err := virtualSigstore.Sign(identity, issuer, manifest)
	if err != nil {
		t.Fatalf("failed to sign manifest: %v", err)
	}

	err = verifyChecksumManifestSignatureWithTrustedMaterial(
		manifest,
		entity,
		virtualSigstore,
	)
	if err == nil {
		t.Fatal("expected wrong signer identity to fail verification")
	}
}
