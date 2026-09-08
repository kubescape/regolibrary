package gitregostore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
}
