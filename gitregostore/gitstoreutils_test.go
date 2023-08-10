package gitregostore

import (
	"errors"
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
			name: "Check Prod gitregostore",
			fields: fields{
				BaseUrl:    "https://github.com",
				Owner:      "kubescape",
				Repository: "regolibrary",
				Branch:     "",
				Path:       "releases",
				Tag:        "latest/download",
			},
			wantedURL: "https://github.com/kubescape/regolibrary/releases/latest/download",
		},
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
	respStr = `[{"name":"TEST","attributes":{"armoBuiltin":true,"controlTypeTags":["security","compliance"],"attackTracks":[{"attackTrack": "container","categories": ["Execution","Initial access"]},{"attackTrack": "network","categories": ["Eavesdropping","Spoofing"]}]},"description":"","remediation":"","rulesNames":["CVE-2022-0185"],"id":"C-0079","long_description":"","test":"","controlID":"C-0079","baseScore":4,"example":""}]`
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
