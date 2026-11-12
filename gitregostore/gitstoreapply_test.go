package gitregostore

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validArtifacts returns a complete, valid set of release artifacts, optionally with some content replaced.
func validArtifacts(overrides map[string]string) *releaseArtifacts {
	files := map[string]string{
		frameworksJsonFileName:            `[{"name":"new-fw"}]`,
		attackTracksJsonFileName:          `[{"metadata":{"name":"new-track"}}]`,
		controlsJsonFileName:              `[{"name":"new-control","controlID":"C-9999"}]`,
		rulesJsonFileName:                 `[{"name":"new-rule"}]`,
		frameworkControlRelationsFileName: "frameworkName,ControlID\nnew-fw,C-9999\n",
		ControlRuleRelationsFileName:      "ControlID,RuleName\nC-9999,new-rule\n",
		defaultConfigInputsFileName:       `{"settings":{"postureControlInputs":{"k":["v"]}}}`,
		systemPostureExceptionFileName:    `[{"name":"new-exception"}]`,
	}
	for k, v := range overrides {
		files[k] = v
	}
	return &releaseArtifacts{files: files, securityFrameworks: `[{"name":"new-security-fw"}]`, hasSecurity: true}
}

// populatedStore returns a store holding the state of an earlier successful pull.
func populatedStore(t *testing.T) *GitRegoStore {
	t.Helper()
	gs := &GitRegoStore{}
	require.NoError(t, gs.applyRelease(validArtifacts(map[string]string{
		frameworksJsonFileName:         `[{"name":"old-fw"}]`,
		attackTracksJsonFileName:       `[{"metadata":{"name":"old-track"}}]`,
		controlsJsonFileName:           `[{"name":"old-control","controlID":"C-0001"}]`,
		rulesJsonFileName:              `[{"name":"old-rule"}]`,
		systemPostureExceptionFileName: `[{"name":"old-exception"}]`,
	})))
	return gs
}

// storeSnapshot captures everything applyRelease publishes.
type storeSnapshot struct {
	frameworks, controls, attackTrackControls, rules, tracks, exceptions []string
	controlRuleRows, frameworkControlRows                                int
	defaultConfigInputs                                                  string
}

func snapshot(gs *GitRegoStore) storeSnapshot {
	gs.frameworksLock.RLock()
	defer gs.frameworksLock.RUnlock()
	gs.controlsLock.RLock()
	defer gs.controlsLock.RUnlock()
	gs.attackTrackControlsLock.RLock()
	defer gs.attackTrackControlsLock.RUnlock()
	gs.rulesLock.RLock()
	defer gs.rulesLock.RUnlock()
	gs.controlRelationsLock.RLock()
	defer gs.controlRelationsLock.RUnlock()
	gs.frameworkRelationsLock.RLock()
	defer gs.frameworkRelationsLock.RUnlock()
	gs.attackTracksLock.RLock()
	defer gs.attackTracksLock.RUnlock()
	gs.DefaultConfigInputsLock.RLock()
	defer gs.DefaultConfigInputsLock.RUnlock()
	gs.systemPostureExceptionPoliciesLock.RLock()
	defer gs.systemPostureExceptionPoliciesLock.RUnlock()

	s := storeSnapshot{
		controlRuleRows:      gs.ControlRuleRelations.Nrow(),
		frameworkControlRows: gs.FrameworkControlRelations.Nrow(),
	}
	for _, f := range gs.Frameworks {
		s.frameworks = append(s.frameworks, f.Name)
	}
	for _, c := range gs.Controls {
		s.controls = append(s.controls, c.Name)
	}
	for _, c := range gs.AttackTrackControls {
		s.attackTrackControls = append(s.attackTrackControls, c.Name)
	}
	for _, r := range gs.Rules {
		s.rules = append(s.rules, r.Name)
	}
	for _, a := range gs.AttackTracks {
		s.tracks = append(s.tracks, a.Metadata["name"].(string))
	}
	for _, e := range gs.SystemPostureExceptionPolicies {
		s.exceptions = append(s.exceptions, e.Name)
	}
	if v, ok := gs.DefaultConfigInputs.Settings.PostureControlInputs["k"]; ok && len(v) == 1 {
		s.defaultConfigInputs = v[0]
	}
	return s
}

func TestApplyReleaseAppliesAllArtifacts(t *testing.T) {
	gs := &GitRegoStore{}

	require.NoError(t, gs.applyRelease(validArtifacts(nil)))

	got := snapshot(gs)
	assert.Equal(t, []string{"new-fw", "new-security-fw"}, got.frameworks)
	assert.Equal(t, []string{"new-control"}, got.controls)
	assert.Equal(t, []string{"new-rule"}, got.rules)
	assert.Equal(t, []string{"new-track"}, got.tracks)
	assert.Equal(t, []string{"new-exception"}, got.exceptions)
	assert.Equal(t, 1, got.controlRuleRows)
	assert.Equal(t, 1, got.frameworkControlRows)
	assert.Equal(t, "v", got.defaultConfigInputs)
}

// Artifacts are processed in alphabetical order (frameworks first), so the malformed artifacts below are
// processed after artifacts that, before staging, would already have replaced the live data.
func TestApplyReleaseFailureLeavesStoreUnchanged(t *testing.T) {
	malformed := []struct {
		name      string
		overrides map[string]string
		art       func(*releaseArtifacts)
	}{
		{name: "malformed rules (processed last)", overrides: map[string]string{rulesJsonFileName: `[{"name":`}},
		{name: "malformed exceptions", overrides: map[string]string{systemPostureExceptionFileName: `{not json`}},
		{name: "malformed controls", overrides: map[string]string{controlsJsonFileName: `[`}},
		{name: "malformed attack tracks", overrides: map[string]string{attackTracksJsonFileName: `nope`}},
		{name: "malformed default config inputs", overrides: map[string]string{defaultConfigInputsFileName: `[]`}},
		{name: "malformed frameworks", overrides: map[string]string{frameworksJsonFileName: `{`}},
		{name: "malformed security frameworks", art: func(a *releaseArtifacts) { a.securityFrameworks = `oops` }},
		{name: "invalid control/rule relations CSV", overrides: map[string]string{ControlRuleRelationsFileName: "a,b\n1,2,3\n"}},
		{name: "invalid framework/control relations CSV", overrides: map[string]string{frameworkControlRelationsFileName: "a,b\n\"1,2\n"}},
	}

	for _, tt := range malformed {
		t.Run(tt.name, func(t *testing.T) {
			gs := populatedStore(t)
			before := snapshot(gs)
			require.Equal(t, []string{"old-rule"}, before.rules)

			artifacts := validArtifacts(tt.overrides)
			if tt.art != nil {
				tt.art(artifacts)
			}

			require.Error(t, gs.applyRelease(artifacts))
			assert.Equal(t, before, snapshot(gs), "a failed apply must not change the store")
		})
	}
}

func TestApplyReleaseFailureOnEmptyStoreStaysEmpty(t *testing.T) {
	gs := &GitRegoStore{}

	require.Error(t, gs.applyRelease(validArtifacts(map[string]string{rulesJsonFileName: `[`})))

	assert.Equal(t, storeSnapshot{}, snapshot(gs))
}

func TestApplyReleaseRetryAfterFailureSucceeds(t *testing.T) {
	gs := populatedStore(t)
	before := snapshot(gs)

	require.Error(t, gs.applyRelease(validArtifacts(map[string]string{rulesJsonFileName: `[`})))
	assert.Equal(t, before, snapshot(gs))

	require.NoError(t, gs.applyRelease(validArtifacts(nil)))
	got := snapshot(gs)
	assert.Equal(t, []string{"new-rule"}, got.rules)
	assert.Equal(t, []string{"new-control"}, got.controls)
	assert.Equal(t, []string{"new-fw", "new-security-fw"}, got.frameworks)
	assert.Equal(t, []string{"new-exception"}, got.exceptions)
}

// End to end: the download succeeds completely but one artifact cannot be decoded.
func TestSetRegoObjectsMalformedArtifactLeavesStoreUnchanged(t *testing.T) {
	rs := newReleaseServer(t)
	rs.extra["rules"] = `[{"name":`
	gs := rs.oldStore()

	err := gs.SetRegoObjectsWithContext(context.Background())
	require.Error(t, err)
	assertStoreUntouched(t, gs)

	rs.mu.Lock()
	delete(rs.extra, "rules")
	rs.mu.Unlock()

	require.NoError(t, gs.SetRegoObjectsWithContext(context.Background()))
	require.Len(t, gs.Rules, 1)
	assert.Equal(t, "new-rule", gs.Rules[0].Name)
}

// Readers holding several store locks at once must never see a mix of two states, and publishing must not
// deadlock with the public getters that nest those locks. Run with -race.
func TestApplyReleaseConcurrentReadersSeeConsistentState(t *testing.T) {
	stateA := validArtifacts(map[string]string{
		frameworksJsonFileName:       `[{"name":"A"}]`,
		controlsJsonFileName:         `[{"name":"A","controlID":"C-9999"}]`,
		rulesJsonFileName:            `[{"name":"A"}]`,
		ControlRuleRelationsFileName: "ControlID,RuleName\nC-9999,A\n",
	})
	stateB := validArtifacts(map[string]string{
		frameworksJsonFileName:       `[{"name":"B"}]`,
		controlsJsonFileName:         `[{"name":"B","controlID":"C-9999"}]`,
		rulesJsonFileName:            `[{"name":"B"}]`,
		ControlRuleRelationsFileName: "ControlID,RuleName\nC-9999,B\n",
	})
	stateA.hasSecurity, stateB.hasSecurity = false, false

	gs := &GitRegoStore{}
	require.NoError(t, gs.applyRelease(stateA))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var mixed sync.Map

	// readers that hold all the locks, in the order used by the publisher: any mix of states is visible here
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s := snapshot(gs)
				if s.frameworks[0] != s.controls[0] || s.controls[0] != s.rules[0] {
					mixed.Store(s.frameworks[0]+s.controls[0]+s.rules[0], true)
				}
			}
		}()
	}

	// readers using the public getters, which nest the locks in their own way
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = gs.GetOPAControlByID("C-9999")
				_, _ = gs.GetOPAFrameworkByName("A")
				_, _ = gs.GetOPAFrameworkByName("B")
				_, _ = gs.GetControlFrameworkSubsections("C-9999", "A")
				_, _ = gs.GetOPAPolicies()
				_, _ = gs.GetOPAControls()
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			next := stateA
			if i%2 == 0 {
				next = stateB
			}
			assert.NoError(t, gs.applyRelease(next))
		}
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("applyRelease did not finish: possible deadlock with concurrent readers")
	}
	close(stop)
	wg.Wait()

	mixed.Range(func(k, _ any) bool {
		t.Errorf("a reader observed a partially applied state: %v", k)
		return true
	})
}
