package gitregostore

import (
	"strings"
	"testing"
)

func gs_tests(t *testing.T, gs *GitRegoStore) {

	index := 0

	// Rules
	policies, err := gs.GetOPAPolicies()
	if err != nil || policies == nil {
		t.Errorf("failed to get all policies %v", err)
	}
	policiesNames, err := gs.GetOPAPoliciesNamesList()
	if err != nil || len(policiesNames) == 0 {
		t.Errorf("failed to get policies names list %v", err)
		return
	}
	policy, err := gs.GetOPAPolicyByName(policiesNames[index])
	if err != nil || policy == nil {
		t.Errorf("failed to get policy by name: '%s', %v", policiesNames[index], err)
	}
	// Controls
	controls, err := gs.GetOPAControls()
	if err != nil || controls == nil {
		t.Errorf("failed to get all controls %v", err)
	}
	controlsNames, err := gs.GetOPAControlsNamesList()
	if err != nil || len(controlsNames) == 0 {
		t.Errorf("failed to get controls names list %v", err)
		return
	}

	control, err := gs.GetOPAControlByName(controlsNames[index])
	if err != nil || control == nil {
		t.Errorf("failed to get control by name: '%s', %v", controlsNames[index], err)
	}
	controlsIDs, err := gs.GetOPAControlsIDsList()
	if err != nil || len(controlsIDs) == 0 {
		t.Errorf("failed to get controls ids list %v", err)
		return
	}

	control, err = gs.GetOPAControlByID(controlsIDs[index])
	if err != nil || control == nil {
		t.Errorf("failed to get control by ID: '%s', %v", controlsNames[index], err)
	}
	// Frameworks
	frameworks, err := gs.GetOPAFrameworks()
	if err != nil || frameworks == nil {
		t.Errorf("failed to get all frameworks %v", err)
	}
	frameworksNames, err := gs.GetOPAFrameworksNamesList()
	if err != nil || len(frameworksNames) == 0 {
		t.Errorf("failed to get frameworks names list %v", err)
		return
	}
	framework, err := gs.GetOPAFrameworkByName(frameworksNames[0])
	if err != nil || framework == nil {
		t.Errorf("failed to get framework by name: '%s', %v", frameworksNames[0], err)
	}

	if len(framework.Controls) == 0 {
		t.Errorf("failed to get controls for framework name: '%s'", framework.Name)
	}

	if len(*framework.ControlsIDs) == 0 {
		t.Errorf("failed to get controls ids for framework name: '%s'", framework.Name)
	}

	for i := range framework.Controls {
		if len(framework.Controls[i].Rules) == 0 {
			t.Errorf("failed to get rules for framework name: '%s', control name: '%s'", framework.Name, framework.Controls[i].Name)
		}

		if len(*framework.ControlsIDs) == 0 {
			t.Errorf("failed to get rules ids for framework name: '%s', control name: '%s'", framework.Name, framework.Controls[i].Name)
		}

	}

	control, err = gs.GetOPAControlByFrameworkNameAndControlName("NSA", "Allow privilege escalation")

	if err != nil || control == nil {
		t.Errorf("failed to get control by framework name 'NSA' and control name 'Allow privilege escalation': %v", err)
	} else {
		if strings.ToLower(control.ControlID) != "c-0016" {
			t.Errorf("wrong control for framework name 'NSA' and control name 'Allow privilege escalation' expected: 'C-0016', found %s", control.ControlID)
		}
	}

}

func TestGetPoliciesMethodsNew(t *testing.T) {
	gs := NewDefaultGitRegoStore(-1)
	err := gs.SetRegoObjects()
	if err != nil {
		t.Errorf("error in SetRegoObjects: %v", err)
	}
	gs_tests(t, gs)

}

func TestGetOPAFrameworkByName(t *testing.T) {
	gs := NewDevGitRegoStore(-1)
	err := gs.SetRegoObjects()
	if err != nil {
		t.Errorf("error in SetRegoObjects: %v", err)
	}

	_, err = gs.GetOPAFrameworkByName("CIS")

	if err != nil {
		t.Errorf("failed to get framework object: %v", err)
	}
}

func TestGetPoliciesMethodsOld(t *testing.T) {
	gs := InitGitRegoStore("https://github.com", "kubescape", "regolibrary", "releases", "latest/download", "", 15)

	gs_tests(t, gs)
}

func TestGetPoliciesMethodsDevNewParams(t *testing.T) {
	gs := InitGitRegoStore("https://raw.githubusercontent.com", "kubescape", "regolibrary", "releaseDev", "/", "dev", -1)

	gs_tests(t, gs)

}

func TestGetPoliciesMethodsDevNew(t *testing.T) {
	gs := NewDevGitRegoStore(-1)
	err := gs.SetRegoObjects()
	if err != nil {
		t.Errorf("error in SetRegoObjects: %v", err)
	}
	gs_tests(t, gs)
}
