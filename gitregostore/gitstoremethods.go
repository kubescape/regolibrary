package gitregostore

import (
	"fmt"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/go-gota/gota/dataframe"
	"github.com/go-gota/gota/series"
	opapolicy "github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"k8s.io/utils/strings/slices"
)

const (
	TypeCompliance = "compliance"
	TypeSecurity   = "security"
)

// =============================================================
// =========================== Rules ===========================
// =============================================================

// GetOPAPolicies returns all the policies of given customer
func (gs *GitRegoStore) GetOPAPolicies() ([]opapolicy.PolicyRule, error) {
	gs.rulesLock.RLock()
	defer gs.rulesLock.RUnlock()

	if gs.Rules == nil {
		return nil, fmt.Errorf("no rules found in GitRegoStore")
	}

	return gs.Rules, nil
}

func (gs *GitRegoStore) GetOPAPoliciesNamesList() ([]string, error) {
	gs.rulesLock.RLock()
	defer gs.rulesLock.RUnlock()

	policiesNameList := make([]string, 0, len(gs.Rules))
	for _, rule := range gs.Rules {
		policiesNameList = append(policiesNameList, rule.Name)
	}

	return policiesNameList, nil
}

// GetOPAPolicyByName returns specific policy by the name
func (gs *GitRegoStore) GetOPAPolicyByName(ruleName string) (*opapolicy.PolicyRule, error) {
	gs.rulesLock.RLock()
	defer gs.rulesLock.RUnlock()

	return gs.getOPAPolicyByName(ruleName)
}

func (gs *GitRegoStore) getOPAPolicyByName(ruleName string) (*opapolicy.PolicyRule, error) {
	for _, ruleToPin := range gs.Rules {
		if !strings.EqualFold(ruleToPin.Name, ruleName) {
			continue
		}

		rule := ruleToPin

		return &rule, nil
	}

	return nil, fmt.Errorf("rule '%s' not found", ruleName)
}

// =============================================================
// =========================== AttackTracks ====================
// =============================================================

func (gs *GitRegoStore) GetAttackTracks() ([]v1alpha1.AttackTrack, error) {
	gs.attackTracksLock.RLock()
	defer gs.attackTracksLock.RUnlock()

	if gs.AttackTracks == nil {
		return nil, fmt.Errorf("no attack tracks found in GitRegoStore")
	}

	return gs.AttackTracks, nil
}

// =============================================================
// =========================== Controls ========================
// =============================================================

// GetOPAControlByName returns specific BaseControl by the name.
//
// Deprecated: use GetOPAControlByFrameworkNameAndControlName.
func (gs *GitRegoStore) GetOPAControlByName(controlName string) (*opapolicy.Control, error) {
	gs.controlsLock.RLock()
	defer gs.controlsLock.RUnlock()

	for _, controlToPin := range gs.Controls {
		// If backward compatibility is supported, extract from patched control name the new name.
		if !strings.EqualFold(controlToPin.Name, controlName) {
			continue
		}

		control := controlToPin
		if len(control.Rules) == 0 {
			err := gs.fillRulesAndRulesIDsInControl(&control)
			if err != nil {
				return nil, err
			}
		}

		return &control, nil
	}

	return nil, fmt.Errorf("control '%s' not found", controlName)
}

// GetOPAControlByID returns specific BaseControl by the ID
func (gs *GitRegoStore) GetOPAControlByID(controlID string) (*opapolicy.Control, error) {
	gs.controlsLock.RLock()
	defer gs.controlsLock.RUnlock()

	return gs.getOPAControlByID(controlID)
}

func (gs *GitRegoStore) getOPAControlByID(controlID string) (*opapolicy.Control, error) {
	for _, controlToPin := range gs.Controls {
		// If backward compatibility is supported, try to find if the controlID sent has a new controlID
		if !strings.EqualFold(controlToPin.ControlID, controlID) {
			continue
		}

		control := controlToPin
		if len(control.Rules) == 0 {
			if err := gs.fillRulesAndRulesIDsInControl(&control); err != nil {
				return nil, err
			}
		}

		return &control, nil
	}

	return nil, fmt.Errorf("control '%s' not found", controlID)
}

// GetOPAControlByFrameworkNameAndControlName - get framework name and control name and return the relevant control object
func (gs *GitRegoStore) GetOPAControlByFrameworkNameAndControlName(frameworkName string, controlName string) (*opapolicy.Control, error) {
	gs.frameworksLock.RLock()
	defer gs.frameworksLock.RUnlock()
	gs.controlsLock.RLock()
	defer gs.controlsLock.RUnlock()

	fw, err := gs.getOPAFrameworkByName(frameworkName) // locks framework
	if err != nil {
		return nil, err
	}

	for _, controlToPin := range fw.Controls {
		// If backward compatibility is supported, extract from patched control name the new name.
		if !strings.EqualFold(controlToPin.Name, controlName) {
			continue
		}

		control := controlToPin

		if len(control.Rules) == 0 {
			if err := gs.fillRulesAndRulesIDsInControl(&control); err != nil {
				return nil, err
			}
		}

		return &control, nil
	}

	return nil, fmt.Errorf("control  name '%s' not found in framework '%s'", controlName, fw.Name)

}

// GetOPAControl returns specific control by the name or ID
func (gs *GitRegoStore) GetOPAControl(c string) (*opapolicy.Control, error) {
	if isControlID(c) {
		return gs.GetOPAControlByID(c)
	} else {
		return gs.GetOPAControlByName(c)
	}
}

// GetOPAControls returns all the controls of given customer
func (gs *GitRegoStore) GetOPAControls() ([]opapolicy.Control, error) {
	gs.controlsLock.RLock()
	defer gs.controlsLock.RUnlock()

	if gs.Controls == nil {
		return nil, fmt.Errorf("no controls found in GitRegoStore")
	}

	controlsList := make([]opapolicy.Control, 0, len(gs.Controls))
	for _, controlToPin := range gs.Controls {
		control := controlToPin

		if err := gs.fillRulesAndRulesIDsInControl(&control); err != nil {
			return nil, err
		}

		controlsList = append(controlsList, control)
	}

	return controlsList, nil
}

func (gs *GitRegoStore) GetOPAControlsNamesList() ([]string, error) {
	gs.controlsLock.RLock()
	defer gs.controlsLock.RUnlock()

	controlsNameList := make([]string, 0, len(gs.Controls))
	for _, control := range gs.Controls {
		controlsNameList = append(controlsNameList, control.Name)
	}

	return controlsNameList, nil
}

func (gs *GitRegoStore) GetOPAControlsIDsList() ([]string, error) {
	gs.controlsLock.RLock()
	defer gs.controlsLock.RUnlock()

	controlsIDList := make([]string, 0, len(gs.Controls))
	for _, control := range gs.Controls {
		controlsIDList = append(controlsIDList, control.ControlID)
	}

	return controlsIDList, nil
}

// GetOpaFrameworkListByControlName returns a list of framework names this control is in
func (gs *GitRegoStore) GetOpaFrameworkListByControlName(controlName string) []string {
	gs.frameworkRelationsLock.RLock()
	defer gs.frameworkRelationsLock.RUnlock()

	fil := gs.FrameworkControlRelations.Filter(
		dataframe.F{Colname: "ControlName", Comparator: series.Eq, Comparando: controlName},
	)
	rows := fil.Nrow()
	frameworksNameList := make([]string, 0, rows)

	for row := 0; row < rows; row++ {
		fwName := fil.Elem(row, 0)
		frameworksNameList = append(frameworksNameList, fwName.String())
	}

	return frameworksNameList
}

// GetOpaFrameworkListByControlID returns a list of framework names this control is in
func (gs *GitRegoStore) GetOpaFrameworkListByControlID(controlID string) []string {
	gs.frameworkRelationsLock.RLock()
	defer gs.frameworkRelationsLock.RUnlock()

	fil := gs.FrameworkControlRelations.Filter(
		dataframe.F{Colname: "ControlID", Comparator: series.Eq, Comparando: controlID},
	)
	rows := fil.Nrow()
	frameworksNameList := make([]string, 0, rows)

	for row := 0; row < rows; row++ {
		fwName := fil.Elem(row, 0)
		frameworksNameList = append(frameworksNameList, fwName.String())
	}

	return frameworksNameList
}

// ===============================================================
// =========================== Frameworks ========================
// ===============================================================

// GetOPAFrameworksByType returns all frameworks of given type
func (gs *GitRegoStore) getOPAFrameworksByType(frameworkType string) ([]opapolicy.Framework, error) {
	gs.frameworksLock.RLock()
	defer gs.frameworksLock.RUnlock()

	if gs.Frameworks == nil {
		return nil, fmt.Errorf("no frameworks found in GitRegoStore")
	}
	frameworksList := make([]opapolicy.Framework, 0, len(gs.Frameworks))
	for _, frameworkToPin := range gs.Frameworks {
		framework := frameworkToPin
		if slices.Contains(framework.TypeTags, frameworkType) {
			frameworksList = append(frameworksList, framework)
		}
	}
	return frameworksList, nil
}

// ====================== compliance frameworks ======================

// GetOPAFrameworks returns all compliance frameworks
func (gs *GitRegoStore) GetOPAFrameworks() ([]opapolicy.Framework, error) {
	complianceFrameworks, err := gs.getOPAFrameworksByType(TypeCompliance)
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance frameworks: %w", err)
	}

	frameworksList := make([]opapolicy.Framework, 0, len(complianceFrameworks))
	for _, frameworkToPin := range complianceFrameworks {
		fw := frameworkToPin
		if err := gs.fillControlsAndControlIDsInFramework(&fw); err != nil {
			return nil, err
		}
		frameworksList = append(frameworksList, fw)
	}

	return frameworksList, nil
}

// GetOPAFrameworksNamesList returns all compliance frameworks names
func (gs *GitRegoStore) GetOPAFrameworksNamesList() ([]string, error) {
	complianceFrameworks, err := gs.getOPAFrameworksByType(TypeCompliance)
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance frameworks: %w", err)
	}
	frameworksNameList := make([]string, 0, len(complianceFrameworks))
	for _, framework := range complianceFrameworks {
		frameworksNameList = append(frameworksNameList, framework.Name)
	}

	return frameworksNameList, nil
}

// ====================== security frameworks ======================

// GetOPAFrameworks returns all security frameworks
func (gs *GitRegoStore) GetOPASecurityFrameworks() ([]opapolicy.Framework, error) {
	securityFrameworks, err := gs.getOPAFrameworksByType(TypeSecurity)
	if err != nil {
		return nil, fmt.Errorf("failed to get security frameworks: %w", err)
	}
	frameworksList := make([]opapolicy.Framework, 0, len(securityFrameworks))
	for _, frameworkToPin := range securityFrameworks {
		fw := frameworkToPin
		if err := gs.fillControlsAndControlIDsInFramework(&fw); err != nil {
			return nil, err
		}
		frameworksList = append(frameworksList, fw)
	}
	return frameworksList, nil
}

// GetOPAFrameworksNamesList returns all security frameworks names
func (gs *GitRegoStore) GetOPASecurityFrameworksNamesList() ([]string, error) {
	securityFrameworks, err := gs.getOPAFrameworksByType(TypeSecurity)
	if err != nil {
		return nil, fmt.Errorf("failed to get security frameworks: %w", err)
	}
	frameworksNameList := make([]string, 0, len(securityFrameworks))
	for _, framework := range securityFrameworks {
		frameworksNameList = append(frameworksNameList, framework.Name)
	}
	return frameworksNameList, nil
}

// GetOPAFrameworkTypeTags returns all type tags of given framework
func (gs *GitRegoStore) GetOPAFrameworkTypeTags(frameworkName string) ([]string, error) {
	framework, err := gs.getOPAFrameworkByName(frameworkName)
	if err != nil {
		return nil, err
	}
	return framework.TypeTags, nil
}

// GetOPAFrameworkByName returns specific framework by the name
func (gs *GitRegoStore) GetOPAFrameworkByName(frameworkName string) (*opapolicy.Framework, error) {
	gs.frameworksLock.RLock()
	defer gs.frameworksLock.RUnlock()

	return gs.getOPAFrameworkByName(frameworkName)
}

func (gs *GitRegoStore) getOPAFrameworkByName(frameworkName string) (*opapolicy.Framework, error) {
	const supportBackwardCompatibilityFramework = true

	for _, frameworkToPin := range gs.Frameworks {
		// If backward compatibility is supported,try to compare the new CIS name.
		if !strings.EqualFold(frameworkToPin.Name, frameworkName) {
			continue
		}

		fw := frameworkToPin

		if err := gs.fillControlsAndControlIDsInFramework(&fw); err != nil {
			return nil, err
		}

		return &fw, nil
	}

	return nil, fmt.Errorf("framework '%s' not found", frameworkName)
}

// ===============================================================

func (gs *GitRegoStore) GetDefaultConfigInputs() (armotypes.CustomerConfig, error) {
	gs.DefaultConfigInputsLock.RLock()
	defer gs.DefaultConfigInputsLock.RUnlock()

	return gs.DefaultConfigInputs, nil
}

func (gs *GitRegoStore) GetSystemPostureExceptionPolicies() ([]armotypes.PostureExceptionPolicy, error) {
	gs.systemPostureExceptionPoliciesLock.RLock()
	defer gs.systemPostureExceptionPoliciesLock.RUnlock()

	return gs.SystemPostureExceptionPolicies, nil
}

// ====================== helpers ======================

func (gs *GitRegoStore) fillRulesAndRulesIDsInControl(control *opapolicy.Control) error {
	gs.controlEscalatedLock.Lock() // this locks all concurrent attempts to fill any control
	defer gs.controlEscalatedLock.Unlock()

	gs.rulesLock.RLock()
	defer gs.rulesLock.RUnlock()

	gs.controlRelationsLock.RLock()
	defer gs.controlRelationsLock.RUnlock()

	fil := gs.ControlRuleRelations.Filter(
		dataframe.F{Colname: "ControlID", Comparator: series.Eq, Comparando: control.ControlID},
	)

	rows := fil.Nrow()
	rulesList := make([]opapolicy.PolicyRule, 0, rows)
	rulesIDList := make([]string, 0, rows)

	for row := 0; row < rows; row++ {
		ruleName := fil.Elem(row, 1)
		rule, err := gs.getOPAPolicyByName(ruleName.String()) // requires R-Lock on Rules
		if err != nil {
			return err
		}
		// add rule to control.rules
		rulesList = append(rulesList, *rule)
		// add ruleId ro control.ruleIds
		rulesIDList = append(rulesIDList, rule.GUID)
	}

	control.Rules = rulesList
	control.RulesIDs = &rulesIDList

	return nil
}

func (gs *GitRegoStore) fillControlsAndControlIDsInFramework(fw *opapolicy.Framework) error {
	gs.frameworkEscalatedLock.Lock()
	defer gs.frameworkEscalatedLock.Unlock()

	gs.rulesLock.RLock()
	defer gs.rulesLock.RUnlock()

	gs.frameworkRelationsLock.RLock()
	defer gs.frameworkRelationsLock.RUnlock()

	fil := gs.FrameworkControlRelations.Filter(
		dataframe.F{Colname: "frameworkName", Comparator: series.Eq, Comparando: fw.Name},
	)

	rows := fil.Nrow()
	controlsList := make([]opapolicy.Control, 0, rows)
	controlsIDList := make([]string, 0, rows)

	// if there are no controls in framework, need to populate them all from base controls.
	if len(fw.Controls) == 0 {
		for row := 0; row < rows; row++ {
			controlID := fil.Elem(row, 1)
			control, err := gs.getOPAControlByID(controlID.String())
			if err != nil {
				return err
			}

			// add control to controlsList
			controlsList = append(controlsList, *control)
			// add controlID to controlsIDList
			controlsIDList = append(controlsIDList, control.ControlID)

		}

		fw.Controls = controlsList
		fw.ControlsIDs = &controlsIDList

		return nil
	}

	// if there are controls, need to populate only the rules.
	for i := range fw.Controls {
		if len(fw.Controls[i].Rules) == 0 {
			// getting the control object using GetOPAControlByID as it handles backward compatibility
			tmpControl, err := gs.GetOPAControlByID(fw.Controls[i].ControlID)
			if err != nil {
				return err
			}

			fw.Controls[i].Rules = tmpControl.Rules
			fw.Controls[i].RulesIDs = tmpControl.RulesIDs
		}
	}

	return nil
}
