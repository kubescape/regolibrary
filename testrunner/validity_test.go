package testing

import (
	"encoding/json"
	"io/ioutil"
	"path"
	"testing"

	"github.com/armosec/opa-utils/reporthandling"
)

/*
	This file tests the validity of the library format
	TODO: define json-schemas for controls, frameworks, rules etc, and test the strcutures of the actual data agains it
*/

const (
	ruleMetadataFile = "rule.metadata.json"
)

var (
	rulesDir = []string{"..", "rules"}
	ctrlsDir = []string{"..", "controls"}
	// fwsDir   = []string{"..", "frameworks"}
)

// TestRulesNames test that there isn't a duplicated rule name, since we use the names as an id
func TestCtrlsRuleNames(t *testing.T) {

	// Get rule names
	ruleNames, err := listRuleNames()
	if err != nil {
		t.Errorf("TestCtrlsRuleNames failed to list rule names %v", err)
		return
	}
	ruleNamesMap := strSliceToMap(ruleNames)

	// List controls
	ctrls, err := listControls()
	if err != nil {
		t.Errorf("TestCtrlsRuleNames failed to list controls %v", err)
		return
	}

	for _, ctrl := range ctrls {
		rules, ok := ctrl["rulesNames"].([]interface{})
		if !ok {
			ctrlJson, err := json.Marshal(ctrl)
			if err != nil {
				// this is unexpected...
				t.Errorf("TestCtrlsRuleNames failed to remarshal ctrl for error printing. error: %v. ctrl: %s", err, ctrl)
				return
			}
			t.Errorf("TestCtrlsRuleNames wrong control structure: %s", string(ctrlJson))
			continue
		}

		// Actual test
		for _, ruleName := range rules {
			if _, ok := ruleNamesMap[ruleName.(string)]; !ok {
				t.Errorf("TestCtrlsRuleNames control include rule that does not exist: %s", ruleName.(string))
			}
		}
	}
}

func listControls() ([]map[string]interface{}, error) {
	baseDir := path.Join(ctrlsDir...)
	rulesDirs, err := ioutil.ReadDir(baseDir)
	if err != nil {
		return nil, err
	}

	ruleNames := []map[string]interface{}{}
	for _, file := range rulesDirs {
		if file.IsDir() {
			continue
		}
		f, err := ioutil.ReadFile(path.Join(baseDir, file.Name()))
		if err != nil {
			return nil, err
		}
		ctrl := map[string]interface{}{}
		err = json.Unmarshal(f, &ctrl)
		if err != nil {
			return nil, err
		}
		ruleNames = append(ruleNames, ctrl)
	}

	return ruleNames, nil
}

func listRuleNames() ([]string, error) {
	baseDir := path.Join(rulesDir...)
	rulesDirs, err := ioutil.ReadDir(baseDir)
	if err != nil {
		return nil, err
	}

	ruleNames := []string{}
	for _, dir := range rulesDirs {
		if !dir.IsDir() {
			continue
		}
		f, err := ioutil.ReadFile(path.Join(baseDir, dir.Name(), ruleMetadataFile))
		if err != nil {
			return nil, err
		}
		rule := reporthandling.PolicyRule{}
		err = json.Unmarshal(f, &rule)
		if err != nil {
			return nil, err
		}
		ruleNames = append(ruleNames, rule.Name)
	}

	return ruleNames, nil
}

func strSliceToMap(in []string) map[string]bool {
	out := map[string]bool{}
	for _, str := range in {
		out[str] = true
	}
	return out
}
