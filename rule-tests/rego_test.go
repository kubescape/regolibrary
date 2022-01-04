package testing

import (
	"fmt"
	"os"
	"regolibrary/opaprocessor"
	"testing"

	"github.com/armosec/opa-utils/reporthandling"
)

func TestAllRules(t *testing.T) {
	file, err := os.Open("./")
	if err != nil {
		t.Errorf("err: %v", err.Error())
	}
	defer file.Close()
	ruleTestDirectories, err := file.Readdirnames(0)
	if err != nil {
		t.Errorf("err: %v", err.Error())
	}
	for _, dir := range ruleTestDirectories {
		isDir, err := opaprocessor.IsDirectory(dir)
		if err != nil {
			t.Errorf("err: %v", err.Error())
		}
		if !isDir {
			continue
		}
		err = runAllTestsForRule(dir)
		if err != nil {
			t.Errorf("err: %v in rule: %v", err.Error(), dir)
		}
	}
}

func TestSingleRule(t *testing.T) {
	dir := "alert-any-hostpath"
	err := runAllTestsForRule(dir)
	if err != nil {
		t.Errorf("err: %v in rule: %v", err.Error(), dir)
	}
}

// dir is the rule name
func runAllTestsForRule(dir string) error {
	rego, err := opaprocessor.GetRego(dir)
	if err != nil {
		return err
	}
	policy, err := opaprocessor.GetPolicy(dir)
	if err != nil {
		return err
	}
	policyRule, err := opaprocessor.SetPolicyRule(policy, rego)
	if err != nil {
		return err
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	testsForRule, err := f.Readdirnames(0)
	if err != nil {
		return err
	}

	// Iterate over each test
	for _, testFile := range testsForRule {
		dir := fmt.Sprintf("%v/%v", dir, testFile)
		err := runSingleTest(dir, policyRule)
		if err != nil {
			return err
		}
	}
	return nil
}

func runSingleTest(dir string, policyRule *reporthandling.PolicyRule) error {
	inputRawResources, err := opaprocessor.GetInputRawResources(dir, policyRule)
	if err != nil {
		return err
	}

	responses, err := opaprocessor.RunSingleRego(policyRule, inputRawResources)
	if err != nil {
		return err
	}

	expectedResponses, err := opaprocessor.GetExpectedResults(dir)
	if err != nil {
		return err
	}
	err = opaprocessor.AssertResponses(responses, expectedResponses)
	if err != nil {
		return err
	}
	return nil
}
