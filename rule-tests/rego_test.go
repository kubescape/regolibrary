package testing

import (
	"fmt"
	"os"
	"regolibrary/opaprocessor"
	"testing"
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
		rego, err := opaprocessor.GetRego(dir)
		if err != nil {
			t.Errorf("err: %v", err.Error())
		}
		policy, err := opaprocessor.GetPolicy(dir)
		if err != nil {
			t.Errorf("err: %v", err.Error())
		}
		policyRule, err := opaprocessor.SetPolicyRule(policy, rego)
		if err != nil {
			t.Errorf("err: %v", err.Error())
		}
		f, err := os.Open(dir)
		if err != nil {
			t.Errorf("err: %v", err.Error())
		}
		defer f.Close()
		testsForRule, err := f.Readdirnames(0)
		if err != nil {
			t.Errorf("err: %v", err.Error())
		}
		// Iterate over each test
		for _, testFile := range testsForRule {
			dir := fmt.Sprintf("%v/%v", dir, testFile)

			inputRawResources, err := opaprocessor.GetInputRawResources(dir, policyRule)
			if err != nil {
				t.Errorf("err: %v", err.Error())
			}

			responses, err := opaprocessor.RunSingleRego(policyRule, inputRawResources)
			if err != nil {
				t.Errorf("err: %v", err.Error())
			}

			expectedResponses, err := opaprocessor.GetExpectedResults(dir)
			if err != nil {
				t.Errorf("err: %v", err.Error())
			}
			if !opaprocessor.AssertResponses(responses, expectedResponses) {
				t.Fail()
			}
		}
	}
}

func TestSingleRule(t *testing.T) {
	// TODO
}
