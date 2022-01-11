package testing

import (
	"fmt"
	"os"
	"testing"
	"testrunner/opaprocessor"
)

var (
	testSingleRegoDirectory = "test-single-rego"
	relativeRuleTestsPath   = "../rules-tests"
)

// Run all tests inside rules-tests
func TestAllRules(t *testing.T) {
	file, err := os.Open(relativeRuleTestsPath)
	if err != nil {
		t.Errorf("err: %v", err.Error())
	}
	defer file.Close()
	// List all files
	ruleTestDirectories, err := file.Readdirnames(0)
	if err != nil {
		t.Errorf("err: %v", err.Error())
	}
	for _, dir := range ruleTestDirectories {
		dir = fmt.Sprintf("%v/%v", relativeRuleTestsPath, dir)
		isDir, err := opaprocessor.IsDirectory(dir)
		if err != nil {
			t.Errorf("err: %v", err.Error())
		}
		if !isDir {
			continue
		}
		err = opaprocessor.RunAllTestsForRule(dir)
		if err != nil {
			t.Errorf("err: %v in rule: %v", err.Error(), dir)
		}
	}
}

func TestSingleRule(t *testing.T) {
	dir := "rule-exposed-dashboard-v1"
	dir = fmt.Sprintf("%v/%v", relativeRuleTestsPath, dir)
	err := opaprocessor.RunAllTestsForRule(dir)
	if err != nil {
		t.Errorf("err: %v in rule: %v", err.Error(), dir)
	}
}
func TestRunRegoOnMultipleYamls(t *testing.T) {
	dir := fmt.Sprintf("%v/input", testSingleRegoDirectory)
	mocks, err := os.Open(dir)
	if err != nil {
		t.Errorf("err: %v in rule: %v", err.Error(), testSingleRegoDirectory)
	}
	mockyamls, err := mocks.Readdirnames(0)
	if err != nil {
		t.Errorf("err: %v in rule: %v", err.Error(), dir)
	}
	var yamlsInput []string
	for _, mockyaml := range mockyamls {
		mock, err := opaprocessor.GetMockContentFromFile(fmt.Sprintf("%v/%v", dir, mockyaml))
		if err != nil {
			t.Errorf("err: %v in rule: %v", err.Error(), dir)
		}
		yamlsInput = append(yamlsInput, mock)
	}
	rego, err := os.ReadFile(fmt.Sprintf("%v/regotest.rego", testSingleRegoDirectory))
	if err != nil {
		t.Errorf("%v", err.Error())
	}
	policyBytes, err := os.ReadFile(fmt.Sprintf("%v/rule.metadata.json", testSingleRegoDirectory))
	if err != nil {
		t.Errorf("err: %v in rule: %v", err.Error(), dir)
	}
	policy := string(policyBytes)
	policyRule, err := opaprocessor.SetPolicyRule(policy, string(rego))
	if err != nil {
		t.Errorf("err: %v in rule: %v", err.Error(), dir)
	}
	result, err := opaprocessor.RunRegoFromYamls(yamlsInput, policyRule)
	if err != nil {
		t.Errorf("err: %v in rule: %v", err.Error(), dir)
	}
	t.Errorf(result)
}
