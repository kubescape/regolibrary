package testing

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"tests/opaprocessor"

	"github.com/armosec/opa-utils/reporthandling"
)

var testSingleRegoDirectory = "test-single-rego"
var opaProcessorDir = "opaprocessor"

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
		if !isDir || dir == testSingleRegoDirectory || dir == opaProcessorDir {
			continue
		}
		err = runAllTestsForRule(dir)
		if err != nil {
			t.Errorf("err: %v in rule: %v", err.Error(), dir)
		}
	}
}

func TestSingleRule(t *testing.T) {
	dir := "rule-list-all-cluster-admins-v1"
	err := runAllTestsForRule(dir)
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
			currentTest := getCurrentTest(dir)
			return fmt.Errorf("%v in test: %v", err.Error(), currentTest)
		}
	}
	return nil
}

func getCurrentTest(dir string) string {
	testDir := strings.Split(dir, "/")
	if len(testDir) > 1 {
		return testDir[len(testDir)-1]
	}
	return ""
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
