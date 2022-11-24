package testing

import (
	"fmt"
	"os"
	"path"
	"testing"
	"testrunner/opaprocessor"

	"github.com/stretchr/testify/assert"
)

var (
	testSingleRegoDirectory = "test-single-rego"
	relativeRuleTestsPath   = "../rules-tests"
)

// Run all tests inside rules-tests
func TestAllRules(t *testing.T) {
	file, err := os.Open(relativeRuleTestsPath)
	assert.NoError(t, err)

	defer file.Close()
	// List all files
	ruleTestDirectories, err := file.Readdirnames(0)
	assert.NoError(t, err)

	for _, dir := range ruleTestDirectories {
		dir = fmt.Sprintf("%v/%v", relativeRuleTestsPath, dir)
		isDir, err := opaprocessor.IsDirectory(dir)
		assert.NoError(t, err)
		if !isDir {
			continue
		}
		opaprocessor.RunAllTestsForRule(t, dir)
	}
}

// Change the dir variable to the name of the rule you want to test (in the rules-tests dir)
func TestSingleRule(t *testing.T) {
	dir := fmt.Sprintf("%v/%v", relativeRuleTestsPath, "etcd-peer-tls-enabled")
	assert.NoError(t, opaprocessor.RunAllTestsForRule(t, dir), fmt.Sprintf("rule: %s", dir))
}

// To print the output
// Change the testDir variable to the directory of the rego you want to test
func TestSingleRego(t *testing.T) {
	testDir := "alert-rw-hostpath"
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
	testDir = fmt.Sprintf("%v/%v", opaprocessor.RelativeRulesPath, testDir)
	rego, err := opaprocessor.GetRego(testDir)
	if err != nil {
		t.Errorf("%v", err.Error())
	}
	policyBytes, err := opaprocessor.GetPolicy(testDir)
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
