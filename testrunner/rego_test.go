package testing

import (
	"flag"
	"fmt"
	"os"
	"testing"
	"testrunner/opaprocessor"

	"github.com/stretchr/testify/assert"
)

var (
	testSingleRegoDirectory = "test-single-rego"
	// relativeRuleTestsPath   = "../rules-tests"
	rulesDirectory = "../rules"
	ruleName       = flag.String("rule", "", "rule to test")
)

// Run all tests inside rules-tests
func TestAllRules(t *testing.T) {
	file, err := os.Open(rulesDirectory)
	assert.NoError(t, err)

	defer file.Close()
	// List all files
	ruleDirectories, err := file.Readdirnames(0)
	assert.NoError(t, err)

	for _, dir := range ruleDirectories {
		dir = fmt.Sprintf("%v/%v", rulesDirectory, dir)
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
	if *ruleName == "" {
		t.Log("please, provide the rule name you want to test using '-rule' flag.")
		os.Exit(1)
	}
	dir := fmt.Sprintf("%v/%v", rulesDirectory, *ruleName)

	assert.NoError(t, opaprocessor.RunAllTestsForRule(t, dir), fmt.Sprintf("rule: %s", dir))
}

// To print the output
// Change the testDir variable to the directory of the rego you want to test
func TestSingleRego(t *testing.T) {
	testDir := "ensure-that-the-scheduler-profiling-argument-is-set-to-false"
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
