package testing

// import (
// 	"context"
// 	"encoding/json"
// 	"fmt"
// 	"os"
// 	"path"
// 	"regexp"
// 	"testing"
// 	"testrunner/opaprocessor"

// 	"github.com/armosec/armoapi-go/armotypes"
// 	"github.com/kubescape/opa-utils/reporthandling"
// 	"github.com/stretchr/testify/assert"

// 	"github.com/nsf/jsondiff"
// 	"github.com/open-policy-agent/opa/bundle"
// 	_ "github.com/open-policy-agent/opa/features/wasm" // Enable Wasm bundle support
// 	"github.com/open-policy-agent/opa/loader"
// 	"github.com/open-policy-agent/opa/rego"
// )

// const (
// 	rulesDirName         = "rules"
// 	rulesTestDirName     = "rules-tests"
// 	ruleMetadataFileName = "rule.metadata.json"
// )

// // TestRegoBundles is the bundle test entry point
// func TestRegoBundles(t *testing.T) {
// 	bundlePath := os.Getenv("BUNDLE")
// 	if bundlePath == "" {
// 		t.Skip("BUNDLE environment variable is not set")
// 	}

// 	// skipped rules
// 	skippedRulesPath := os.Getenv("SKIPPED_RULES")
// 	skippedRules := map[string]bool{}
// 	if skippedRulesPath != "" {
// 		skippedRulesBytes, err := os.ReadFile(skippedRulesPath)
// 		if err != nil {
// 			t.Fatalf("Failed to read skipped rules file: %v", err)
// 		}
// 		skipper := struct {
// 			SkippedRules []string `json:"rules"`
// 		}{}
// 		err = json.Unmarshal(skippedRulesBytes, &skipper)
// 		if err != nil {
// 			t.Fatalf("Failed to unmarshal skipped rules file: %v", err)
// 		}
// 		for _, rule := range skipper.SkippedRules {
// 			skippedRules[rule] = true
// 		}
// 	}

// 	t.Run("rules", func(t *testing.T) {
// 		testBundle(t, bundlePath, skippedRules)
// 	})

// 	t.Run("controls and frameworks", func(t *testing.T) {
// 		testBundleControlsAndFrameworks(t, bundlePath)
// 	})
// }

// // testBundleControlsAndFrameworks tests the generated controls and frameworks.
// // It tests only one rule, but it's enough since all the
// // controls and frameworks are generated.
// func testBundleControlsAndFrameworks(t *testing.T, bundlePath string) {

// 	testRule := "resource-policies"
// 	testControl := "C-0009"
// 	testFramework := "ArmoBest"

// 	normalizedRule := normalizeRuleName(testRule)
// 	normalizedControl := normalizeRuleName(testControl)
// 	normalizedFramework := normalizeRuleName(testFramework)

// 	cases := []struct {
// 		name  string
// 		query string
// 	}{
// 		{
// 			name:  "framework",
// 			query: fmt.Sprintf("data.armo_builtins.frameworks.%s.deny", normalizedFramework),
// 		},
// 		{
// 			name:  "control",
// 			query: fmt.Sprintf("data.armo_builtins.controls.%s.deny", normalizedControl),
// 		},
// 	}

// 	// Load the bundle
// 	b, err := loader.NewFileLoader().AsBundle(bundlePath)
// 	assert.NoError(t, err)
// 	if err != nil {
// 		t.FailNow()
// 	}

// 	// get input
// 	ruleDir := path.Join("..", rulesDirName, testRule)
// 	ruleMetadata, err := readRuleMetadata(ruleDir)
// 	assert.NoError(t, err)

// 	testsPath := path.Join(relativeRuleTestsPath, testRule)
// 	testCases, err := os.ReadDir(testsPath)
// 	assert.NoError(t, err)

// 	for _, testDir := range testCases {
// 		if !testDir.IsDir() {
// 			continue
// 		}

// 		if !isFailingTest(path.Join(testsPath, testDir.Name())) {
// 			continue
// 		}

// 		t.Run(testDir.Name(), func(t *testing.T) {
// 			testDir := path.Join(testsPath, testDir.Name())

// 			// get input
// 			input, err := opaprocessor.GetInputRawResources(testDir, &ruleMetadata)
// 			assert.NoError(t, err)

// 			// eval rule
// 			ruleRs := slowEval(t, b, getBundleQueryForRuleName(normalizedRule)+".deny", input).([]interface{})
// 			assert.Greater(t, len(ruleRs), 0, "rule should have at least one result")
// 			for _, tt := range cases {
// 				t.Run(tt.name, func(t *testing.T) {

// 					// Verbose result level test
// 					t.Run("verbose", func(t *testing.T) {
// 						b.Data["settings"] = map[string]interface{}{
// 							"verbose": true,
// 						}
// 						testRs := slowEval(t, b, tt.query, input).([]interface{})
// 						jsonAssertContain(t, ruleRs, testRs)
// 					})

// 					// Metadata results level test
// 					t.Run("metadata", func(t *testing.T) {
// 						b.Data["settings"] = map[string]interface{}{
// 							"verbose":  false,
// 							"metadata": true,
// 						}
// 						tmp := slowEval(t, b, tt.query, input).(map[string]interface{})["results"]
// 						testRs, ok := tmp.([]interface{})
// 						if !ok { // framework results
// 							testRs = tmp.(map[string]interface{})[normalizedControl].(map[string]interface{})["results"].([]interface{})
// 						}
// 						jsonAssertContain(t, ruleRs, testRs)
// 					})

// 					// No metadata results level test
// 					t.Run("no-metadata", func(t *testing.T) {
// 						b.Data["settings"] = map[string]interface{}{
// 							"verbose":  false,
// 							"metadata": false,
// 						}
// 						testRs := slowEval(t, b, tt.query, input).([]interface{})
// 						jsonAssertContain(t, ruleRs, testRs)
// 					})
// 				})
// 			}
// 		})
// 	}

// }

// func isFailingTest(testDir string) bool {
// 	data, _ := opaprocessor.GetExpectedResults(testDir)
// 	return len(data) > 0
// }

// // slowEval evaluates the bundle with the given query
// func slowEval(t *testing.T, b *bundle.Bundle, query string, input interface{}) interface{} {
// 	r, err := lowLevelPrepareBundle(b, query) // For some reason, this line takes a lot of time even though the bundle is already loaded
// 	assert.NoError(t, err)
// 	if err != nil {
// 		t.FailNow()
// 	}
// 	rs, err := r.Eval(context.Background(), rego.EvalInput(input))
// 	assert.NoError(t, err)
// 	if err != nil {
// 		t.FailNow()
// 	}
// 	assertRegoRes(t, rs, err)
// 	return rs[0].Expressions[0].Value
// }

// func assertRegoRes(t *testing.T, rs rego.ResultSet, err error) {
// 	assert.NoError(t, err)
// 	assert.Greater(t, len(rs), 0)
// 	if len(rs) == 0 {
// 		t.FailNow()
// 	}
// 	assert.Greater(t, len(rs[0].Expressions), 0)
// 	if len(rs[0].Expressions) == 0 {
// 		t.FailNow()
// 	}

// 	if val, ok := rs[0].Expressions[0].Value.([]interface{}); ok {
// 		assert.Greater(t, len(val), 0)
// 	}

// 	if val, ok := rs[0].Expressions[0].Value.(map[string]interface{}); ok {
// 		assert.Greater(t, len(val), 0)
// 	}
// }

// // jsonAssertContain asserts that the expected json is contained in the actual json
// func jsonAssertContain(t *testing.T, expected, actual interface{}) {
// 	t.Helper()

// 	// marshal
// 	expectedBytes, err := json.Marshal(expected)
// 	assert.NoError(t, err)
// 	actualBytes, err := json.Marshal(actual)
// 	assert.NoError(t, err)

// 	// Superset equality means the first object is a superset of the second object,
// 	// so we are switching the order of the arguments to make sure all the expected fields are present
// 	diff, _ := jsondiff.Compare(actualBytes, expectedBytes, &jsondiff.Options{})
// 	assert.LessOrEqual(t, diff, jsondiff.SupersetMatch)
// }

// func loadDefaultConfigInputs() (map[string][]string, error) {
// 	var ret map[string][]string
// 	ConfigInput, err := os.ReadFile("../default-config-inputs.json")
// 	if err != nil {
// 		return ret, err
// 	}

// 	var customerConfig *armotypes.CustomerConfig
// 	err = json.Unmarshal(ConfigInput, &customerConfig)
// 	return customerConfig.Settings.PostureControlInputs, err
// }

// func normalizeRuleName(ruleName string) string {
// 	var re = regexp.MustCompile(`[^a-zA-Z0-9_]`)
// 	return re.ReplaceAllString(ruleName, "_")
// }

// func getBundleQueryForRule(rule reporthandling.PolicyRule) string {
// 	return getBundleQueryForRuleName(rule.Name)
// }

// func getBundleQueryForRuleName(ruleName string) string {
// 	return fmt.Sprintf("data.armo_builtins.rules.%s.raw", normalizeRuleName(ruleName))
// }

// func readRuleMetadata(ruleDir string) (reporthandling.PolicyRule, error) {
// 	var rule reporthandling.PolicyRule
// 	metadataFile, err := os.ReadFile(path.Join(ruleDir, ruleMetadataFileName))
// 	if err != nil {
// 		return rule, err
// 	}
// 	err = json.Unmarshal(metadataFile, &rule)
// 	return rule, err
// }

// func prepareBundle(b *bundle.Bundle, rule reporthandling.PolicyRule, controlInputs map[string][]string) (rego.PreparedEvalQuery, error) {
// 	if controlInputs != nil {
// 		b.Data = map[string]interface{}{"postureControlInputs": controlInputs}
// 	}
// 	return lowLevelPrepareBundle(b, getBundleQueryForRule(rule))
// }

// func lowLevelPrepareBundle(b *bundle.Bundle, query string) (rego.PreparedEvalQuery, error) {
// 	return rego.New(
// 		rego.Query(query),
// 		rego.ParsedBundle("test", b),
// 	).PrepareForEval(context.Background())
// }

// // processResult - process the result of the rego evaluation,
// // for further comparison with the expected result.
// // We probably don't need this, keeping for backwards compatibility
// func processResult(rs rego.ResultSet) ([]reporthandling.RuleResponse, error) {
// 	// Process the results
// 	// We probably don't need this, keeping for backwards compatibility
// 	results, err := reporthandling.ParseRegoResult(&rs)
// 	if err != nil {
// 		return results, err
// 	}

// 	// Remove overload from results
// 	// We probably don't need this, keeping for backwards compatibility
// 	ruleReport := reporthandling.RuleReport{
// 		RuleResponses: results,
// 	}
// 	keepFields := []string{"kind", "apiVersion", "metadata"}
// 	keepMetadataFields := []string{"name", "labels"}
// 	ruleReport.RuleResponses = results
// 	ruleReport.RemoveData(keepFields, keepMetadataFields)
// 	return results, nil
// }

// func testBundle(t *testing.T, bundlePath string, skipRules map[string]bool) {
// 	// TODO: get rid of all the old opaprocessor functions

// 	/*
// 		Load the bundle
// 		Currently OPA API doesn't support querying different rules
// 		using `rego.New(rego.LoadBundle(bundlePath), ...)`.
// 		So we must create another rego object for every rule,
// 		if we don't want to run all the rules in the bundle,
// 		every time we evaluate a rule (using armo_builtins.rules).
// 		since we have different inputs for each rule.
// 		It worth benchmarking though.

// 		In order not to load the bundle every time, we use the `rego.ParsedBundle` option
// 	*/
// 	b, err := loader.NewFileLoader().AsBundle(bundlePath)
// 	assert.NoError(t, err)

// 	// // Read default config inputs
// 	// defaultConfigInputs, err := loadDefaultConfigInputs()
// 	// assert.NoError(t, err)

// 	// List all files
// 	rulesTest, err := os.ReadDir(relativeRuleTestsPath)
// 	assert.NoError(t, err)

// 	for _, ruleTest := range rulesTest {
// 		if !ruleTest.IsDir() {
// 			continue
// 		}
// 		bundleTestRule(t, b, ruleTest.Name(), skipRules)
// 	}
// }

// // bundleTestRule tests a single rule in a bundle
// func bundleTestRule(t *testing.T, b *bundle.Bundle, ruleDir string, skipRules map[string]bool) {
// 	ruleMetadata, err := readRuleMetadata(path.Join("..", rulesDirName, ruleDir))
// 	assert.NoError(t, err)

// 	// Skip rule if it's in the skip list
// 	if skipRules[ruleMetadata.Name] {
// 		t.Skip(fmt.Sprintf("Skipping rule %s", ruleMetadata.Name))
// 	}

// 	defaultRuleRego, err := prepareBundle(b, ruleMetadata, nil)
// 	assert.NoError(t, err)

// 	t.Run(ruleDir, func(t *testing.T) {
// 		testsPath := path.Join(relativeRuleTestsPath, ruleDir)
// 		testCases, err := os.ReadDir(testsPath)
// 		assert.NoError(t, err)

// 		for _, testDir := range testCases {
// 			if !testDir.IsDir() {
// 				continue
// 			}
// 			t.Run(testDir.Name(), func(t *testing.T) {
// 				bundleTestCase(t, testsPath, testDir.Name(), ruleMetadata, defaultRuleRego, b)
// 			})
// 		}
// 	})
// }

// // bundleTestCase tests a single test case for a rule in a bundle
// func bundleTestCase(t *testing.T, testsPath, testDir string, ruleMetadata reporthandling.PolicyRule, defaultRuleRego rego.PreparedEvalQuery, b *bundle.Bundle) {
// 	testPath := path.Join(testsPath, testDir)

// 	input, err := opaprocessor.GetInputRawResources(testPath, &ruleMetadata)
// 	assert.NoError(t, err)

// 	// Get Config input
// 	data, err := opaprocessor.GetData(testPath, &ruleMetadata)
// 	assert.NoError(t, err)

// 	var pq rego.PreparedEvalQuery = defaultRuleRego
// 	if len(data) != 0 {
// 		postureControlInput, err := loadDefaultConfigInputs()
// 		assert.NoError(t, err)
// 		for i := range data {
// 			postureControlInput[i] = data[i]
// 		}
// 		pq, err = prepareBundle(b, ruleMetadata, postureControlInput)
// 		assert.NoError(t, err)
// 	}

// 	// Run the query
// 	rs, err := pq.Eval(context.Background(), rego.EvalInput(input))
// 	assert.NoError(t, err)

// 	// Process the results
// 	results, err := processResult(rs)
// 	assert.NoError(t, err)

// 	// Compare against expected results
// 	expectedResponses, err := opaprocessor.GetExpectedResults(testPath)
// 	assert.NoError(t, err)

// 	err = opaprocessor.AssertResponses(t, results, expectedResponses)
// 	assert.NoError(t, err)
// }
