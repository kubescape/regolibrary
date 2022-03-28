package opaprocessor

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/opa-utils/objectsenvelopes"
	"github.com/armosec/opa-utils/reporthandling"
	"gopkg.in/yaml.v2"
)

var (
	RelativeRulesPath = "../rules"
	expectedFilename  = "expected.json"
)

func convertYamlToJson(i interface{}) interface{} {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range x {
			if s, ok := k.(string); ok {
				m2[s] = convertYamlToJson(v)
			}
		}
		return m2
	case []interface{}:
		for i, v := range x {
			x[i] = convertYamlToJson(v)
		}
	}
	return i
}

func GetInputRawResources(dir string, policyRule *reporthandling.PolicyRule) ([]map[string]interface{}, error) {
	var IMetadataResources []workloadinterface.IMetadata

	resources, err := GetInputResources(fmt.Sprintf("%v/input", dir))
	if err != nil {
		return nil, err
	}
	for _, resp := range resources {
		if resp == nil {
			return nil, fmt.Errorf("resource is nil")
		}
		metadataResource := objectsenvelopes.NewObject(resp)
		// if metadataResource.GetNamespace() == "" {
		// 	metadataResource.SetNamespace("default")
		// }
		IMetadataResources = append(IMetadataResources, metadataResource)
	}
	IMetadataResources, _ = reporthandling.RegoResourcesAggregator(policyRule, IMetadataResources)
	inputRawResources := workloadinterface.ListMetaToMap(IMetadataResources)
	return inputRawResources, nil
}

func GetMockContentFromFile(filename string) (string, error) {
	mockContent, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	var body interface{}
	if err := yaml.Unmarshal([]byte(mockContent), &body); err != nil {
		return "", err
	}
	body = convertYamlToJson(body)

	mockContentJson, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return string(mockContentJson), err
}

func AssertResponses(responses []reporthandling.RuleResponse, expectedResponses []reporthandling.RuleResponse) error {
	if len(expectedResponses) != len(responses) {
		return fmt.Errorf("length of responses is different (%d instead of %d)", len(responses), len(expectedResponses))
	}
	for i := 0; i < len(expectedResponses); i++ {
		if !assertResponses(responses, &expectedResponses[i]) {
			return fmt.Errorf("responses not matching")
		}
	}
	return nil
	// for i := 0; i < len(responses); i++ {
	// 	if expectedResponses[i].RuleStatus != responses[i].RuleStatus {
	// 		return fmt.Errorf("the field 'RuleStatus' is different for response %v. expected: %v, got :%v", i, expectedResponses[i].RuleStatus, responses[i].RuleStatus)
	// 	}
	// 	if len(expectedResponses[i].AlertObject.ExternalObjects) != len(responses[i].AlertObject.ExternalObjects) {
	// 		return fmt.Errorf("length of 'ExternalObjects' is different for response %v. expected: %v, got :%v", i, expectedResponses[i].AlertObject.ExternalObjects, responses[i].AlertObject.ExternalObjects)
	// 	}
	// 	if len(expectedResponses[i].AlertObject.K8SApiObjects) != len(responses[i].AlertObject.K8SApiObjects) {
	// 		return fmt.Errorf("length of 'K8SApiObjects' is different for response %v. expected: %v, got :%v", i, expectedResponses[i].AlertObject.K8SApiObjects, responses[i].AlertObject.K8SApiObjects)
	// 	}
	// 	err := CompareAlertObject(expectedResponses[i].AlertObject, responses[i].AlertObject)
	// 	if err != nil {
	// 		return fmt.Errorf("%v for response %v", err.Error(), i)
	// 	}
	// 	if len(expectedResponses[i].FailedPaths) != len(responses[i].FailedPaths) {
	// 		return fmt.Errorf("length of 'FailedPaths' is different for response %v. expected: %v, got :%v", i, expectedResponses[i].FailedPaths, responses[i].FailedPaths)
	// 	}
	// 	err = CompareFailedPaths(expectedResponses[i].FailedPaths, responses[i].FailedPaths)
	// 	if err != nil {
	// 		return fmt.Errorf("%v for response %v", err.Error(), i)
	// 	}
	// 	if len(expectedResponses[i].FixPaths) != len(responses[i].FixPaths) {
	// 		return fmt.Errorf("length of 'FixPaths' is different for response %v. expected: %v, got :%v", i, expectedResponses[i].FixPaths, responses[i].FixPaths)
	// 	}
	// 	err = CompareFixPaths(expectedResponses[i].FixPaths, responses[i].FixPaths)
	// 	if err != nil {
	// 		return fmt.Errorf("%v for response %v", err.Error(), i)
	// 	}
	// }
	// return nil
}

func hash(s *reporthandling.RuleResponse) []byte {
	var b bytes.Buffer
	gob.NewEncoder(&b).Encode(*s)
	return b.Bytes()
}

func comapreRuleResponse(s1, s2 *reporthandling.RuleResponse) bool {
	return bytes.Compare(hash(s1), hash(s2)) == 0
}
func assertResponses(responses []reporthandling.RuleResponse, expectedResponse *reporthandling.RuleResponse) bool {

	for i := 0; i < len(responses); i++ {
		if comapreRuleResponse(&responses[i], expectedResponse) {
			return true
		}
	}
	return false
}

func CompareFixPaths(expected []armotypes.FixPath, actual []armotypes.FixPath) error {
	eq := reflect.DeepEqual(expected, actual)
	if !eq {
		return fmt.Errorf("field 'FixPaths' is different. expected: %v, got :%v", expected, actual)
	}
	return nil
}

func CompareFailedPaths(expected []string, actual []string) error {
	eq := reflect.DeepEqual(expected, actual)
	if !eq {
		return fmt.Errorf("field 'FailedPaths' is different. expected: %v, got :%v", expected, actual)
	}
	return nil
}

func CompareAlertObject(expected reporthandling.AlertObject, actual reporthandling.AlertObject) error {

	expectedinJson, err := json.Marshal(expected)
	if err != nil {
		return fmt.Errorf("expected response is not valid json")
	}
	actualinJson, err := json.Marshal(actual)
	if err != nil {
		return fmt.Errorf(" response is not valid json")
	}
	var eq bool
	if len(expected.ExternalObjects) > 0 {
		eq = reflect.DeepEqual(expected.ExternalObjects, actual.ExternalObjects)
		if !eq {
			return fmt.Errorf("field 'ExternalObjects' is different. expected: %v, got :%v", string(expectedinJson), string(actualinJson))
		}
	}
	if len(expected.K8SApiObjects) > 0 {
		eq = reflect.DeepEqual(expected.K8SApiObjects, actual.K8SApiObjects)
		if !eq {
			return fmt.Errorf("field 'K8SApiObjects' is different .expected: %v, got :%v", string(expectedinJson), string(actualinJson))
		}
	}
	return nil
}

func IsDirectory(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fileInfo.IsDir(), err
}

func SetPolicyRule(policy string, rego string) (*reporthandling.PolicyRule, error) {
	policyRule := reporthandling.PolicyRule{}
	err := json.Unmarshal([]byte(policy), &policyRule)
	if err != nil {
		return nil, err
	}
	policyRule.Rule = rego
	return &policyRule, nil
}

func GetExpectedResults(dir string) ([]reporthandling.RuleResponse, error) {
	expected, err := ioutil.ReadFile(fmt.Sprintf("%v/%v", dir, expectedFilename))
	if err != nil {
		return nil, err
	}
	expectedResponses := []reporthandling.RuleResponse{}
	err = json.Unmarshal([]byte(expected), &expectedResponses)
	if err != nil {
		expectedResponse := reporthandling.RuleResponse{}
		err = json.Unmarshal([]byte(expected), &expectedResponse)
		if err != nil {
			return nil, err
		}
		expectedResponses = []reporthandling.RuleResponse{expectedResponse}
	}
	return expectedResponses, nil
}

func GetInputResources(dir string) ([]map[string]interface{}, error) {
	inputs, _ := ioutil.ReadDir(dir)
	var resources []map[string]interface{}

	for _, input := range inputs {
		var resource map[string]interface{}
		mock, err := GetMockContentFromFile(fmt.Sprintf("%v/%v", dir, input.Name()))
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal([]byte(mock), &resource)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

func RunAllTestsForRule(dir string) error {
	ruleNameSplited := strings.Split(dir, "/")
	ruleName := ruleNameSplited[len(ruleNameSplited)-1]
	regoDir := fmt.Sprintf("%v/%v", RelativeRulesPath, ruleName)

	rego, err := GetRego(regoDir)
	if err != nil {
		return err
	}
	policy, err := GetPolicy(dir)
	if err != nil {
		return err
	}
	policyRule, err := SetPolicyRule(policy, rego)
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
		if GetCurrentTest(dir) == "clusterrole-clusterrolebinding" {
			fmt.Printf("A")
		}
		err := RunSingleTest(dir, policyRule)
		if err != nil {
			err := RunSingleTest(dir, policyRule)

			return fmt.Errorf("%v in test: %v with policy %v", err.Error(), GetCurrentTest(dir), policyRule.Name)
		}
	}
	return nil
}

func GetCurrentTest(dir string) string {
	testDir := strings.Split(dir, "/")
	if len(testDir) > 1 {
		return testDir[len(testDir)-1]
	}
	return ""
}

func RunSingleTest(dir string, policyRule *reporthandling.PolicyRule) error {
	inputRawResources, err := GetInputRawResources(dir, policyRule)
	if err != nil {
		return err
	}

	responses, err := RunSingleRego(policyRule, inputRawResources)
	if err != nil {
		return err
	}

	expectedResponses, err := GetExpectedResults(dir)
	if err != nil {
		return err
	}
	err = AssertResponses(responses, expectedResponses)
	if err != nil {
		return err
	}
	return nil
}
