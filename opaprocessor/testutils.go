package opaprocessor

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"

	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/opa-utils/objectsenvelopes"
	"github.com/armosec/opa-utils/reporthandling"
	"gopkg.in/yaml.v2"
)

var expectedFilename = "expected.json"

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
		metadataResource := objectsenvelopes.NewObject(resp)
		IMetadataResources = append(IMetadataResources, metadataResource)
		IMetadataResources, _ = reporthandling.RegoResourcesAggregator(policyRule, IMetadataResources)
	}
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

// func AssertResponses(responses []reporthandling.RuleResponse, expectedResponses []reporthandling.RuleResponse) bool {
// 	return reflect.DeepEqual(responses, expectedResponses)
// }

func AssertResponses(responses []reporthandling.RuleResponse, expectedResponses []reporthandling.RuleResponse) error {
	if len(expectedResponses) != len(responses) {
		return fmt.Errorf("lenght of responses is different")
	}
	for i := 0; i < len(expectedResponses); i++ {
		if expectedResponses[i].RuleStatus != responses[i].RuleStatus {
			return fmt.Errorf("the field 'RuleStatus' is different for response %v", i)
		}
		if len(expectedResponses[i].AlertObject.ExternalObjects) != len(responses[i].AlertObject.ExternalObjects) {
			return fmt.Errorf("lenght of 'ExternalObjects' is different for response %v", i)
		}
		if len(expectedResponses[i].AlertObject.K8SApiObjects) != len(responses[i].AlertObject.K8SApiObjects) {
			return fmt.Errorf("lenght of 'K8SApiObjects' is different for response %v", i)
		}
		err := CompareAlertObject(expectedResponses[i].AlertObject, responses[i].AlertObject)
		if err != nil {
			return fmt.Errorf("%v for response %v", err.Error(), i)
		}
		if len(expectedResponses[i].FailedPaths) != len(responses[i].FailedPaths) {
			return fmt.Errorf("lenght of 'FailedPaths' is different for response %v", i)
		}
		err = CompareFailedPaths(expectedResponses[i].FailedPaths, responses[i].FailedPaths)
		if err != nil {
			return fmt.Errorf("%v for response %v", err.Error(), i)
		}

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

	eq := reflect.DeepEqual(expected.ExternalObjects, actual.ExternalObjects)
	if !eq {
		return fmt.Errorf("field 'ExternalObjects' is different. expected: %v, got :%v", expected, actual)
	}
	eq = reflect.DeepEqual(expected.K8SApiObjects, actual.K8SApiObjects)
	if !eq {
		return fmt.Errorf("field 'K8SApiObjects' is different .expected: %v, got :%v", expected, actual)
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
	resource := make(map[string]interface{})
	for _, input := range inputs {
		mock, _ := GetMockContentFromFile(fmt.Sprintf("%v/%v", dir, input.Name()))
		err := json.Unmarshal([]byte(mock), &resource)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return resources, nil
}
