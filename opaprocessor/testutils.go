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

var relevantFields = []string{"FailedPaths", "RuleStatus", "AlertObject"}

// AlertMessage string                            `json:"alertMessage"`
// 	FailedPaths  []string                          `json:"failedPaths"`
// 	RuleStatus   string                            `json:"ruleStatus"`
// 	PackageName  string                            `json:"packagename"`
// 	AlertScore   AlertScore                        `json:"alertScore"`
// 	AlertObject  AlertObject                       `json:"alertObject"`
// 	Context      []string                          `json:"context,omitempty"`  // TODO - Remove
// 	Rulename     string                            `json:"rulename,omitempty"` // TODO - Remove
// 	Exception    *armotypes.PostureExceptionPolicy `json:"exception,omitempty"`
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

func AssertResponses(responses []reporthandling.RuleResponse, expectedResponses []reporthandling.RuleResponse) bool {
	return reflect.DeepEqual(responses, expectedResponses)
}

// 	if len(expectedResponses) != len(responses) {
// 		return false
// 	}
// 	for i := 0; i < len(expectedResponses); i++ {
// 		if expectedResponses[i].RuleStatus != responses[i].RuleStatus {
// 			return false
// 		}
// 		if len(expectedResponses[i].AlertObject.ExternalObjects) != len(responses[i].AlertObject.ExternalObjects) {
// 			return false
// 		}
// 		if len(expectedResponses[i].AlertObject.K8SApiObjects) != len(responses[i].AlertObject.K8SApiObjects) {
// 			return false
// 		}
// 		if !CompareAlertObject(expectedResponses[i].AlertObject, responses[i].AlertObject) {
// 			return false
// 		}
// 	}

// 	return true

// }

// func CompareAlertObject(obj1 reporthandling.AlertObject, obj2 reporthandling.AlertObject) bool {

// 	eq := reflect.DeepEqual(obj1.ExternalObjects, obj2.ExternalObjects)
// 	if !eq {
// 		return false
// 	}
// 	eq = reflect.DeepEqual(obj1.K8SApiObjects, obj2.K8SApiObjects)
// 	return eq
// }
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
