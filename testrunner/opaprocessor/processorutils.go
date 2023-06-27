package opaprocessor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yannh/kubeconform/pkg/resource"
	"github.com/yannh/kubeconform/pkg/validator"
	"gopkg.in/yaml.v3"
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

// validateInputResource return an error in case the provided k8s resource is not considered valid.
// It uses packages from kubeconform project in order to validate resources.
func validateInputResource(res []byte) error {
	k8sResource := resource.Resource{
		Bytes: res,
	}
	schemaLocation := []string{}
	var val validator.Validator
	val, err := validator.New(schemaLocation,
		validator.Opts{
			Cache:                "",
			Debug:                false,
			SkipTLS:              false,
			SkipKinds:            map[string]struct{}{},
			RejectKinds:          map[string]struct{}{},
			KubernetesVersion:    "master",
			Strict:               false,
			IgnoreMissingSchemas: true,
		},
	)
	if err != nil {
		return err
	}

	result := val.ValidateResource(k8sResource)
	if result.Err != nil {
		return result.Err
	}
	return nil
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

// GetData reads test data for the rego data channel
func GetData(dir string, policyRule *reporthandling.PolicyRule) (*resources.RegoDependenciesData, error) {
	ret := &resources.RegoDependenciesData{}
	dataPath := path.Join(dir, "data.json")
	data, err := os.ReadFile(dataPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ret, nil
		}
		return ret, fmt.Errorf("failed to get rule %w", err)
	}

	tmp := &resources.RegoDependenciesData{}
	err = json.Unmarshal(data, tmp)
	return tmp, err
}

func GetMockContentFromFile(filename string) (string, error) {
	mockContent, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}

	// validate input resource using kubeconform packages
	if err = validateInputResource(mockContent); err != nil {
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

func marshallIgnoreErrors(v interface{}) string {
	ret, _ := json.Marshal(v)
	return string(ret)
}

func AssertResponses(t *testing.T, responses []reporthandling.RuleResponse, expectedResponses []reporthandling.RuleResponse) error {
	sortFunc := func(i, j int, src []reporthandling.RuleResponse) bool {
		return strings.Compare(marshallIgnoreErrors(src[i]), marshallIgnoreErrors(src[j])) == 1
	}

	sort.Slice(responses, func(i, j int) bool { return sortFunc(i, j, responses) })
	sort.Slice(expectedResponses, func(i, j int) bool { return sortFunc(i, j, expectedResponses) })

	actual, err := json.MarshalIndent(responses, "", "   ")
	if err != nil {
		return err
	}
	expected, err := json.MarshalIndent(expectedResponses, "", "   ")
	if err != nil {
		return err
	}

	require.JSONEq(t, string(expected), string(actual))
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
	expected, err := os.ReadFile(fmt.Sprintf("%v/%v", dir, expectedFilename))
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
	inputs, _ := os.ReadDir(dir)
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

func RunAllTestsForRule(t *testing.T, ruleDir string) error {
	ruleNameSplited := strings.Split(ruleDir, "/")
	ruleName := ruleNameSplited[len(ruleNameSplited)-1]
	regoDir := fmt.Sprintf("%v/%v", RelativeRulesPath, ruleName)

	rego, err := GetRego(regoDir)
	if err != nil {
		return err
	}
	policy, err := GetPolicy(ruleDir)
	if err != nil {
		return err
	}
	policyRule, err := SetPolicyRule(policy, rego)
	if err != nil {
		return err
	}
	f, err := os.Open(fmt.Sprintf("%v/test", ruleDir))
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
		t.Run(
			fmt.Sprintf("%s/%s", ruleName, testFile), func(t *testing.T) {
				dir := fmt.Sprintf("%v/test/%v", ruleDir, testFile)
				assert.NoError(t, RunSingleTest(t, dir, policyRule))
			},
		)
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

func RunSingleTest(t *testing.T, dir string, policyRule *reporthandling.PolicyRule) error {

	data, err := GetData(dir, policyRule)
	if err != nil {
		return err
	}

	inputRawResources, err := GetInputRawResources(dir, policyRule)
	if err != nil {
		return err
	}

	responses, err := RunSingleRego(policyRule, inputRawResources, data)
	if err != nil {
		return err
	}

	expectedResponses, err := GetExpectedResults(dir)
	if err != nil {
		return fmt.Errorf("expected.json doesn't match: %v", err)
	}

	err = AssertResponses(t, responses, expectedResponses)
	return err
}
