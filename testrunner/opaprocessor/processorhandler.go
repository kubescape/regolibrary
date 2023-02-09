package opaprocessor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"gopkg.in/yaml.v3"

	"github.com/golang/glog"

	"github.com/kubescape/opa-utils/resources"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

type OPAProcessor struct {
	regoDependenciesData *resources.RegoDependenciesData
}

var regoFile = "raw.rego"
var metadataFile = "rule.metadata.json"

func NewOPAProcessorMock() *OPAProcessor {
	return &OPAProcessor{
		&resources.RegoDependenciesData{},
	}
}

func GetRego(regoDir string) (string, error) {

	dir := fmt.Sprintf("%v/%v", regoDir, regoFile)

	rego, err := os.ReadFile(dir)
	if err != nil {
		return "", err
	}
	return string(rego), err

}

func GetPolicy(currentDirectoryOfTest string) (string, error) {
	ruleNameSplited := strings.Split(currentDirectoryOfTest, "/")
	ruleName := ruleNameSplited[len(ruleNameSplited)-1]

	dir := fmt.Sprintf("%v/../../rules/%v/%v", currentDirectoryOfTest, ruleName, metadataFile)

	policy, err := os.ReadFile(dir)
	if err != nil {
		return "", err
	}
	return string(policy), err

}

func getRuleDependencies() (map[string]string, error) {
	modules := resources.LoadRegoModules()
	if len(modules) == 0 {
		glog.Warningf("failed to load rule dependencies")
	}
	return modules, nil
}
func RunRegoFromYamls(ymls []string, policyRule *reporthandling.PolicyRule) (string, error) {
	policyRule.Name = "test"
	var body interface{}
	var allResources []map[string]interface{}
	for _, yml := range ymls {
		if err := yaml.Unmarshal([]byte(yml), &body); err != nil {
			return "", err
		}
		body = convertYamlToJson(body)
		mockContentJson, err := json.Marshal(body)
		if err != nil {
			return "", err
		}
		var resource map[string]interface{}
		err = json.Unmarshal([]byte(mockContentJson), &resource)
		if err != nil {
			return "", err
		}
		allResources = append(allResources, resource)
	}
	var IMetadataResources []workloadinterface.IMetadata
	for _, resp := range allResources {
		if resp == nil {
			return "", fmt.Errorf("resource is nil")
		}
		metadataResource := objectsenvelopes.NewObject(resp)

		IMetadataResources = append(IMetadataResources, metadataResource)
	}
	IMetadataResources, _ = reporthandling.RegoResourcesAggregator(policyRule, IMetadataResources)
	inputRawResources := workloadinterface.ListMetaToMap(IMetadataResources)
	response, err := RunSingleRego(policyRule, inputRawResources, &resources.RegoDependenciesData{})
	if err != nil {
		return "", err
	}
	responseMarshal, err := json.Marshal(response)
	if err != nil {
		return "", err
	}
	return string(responseMarshal), nil
}
func RunSingleRego(rule *reporthandling.PolicyRule, inputObj []map[string]interface{}, data *resources.RegoDependenciesData) ([]reporthandling.RuleResponse, error) {
	ruleReport := reporthandling.RuleReport{
		Name: rule.Name,
	}

	modules, err := getRuleDependencies()
	if err != nil {
		return nil, err
	}
	modules[rule.Name] = rule.Rule
	compiled, err := ast.CompileModules(modules)
	if err != nil {
		return nil, err
	}

	opaProcessor := NewOPAProcessorMock()

	result, err := opaProcessor.regoEval(inputObj, compiled, *data)
	ruleReport.RuleResponses = result
	keepFields := []string{"kind", "apiVersion", "metadata"}
	keepMetadataFields := []string{"name", "labels"}
	ruleReport.RemoveData(keepFields, keepMetadataFields)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (opap *OPAProcessor) regoEval(inputObj []map[string]interface{}, compiledRego *ast.Compiler, data resources.RegoDependenciesData) ([]reporthandling.RuleResponse, error) {
	configInput, err := os.ReadFile("../default-config-inputs.json")
	if err != nil {
		return nil, err
	}

	var customerConfig *armotypes.CustomerConfig
	err = json.Unmarshal(configInput, &customerConfig)
	if err != nil {
		return nil, err
	}
	postureControlInput := customerConfig.Settings.PostureControlInputs
	for i := range data.PostureControlInputs {
		postureControlInput[i] = data.PostureControlInputs[i]
	}
	opap.regoDependenciesData.PostureControlInputs = postureControlInput
	opap.regoDependenciesData.DataControlInputs = data.DataControlInputs
	store, err := opap.regoDependenciesData.TOStorage()
	if err != nil {
		return nil, err
	}

	rego := rego.New(
		rego.Query("data.armo_builtins"), // get package name from rule
		rego.Compiler(compiledRego),
		rego.Input(inputObj),
		rego.Store(store),
	)

	// Run evaluation
	resultSet, err := rego.Eval(context.Background())
	if err != nil {
		return nil, err
	}
	results, err := reporthandling.ParseRegoResult(&resultSet)
	if err != nil {
		return results, err
	}

	return results, nil
}
