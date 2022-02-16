package opaprocessor

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/objectsenvelopes"
	"github.com/armosec/opa-utils/reporthandling"
	"gopkg.in/yaml.v2"

	"github.com/golang/glog"

	"github.com/armosec/opa-utils/resources"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

type OPAProcessor struct {
	*cautils.OPASessionObj
	regoDependenciesData *resources.RegoDependenciesData
}

var regoFile = "raw.rego"
var metadataFile = "rule.metadata.json"

func NewOPAProcessorMock() *OPAProcessor {
	return &OPAProcessor{
		&cautils.OPASessionObj{},
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

func NewOPAProcessor(sessionObj *cautils.OPASessionObj, regoDependenciesData *resources.RegoDependenciesData) *OPAProcessor {
	if regoDependenciesData != nil && sessionObj != nil {
		regoDependenciesData.PostureControlInputs = sessionObj.RegoInputData.PostureControlInputs
	}
	return &OPAProcessor{
		OPASessionObj:        sessionObj,
		regoDependenciesData: regoDependenciesData,
	}
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
	var resources []map[string]interface{}
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
		resources = append(resources, resource)
	}
	var IMetadataResources []workloadinterface.IMetadata
	for _, resp := range resources {
		if resp == nil {
			return "", fmt.Errorf("resource is nil")
		}
		metadataResource := objectsenvelopes.NewObject(resp)
		// if metadataResource.GetNamespace() == "" {
		// 	metadataResource.SetNamespace("default")
		// }
		IMetadataResources = append(IMetadataResources, metadataResource)
	}
	IMetadataResources, _ = reporthandling.RegoResourcesAggregator(policyRule, IMetadataResources)
	inputRawResources := workloadinterface.ListMetaToMap(IMetadataResources)
	response, err := RunSingleRego(policyRule, inputRawResources)
	if err != nil {
		return "", err
	}
	responseMarshal, err := json.Marshal(response)
	if err != nil {
		return "", err
	}
	return string(responseMarshal), nil
}
func RunSingleRego(rule *reporthandling.PolicyRule, inputObj []map[string]interface{}) ([]reporthandling.RuleResponse, error) {
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

	result, err := opaProcessor.regoEval(inputObj, compiled)
	ruleReport.RuleResponses = result
	keepFields := []string{"kind", "apiVersion", "metadata"}
	keepMetadataFields := []string{"name", "labels"}
	ruleReport.RemoveData(keepFields, keepMetadataFields)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (opap *OPAProcessor) regoEval(inputObj []map[string]interface{}, compiledRego *ast.Compiler) ([]reporthandling.RuleResponse, error) {
	configInput, err := ioutil.ReadFile("../default-config-inputs.json")
	if err != nil {
		return nil, err
	}

	var customerConfig *armotypes.CustomerConfig
	err = json.Unmarshal(configInput, &customerConfig)
	if err != nil {
		return nil, err
	}
	postureControlInput := customerConfig.Settings.PostureControlInputs
	opap.regoDependenciesData.PostureControlInputs = postureControlInput
	store, err := resources.TOStorage(postureControlInput)
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
