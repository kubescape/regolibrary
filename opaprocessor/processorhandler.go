package opaprocessor

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/reporthandling"

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

func GetRego(currentDirectoryOfTest string) (string, error) {
	ruleNameSplited := strings.Split(currentDirectoryOfTest, "/")
	ruleName := ruleNameSplited[len(ruleNameSplited)-1]

	dir := fmt.Sprintf("%v/../../rules/%v/%v", currentDirectoryOfTest, ruleName, regoFile)

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
	store, err := opap.regoDependenciesData.TOStorage() // get store
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
