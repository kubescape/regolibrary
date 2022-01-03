package testing

import (
	"encoding/json"
	"regolibrary/opaprocessor"
	"testing"

	"github.com/armosec/opa-utils/reporthandling"
)

// for file in current directory
//     get input
//     get expected
//     test

func runAllTests()

func TestRego(t *testing.T) {
	rego, err := opaprocessor.GetRego()
	if err != nil {
		t.Errorf("err: %v", err.Error())
	}

	mocks := []string{"mock1.yaml"}

	resources, err := opaprocessor.GetMocks(mocks)
	if err != nil {
		t.Errorf("err: %v", err.Error())
	}

	responses, err := opaprocessor.RunSingleRego(rego, resources)
	if err != nil {
		t.Errorf("err: %v", err.Error())
	}
	expectedResponse := reporthandling.RuleResponse{}
	err = json.Unmarshal([]byte(mockResponse), &expectedResponse)
	if err != nil {
		t.Errorf("err: %v", err.Error())
	}
	expectedResponses := []reporthandling.RuleResponse{expectedResponse}

	if !opaprocessor.AssertResponses(responses, expectedResponses) {
		t.Fail()
	}

}
