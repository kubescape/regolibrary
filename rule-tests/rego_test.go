package testing

import (
	"fmt"
	"io/ioutil"
	"regolibrary/opaprocessor"
	"testing"
)

// for file in current directory
//     get input
//     get expected
//     test

func TestRunAllTests(t *testing.T) {
	ruleTestDirectories, err := ioutil.ReadDir("./")
	if err != nil {
		t.Errorf("err: %v", err.Error())
	}
	for _, f := range ruleTestDirectories {
		rego, err := opaprocessor.GetRego(f.Name())
		if err != nil {
			t.Errorf("err: %v", err.Error())
		}
		testsForRule, _ := ioutil.ReadDir(f.Name())

		// Iterate over each test
		for _, testFile := range testsForRule {
			dir := fmt.Sprintf("%v/%v", f.Name(), testFile.Name())
			resources, err := opaprocessor.GetInputResources(fmt.Sprintf("%v/input", dir))
			if err != nil {
				t.Errorf("err: %v", err.Error())
			}
			responses, err := opaprocessor.RunSingleRego(rego, resources)
			if err != nil {
				t.Errorf("err: %v", err.Error())
			}

			expectedResponses, err := opaprocessor.GetExpectedResults(dir)
			if err != nil {
				t.Errorf("err: %v", err.Error())
			}
			if !opaprocessor.AssertResponses(responses, expectedResponses) {
				t.Fail()
			}
		}
	}
}

// func TestRego(t *testing.T) {
// 	rego, err := opaprocessor.GetRego()
// 	if err != nil {
// 		t.Errorf("err: %v", err.Error())
// 	}

// 	mocks := []string{"mock1.yaml"}

// 	resources, err := opaprocessor.GetMocks(mocks)
// 	if err != nil {
// 		t.Errorf("err: %v", err.Error())
// 	}

// 	responses, err := opaprocessor.RunSingleRego(rego, resources)
// 	if err != nil {
// 		t.Errorf("err: %v", err.Error())
// 	}
// 	expectedResponse := reporthandling.RuleResponse{}
// 	err = json.Unmarshal([]byte(mockResponse), &expectedResponse)
// 	if err != nil {
// 		t.Errorf("err: %v", err.Error())
// 	}
// 	expectedResponses := []reporthandling.RuleResponse{expectedResponse}

// 	if !opaprocessor.AssertResponses(responses, expectedResponses) {
// 		t.Fail()
// 	}

// }
