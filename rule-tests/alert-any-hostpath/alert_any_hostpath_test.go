package testing

import (
	"encoding/json"
	"regolibrary/opaprocessor"
	"testing"

	"github.com/armosec/opa-utils/reporthandling"
)

var mockResponse = `
{
	"alertMessage": "pod: test-pd has: test-volume as hostPath volume",
	"failedPaths": [
		""
	],
	"ruleStatus": "",
	"packagename": "armo_builtins",
	"alertScore": 7,
	"alertObject": {
		"k8sApiObjects": [
			{
				"apiVersion": "v1",
				"kind": "Pod",
				"metadata": {
					"name": "test-pd",
					"namespace": "default"
				}
			}
		]
	}
}
`

var mock1 = `
apiVersion: v1
kind: Pod
metadata:
  name: test-pd
spec:
  containers:
  - image: k8s.gcr.io/test-webserver
    name: test-container
    volumeMounts:
    - mountPath: /test-pd
      name: test-volume
  volumes:
  - name: test-volume
    hostPath:   #we are looking for this parameter 
      path: /var
`

func TestFailed(t *testing.T) {
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
	var expectedResponse reporthandling.RuleResponse
	json.Unmarshal([]byte(mockResponse), &expectedResponse)
	expectedResponses := []reporthandling.RuleResponse{expectedResponse}

	if !opaprocessor.AssertResponses(responses, expectedResponses) {
		t.Fail()
	}

}
