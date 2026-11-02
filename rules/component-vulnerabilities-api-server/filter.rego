# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msga if {
	some res in input
	res.apiVersion == "componentvulns.kubescape.cloud/v1beta0"
	res.kind == "APIServerVulnerabilities"

	msga := {
		"alertMessage": "",
		"packagename": "armo_builtins",
		"alertScore": 0,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [res]},
	}
}
