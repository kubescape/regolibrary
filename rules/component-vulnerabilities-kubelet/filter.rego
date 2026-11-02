# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msga if {
	assessed := {res.metadata.name |
		some res in input
		res.apiVersion == "componentvulns.kubescape.cloud/v1beta0"
		res.kind == "KubeletVulnerabilities"
	}

	some node in input
	node.kind == "Node"
	node.metadata.name in assessed

	msga := {
		"alertMessage": "",
		"packagename": "armo_builtins",
		"alertScore": 0,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [node]},
	}
}
