package armo_builtins

import rego.v1

deny contains msga if {
	namespace := input[_]
	namespace.kind == "Namespace"

	msga := {
		"alertMessage": sprintf("Namespace: %v", [namespace.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [namespace]},
	}
}
