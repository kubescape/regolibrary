package armo_builtins

import rego.v1

# returns all namespace objects in cluster
deny contains msga if {
	namespace = input[_]
	namespace.kind == "Namespace"

	msga := {
		"alertMessage": sprintf("review the following namespace: %v", [namespace.metadata.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [namespace]},
	}
}
