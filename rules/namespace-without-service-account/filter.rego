package armo_builtins

import rego.v1

# Fails if namespace does not have service accounts (not incluiding default)
deny contains msga if {
	namespace := input[_]
	namespace.kind == "Namespace"

	msga := {
		"alertMessage": sprintf("Namespace: %v does not have any service accounts besides 'default'", [namespace.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [namespace]},
	}
}
