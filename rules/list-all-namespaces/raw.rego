# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# returns all namespace objects in cluster
deny contains msga if {
    some namespace in input
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
