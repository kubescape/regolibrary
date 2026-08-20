# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# return ListEntitiesForPolicies resource in GCP
deny contains msg if {
	resources := input[_]
	resources.kind == "ListEntitiesForPolicies"
	resources.apiVersion == "container.googleapis.com/v1"
	resources.metadata.provider == "gke"

	msg := {
		"alertMessage": "",
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"externalObjects": resources},
	}
}
