package armo_builtins

import rego.v1

# return ListEntitiesForPolicies resource in azure
deny contains msg if {
	resources := input[_]
	resources.kind == "ListEntitiesForPolicies"
	resources.apiVersion == "management.azure.com/v1"
	resources.metadata.provider == "aks"

	msg := {
		"alertMessage": "",
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"externalObjects": resources},
	}
}
