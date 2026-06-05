# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# deny if servicePrincipal has permissions that are not read-only
deny contains msga if {
	resources := input[_]
	resources.kind == "ListEntitiesForPolicies"
	resources.metadata.provider == "aks"

	roleAssignment := resources.data.roleAssignments[_]
	roleAssignment.properties.principalType == "ServicePrincipal"

	policies := input[_]
	policies.kind == "PolicyVersion"
	policies.metadata.provider == "aks"

	policy := policies.data.roleDefinitions[_]
	policy.id == roleAssignment.properties.roleDefinitionId

	# check if policy has at least one action that is not read
    permission := policy.properties.permissions[_]
    action := permission.actions[_]
    not endswith(action, "read")

	msga := {
		"alertMessage": "ServicePrincipal has permissions that are not read-only to ACR.",
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"externalObjects": resources},
	}
}
