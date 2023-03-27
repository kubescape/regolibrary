package armo_builtins

import future.keywords.every

# deny if servicePrincipal has permissions that are not read-only
deny[msga] {
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
	some action in policy.properties.permissions[_].actions
		not endswith(action, "read")

	msga := {
		"alertMessage": "ServicePrincipal has permissions that are not read-only to ACR.",
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"externalObject": resources
		}
	}
}
