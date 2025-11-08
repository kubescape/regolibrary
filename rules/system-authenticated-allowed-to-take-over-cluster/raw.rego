package armo_builtins

import rego.v1

deny contains msga if {
	subjectVector := input[_]

	rolebinding := subjectVector.relatedObjects[j]
	endswith(rolebinding.kind, "Binding")

	subject := rolebinding.subjects[k]

	# Check if the subject is gourp
	subject.kind == "Group"

	# Check if the subject is system:authenticated
	subject.name == "system:authenticated"

	# Find the bound roles
	role := subjectVector.relatedObjects[i]
	endswith(role.kind, "Role")

	# Check if the role and rolebinding bound
	is_same_role_and_binding(role, rolebinding)

	# Check if the role has access to workloads, exec, attach, portforward
	rule := role.rules[p]
	rule.resources[l] in ["*", "pods", "pods/exec", "pods/attach", "pods/portforward", "deployments", "statefulset", "daemonset", "jobs", "cronjobs", "nodes", "secrets"]

	finalpath := array.concat([""], [
		sprintf("relatedObjects[%d].subjects[%d]", [j, k]),
		sprintf("relatedObjects[%d].roleRef.name", [i]),
	])

	msga := {
		"alertMessage": "system:authenticated has sensitive roles",
		"alertScore": 5,
		"reviewPaths": finalpath,
		"failedPaths": finalpath,
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": subjectVector,
		},
	}
}

is_same_role_and_binding(role, rolebinding) if {
	rolebinding.kind == "RoleBinding"
	role.kind == "Role"
	rolebinding.metadata.namespace == role.metadata.namespace
	rolebinding.roleRef.name == role.metadata.name
	rolebinding.roleRef.kind == role.kind
	startswith(role.apiVersion, rolebinding.roleRef.apiGroup)
}

is_same_role_and_binding(role, rolebinding) if {
	rolebinding.kind == "ClusterRoleBinding"
	role.kind == "ClusterRole"
	rolebinding.roleRef.name == role.metadata.name
	rolebinding.roleRef.kind == role.kind
	startswith(role.apiVersion, rolebinding.roleRef.apiGroup)
}
