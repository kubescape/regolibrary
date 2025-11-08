package armo_builtins

import rego.v1

# Returns the rbac permission of each service account
deny contains msga if {
	subjectVector := input[_]
	subjectVector.kind == "ServiceAccount"

	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	endswith(role.kind, "Role")
	endswith(rolebinding.kind, "Binding")

	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	msga := {
		"alertMessage": sprintf("service account: %v has the following permissions in the cluster", [subjectVector.name]),
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": subjectVector,
		},
	}
}

# ===============================================================

# for service accounts
is_same_subjects(subjectVector, subject) if {
	subjectVector.kind == subject.kind
	subjectVector.name == subject.name
	subjectVector.namespace == subject.namespace
}
