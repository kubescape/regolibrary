# regal ignore:directory-package-mismatch
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
	is_same_subjects(subjectVector, subject, rolebinding)

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
is_same_subjects(subjectVector, subject, rolebinding) if {
	subjectVector.kind == subject.kind
	subjectVector.name == subject.name
	subject_namespace(subjectVector, rolebinding) == subject_namespace(subject, rolebinding)
}

# A RoleBinding can leave out the namespace of a ServiceAccount subject,
# which Kubernetes then resolves to the RoleBinding's own namespace
# ("default" for a RoleBinding manifest without one, as in yaml scans)
subject_namespace(subject, _) := subject.namespace

subject_namespace(subject, rolebinding) := object.get(rolebinding.metadata, "namespace", "default") if {
	subject.kind == "ServiceAccount"
	not subject.namespace
	rolebinding.kind == "RoleBinding"
}
