# regal ignore:directory-package-mismatch  
package armo_builtins

import rego.v1

deny contains msga if {
	reviewPath := "roleRef"
	wl := input[_]
	start_of_path := get_start_of_path(wl)
	wl_spec := object.get(wl, start_of_path, [])

	# get service account wl is using
	sa := input[_]
	sa.kind == "ServiceAccount"
	is_same_sa(wl_spec, sa.metadata, wl.metadata)

	# check service account token is mounted
	is_sa_auto_mounted(wl_spec, sa)

	# check if sa has administrative roles
	role := input[_]
	role.kind in ["Role", "ClusterRole"]
	is_administrative_role(role)

	rolebinding := input[_]
	rolebinding.kind in ["RoleBinding", "ClusterRoleBinding"]
	rolebinding.roleRef.name == role.metadata.name
	rolebinding.subjects[j].kind == "ServiceAccount"
	rolebinding.subjects[j].name == sa.metadata.name
	subject_namespace(rolebinding.subjects[j], rolebinding) == obj_namespace(sa)

	deletePath := sprintf("subjects[%d]", [j])

	msga := {
		"alertMessage": sprintf("%v: %v in the following namespace: %v has administrative roles", [wl.kind, wl.metadata.name, obj_namespace(wl)]),
		"packagename": "armo_builtins",
		"alertScore": 9,
		"alertObject": {"k8sApiObjects": [wl]},
		"relatedObjects": [
			{"object": sa},
			{
				"object": rolebinding,
				"reviewPaths": [reviewPath],
				"deletePaths": [deletePath],
			},
			{"object": role},
		],
	}
}

get_start_of_path(workload) := start_of_path if {
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[workload.kind]
	start_of_path := ["spec", "template", "spec"]
}

get_start_of_path(workload) := start_of_path if {
	workload.kind == "Pod"
	start_of_path := ["spec"]
}

get_start_of_path(workload) := start_of_path if {
	workload.kind == "CronJob"
	start_of_path := ["spec", "jobTemplate", "spec", "template", "spec"]
}

is_sa_auto_mounted(wl_spec, sa) if {
	# automountServiceAccountToken not in pod spec
	not wl_spec.automountServiceAccountToken == false
	not wl_spec.automountServiceAccountToken == true

	not sa.automountServiceAccountToken == false
}

is_sa_auto_mounted(wl_spec, sa) if {
	# automountServiceAccountToken set to true in pod spec
	wl_spec.automountServiceAccountToken == true
}

is_same_sa(wl_spec, sa_metadata, wl_metadata) if {
	service_account_name(wl_spec) == sa_metadata.name
	is_same_namespace(sa_metadata, wl_metadata)
}

# serviceAccount is the deprecated alias of serviceAccountName, which wins when
# both are set; with neither set the pod runs as the "default" service account
service_account_name(wl_spec) := wl_spec.serviceAccountName if {
	wl_spec.serviceAccountName != ""
} else := wl_spec.serviceAccount if {
	wl_spec.serviceAccount != ""
} else := "default"

# A manifest without metadata.namespace (yaml scans) is created in the
# namespace it is applied to, "default" unless another one is chosen
obj_namespace(obj) := object.get(obj.metadata, "namespace", "default")

# A RoleBinding can leave out the namespace of a ServiceAccount subject,
# which Kubernetes then resolves to the RoleBinding's own namespace
# ("default" for a RoleBinding manifest without one, as in yaml scans)
subject_namespace(subject, _) := subject.namespace

subject_namespace(subject, rolebinding) := obj_namespace(rolebinding) if {
	not subject.namespace
	rolebinding.kind == "RoleBinding"
}

# is_same_namespace supports cases where ns is not configured in the metadata
# for yaml scans
is_same_namespace(metadata1, metadata2) if {
	metadata1.namespace == metadata2.namespace
}

is_same_namespace(metadata1, metadata2) if {
	not metadata1.namespace
	not metadata2.namespace
}

is_same_namespace(metadata1, metadata2) if {
	not metadata2.namespace
	metadata1.namespace == "default"
}

is_same_namespace(metadata1, metadata2) if {
	not metadata1.namespace
	metadata2.namespace == "default"
}

is_administrative_role(role) if {
	administrative_resources := ["*"]
	administrative_verbs := ["*"]
	administrative_api_groups := ["", "*"]

	administrative_rule := [rule |
		rule = role.rules[i]
		rule.resources[a] in administrative_resources
		rule.verbs[b] in administrative_verbs
		rule.apiGroups[c] in administrative_api_groups
	]
	count(administrative_rule) > 0
}
