package armo_builtins

import data.cautils

# input: clusterrolebindings + rolebindings
# apiversion: rbac.authorization.k8s.io/v1
# returns subjects that can exec into container

deny[msga] {
	 roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
	can_exec_to_pod_resource(rule)
	can_exec_to_pod_verb(rule)

	rolebinding.roleRef.kind == "Role"
	rolebinding.roleRef.name == role.metadata.name

   	subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

	msga := {
		"alertMessage": sprintf("the following %v: %v, can exec into  containers", [subject.kind, subject.name]),
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [role, rolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
	}
}


# input: clusterrolebindings + rolebindings
# apiversion: rbac.authorization.k8s.io/v1
# returns subjects that can exec into container

deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
	can_exec_to_pod_resource(rule)
	can_exec_to_pod_verb(rule)

	rolebinding.roleRef.kind == "ClusterRole"
	rolebinding.roleRef.name == role.metadata.name

    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

	msga := {
		"alertMessage": sprintf("the following %v: %v, can exec into  containers", [subject.kind, subject.name]),
		"alertScore": 9,
		"failedPaths": [path],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [role, rolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
	}
}

# input: clusterrolebindings + rolebindings
# apiversion: rbac.authorization.k8s.io/v1
# returns subjects that can exec into container

deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
	can_exec_to_pod_resource(rule)
	can_exec_to_pod_verb(rule)

	rolebinding.roleRef.kind == "ClusterRole"
	rolebinding.roleRef.name == role.metadata.name

    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    msga := {
		"alertMessage": sprintf("the following %v: %v, can exec into  containers", [subject.kind, subject.name]),
		"alertScore": 9,
		"failedPaths": [path],
		"packagename": "armo_builtins",
  		"alertObject": {
			"k8sApiObjects": [role, rolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
	}
}

can_exec_to_pod_verb(rule) {
	cautils.list_contains(rule.verbs, "create")
}
can_exec_to_pod_verb(rule)  {
	cautils.list_contains(rule.verbs, "*")
}

can_exec_to_pod_resource(rule)  {
	cautils.list_contains(rule.resources, "pods/exec")

}
can_exec_to_pod_resource(rule)  {
	cautils.list_contains(rule.resources, "pods/*")
}
can_exec_to_pod_resource(rule) {
	is_api_group(rule)
	cautils.list_contains(rule.resources, "*")
}

is_api_group(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == ""
}

is_api_group(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "*"
}