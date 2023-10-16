package armo_builtins

import data.cautils

deny[msga] {
	roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
	canForwardToPodResource(rule)
	canForwardToPodVerb(rule)

	rolebinding.roleRef.kind == "Role"
	rolebinding.roleRef.name == role.metadata.name

    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

	msga := {
		"alertMessage": sprintf("the following %v: %v, can do port forwarding", [subject.kind, subject.name]),
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


deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
	canForwardToPodResource(rule)
	canForwardToPodVerb(rule)

	rolebinding.roleRef.kind == "ClusterRole"
	rolebinding.roleRef.name == role.metadata.name

    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

	msga := {
		"alertMessage": sprintf("the following %v: %v, can do port forwarding", [subject.kind, subject.name]),
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



deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
	canForwardToPodResource(rule)
	canForwardToPodVerb(rule)

	rolebinding.roleRef.kind == "ClusterRole"
	rolebinding.roleRef.name == role.metadata.name

    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    msga := {
		"alertMessage": sprintf("the following %v: %v, can do port forwarding", [subject.kind, subject.name]),
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

canForwardToPodVerb(rule) {
	cautils.list_contains(rule.verbs, "create")
}

canForwardToPodVerb(rule) {
	cautils.list_contains(rule.verbs, "get")
}
canForwardToPodVerb(rule) {
	cautils.list_contains(rule.verbs, "*")
}

canForwardToPodResource(rule) {
	cautils.list_contains(rule.resources,"pods/portforward")
}
canForwardToPodResource(rule) {
	cautils.list_contains(rule.resources,"pods/*")
}
canForwardToPodResource(rule) {
	is_api_group(rule)
	cautils.list_contains(rule.resources,"*")
}

is_api_group(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == ""
}

is_api_group(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "*"
}
