package armo_builtins

import data.cautils

# fails if user can list/get secrets
#RoleBinding to Role
deny[msga] {
    roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canViewSecretsResource(rule)
    canViewSecretsVerb(rule)

    rolebinding.roleRef.kind == "Role"
    rolebinding.roleRef.name == role.metadata.name

    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    msga := {
	    "alertMessage": sprintf("The following %v: %v can read secrets", [subject.kind, subject.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
       "failedPaths": [path],
        "alertObject": {
			"k8sApiObjects": [role,rolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
    }
}


# fails if user can list/get secrets
#RoleBinding to ClusterRole
deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canViewSecretsResource(rule)
    canViewSecretsVerb(rule)

    rolebinding.roleRef.kind == "ClusterRole"
    rolebinding.roleRef.name == role.metadata.name


    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    msga := {
	    "alertMessage": sprintf("The following %v: %v can read secrets", [subject.kind, subject.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
       "failedPaths": [path],
          "alertObject": {
			"k8sApiObjects": [role,rolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
    }
}

# fails if user can list/get secrets
# ClusterRoleBinding to ClusterRole
deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    clusterrolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
    clusterrolebinding := clusterrolebindings[_]

    rule:= role.rules[_]
    canViewSecretsResource(rule)
    canViewSecretsVerb(rule)

    clusterrolebinding.roleRef.kind == "ClusterRole"
    clusterrolebinding.roleRef.name == role.metadata.name

    subject := clusterrolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    msga := {
	    "alertMessage": sprintf("The following %v: %v can read secrets", [subject.kind, subject.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
       "failedPaths": [path],
        "alertObject": {
			"k8sApiObjects": [role,clusterrolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
    }
}




canViewSecretsVerb(rule) {
    cautils.list_contains(rule.verbs,"get")
}

canViewSecretsVerb(rule) {
    cautils.list_contains(rule.verbs,"list")
}

canViewSecretsVerb(rule) {
    cautils.list_contains(rule.verbs,"watch")
}


canViewSecretsVerb(rule) {
    cautils.list_contains(rule.verbs,"*")
}


canViewSecretsResource(rule) {
    cautils.list_contains(rule.resources,"secrets")
}

canViewSecretsResource(rule) {
    is_api_group(rule)
    cautils.list_contains(rule.resources,"*")
}

is_api_group(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "*"
}
is_api_group(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == ""
}