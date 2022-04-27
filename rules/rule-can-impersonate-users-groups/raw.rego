
package armo_builtins
import data.cautils as cautils


deny[msga] {
	 roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
	canImpersonateVerb(rule)
    canImpersonateResource(rule)

	rolebinding.roleRef.kind == "Role"
	rolebinding.roleRef.name == role.metadata.name
	
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

	msga := {
		"alertMessage": sprintf("the following %v: %v, can impersonate users", [subject.kind, subject.name]),
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


deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
	canImpersonateVerb(rule)
    canImpersonateResource(rule)

	rolebinding.roleRef.kind == "ClusterRole"
	rolebinding.roleRef.name == role.metadata.name
	
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

	msga := {
		"alertMessage": sprintf("the following %v: %v,  can impersonate users", [subject.kind, subject.name]),
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



deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
	canImpersonateVerb(rule)
    canImpersonateResource(rule)

	rolebinding.roleRef.kind == "ClusterRole"
	rolebinding.roleRef.name == role.metadata.name
	
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    msga := {
		"alertMessage": sprintf("the following %v: %v, can impersonate users", [subject.kind, subject.name]),
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


canImpersonateVerb(rule) {
		cautils.list_contains(rule.verbs, "impersonate")
}
canImpersonateVerb(rule) {
		cautils.list_contains(rule.verbs, "*")
}


canImpersonateResource(rule) {
	cautils.list_contains(rule.resources,"users")
}

canImpersonateResource(rule) {
	cautils.list_contains(rule.resources,"serviceaccounts")
}

canImpersonateResource(rule) {
	cautils.list_contains(rule.resources,"groups")
}

canImpersonateResource(rule) {
	cautils.list_contains(rule.resources,"uids")
}

canImpersonateResource(rule) {
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