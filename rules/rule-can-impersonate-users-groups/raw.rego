
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
	
    subjects := rolebinding.subjects[_]

	msga := {
		"alertMessage": sprintf("the following %v: %v, can impersonate users", [subjects.kind, subjects.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [role, rolebinding],
			"externalObjects": {
				"subject" : [subjects]
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
	
    subjects := rolebinding.subjects[_]

	msga := {
		"alertMessage": sprintf("the following %v: %v,  can impersonate users", [subjects.kind, subjects.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [role, rolebinding],
			"externalObjects": {
				"subject" : [subjects]
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
	
    subjects := rolebinding.subjects[_]

    msga := {
		"alertMessage": sprintf("the following %v: %v, can impersonate users", [subjects.kind, subjects.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
  		"alertObject": {
			"k8sApiObjects": [role, rolebinding],
			"externalObjects": {
				"subject" : [subjects]
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
	isApiGroup(rule)
	cautils.list_contains(rule.resources,"*")
}

isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "*"
}

isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == ""
}