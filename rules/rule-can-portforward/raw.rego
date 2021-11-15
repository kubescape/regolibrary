
package armo_builtins
import data.cautils as cautils


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
	
    subjects := rolebinding.subjects[_]

	msga := {
		"alertMessage": sprintf("the following %v: %v, can do port forwarding", [subjects.kind, subjects.name]),
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
	canForwardToPodResource(rule)
	canForwardToPodVerb(rule)

	rolebinding.roleRef.kind == "ClusterRole"
	rolebinding.roleRef.name == role.metadata.name
	
    subjects := rolebinding.subjects[_]

	msga := {
		"alertMessage": sprintf("the following %v: %v, can do port forwarding", [subjects.kind, subjects.name]),
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
	canForwardToPodResource(rule)
	canForwardToPodVerb(rule)

	rolebinding.roleRef.kind == "ClusterRole"
	rolebinding.roleRef.name == role.metadata.name
	
    subjects := rolebinding.subjects[_]

    msga := {
		"alertMessage": sprintf("the following %v: %v, can do port forwarding", [subjects.kind, subjects.name]),
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
	isApiGroup(rule)
	cautils.list_contains(rule.resources,"*")
}

isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == ""
}

isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "*"
}
