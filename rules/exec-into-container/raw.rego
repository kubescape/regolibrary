
package armo_builtins
import data.cautils as cautils


# input: clusterrolebindings + rolebindings
# apiversion: rbac.authorization.k8s.io/v1 
# returns subjects that can exec into container

deny[msga] {
	 roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
	canExecToPodResource(rule)
	canExecToPodVerb(rule)

	rolebinding.roleRef.kind == "Role"
	rolebinding.roleRef.name == role.metadata.name
	
    subjects := rolebinding.subjects[_]

	msga := {
		"alertMessage": sprintf("the following %v: %v, can exec into  containers", [subjects.kind, subjects.name]),
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


# input: clusterrolebindings + rolebindings
# apiversion: rbac.authorization.k8s.io/v1 
# returns subjects that can exec into container

deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
	canExecToPodResource(rule)
	canExecToPodVerb(rule)

	rolebinding.roleRef.kind == "ClusterRole"
	rolebinding.roleRef.name == role.metadata.name
	
    subjects := rolebinding.subjects[_]

	msga := {
		"alertMessage": sprintf("the following %v: %v, can exec into  containers", [subjects.kind, subjects.name]),
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

# input: clusterrolebindings + rolebindings
# apiversion: rbac.authorization.k8s.io/v1 
# returns subjects that can exec into container

deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
	canExecToPodResource(rule)
	canExecToPodVerb(rule)

	rolebinding.roleRef.kind == "ClusterRole"
	rolebinding.roleRef.name == role.metadata.name
	
    subjects := rolebinding.subjects[_]

    msga := {
		"alertMessage": sprintf("the following %v: %v, can exec into  containers", [subjects.kind, subjects.name]),
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

canExecToPodVerb(rule) {
	cautils.list_contains(rule.verbs, "create")
}
canExecToPodVerb(rule) {
	cautils.list_contains(rule.verbs, "*")
}

canExecToPodResource(rule) {
	cautils.list_contains(rule.resources,"pods/exec")
}
canExecToPodResource(rule) {
	cautils.list_contains(rule.resources,"pods/*")
}
canExecToPodResource(rule) {
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