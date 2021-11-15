
package armo_builtins
import data.cautils as cautils



# fails if user has create/delete access to services
# RoleBinding to Role
deny[msga] {
    roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canCreateDeleteToServiceResource(rule)
    canCreateDeleteToServiceVerb(rule)

    rolebinding.roleRef.kind == "Role"
    rolebinding.roleRef.name == role.metadata.name

    subjects := rolebinding.subjects[_]

    	msga := {
	     "alertMessage": sprintf("The following %v: %v can create/delete  services", [subjects.kind, subjects.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,rolebinding],
			"externalObjects": {
				"subject" : [subjects]
			}
		}
     }
}

# fails if user has create/delete access to services
# RoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]

    canCreateDeleteToServiceResource(rule)
    canCreateDeleteToServiceVerb(rule)

    rolebinding.roleRef.kind == "ClusterRole"
    rolebinding.roleRef.name == role.metadata.name

    subjects := rolebinding.subjects[_]

    	msga := {
	     "alertMessage": sprintf("The following %v: %v can create/delete  services", [subjects.kind, subjects.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,rolebinding],
			"externalObjects": {
				"subject" : [subjects]
			}
		}
     }

}

# fails if user has create/delete access to services
# ClusterRoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
     clusterrolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
     clusterrolebinding := clusterrolebindings[_]

    rule:= role.rules[_]

    canCreateDeleteToServiceResource(rule)
    canCreateDeleteToServiceVerb(rule)

    clusterrolebinding.roleRef.kind == "ClusterRole"
    clusterrolebinding.roleRef.name == role.metadata.name
    subjects := clusterrolebinding.subjects[_]

    	msga := {
	     "alertMessage": sprintf("The following %v: %v can create/delete  services", [subjects.kind, subjects.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,clusterrolebinding],
			"externalObjects": {
				"subject" : [subjects]
			}
		}
     }
}


canCreateDeleteToServiceResource(rule) {
    cautils.list_contains(rule.resources, "services")
}

canCreateDeleteToServiceResource(rule) {
    isApiGroup(rule)
    cautils.list_contains(rule.resources, "*")
}

isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "*"
}

isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == ""
}

canCreateDeleteToServiceVerb(rule) {
     cautils.list_contains(rule.verbs, "create")
}

canCreateDeleteToServiceVerb(rule) {
     cautils.list_contains(rule.verbs, "delete")
}

canCreateDeleteToServiceVerb(rule) {
     cautils.list_contains(rule.verbs, "deletecollection")
}

canCreateDeleteToServiceVerb(rule) {
     cautils.list_contains(rule.verbs, "*")
}