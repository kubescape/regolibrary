
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

    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    	msga := {
	     "alertMessage": sprintf("The following %v: %v can create/delete  services", [subject.kind, subject.name]),
		"alertScore": 9,
         "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,rolebinding],
			"externalObjects": {
				"subject" : [subject]
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

    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    	msga := {
	     "alertMessage": sprintf("The following %v: %v can create/delete  services", [subject.kind, subject.name]),
		"alertScore": 9,
         "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,rolebinding],
			"externalObjects": {
				"subject" : [subject]
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
    subject := clusterrolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    	msga := {
	     "alertMessage": sprintf("The following %v: %v can create/delete  services", [subject.kind, subject.name]),
		"alertScore": 9,
         "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,clusterrolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
     }
}


canCreateDeleteToServiceResource(rule) {
    cautils.list_contains(rule.resources, "services")
}

canCreateDeleteToServiceResource(rule) {
    is_api_group(rule)
    cautils.list_contains(rule.resources, "*")
}

is_api_group(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "*"
}

is_api_group(rule) {
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