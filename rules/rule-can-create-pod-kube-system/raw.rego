
package armo_builtins
import data.cautils as cautils

# fails if user has create access to pods within kube-system namespace
# RoleBinding to Role
deny[msga] {
    roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]

    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canCreateToPodNamespace(role)
    canCreateToPodResource(rule)
    canCreateToPodVerb(rule)

    rolebinding.roleRef.kind == "Role"
    rolebinding.roleRef.name == role.metadata.name
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    msga := {
	    "alertMessage": sprintf("The following %v: %v can create pods in kube-system", [subject.kind, subject.name]),
		"alertScore": 3,
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




# fails if user has create access to pods within kube-system namespace
# RoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canCreateToPodNamespace(rolebinding)
    canCreateToPodResource(rule)
    canCreateToPodVerb(rule)



    rolebinding.roleRef.kind == "ClusterRole"
    rolebinding.roleRef.name == role.metadata.name
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    msga := {
    	"alertMessage": sprintf("The following %v: %v can create pods in kube-system", [subject.kind, subject.name]),
		"alertScore": 3,
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




# fails if user has create access to pods within kube-system namespace
# ClusterRoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
     clusterrolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
     clusterrolebinding := clusterrolebindings[_]

    rule:= role.rules[_]
    canCreateToPodResource(rule)
    canCreateToPodVerb(rule)

    clusterrolebinding.roleRef.kind == "ClusterRole"
    clusterrolebinding.roleRef.name == role.metadata.name

    subject := clusterrolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    msga := {
	    "alertMessage": sprintf("The following %v: %v can create pods in kube-system", [subject.kind, subject.name]),
		"alertScore": 3,
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


canCreateToPodResource(rule){
    cautils.list_contains(rule.resources,"pods")
}

canCreateToPodResource(rule){
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

canCreateToPodVerb(rule) {
    cautils.list_contains(rule.verbs, "create")
}


canCreateToPodVerb(rule) {
    cautils.list_contains(rule.verbs, "*")
}

canCreateToPodNamespace(role) {
        role.metadata.namespace == "kube-system"
}
