
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
    can_create_to_pod_namespace(role)
    can_create_to_pod_resource(rule)
    can_create_to_pod_verb(rule)

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
    can_create_to_pod_namespace(rolebinding)
    can_create_to_pod_resource(rule)
    can_create_to_pod_verb(rule)



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
    can_create_to_pod_resource(rule)
    can_create_to_pod_verb(rule)

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


can_create_to_pod_resource(rule){
    cautils.list_contains(rule.resources,"pods")
}

can_create_to_pod_resource(rule){
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

can_create_to_pod_verb(rule) {
    cautils.list_contains(rule.verbs, "create")
}


can_create_to_pod_verb(rule) {
    cautils.list_contains(rule.verbs, "*")
}

can_create_to_pod_namespace(role) {
        role.metadata.namespace == "kube-system"
}
