package armo_builtins

import data.cautils

# fails if user has create/modify access to pods
# RoleBinding to Role
deny [msga] {
    roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    can_create_modify_to_pod_resource(rule)
    can_create_modify_to_pod_verb(rule)

    rolebinding.roleRef.kind == "Role"
    rolebinding.roleRef.name == role.metadata.name

    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    	msga := {
	"alertMessage": sprintf("The following %v: %v can create/modify workloads", [subject.kind, subject.name]),
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

# fails if user has create/modify access to pods
# RoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    can_create_modify_to_pod_resource(rule)
    can_create_modify_to_pod_verb(rule)

    rolebinding.roleRef.kind == "ClusterRole"
    rolebinding.roleRef.name == role.metadata.name
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    	msga := {
	"alertMessage": sprintf("The following %v: %v can create/modify workloads", [subject.kind, subject.name]),
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

# fails if user has create/modify access to pods
# ClusterRoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
     clusterrolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
     clusterrolebinding := clusterrolebindings[_]

    rule:= role.rules[_]
    can_create_modify_to_pod_resource(rule)
    can_create_modify_to_pod_verb(rule)

    clusterrolebinding.roleRef.kind == "ClusterRole"
    clusterrolebinding.roleRef.name == role.metadata.name

    subject := clusterrolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    	msga := {
		"alertMessage": sprintf("The following %v: %v can create/modify workloads", [subject.kind, subject.name]),
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




can_create_modify_to_pod_resource(rule){
    cautils.list_contains(rule.resources,"pods")
}

can_create_modify_to_pod_resource(rule){
    cautils.list_contains(rule.resources,"deployments")
}

can_create_modify_to_pod_resource(rule){
    cautils.list_contains(rule.resources,"daemonsets")
}

can_create_modify_to_pod_resource(rule){
    cautils.list_contains(rule.resources,"replicasets")
}
can_create_modify_to_pod_resource(rule){
    cautils.list_contains(rule.resources,"statefulsets")
}
can_create_modify_to_pod_resource(rule){
    cautils.list_contains(rule.resources,"jobs")
}
can_create_modify_to_pod_resource(rule){
    cautils.list_contains(rule.resources,"cronjobs")
}
can_create_modify_to_pod_resource(rule){
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

can_create_modify_to_pod_verb(rule) {
    cautils.list_contains(rule.verbs, "create")
}

can_create_modify_to_pod_verb(rule) {
    cautils.list_contains(rule.verbs, "patch")
}

can_create_modify_to_pod_verb(rule) {
    cautils.list_contains(rule.verbs, "update")
}

can_create_modify_to_pod_verb(rule) {
    cautils.list_contains(rule.verbs, "*")
}