
package armo_builtins
import data.cautils as cautils



# fails if user has create/modify access to pods 
# RoleBinding to Role
deny [msga] {
    roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canCreateModifyToPodResource(rule)
    canCreateModifyToPodVerb(rule)

    rolebinding.roleRef.kind == "Role"
    rolebinding.roleRef.name == role.metadata.name

    subjects := rolebinding.subjects[_]

    	msga := {
	"alertMessage": sprintf("The following %v: %v can create/modify workloads", [subjects.kind, subjects.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
        "alertObject": {
			"k8sApiObjects": [role,rolebinding]
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
    canCreateModifyToPodResource(rule)
    canCreateModifyToPodVerb(rule)

    rolebinding.roleRef.kind == "ClusterRole"
    rolebinding.roleRef.name == role.metadata.name
    subjects := rolebinding.subjects[_]

    	msga := {
	"alertMessage": sprintf("The following %v: %v can create/modify workloads", [subjects.kind, subjects.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
        "alertObject": {
			"k8sApiObjects": [role,rolebinding]
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
    canCreateModifyToPodResource(rule)
    canCreateModifyToPodVerb(rule)

    clusterrolebinding.roleRef.kind == "ClusterRole"
    clusterrolebinding.roleRef.name == role.metadata.name

    subjects := clusterrolebinding.subjects[_]

    	msga := {
		"alertMessage": sprintf("The following %v: %v can create/modify workloads", [subjects.kind, subjects.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,clusterrolebinding]
		}
     }
}




canCreateModifyToPodResource(rule){
    cautils.list_contains(rule.resources,"pods")
}

canCreateModifyToPodResource(rule){
    cautils.list_contains(rule.resources,"deployments")
}

canCreateModifyToPodResource(rule){
    cautils.list_contains(rule.resources,"daemonsets")
}

canCreateModifyToPodResource(rule){
    cautils.list_contains(rule.resources,"replicasets")
}
canCreateModifyToPodResource(rule){
    cautils.list_contains(rule.resources,"statefulsets")
}
canCreateModifyToPodResource(rule){
    cautils.list_contains(rule.resources,"jobs")
}
canCreateModifyToPodResource(rule){
    cautils.list_contains(rule.resources,"cronjobs")
}
canCreateModifyToPodResource(rule){
    cautils.list_contains(rule.resources,"*")
}

canCreateModifyToPodVerb(rule) {
    cautils.list_contains(rule.verbs, "create")
}

canCreateModifyToPodVerb(rule) {
    cautils.list_contains(rule.verbs, "patch")
}

canCreateModifyToPodVerb(rule) {
    cautils.list_contains(rule.verbs, "update")
}

canCreateModifyToPodVerb(rule) {
    cautils.list_contains(rule.verbs, "*")
}
