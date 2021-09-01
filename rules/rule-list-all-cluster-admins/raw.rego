package armo_builtins
import data.cautils as cautils

# input: roles
# apiversion: v1
# does: returns roles+ related subjects in rolebinding

deny[msga] {
	 roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
	canCreate(rule)
	canCreateResources(rule)

	rolebinding.roleRef.kind == "Role"
	rolebinding.roleRef.name == role.metadata.name
    subjects := rolebinding.subjects[_]

    	msga := {
	"alertMessage": sprintf("the following %v: %v have high privileges, such as cluster-admin", [subjects.kind, subjects.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
         "alertObject": {
			"k8sApiObjects": [role,rolebinding]
		}
     }
}

# input: ClusterRole
# apiversion: v1
# does: returns clusterroles+ related subjects in rolebinding

deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
	canCreate(rule)
	canCreateResources(rule)

	rolebinding.roleRef.kind == "ClusterRole"
	rolebinding.roleRef.name == role.metadata.name
    
    subjects := rolebinding.subjects[_]

    	msga := {
	"alertMessage": sprintf("the following %v: %v have high privileges, such as cluster-admin", [subjects.kind, subjects.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
         "alertObject": {
			"k8sApiObjects": [role,rolebinding]
		}
     }
}

# input: ClusterRole
# apiversion: v1
# does:	returns clusterroles+ related subjects in clusterrolebinding

deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
	canCreate(rule)
	canCreateResources(rule)

	rolebinding.roleRef.kind == "ClusterRole"
	rolebinding.roleRef.name == role.metadata.name
	
    subjects := rolebinding.subjects[_]

    	msga := {
	"alertMessage": sprintf("the following %v: %v have high privileges, such as cluster-admin", [subjects.kind, subjects.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
         "alertObject": {
			"k8sApiObjects": [role,rolebinding]
		}
     }
}


canCreate(rule) {
	cautils.list_contains(rule.verbs,"*")
}
canCreateResources(rule){
	cautils.list_contains(rule.resources,"*")
}
