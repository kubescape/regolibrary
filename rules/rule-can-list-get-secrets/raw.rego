package armo_builtins
import data.cautils as cautils


# fails if user can list/get secrets 
#RoleBinding to Role
deny[msga] {
    roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canViewSecretsResource(rule)
    canViewSecretsVerb(rule)

    rolebinding.roleRef.kind == "Role"
    rolebinding.roleRef.name == role.metadata.name

    subjects := rolebinding.subjects[_]

    	msga := {
	"alertMessage": sprintf("the following %v: %v can read  secrets", [subjects.kind, subjects.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,rolebinding]
		}
     }


}


# fails if user can list/get secrets 
#RoleBinding to ClusterRole
deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canViewSecretsResource(rule)
    canViewSecretsVerb(rule)

    rolebinding.roleRef.kind == "ClusterRole"
    rolebinding.roleRef.name == role.metadata.name


    subjects := rolebinding.subjects[_]

    	msga := {
	"alertMessage": sprintf("the following %v: %v can read  secrets", [subjects.kind, subjects.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,rolebinding]
		}
     }
}

# fails if user can list/get secrets 
# ClusterRoleBinding to ClusterRole
deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    clusterrolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
    clusterrolebinding := clusterrolebindings[_]

    rule:= role.rules[_]
    canViewSecretsResource(rule)
    canViewSecretsVerb(rule)

    clusterrolebinding.roleRef.kind == "ClusterRole"
    clusterrolebinding.roleRef.name == role.metadata.name

    subjects := clusterrolebinding.subjects[_]

    	msga := {
	"alertMessage": sprintf("the following %v: %v can read  secrets", [subjects.kind, subjects.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,clusterrolebinding]
		}
     }

}




canViewSecretsVerb(rule) {
    cautils.list_contains(rule.verbs,"get")
}

canViewSecretsVerb(rule) {
    cautils.list_contains(rule.verbs,"list")
}

canViewSecretsVerb(rule) {
    cautils.list_contains(rule.verbs,"watch")
}


canViewSecretsVerb(rule) {
    cautils.list_contains(rule.verbs,"*")
}


canViewSecretsResource(rule) {
    cautils.list_contains(rule.resources,"secrets")
}

canViewSecretsResource(rule) {
    cautils.list_contains(rule.resources,"*")
}