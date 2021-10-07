
package armo_builtins
import data.cautils as cautils

# fails if user has impersonate access to users/groups
# RoleBinding to Role
deny[msga] {
    roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]

    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canImpersonateToUsersGroupsResource(rule)
    canImpersonateToUsersGroupsVerb(rule)

    rolebinding.roleRef.kind == "Role"
    rolebinding.roleRef.name == role.metadata.name
    subjects := rolebinding.subjects[_]

    	msga := {
	     "alertMessage": sprintf("The following %v: %v can impersonate users/groups", [subjects.kind, subjects.name]),
		"alertScore": 3,
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,rolebinding],
			"externalObjects": {
				"subject" : [subjects]
			}
		}
     }
}

# fails if user has impersonate access to users/groups
# RoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canImpersonateToUsersGroupsResource(rule)
    canImpersonateToUsersGroupsVerb(rule)


    rolebinding.roleRef.kind == "ClusterRole"
    rolebinding.roleRef.name == role.metadata.name

    subjects := rolebinding.subjects[_]

    	msga := {
	     "alertMessage": sprintf("The following %v: %v can impersonate users/groups", [subjects.kind, subjects.name]),
		"alertScore": 3,
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,rolebinding],
			"externalObjects": {
				"subject" : [subjects]
			}
		}
     }
}


# fails if user has impersonate access to users/groups
# ClusterRoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
     clusterrolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
     clusterrolebinding := clusterrolebindings[_]

    rule:= role.rules[_]
    canImpersonateToUsersGroupsResource(rule)
    canImpersonateToUsersGroupsVerb(rule)

    clusterrolebinding.roleRef.kind == "ClusterRole"
    clusterrolebinding.roleRef.name == role.metadata.name
    subjects := clusterrolebinding.subjects[_]

    	msga := {
	     "alertMessage": sprintf("The following %v: %v can impersonate users/groups", [subjects.kind, subjects.name]),
		"alertScore": 3,
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,clusterrolebinding],
			"externalObjects": {
				"subject" : [subjects]
			}
		}
     }
}



canImpersonateToUsersGroupsResource(rule) {
     cautils.list_contains(rule.resources,"users")
}

canImpersonateToUsersGroupsResource(rule) {
     cautils.list_contains(rule.resources,"groups")
}

canImpersonateToUsersGroupsResource(rule) {
     cautils.list_contains(rule.resources,"*")
}

canImpersonateToUsersGroupsVerb(rule) {
    cautils.list_contains(rule.verbs, "impersonate")
}

canImpersonateToUsersGroupsVerb(rule) {
    cautils.list_contains(rule.verbs, "*")
}


