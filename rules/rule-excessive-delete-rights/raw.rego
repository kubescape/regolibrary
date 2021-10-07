package armo_builtins
import data.cautils as cautils


# fails if user can can delete important resources
#RoleBinding to Role
deny[msga] {
    roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canDeleteResource(rule)
    canDeleteVerb(rule)

    rolebinding.roleRef.kind == "Role"
    rolebinding.roleRef.name == role.metadata.name

    subjects := rolebinding.subjects[_]

    msga := {
	    "alertMessage": sprintf("The following %v: %v can delete important resources", [subjects.kind, subjects.name]),
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


# fails if user can can delete important resources
#RoleBinding to ClusterRole
deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canDeleteResource(rule)
    canDeleteVerb(rule)

    rolebinding.roleRef.kind == "ClusterRole"
    rolebinding.roleRef.name == role.metadata.name

    subjects := rolebinding.subjects[_]

    msga := {
	    "alertMessage": sprintf("The following %v: %v can delete important resources", [subjects.kind, subjects.name]),
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

# fails if user can can delete important resources
# ClusterRoleBinding to ClusterRole
deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    clusterrolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
    clusterrolebinding := clusterrolebindings[_]

    rule:= role.rules[_]
    canDeleteResource(rule)
    canDeleteVerb(rule)

    clusterrolebinding.roleRef.kind == "ClusterRole"
    clusterrolebinding.roleRef.name == role.metadata.name


    subjects := clusterrolebinding.subjects[_]

    msga := {
	    "alertMessage": sprintf("The following %v: %v can delete important resources", [subjects.kind, subjects.name]),
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


canDeleteVerb(rule) {
    cautils.list_contains(rule.verbs,"delete")
}

canDeleteVerb(rule) {
    cautils.list_contains(rule.verbs,"deletecollection")
}

canDeleteVerb(rule) {
    cautils.list_contains(rule.verbs,"*")
}

canDeleteResource(rule) {
    cautils.list_contains(rule.resources,"secrets")
}
canDeleteResource(rule) {
    cautils.list_contains(rule.resources,"pods")
}
canDeleteResource(rule) {
    cautils.list_contains(rule.resources,"services")
}
canDeleteResource(rule) {
    cautils.list_contains(rule.resources,"deployments")
}
canDeleteResource(rule) {
    cautils.list_contains(rule.resources,"replicasets")
}
canDeleteResource(rule) {
    cautils.list_contains(rule.resources,"daemonsets")
}
canDeleteResource(rule) {
    cautils.list_contains(rule.resources,"statefulsets")
}
canDeleteResource(rule) {
    cautils.list_contains(rule.resources,"jobs")
}
canDeleteResource(rule) {
    cautils.list_contains(rule.resources,"cronjobs")
}
canDeleteResource(rule) {
    cautils.list_contains(rule.resources,"*")
}