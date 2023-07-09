package armo_builtins

import data.cautils

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

    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    msga := {
	    "alertMessage": sprintf("The following %v: %v can delete important resources", [subject.kind, subject.name]),
		"alertScore": 9,
		"fixPaths": [],
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

    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    msga := {
	    "alertMessage": sprintf("The following %v: %v can delete important resources", [subject.kind, subject.name]),
		"alertScore": 9,
		"fixPaths": [],
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


    subject := clusterrolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    msga := {
	    "alertMessage": sprintf("The following %v: %v can delete important resources", [subject.kind, subject.name]),
		"alertScore": 9,
		"fixPaths": [],
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


canDeleteVerb(rule) {
	cautils.list_contains(rule.verbs, "delete")
}

canDeleteVerb(rule) {
	cautils.list_contains(rule.verbs, "deletecollection")
}

canDeleteVerb(rule)  {
	cautils.list_contains(rule.verbs, "*")
}

canDeleteResource(rule) {
	cautils.list_contains(rule.resources, "secrets")
}
canDeleteResource(rule)  {
	cautils.list_contains(rule.resources, "pods")
}
canDeleteResource(rule)  {
	cautils.list_contains(rule.resources, "services")
}
canDeleteResource(rule) {
	cautils.list_contains(rule.resources, "deployments")
}
canDeleteResource(rule) {
	cautils.list_contains(rule.resources, "replicasets")
}
canDeleteResource(rule) {
	cautils.list_contains(rule.resources, "daemonsets")
}
canDeleteResource(rule) {
	cautils.list_contains(rule.resources, "statefulsets")
}
canDeleteResource(rule) {
	cautils.list_contains(rule.resources, "jobs")
}
canDeleteResource(rule) {
	cautils.list_contains(rule.resources, "cronjobs")
}
canDeleteResource(rule)  {
    is_api_group(rule)
	cautils.list_contains(rule.resources, "*")
}


is_api_group(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == ""
}
is_api_group(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "*"
}
is_api_group(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "apps"
}
is_api_group(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "batch"
}

