package armo_builtins
import data.cautils as cautils



# fails if user can delete logs of pod 
#RoleBinding to Role
deny [msga] {
    roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canDeleteLogs(rule)

    rolebinding.roleRef.kind == "Role"
    rolebinding.roleRef.name == role.metadata.name
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    msga := {
      "alertMessage": sprintf("The following %v: %v can delete logs", [subject.kind, subject.name]),
      "alertScore": 6,
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


# fails if user can delete logs of pod 
# RoleBinding to ClusterRole
deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canDeleteLogs(rule)

    rolebinding.roleRef.kind == "ClusterRole"
    rolebinding.roleRef.name == role.metadata.name


    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    msga := {
      "alertMessage": sprintf("The following %v: %v can delete logs", [subject.kind, subject.name]),
      "alertScore": 6,
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

# fails if user can delete logs of pod 
# ClusterRoleBinding to ClusterRole
deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    clusterrolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
    clusterrolebinding := clusterrolebindings[_]

    rule:= role.rules[_]
    canDeleteLogs(rule)

    clusterrolebinding.roleRef.kind == "ClusterRole"
    clusterrolebinding.roleRef.name == role.metadata.name


    subject := clusterrolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    msga := {
      "alertMessage": sprintf("The following %v: %v can delete logs", [subject.kind, subject.name]),
      "alertScore": 6,
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




canDeleteLogs(rule) {
 cautils.list_contains(rule.resources,"*")
 isApiGroup(rule)
 cautils.list_contains(rule.verbs,"*")
}

canDeleteLogs(rule) {
 cautils.list_contains(rule.resources,"pods/log")
 cautils.list_contains(rule.verbs,"delete")
}
canDeleteLogs(rule) {
 cautils.list_contains(rule.resources,"pods/log")
 cautils.list_contains(rule.verbs,"*")
}

canDeleteLogs(rule) {
 cautils.list_contains(rule.resources,"*")
 isApiGroup(rule)
 cautils.list_contains(rule.verbs,"delete")
}

canDeleteLogs(rule) {
 cautils.list_contains(rule.resources,"pods/*")
 cautils.list_contains(rule.verbs,"delete")
}
canDeleteLogs(rule) {
 cautils.list_contains(rule.resources,"pods/*")
 cautils.list_contains(rule.verbs,"*")
}

canDeleteLogs(rule) {
 cautils.list_contains(rule.resources,"*")
 isApiGroup(rule)
 cautils.list_contains(rule.verbs,"deletecollection")
}
isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "*"
}
isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == ""
}