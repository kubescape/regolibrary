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

    rule:= role.rules[i]
	canCreate(rule, i)
	canCreateResources(rule, i)

	rolebinding.roleRef.kind == "Role"
	rolebinding.roleRef.name == role.metadata.name
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    msga := {
		"alertMessage": sprintf("The following %v: %v have high privileges, such as cluster-admin", [subject.kind, subject.name]),
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

# input: ClusterRole
# apiversion: v1
# does: returns clusterroles+ related subjects in rolebinding

deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[i]
	canCreate(rule, i)
	canCreateResources(rule, i)

	rolebinding.roleRef.kind == "ClusterRole"
	rolebinding.roleRef.name == role.metadata.name
    
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    msga := {
		"alertMessage": sprintf("The following %v: %v have high privileges, such as cluster-admin", [subject.kind, subject.name]),
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

# input: ClusterRole
# apiversion: v1
# does:	returns clusterroles+ related subjects in clusterrolebinding

deny[msga] {
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[i]
	canCreate(rule, i)
    canCreateResources(rule, i)

	rolebinding.roleRef.kind == "ClusterRole"
	rolebinding.roleRef.name == role.metadata.name
	
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

	msga := {
		"alertMessage": sprintf("The following %v: %v have high privileges, such as cluster-admin", [subject.kind, subject.name]),
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


canCreate(rule, i) {
	verb := rule.verbs[j]
	verb == "*"
}

canCreateResources(rule, i){
	isApiGroup(rule)
	resource := rule.resources[j]
	resource == "*"
}

isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == ""
}

isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "*"
}
