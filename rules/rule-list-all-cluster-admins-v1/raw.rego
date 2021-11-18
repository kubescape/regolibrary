package armo_builtins
import data.cautils as cautils

# returns subjects related subjects in rolebinding
deny[msga] {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	endswith(subjectVector.relatedObjects[i].kind, "Role")
	endswith(subjectVector.relatedObjects[j].kind, "Binding")

    rule:= role.rules[_]
	canCreate(rule)
	canCreateResources(rule)

    msga := {
		"alertMessage": sprintf("Subject: %v-%v have high privileges, such as cluster-admin", [subjectVector.kind, subjectVector.name]),
		"alertScore": 3,
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [role, rolebinding],
			"externalObjects": subjectVector
		}
  	}
}


canCreate(rule) {
	cautils.list_contains(rule.verbs,"*")
}
canCreateResources(rule){
	isApiGroup(rule)
	cautils.list_contains(rule.resources,"*")
}
isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == ""
}
isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "*"
}
