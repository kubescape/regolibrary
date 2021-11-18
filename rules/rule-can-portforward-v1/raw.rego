package armo_builtins
import data.cautils as cautils

deny[msga] {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	endswith(subjectVector.relatedObjects[i].kind, "Role")
	endswith(subjectVector.relatedObjects[j].kind, "Binding")

    rule:= role.rules[_]
	canForwardToPodResource(rule)
	canForwardToPodVerb(rule)

	msga := {
		"alertMessage": sprintf("Subject: %v-%v can do port forwarding", [subjectVector.kind, subjectVector.name]),
		"alertScore": 3,
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [role, rolebinding],
			"externalObjects": subjectVector
		}
  	}
}


canForwardToPodVerb(rule) {
	cautils.list_contains(rule.verbs, "create")
}
canForwardToPodVerb(rule) {
	cautils.list_contains(rule.verbs, "get")
}
canForwardToPodVerb(rule) {
	cautils.list_contains(rule.verbs, "*")
}

canForwardToPodResource(rule) {
	cautils.list_contains(rule.resources,"pods/portforward")
}
canForwardToPodResource(rule) {
	cautils.list_contains(rule.resources,"pods/*")
}
canForwardToPodResource(rule) {
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
