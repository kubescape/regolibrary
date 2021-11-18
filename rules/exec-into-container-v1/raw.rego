package armo_builtins
import data.cautils as cautils

# input: regoResponseVectorObject
# returns subjects that can exec into container

deny[msga] {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	endswith(subjectVector.relatedObjects[i].kind, "Role")
	endswith(subjectVector.relatedObjects[j].kind, "Binding")

	rule:= role.rules[_]
	canExecToPodVerb(rule)
	canExecToPodResource(rule)

	msga := {
		"alertMessage": sprintf("Subject: %v-%v can exec into containers", [subjectVector.kind, subjectVector.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [role, rolebinding],
			"externalObjects": subjectVector
		}
	}
}

canExecToPodVerb(rule) {
	cautils.list_contains(rule.verbs, "create")
}
canExecToPodVerb(rule) {
	cautils.list_contains(rule.verbs, "*")
}

canExecToPodResource(rule) {
	cautils.list_contains(rule.resources,"pods/exec")
}
canExecToPodResource(rule) {
	cautils.list_contains(rule.resources,"pods/*")
}
canExecToPodResource(rule) {
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