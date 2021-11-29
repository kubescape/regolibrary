package armo_builtins
import data.cautils as cautils

deny[msga] {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	endswith(subjectVector.relatedObjects[i].kind, "Role")
	endswith(subjectVector.relatedObjects[j].kind, "Binding")

	rule:= role.rules[_]
	canImpersonateVerb(rule)
	canImpersonateResource(rule)

	subject := rolebinding.subjects[k]
 	path := sprintf("subjects[%v]", [format_int(k, 10)])

	msga := {
		"alertMessage": sprintf("Subject: %v-%v can impersonate users", [subjectVector.kind, subjectVector.name]),
		"alertScore": 3,
		 "failedPaths": [path],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": subjectVector
		}
  	}
}

canImpersonateVerb(rule) {
	cautils.list_contains(rule.verbs, "impersonate")
}
canImpersonateVerb(rule) {
	cautils.list_contains(rule.verbs, "*")
}

canImpersonateResource(rule) {
	cautils.list_contains(rule.resources,"users")
}
canImpersonateResource(rule) {
	cautils.list_contains(rule.resources,"serviceaccounts")
}
canImpersonateResource(rule) {
	cautils.list_contains(rule.resources,"groups")
}
canImpersonateResource(rule) {
	cautils.list_contains(rule.resources,"uids")
}
canImpersonateResource(rule) {
	isApiGroup(rule)
	cautils.list_contains(rule.resources,"*")
}

isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "*"
}
isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == ""
}