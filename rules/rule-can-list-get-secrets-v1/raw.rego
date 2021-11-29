package armo_builtins
import data.cautils as cautils

# fails if user can list/get secrets 
deny[msga] {
    subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	endswith(subjectVector.relatedObjects[i].kind, "Role")
	endswith(subjectVector.relatedObjects[j].kind, "Binding")

    rule:= role.rules[_]
    canViewSecretsResource(rule)
    canViewSecretsVerb(rule)

	subject := rolebinding.subjects[k]
 	path := sprintf("subjects[%v]", [format_int(k, 10)])

    msga := {
		"alertMessage": sprintf("Subject: %v-%v can read secrets", [subjectVector.kind, subjectVector.name]),
		"alertScore": 3,
		 "failedPaths": [path],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": subjectVector
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