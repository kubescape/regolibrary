package armo_builtins
import data.cautils as cautils

# fails if user can can delete important resources
deny[msga] {
    subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	endswith(subjectVector.relatedObjects[i].kind, "Role")
	endswith(subjectVector.relatedObjects[j].kind, "Binding")

    rule:= role.rules[_]
    canDeleteResource(rule)
    canDeleteVerb(rule)

    msga := {
		"alertMessage": sprintf("Subject: %v-%v can delete important resources", [subjectVector.kind, subjectVector.name]),
		"alertScore": 3,
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [role, rolebinding],
			"externalObjects": subjectVector
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
isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "apps"
}
isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "batch"
}

