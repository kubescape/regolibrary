package armo_builtins
import data.cautils as cautils

# fails if user has create/delete access to services
deny[msga] {
    subjectVector := input[_]
    role := subjectVector.relatedObjects[i]
    rolebinding := subjectVector.relatedObjects[j]
    endswith(subjectVector.relatedObjects[i].kind, "Role")
    endswith(subjectVector.relatedObjects[j].kind, "Binding")

    rule:= role.rules[_]
    canCreateDeleteToServiceResource(rule)
    canCreateDeleteToServiceVerb(rule)

    subject := rolebinding.subjects[k]
    path := sprintf("subjects[%v]", [format_int(k, 10)])

    	msga := {
          "alertMessage": sprintf("Subject: %v-%v can create/delete services", [subjectVector.kind, subjectVector.name]),
          "alertScore": 3,
          "failedPaths": [path],
          "packagename": "armo_builtins",
          "alertObject": {
               "k8sApiObjects": [],
               "externalObjects": subjectVector
          }
     }
}


canCreateDeleteToServiceResource(rule) {
    cautils.list_contains(rule.resources, "services")
}
canCreateDeleteToServiceResource(rule) {
    isApiGroup(rule)
    cautils.list_contains(rule.resources, "*")
}

isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "*"
}
isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == ""
}

canCreateDeleteToServiceVerb(rule) {
     cautils.list_contains(rule.verbs, "create")
}
canCreateDeleteToServiceVerb(rule) {
     cautils.list_contains(rule.verbs, "delete")
}
canCreateDeleteToServiceVerb(rule) {
     cautils.list_contains(rule.verbs, "deletecollection")
}
canCreateDeleteToServiceVerb(rule) {
     cautils.list_contains(rule.verbs, "*")
}