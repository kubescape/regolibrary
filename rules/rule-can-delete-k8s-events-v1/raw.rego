package armo_builtins
import data.cautils as cautils

# fails if user can delete events
deny [msga] {
    subjectVector := input[_]
    role := subjectVector.relatedObjects[i]
    rolebinding := subjectVector.relatedObjects[j]
    endswith(subjectVector.relatedObjects[i].kind, "Role")
    endswith(subjectVector.relatedObjects[j].kind, "Binding")

    rule:= role.rules[_]
    canDeleteEventsResource(rule)
    canDeleteEventsVerb(rule)

    msga := {
        "alertMessage": sprintf("Subject: %v-%v can delete events", [subjectVector.kind, subjectVector.name]),
        "alertScore": 3,
        "packagename": "armo_builtins",
        "alertObject": {
            "k8sApiObjects": [role, rolebinding],
            "externalObjects": subjectVector
        }
    }
}


canDeleteEventsResource(rule) {
    cautils.list_contains(rule.resources,"events")
}
canDeleteEventsResource(rule) {
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

canDeleteEventsVerb(rule) {
    cautils.list_contains(rule.verbs,"delete")
}
canDeleteEventsVerb(rule) {
    cautils.list_contains(rule.verbs,"deletecollection")
}
canDeleteEventsVerb(rule) {
    cautils.list_contains(rule.verbs,"*")
}