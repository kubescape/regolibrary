package armo_builtins
import data.cautils as cautils

# fails if user has create access to pods within kube-system namespace
deny[msga] {
    subjectVector := input[_]
    role := subjectVector.relatedObjects[i]
    rolebinding := subjectVector.relatedObjects[j]
    endswith(subjectVector.relatedObjects[i].kind, "Role")
    endswith(subjectVector.relatedObjects[j].kind, "Binding")

    rule:= role.rules[_]
    canCreateToPodNamespace(role)
    canCreateToPodResource(rule)
    canCreateToPodVerb(rule)

    msga := {
        "alertMessage": sprintf("Subject: %v-%v can create pods in kube-system", [subjectVector.kind, subjectVector.name]),
        "alertScore": 3,
        "packagename": "armo_builtins",
        "alertObject": {
            "k8sApiObjects": [role, rolebinding],
            "externalObjects": subjectVector
        }
    }
}

canCreateToPodResource(rule){
    cautils.list_contains(rule.resources,"pods")
}
canCreateToPodResource(rule){
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

canCreateToPodVerb(rule) {
    cautils.list_contains(rule.verbs, "create")
}
canCreateToPodVerb(rule) {
    cautils.list_contains(rule.verbs, "*")
}

canCreateToPodNamespace(role) {
    role.metadata.namespace == "kube-system"
}
