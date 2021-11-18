
package armo_builtins
import data.cautils as cautils

# fails if subject has create/modify access to pods 
deny [msga] {
    subjectVector := input[_]
    role := subjectVector.relatedObjects[i]
    rolebinding := subjectVector.relatedObjects[j]
    endswith(subjectVector.relatedObjects[i].kind, "Role")
    endswith(subjectVector.relatedObjects[j].kind, "Binding")

    rule:= role.rules[_]
    canCreateModifyToPodResource(rule)
    canCreateModifyToPodVerb(rule)

    msga := {
        "alertMessage": sprintf("Subject: %v-%v can create/modify workloads", [subjectVector.kind, subjectVector.name]),
        "alertScore": 3,
        "packagename": "armo_builtins",
        "alertObject": {
            "k8sApiObjects": [role, rolebinding],
            "externalObjects": subjectVector
        }
    }
}


canCreateModifyToPodResource(rule){
    cautils.list_contains(rule.resources,"pods")
}
canCreateModifyToPodResource(rule){
    cautils.list_contains(rule.resources,"deployments")
}
canCreateModifyToPodResource(rule){
    cautils.list_contains(rule.resources,"daemonsets")
}
canCreateModifyToPodResource(rule){
    cautils.list_contains(rule.resources,"replicasets")
}
canCreateModifyToPodResource(rule){
    cautils.list_contains(rule.resources,"statefulsets")
}
canCreateModifyToPodResource(rule){
    cautils.list_contains(rule.resources,"jobs")
}
canCreateModifyToPodResource(rule){
    cautils.list_contains(rule.resources,"cronjobs")
}
canCreateModifyToPodResource(rule){
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

canCreateModifyToPodVerb(rule) {
    cautils.list_contains(rule.verbs, "create")
}
canCreateModifyToPodVerb(rule) {
    cautils.list_contains(rule.verbs, "patch")
}
canCreateModifyToPodVerb(rule) {
    cautils.list_contains(rule.verbs, "update")
}
canCreateModifyToPodVerb(rule) {
    cautils.list_contains(rule.verbs, "*")
}