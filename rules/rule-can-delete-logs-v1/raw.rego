package armo_builtins
import data.cautils as cautils

# fails if user can delete logs of pod 
deny [msga] {
  subjectVector := input[_]
  role := subjectVector.relatedObjects[i]
  rolebinding := subjectVector.relatedObjects[j]
  endswith(subjectVector.relatedObjects[i].kind, "Role")
  endswith(subjectVector.relatedObjects[j].kind, "Binding")

  rule:= role.rules[_]
  canDeleteLogs(rule)

  msga := {
    "alertMessage": sprintf("Subject: %v-%v can delete logs", [subjectVector.kind, subjectVector.name]),
    "alertScore": 3,
    "packagename": "armo_builtins",
    "alertObject": {
      "k8sApiObjects": [],
      "externalObjects": subjectVector
    }
  }
}

canDeleteLogs(rule) {
  cautils.list_contains(rule.resources,"*")
  isApiGroup(rule)
  cautils.list_contains(rule.verbs,"*")
}
canDeleteLogs(rule) {
  cautils.list_contains(rule.resources,"pods/log")
  cautils.list_contains(rule.verbs,"delete")
}
canDeleteLogs(rule) {
  cautils.list_contains(rule.resources,"pods/log")
  cautils.list_contains(rule.verbs,"*")
}
canDeleteLogs(rule) {
  cautils.list_contains(rule.resources,"*")
  isApiGroup(rule)
  cautils.list_contains(rule.verbs,"delete")
}
canDeleteLogs(rule) {
  cautils.list_contains(rule.resources,"pods/*")
  cautils.list_contains(rule.verbs,"delete")
}
canDeleteLogs(rule) {
  cautils.list_contains(rule.resources,"pods/*")
  cautils.list_contains(rule.verbs,"*")
}
canDeleteLogs(rule) {
  cautils.list_contains(rule.resources,"*")
  isApiGroup(rule)
  cautils.list_contains(rule.verbs,"deletecollection")
}

isApiGroup(rule) {
  apiGroup := rule.apiGroups[_]
  apiGroup == "*"
}
isApiGroup(rule) {
  apiGroup := rule.apiGroups[_]
  apiGroup == ""
}