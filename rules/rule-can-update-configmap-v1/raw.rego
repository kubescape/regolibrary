package armo_builtins
import data.cautils as cautils

# Fails if user can modify all configmaps, or if he can modify the 'coredns' configmap (default for coredns)
deny [msga] {
     subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	endswith(subjectVector.relatedObjects[i].kind, "Role")
	endswith(subjectVector.relatedObjects[j].kind, "Binding")

     rule:= role.rules[_]
     canModifyConfigMapResource(rule)
     canModifyConfigMapVerb(rule)

    	msga := {
		"alertMessage": sprintf("Subject: %v-%v can modify 'coredns' configmap", [subjectVector.kind, subjectVector.name]),
		"alertScore": 3,
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [role, rolebinding],
			"externalObjects": subjectVector
		}
  	}
}

canModifyConfigMapResource(rule) {
     not rule.resourceNames
     cautils.list_contains(rule.resources,"configmaps")
}
canModifyConfigMapResource(rule) {
     not rule.resourceNames
     cautils.list_contains(rule.resources,"*")
}
canModifyConfigMapResource(rule) {
     cautils.list_contains(rule.resources,"configmaps")
     cautils.list_contains(rule.resourceNames,"coredns")
}

canModifyConfigMapVerb(rule) {
     cautils.list_contains(rule.verbs,"update")
}
canModifyConfigMapVerb(rule) {
     cautils.list_contains(rule.verbs,"patch")
}
canModifyConfigMapVerb(rule) {
     cautils.list_contains(rule.verbs,"*")
}
