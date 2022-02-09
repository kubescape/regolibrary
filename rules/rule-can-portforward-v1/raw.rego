package armo_builtins
import data.cautils as cautils

deny[msga] {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	endswith(subjectVector.relatedObjects[i].kind, "Role")
	endswith(subjectVector.relatedObjects[j].kind, "Binding")

	rule:= role.rules[p]
	subject := rolebinding.subjects[k]

	verbs := ["create", "get", "*"]
  	verbsPath := [sprintf("relatedObjects[%v].rules[%v].verbs[%v]", [format_int(i, 10),format_int(p, 10), format_int(l, 10)])  | verb =  rule.verbs[l];cautils.list_contains(verbs, verb)]
	count(verbsPath) > 0

	apiGroups := ["", "*"]
	apiGroupsPath := [sprintf("relatedObjects[%v].rules[%v].apiGroups[%v]", [format_int(i, 10),format_int(p, 10), format_int(a, 10)])  | apiGroup =  rule.apiGroups[a];cautils.list_contains(apiGroups, apiGroup)]
	count(apiGroupsPath) > 0

	resources := ["pods/portforward", "pods/*", "*"]
	resourcesPath := [sprintf("relatedObjects[%v].rules[%v].resources[%v]", [format_int(i, 10),format_int(p, 10), format_int(l, 10)])  | resource =  rule.resources[l]; cautils.list_contains(resources, resource)]
	count(resourcesPath) > 0

	path := array.concat(resourcesPath, verbsPath)
	path2 := array.concat(path, apiGroupsPath)
	path3 := array.concat(path2, [sprintf("relatedObjects[%v].roleRef.subjects[%v]", [format_int(j, 10), format_int(k, 10)])])
	finalpath := array.concat(path3, [sprintf("relatedObjects[%v].roleRef.name", [format_int(j, 10)])])

	msga := {
		"alertMessage": sprintf("Subject: %v-%v can do port forwarding", [subjectVector.kind, subjectVector.name]),
		"alertScore": 3,
		"failedPaths": finalpath,
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": subjectVector
		}
  	}
}