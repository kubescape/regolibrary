package armo_builtins
import data.cautils as cautils

# returns subjects with cluster admin role
deny[msga] {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	endswith(subjectVector.relatedObjects[i].kind, "Role")
	endswith(subjectVector.relatedObjects[j].kind, "Binding")

	rule:= role.rules[p]
	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	# check only cluster-admin role and only clusterrolebinding
	role.metadata.name == "cluster-admin"
	rolebinding.kind == "ClusterRoleBinding"

	verbs := ["*"]
  	verb_path := [sprintf("relatedObjects[%v].rules[%v].verbs[%v]", [format_int(i, 10),format_int(p, 10), format_int(l, 10)])  | verb =  rule.verbs[l];cautils.list_contains(verbs, verb)]
	count(verb_path) > 0

	api_groups := ["*", ""]
	api_groups_path := [sprintf("relatedObjects[%v].rules[%v].apiGroups[%v]", [format_int(i, 10),format_int(p, 10), format_int(a, 10)])  | apiGroup =  rule.apiGroups[a];cautils.list_contains(api_groups, apiGroup)]
	count(api_groups_path) > 0

	resources := ["*"]
	resources_path := [sprintf("relatedObjects[%v].rules[%v].resources[%v]", [format_int(i, 10),format_int(p, 10), format_int(l, 10)])  | resource =  rule.resources[l]; cautils.list_contains(resources, resource)]
	count(resources_path) > 0

	path := array.concat(resources_path, verb_path)
	path2 := array.concat(path, api_groups_path)
	path3 := array.concat(path2, [sprintf("relatedObjects[%v].subjects[%v]", [format_int(j, 10), format_int(k, 10)])])
	finalpath := array.concat(path3, [sprintf("relatedObjects[%v].roleRef.name", [format_int(j, 10)])])

    msga := {
		"alertMessage": sprintf("Subject: %v-%v is bound to cluster-admin role", [subjectVector.kind, subjectVector.name]),
		"alertScore": 3,
		"fixPaths": [],
		"failedPaths": finalpath,
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": subjectVector
		}
  	}
}

# for service accounts
is_same_subjects(subjectVector, subject){
	subjectVector.kind == subject.kind
	subjectVector.name == subject.name
	subjectVector.namespace == subject.namespace
}

# for users/ groups
is_same_subjects(subjectVector, subject){
	subjectVector.kind == subject.kind
	subjectVector.name == subject.name
	subjectVector.apiGroup == subject.apiGroup
}