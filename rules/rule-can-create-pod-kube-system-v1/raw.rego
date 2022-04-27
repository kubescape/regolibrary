package armo_builtins
import data.cautils as cautils

# fails if user has create access to pods within kube-system namespace
deny[msga] {
    subjectVector := input[_]
    role := subjectVector.relatedObjects[i]
    rolebinding := subjectVector.relatedObjects[j]
    endswith(subjectVector.relatedObjects[i].kind, "Role")
    endswith(subjectVector.relatedObjects[j].kind, "Binding")


    can_create_to_pod_namespace(role)
    rule:= role.rules[p]

	subject := rolebinding.subjects[k]

	verbs := ["create", "*"]
    verb_path := [sprintf("relatedObjects[%v].rules[%v].verbs[%v]", [format_int(i, 10),format_int(p, 10), format_int(l, 10)])  | verb =  rule.verbs[l];cautils.list_contains(verbs, verb)]
	count(verb_path) > 0

	api_groups := ["", "*"]
	api_groups_path := [sprintf("relatedObjects[%v].rules[%v].apiGroups[%v]", [format_int(i, 10),format_int(p, 10), format_int(a, 10)])  | apiGroup =  rule.apiGroups[a];cautils.list_contains(api_groups, apiGroup)]
	count(api_groups_path) > 0

	resources := ["pods", "*"]
	resources_path := [sprintf("relatedObjects[%v].rules[%v].resources[%v]", [format_int(i, 10),format_int(p, 10), format_int(l, 10)])  | resource =  rule.resources[l]; cautils.list_contains(resources, resource)]
	count(resources_path) > 0


	path := array.concat(resources_path, verb_path)
	path2 := array.concat(path, api_groups_path)
	path3 := array.concat(path2, [sprintf("relatedObjects[%v].subjects[%v]", [format_int(j, 10), format_int(k, 10)])])
	finalpath := array.concat(path3, [sprintf("relatedObjects[%v].roleRef.name", [format_int(j, 10)])])

	

    msga := {
        "alertMessage": sprintf("Subject: %v-%v can create pods in kube-system", [subjectVector.kind, subjectVector.name]),
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

can_create_to_pod_namespace(role) {
    role.metadata.namespace == "kube-system"
}
