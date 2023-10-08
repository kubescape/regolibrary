package armo_builtins

# input: regoResponseVectorObject
# fails if a subject that is not dashboard service account is bound to dashboard role

deny[msga] {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	endswith(subjectVector.relatedObjects[i].kind, "Role")
	endswith(subjectVector.relatedObjects[j].kind, "Binding")

	role.metadata.name == "kubernetes-dashboard"
	subjectVector.name != "kubernetes-dashboard"

	subject := rolebinding.subjects[k]
    path := [sprintf("relatedObjects[%v].subjects[%v]", [format_int(j, 10), format_int(k, 10)])]
	finalpath := array.concat(path, [sprintf("relatedObjects[%v].roleRef.name", [format_int(j, 10)])])
	msga := {
		"alertMessage": sprintf("Subject: %v-%v is bound to dashboard role/clusterrole", [subjectVector.kind, subjectVector.name]),
		"alertScore": 9,
		"reviewPaths": finalpath,
		"failedPaths": finalpath,
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": subjectVector
		}
	}
}