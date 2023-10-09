package armo_builtins

# Fails is rolebinding/clusterrolebinding gives permissions to anonymous user
deny[msga] {
    rolebindings := [rolebinding | rolebinding = input[_]; endswith(rolebinding.kind, "Binding")]
    rolebinding := rolebindings[_]
    subject := rolebinding.subjects[i]
    isAnonymous(subject)
    delete_path := sprintf("subjects[%d]", [i])
    msga := {
        "alertMessage": sprintf("the following RoleBinding: %v gives permissions to anonymous users", [rolebinding.metadata.name]),
        "alertScore": 9,
        "deletePaths": [delete_path],
        "failedPaths": [delete_path],
        "packagename": "armo_builtins",
        "alertObject": {
            "k8sApiObjects": [rolebinding]
        }
    }
}


isAnonymous(subject) {
    subject.name == "system:anonymous"
}

isAnonymous(subject) {
    subject.name == "system:unauthenticated"
}
