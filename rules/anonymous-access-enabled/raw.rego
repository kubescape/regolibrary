package armo_builtins

# Fails is rolebinding/clusterrolebinding gives permissions to anonymous user
deny[msga] {
    rolebindings := [rolebinding | rolebinding = input[_]; endswith(rolebinding.kind, "Binding")]
    rolebinding := rolebindings[_]

    isAnonymous(rolebinding)

    msga := {
        "alertMessage": sprintf("the following RoleBinding: %v gives permissions to anonymous users", [rolebinding.metadata.name]),
        "alertScore": 9,
        "packagename": "armo_builtins",
        "alertObject": {
            "k8sApiObjects": [rolebinding]
        }
    }
}


isAnonymous(binding) {
    subject := binding.subjects[_]
    subject.name == "system:anonymous"
}


isAnonymous(binding) {
    subject := binding.subjects[_]
    subject.name == "system:unauthenticated"
}
