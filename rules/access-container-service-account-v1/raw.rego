package armo_builtins


# Returns the rbac permission of each service account
deny[msga] {
    serviceAccounts := [serviceaccount |  serviceaccount= input[_]; serviceaccount.kind == "ServiceAccount"]
    serviceaccount := serviceAccounts[_]
    serviceAccountName := serviceaccount.metadata.name

    not saTokenNotAutoMount(serviceaccount)

    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
	rolebinding := rolebindings[_]
    rolesubject := rolebinding.subjects[_]
    rolesubject.name == serviceAccountName
    rolesubject.namespace == serviceaccount.metadata.namespace

    roles := [role |  role = input[_]; role.kind == "Role"]
    role := roles[_]
    role.metadata.name == rolebinding.roleRef.name

    savector = {"name": serviceaccount.metadata.name,
				"namespace": serviceaccount.metadata.namespace,
				"kind": serviceaccount.kind,
				"relatedObjects": [role, rolebinding]}

	msga := {
		"alertMessage": sprintf("service account: %v has the following permissions in the cluster: %v", [serviceAccountName, rolebinding.roleRef.name]),
		"packagename": "armo_builtins",
        "failedPaths": [],
        "fixPaths":[],
		"alertScore": 7,
        "alertObject": {
			"k8sApiObjects": [],
            "externalObjects": savector
		}
	}
}

# Returns the rbac permission of each service account
deny[msga] {
    serviceAccounts := [serviceaccount |  serviceaccount= input[_]; serviceaccount.kind == "ServiceAccount"]
    serviceaccount := serviceAccounts[_]
    serviceAccountName := serviceaccount.metadata.name

    not saTokenNotAutoMount(serviceaccount)

    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
	rolebinding := rolebindings[_]
    rolesubject := rolebinding.subjects[_]
    rolesubject.name == serviceAccountName
    rolesubject.namespace == serviceaccount.metadata.namespace

    roles := [role |  role = input[_]; role.kind == "ClusterRole"]
    role := roles[_]
    role.metadata.name == rolebinding.roleRef.name

    savector = {"name": serviceaccount.metadata.name,
				"namespace": serviceaccount.metadata.namespace,
				"kind": serviceaccount.kind,
				"relatedObjects": [role, rolebinding]}

	msga := {
		"alertMessage": sprintf("service account: %v has the following permissions in the cluster: %v", [serviceAccountName, rolebinding.roleRef.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
        "failedPaths": [],
        "fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": savector
		}
	}
}

# Returns the rbac permission of each service account
deny[msga] {
    serviceAccounts := [serviceaccount |  serviceaccount= input[_]; serviceaccount.kind == "ServiceAccount"]
    serviceaccount := serviceAccounts[_]
    serviceAccountName := serviceaccount.metadata.name

    not saTokenNotAutoMount(serviceaccount)

    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
	rolebinding := rolebindings[_]
    rolesubject := rolebinding.subjects[_]
    rolesubject.name == serviceAccountName
    rolesubject.namespace == serviceaccount.metadata.namespace

    roles := [role |  role = input[_]; role.kind == "ClusterRole"]
    role := roles[_]
    role.metadata.name == rolebinding.roleRef.name

    savector = {"name": serviceaccount.metadata.name,
				"namespace": serviceaccount.metadata.namespace,
				"kind": serviceaccount.kind,
				"relatedObjects": [role, rolebinding]}

	msga := {
		"alertMessage": sprintf("service account: %v has the following permissions in the cluster: %v", [serviceAccountName, rolebinding.roleRef.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
        "failedPaths": [],
        "fixPaths":[],
        "alertObject": {
			"k8sApiObjects": [],
            "externalObjects": savector
		}
	}
}

# ===============================================================

saTokenNotAutoMount(serviceaccount) {
    serviceaccount.automountServiceAccountToken == false
}

