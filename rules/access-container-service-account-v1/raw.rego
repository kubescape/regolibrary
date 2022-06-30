package armo_builtins


# Returns the rbac permission of each service account
deny[msga] {
    service_accounts := [service_account |  service_account= input[_]; service_account.kind == "ServiceAccount"]
    service_account := service_accounts[_]
    service_account_name := service_account.metadata.name

    not saTokenNotAutoMount(service_account)

    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
	rolebinding := rolebindings[_]
    rolesubject := rolebinding.subjects[_]
    rolesubject.name == service_account_name
    rolesubject.namespace == service_account.metadata.namespace

    roles := [role |  role = input[_]; role.kind == "Role"]
    role := roles[_]
    role.metadata.name == rolebinding.roleRef.name

    savector = {"name": service_account.metadata.name,
				"namespace": service_account.metadata.namespace,
				"kind": service_account.kind,
				"relatedObjects": [role, rolebinding]}

	msga := {
		"alertMessage": sprintf("service account: %v has the following permissions in the cluster: %v", [service_account_name, rolebinding.roleRef.name]),
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
    service_accounts := [service_account |  service_account= input[_]; service_account.kind == "ServiceAccount"]
    service_account := service_accounts[_]
    service_account_name := service_account.metadata.name

    not saTokenNotAutoMount(service_account)

    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
	rolebinding := rolebindings[_]
    rolesubject := rolebinding.subjects[_]
    rolesubject.name == service_account_name
    rolesubject.namespace == service_account.metadata.namespace

    roles := [role |  role = input[_]; role.kind == "ClusterRole"]
    role := roles[_]
    role.metadata.name == rolebinding.roleRef.name

    savector = {"name": service_account.metadata.name,
				"namespace": service_account.metadata.namespace,
				"kind": service_account.kind,
				"relatedObjects": [role, rolebinding]}

	msga := {
		"alertMessage": sprintf("service account: %v has the following permissions in the cluster: %v", [service_account_name, rolebinding.roleRef.name]),
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
    service_accounts := [service_account |  service_account= input[_]; service_account.kind == "ServiceAccount"]
    service_account := service_accounts[_]
    service_account_name := service_account.metadata.name

    not saTokenNotAutoMount(service_account)

    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
	rolebinding := rolebindings[_]
    rolesubject := rolebinding.subjects[_]
    rolesubject.name == service_account_name
    rolesubject.namespace == service_account.metadata.namespace

    roles := [role |  role = input[_]; role.kind == "ClusterRole"]
    role := roles[_]
    role.metadata.name == rolebinding.roleRef.name

    savector = {"name": service_account.metadata.name,
				"namespace": service_account.metadata.namespace,
				"kind": service_account.kind,
				"relatedObjects": [role, rolebinding]}

	msga := {
		"alertMessage": sprintf("service account: %v has the following permissions in the cluster: %v", [service_account_name, rolebinding.roleRef.name]),
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

saTokenNotAutoMount(service_account) {
    service_account.automountServiceAccountToken == false
}

