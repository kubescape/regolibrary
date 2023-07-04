package armo_builtins

#  -- ----     For workloads     -- ----   
# Fails if pod mount tokens  by default (either by its config or by its SA config)

 # POD  
deny [msga]{
    pod := input[_]
    pod.kind == "Pod"
    
    beggining_of_path := "spec."
    wl_namespace := pod.metadata.namespace
    result := is_sa_auto_mounted(pod.spec, beggining_of_path, wl_namespace)
    failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)

    msga := {
        "alertMessage": sprintf("Pod: %v in the following namespace: %v mounts service account tokens by default", [pod.metadata.name, pod.metadata.namespace]),
        "alertScore": 9,
        "packagename": "armo_builtins",
        "fixPaths": fixed_path,
        "failedPaths": failed_path,
        "alertObject": {
            "k8sApiObjects": [pod]
        }
    }
}    

# WORKLOADS
deny[msga] {
    wl := input[_]
    spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
    spec_template_spec_patterns[wl.kind]
    beggining_of_path := "spec.template.spec."

    wl_namespace := wl.metadata.namespace
    result := is_sa_auto_mounted(wl.spec.template.spec, beggining_of_path, wl_namespace)
    failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)

    msga := {
        "alertMessage":  sprintf("%v: %v in the following namespace: %v mounts service account tokens by default", [wl.kind, wl.metadata.name, wl.metadata.namespace]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "fixPaths": fixed_path,
        "failedPaths": failed_path,
        "alertObject": {
            "k8sApiObjects": [wl]
        }
    }
}

# CRONJOB
deny[msga] {
    wl := input[_]
    wl.kind == "CronJob"
    container = wl.spec.jobTemplate.spec.template.spec.containers[i]
    beggining_of_path := "spec.jobTemplate.spec.template.spec."
   
    wl_namespace := wl.metadata.namespace
    result := is_sa_auto_mounted(wl.spec.jobTemplate.spec.template.spec, beggining_of_path, wl_namespace)
    failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)

    msga := {
        "alertMessage": sprintf("%v: %v in the following namespace: %v mounts service account tokens by default", [wl.kind, wl.metadata.name, wl.metadata.namespace]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "fixPaths": fixed_path,
        "failedPaths": failed_path,
        "alertObject": {
            "k8sApiObjects": [wl]
        }
    }
}

 #  -- ----     For workloads     -- ----     
is_sa_auto_mounted(spec, beggining_of_path, wl_namespace) = [failed_path, fix_path]   {
    # automountServiceAccountToken not in pod spec
    not spec.automountServiceAccountToken == false
    not spec.automountServiceAccountToken == true

    # check if SA  automount by default
    sa := input[_]
    is_same_sa(spec, sa.metadata.name)
    is_same_namespace(sa.metadata.namespace , wl_namespace)
    has_service_account_binding(sa)

    # path is pod spec
    fix_path = { "path": sprintf("%vautomountServiceAccountToken", [beggining_of_path]), "value": "false"}
    failed_path = ""
}

get_failed_path(paths) = [paths[0]] {
    paths[0] != ""
} else = []


get_fixed_path(paths) = [paths[1]] {
    paths[1] != ""
} else = []

is_sa_auto_mounted(spec, beggining_of_path, wl_namespace) =  [failed_path, fix_path]  {
    # automountServiceAccountToken set to true in pod spec
    spec.automountServiceAccountToken == true
    
    # SA automount by default
    service_accounts := [service_account | service_account = input[_]; service_account.kind == "ServiceAccount"]
    count(service_accounts) > 0
    sa := service_accounts[_]
    is_same_sa(spec, sa.metadata.name)
    is_same_namespace(sa.metadata.namespace , wl_namespace)
    has_service_account_binding(sa)

    failed_path = sprintf("%vautomountServiceAccountToken", [beggining_of_path])
    fix_path = ""
}

is_same_sa(spec, serviceAccountName) {
    spec.serviceAccountName == serviceAccountName
}

is_same_sa(spec, serviceAccountName) {
    not spec.serviceAccountName 
    serviceAccountName == "default"
}

is_same_namespace(metadata1, metadata2) {
    metadata1.namespace == metadata2.namespace
}

is_same_namespace(metadata1, metadata2) {
    not metadata1.namespace
    not metadata2.namespace
}

is_same_namespace(metadata1, metadata2) {
    not metadata2.namespace
    metadata1.namespace == "default"
}

is_same_namespace(metadata1, metadata2) {
    not metadata1.namespace
    metadata2.namespace == "default"
}

# checks if RoleBinding has a bind with the given ServiceAccount
has_service_account_binding(service_account) {
    role_bindings := [role_binding | role_binding = input[_]; role_binding.kind == "RoleBinding"]
    role_binding := role_bindings[_]
    role_binding.subjects[_].name == service_account.metadata.name
    role_binding.subjects[_].namespace == service_account.metadata.namespace
    role_binding.subjects[_].kind == "ServiceAccount"
}

# checks if ClusterRoleBinding has a bind with the given ServiceAccount
has_service_account_binding(service_account) {
    cluster_role_bindings := [cluster_role_binding | cluster_role_binding = input[_]; cluster_role_binding.kind == "ClusterRoleBinding"]
    cluster_role_binding := cluster_role_bindings[_]
    cluster_role_binding.subjects[_].name == service_account.metadata.name
    cluster_role_binding.subjects[_].namespace == service_account.metadata.namespace
    cluster_role_binding.subjects[_].kind == "ServiceAccount"
}
