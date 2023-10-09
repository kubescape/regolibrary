package armo_builtins

deny[msga] {
    wl := input[_]
    start_of_path := get_beginning_of_path(wl)
    spec := object.get(wl, start_of_path, [])

    sa := input[_]
    sa.kind == "ServiceAccount"
    is_same_sa(spec, sa.metadata.name)
    is_same_namespace(sa.metadata , wl.metadata)
    has_service_account_binding(sa)
    result := is_sa_auto_mounted_and_bound(spec, start_of_path, sa)

    failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)

    msga := {
        "alertMessage": sprintf("%v: %v in the following namespace: %v mounts service account tokens by default", [wl.kind, wl.metadata.name, wl.metadata.namespace]),
        "packagename": "armo_builtins",
        "alertScore": 9,
        "fixPaths": fixed_path,
        "reviewPaths": failed_path,
        "failedPaths": failed_path,
        "alertObject": {
            "k8sApiObjects": [wl]
        },
        "relatedObjects": [{
            "object": sa
        }]
    }
}


get_beginning_of_path(workload) = start_of_path {
    spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
    spec_template_spec_patterns[workload.kind]
    start_of_path := ["spec", "template", "spec"]
}

get_beginning_of_path(workload) = start_of_path {
    workload.kind == "Pod"
    start_of_path := ["spec"]
}

get_beginning_of_path(workload) = start_of_path {
    workload.kind == "CronJob"
    start_of_path := ["spec", "jobTemplate", "spec", "template", "spec"]
}


 #  -- ----     For workloads     -- ----     
is_sa_auto_mounted_and_bound(spec, start_of_path, sa) = [failed_path, fix_path]   {
    # automountServiceAccountToken not in pod spec
    not spec.automountServiceAccountToken == false
    not spec.automountServiceAccountToken == true

    not sa.automountServiceAccountToken == false

    fix_path = { "path": sprintf("%v.automountServiceAccountToken", [concat(".", start_of_path)]), "value": "false"}
    failed_path = ""
}

is_sa_auto_mounted_and_bound(spec, start_of_path, sa) =  [failed_path, fix_path]  {
    # automountServiceAccountToken set to true in pod spec
    spec.automountServiceAccountToken == true

    failed_path = sprintf("%v.automountServiceAccountToken", [concat(".", start_of_path)])
    fix_path = ""
}

get_failed_path(paths) = [paths[0]] {
    paths[0] != ""
} else = []


get_fixed_path(paths) = [paths[1]] {
    paths[1] != ""
} else = []


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

# checks if RoleBinding/ClusterRoleBinding has a bind with the given ServiceAccount
has_service_account_binding(service_account) {
    role_bindings := [role_binding | role_binding = input[_]; endswith(role_binding.kind, "Binding")]
    role_binding := role_bindings[_]
    role_binding.subjects[_].name == service_account.metadata.name
    role_binding.subjects[_].namespace == service_account.metadata.namespace
    role_binding.subjects[_].kind == "ServiceAccount"
}

# checks if RoleBinding/ClusterRoleBinding has a bind with the system:authenticated group
# which gives access to all authenticated users, including service accounts
has_service_account_binding(service_account) {
    role_bindings := [role_binding | role_binding = input[_]; endswith(role_binding.kind, "Binding")]
    role_binding := role_bindings[_]
    role_binding.subjects[_].name == "system:authenticated"
}

# checks if RoleBinding/ClusterRoleBinding has a bind with the "system:serviceaccounts" group
# which gives access to all service accounts
has_service_account_binding(service_account) {
    role_bindings := [role_binding | role_binding = input[_]; endswith(role_binding.kind, "Binding")]
    role_binding := role_bindings[_]
    role_binding.subjects[_].name == "system:serviceaccounts"
}
