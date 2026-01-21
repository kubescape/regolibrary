package armo_builtins

import future.keywords.in

# Memoize by type for better performance
serviceaccounts := [sa |
    sa := input[_]
    sa.kind == "ServiceAccount"
]
roles := [r |
    r := input[_]
    r.kind in ["Role", "ClusterRole"]
]
rolebindings := [rb |
    rb := input[_]
    rb.kind in ["RoleBinding", "ClusterRoleBinding"]
]

deny[msga] {
    wl := input[_]
    start_of_path := get_start_of_path(wl)
    wl_spec := object.get(wl, start_of_path, [])

    # get service account wl is using
    sa := serviceaccounts[_]
    is_same_sa(wl_spec, sa.metadata, wl.metadata)

    # check service account token is mounted
    is_sa_auto_mounted(wl_spec, sa)

    # check if sa has administrative roles
    role := roles[_]
    is_administrative_role(role)

    rolebinding := rolebindings[_]
    rolebinding.roleRef.name == role.metadata.name
    rolebinding.subjects[j].kind == "ServiceAccount"
    rolebinding.subjects[j].name == sa.metadata.name
    rolebinding.subjects[j].namespace == sa.metadata.namespace

    reviewPath := "roleRef"
    deletePath := sprintf("subjects[%d]", [j])

    msga := {
        "alertMessage": sprintf("%v: %v in the following namespace: %v has administrative roles", [wl.kind, wl.metadata.name, wl.metadata.namespace]),
        "packagename": "armo_builtins",
        "alertScore": 9,
        "alertObject": {
            "k8sApiObjects": [wl]
        },
        "relatedObjects": [{
            "object": sa,
        },
        {
            "object": rolebinding,
            "reviewPaths": [reviewPath],
            "deletePaths": [deletePath],
        },
        {
            "object": role,
        },]
    }
}


get_start_of_path(workload) = start_of_path {
    spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
    spec_template_spec_patterns[workload.kind]
    start_of_path := ["spec", "template", "spec"]
}

get_start_of_path(workload) = start_of_path {
    workload.kind == "Pod"
    start_of_path := ["spec"]
}

get_start_of_path(workload) = start_of_path {
    workload.kind == "CronJob"
    start_of_path := ["spec", "jobTemplate", "spec", "template", "spec"]
}


is_sa_auto_mounted(wl_spec, sa)    {
    # automountServiceAccountToken not in pod spec
    not wl_spec.automountServiceAccountToken == false
    not wl_spec.automountServiceAccountToken == true

    not sa.automountServiceAccountToken == false
}

is_sa_auto_mounted(wl_spec, sa)  {
    # automountServiceAccountToken set to true in pod spec
    wl_spec.automountServiceAccountToken == true
}


is_same_sa(wl_spec, sa_metadata, wl_metadata) {
    wl_spec.serviceAccountName == sa_metadata.name
    is_same_namespace(sa_metadata , wl_metadata)
}

is_same_sa(wl_spec, sa_metadata, wl_metadata) {
    not wl_spec.serviceAccountName 
    sa_metadata.name == "default"
    is_same_namespace(sa_metadata , wl_metadata)
}

# is_same_namespace supports cases where ns is not configured in the metadata
# for yaml scans
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


is_administrative_role(role){
    administrative_resources := ["*"]
    administrative_verbs := ["*"]
    administrative_api_groups := ["", "*"]
    
    administrative_rule := [rule | rule = role.rules[i] ; 
                        rule.resources[a] in administrative_resources ; 
                        rule.verbs[b] in administrative_verbs ; 
                        rule.apiGroups[c] in administrative_api_groups]
    count(administrative_rule) > 0
}
