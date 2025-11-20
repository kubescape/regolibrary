package armo_builtins

import future.keywords.in

deny[msga] {
    # Use 'some' for explicit iteration - more efficient
    some wl in input
    start_of_path := get_start_of_path(wl)
    wl_spec := object.get(wl, start_of_path, [])

    # get service account wl is using
    some sa in input
    sa.kind == "ServiceAccount"
    is_same_sa(wl_spec, sa.metadata, wl.metadata)

    # check service account token is mounted
    is_sa_auto_mounted(wl_spec, sa)

    # check if sa has cluster takeover roles
    some role in input
    role.kind in ["Role", "ClusterRole"]
    is_takeover_role(role)

    some rolebinding in input
	rolebinding.kind in ["RoleBinding", "ClusterRoleBinding"]
    rolebinding.roleRef.name == role.metadata.name
    rolebinding.roleRef.kind == role.kind
    
    # Use 'some' for subject iteration
    some j
    rolebinding.subjects[j].kind == "ServiceAccount"
    rolebinding.subjects[j].name == sa.metadata.name
    rolebinding.subjects[j].namespace == sa.metadata.namespace

    deletePath := sprintf("subjects[%d]", [j])

    msga := {
        "alertMessage": sprintf("%v: %v in the following namespace: %v has cluster takeover roles", [wl.kind, wl.metadata.name, wl.metadata.namespace]),
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


# look for rule allowing create/update workloads
is_takeover_role(role){
    # Use sets for O(1) membership checks
    takeover_resources_set := {"pods", "*"}
    takeover_verbs_set := {"create", "update", "patch", "*"}
    takeover_api_groups_set := {"", "*"}
    
    # Direct membership checks - more efficient than array comprehension
    some i
    rule := role.rules[i]
    some resource in rule.resources
    resource in takeover_resources_set
    some verb in rule.verbs
    verb in takeover_verbs_set
    some apiGroup in rule.apiGroups
    apiGroup in takeover_api_groups_set
}

# look for rule allowing secret access
is_takeover_role(role){
    # Use sets for O(1) membership checks
    takeover_resources_set := {"secrets", "*"}
    takeover_verbs_set := {"get", "list", "watch", "*"}
    takeover_api_groups_set := {"", "*"}
    
    # Direct membership checks - more efficient than array comprehension
    some i
    rule := role.rules[i]
    some resource in rule.resources
    resource in takeover_resources_set
    some verb in rule.verbs
    verb in takeover_verbs_set
    some apiGroup in rule.apiGroups
    apiGroup in takeover_api_groups_set
}
