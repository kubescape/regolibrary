package armo_builtins

workload_template_kinds := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}

deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.containers[i]
    start_of_path := "spec"
    run_as_user_fixpath := evaluate_workload_run_as_user(container, pod, start_of_path)
    run_as_group_fixpath := evaluate_workload_run_as_group(container, pod, start_of_path)
    all_fixpaths := array.concat(run_as_user_fixpath, run_as_group_fixpath)
    count(all_fixpaths) > 0
    fixPaths := get_fixed_paths(all_fixpaths, i)
    msga := {
        "alertMessage": sprintf("container: %v in pod: %v may run as root", [container.name, pod.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "reviewPaths": [],
        "failedPaths": [],
        "fixPaths": fixPaths,
        "alertObject": {"k8sApiObjects": [pod]}
    }
}

deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.initContainers[i]
    start_of_path := "spec"
    run_as_user_fixpath := evaluate_workload_run_as_user(container, pod, start_of_path)
    run_as_group_fixpath := evaluate_workload_run_as_group(container, pod, start_of_path)
    all_fixpaths := array.concat(run_as_user_fixpath, run_as_group_fixpath)
    count(all_fixpaths) > 0
    fixPaths := get_fixed_paths_init(all_fixpaths, i)
    msga := {
        "alertMessage": sprintf("initContainer: %v in pod: %v may run as root", [container.name, pod.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "reviewPaths": [],
        "failedPaths": [],
        "fixPaths": fixPaths,
        "alertObject": {"k8sApiObjects": [pod]}
    }
}

deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.ephemeralContainers[i]
    start_of_path := "spec"
    run_as_user_fixpath := evaluate_workload_run_as_user(container, pod, start_of_path)
    run_as_group_fixpath := evaluate_workload_run_as_group(container, pod, start_of_path)
    all_fixpaths := array.concat(run_as_user_fixpath, run_as_group_fixpath)
    count(all_fixpaths) > 0
    fixPaths := get_fixed_paths_ephemeral(all_fixpaths, i)
    msga := {
        "alertMessage": sprintf("ephemeralContainer: %v in pod: %v may run as root", [container.name, pod.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "reviewPaths": [],
        "failedPaths": [],
        "fixPaths": fixPaths,
        "alertObject": {"k8sApiObjects": [pod]}
    }
}

deny[msga] {
    wl := input[_]
    workload_template_kinds[wl.kind]
    container := wl.spec.template.spec.containers[i]
    start_of_path := "spec.template.spec"
    run_as_user_fixpath := evaluate_workload_run_as_user(container, wl.spec.template, start_of_path)
    run_as_group_fixpath := evaluate_workload_run_as_group(container, wl.spec.template, start_of_path)
    all_fixpaths := array.concat(run_as_user_fixpath, run_as_group_fixpath)
    count(all_fixpaths) > 0
    fixPaths := get_fixed_paths(all_fixpaths, i)
    msga := {
        "alertMessage": sprintf("container: %v in %v: %v may run as root", [container.name, wl.kind, wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "reviewPaths": [],
        "failedPaths": [],
        "fixPaths": fixPaths,
        "alertObject": {"k8sApiObjects": [wl]}
    }
}

deny[msga] {
    wl := input[_]
    workload_template_kinds[wl.kind]
    container := wl.spec.template.spec.initContainers[i]
    start_of_path := "spec.template.spec"
    run_as_user_fixpath := evaluate_workload_run_as_user(container, wl.spec.template, start_of_path)
    run_as_group_fixpath := evaluate_workload_run_as_group(container, wl.spec.template, start_of_path)
    all_fixpaths := array.concat(run_as_user_fixpath, run_as_group_fixpath)
    count(all_fixpaths) > 0
    fixPaths := get_fixed_paths_init(all_fixpaths, i)
    msga := {
        "alertMessage": sprintf("initContainer: %v in %v: %v may run as root", [container.name, wl.kind, wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "reviewPaths": [],
        "failedPaths": [],
        "fixPaths": fixPaths,
        "alertObject": {"k8sApiObjects": [wl]}
    }
}

deny[msga] {
    wl := input[_]
    workload_template_kinds[wl.kind]
    container := wl.spec.template.spec.ephemeralContainers[i]
    start_of_path := "spec.template.spec"
    run_as_user_fixpath := evaluate_workload_run_as_user(container, wl.spec.template, start_of_path)
    run_as_group_fixpath := evaluate_workload_run_as_group(container, wl.spec.template, start_of_path)
    all_fixpaths := array.concat(run_as_user_fixpath, run_as_group_fixpath)
    count(all_fixpaths) > 0
    fixPaths := get_fixed_paths_ephemeral(all_fixpaths, i)
    msga := {
        "alertMessage": sprintf("ephemeralContainer: %v in %v: %v may run as root", [container.name, wl.kind, wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "reviewPaths": [],
        "failedPaths": [],
        "fixPaths": fixPaths,
        "alertObject": {"k8sApiObjects": [wl]}
    }
}

deny[msga] {
    wl := input[_]
    wl.kind == "CronJob"
    container = wl.spec.jobTemplate.spec.template.spec.containers[i]
    start_of_path := "spec.jobTemplate.spec.template.spec"
    run_as_user_fixpath := evaluate_workload_run_as_user(container, wl.spec.jobTemplate.spec.template, start_of_path)
    run_as_group_fixpath := evaluate_workload_run_as_group(container, wl.spec.jobTemplate.spec.template, start_of_path)
    all_fixpaths := array.concat(run_as_user_fixpath, run_as_group_fixpath)
    count(all_fixpaths) > 0
    fixPaths := get_fixed_paths(all_fixpaths, i)
    msga := {
        "alertMessage": sprintf("container: %v in %v: %v may run as root", [container.name, wl.kind, wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "reviewPaths": [],
        "failedPaths": [],
        "fixPaths": fixPaths,
        "alertObject": {"k8sApiObjects": [wl]}
    }
}

deny[msga] {
    wl := input[_]
    wl.kind == "CronJob"
    container = wl.spec.jobTemplate.spec.template.spec.initContainers[i]
    start_of_path := "spec.jobTemplate.spec.template.spec"
    run_as_user_fixpath := evaluate_workload_run_as_user(container, wl.spec.jobTemplate.spec.template, start_of_path)
    run_as_group_fixpath := evaluate_workload_run_as_group(container, wl.spec.jobTemplate.spec.template, start_of_path)
    all_fixpaths := array.concat(run_as_user_fixpath, run_as_group_fixpath)
    count(all_fixpaths) > 0
    fixPaths := get_fixed_paths_init(all_fixpaths, i)
    msga := {
        "alertMessage": sprintf("initContainer: %v in %v: %v may run as root", [container.name, wl.kind, wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "reviewPaths": [],
        "failedPaths": [],
        "fixPaths": fixPaths,
        "alertObject": {"k8sApiObjects": [wl]}
    }
}

deny[msga] {
    wl := input[_]
    wl.kind == "CronJob"
    container = wl.spec.jobTemplate.spec.template.spec.ephemeralContainers[i]
    start_of_path := "spec.jobTemplate.spec.template.spec"
    run_as_user_fixpath := evaluate_workload_run_as_user(container, wl.spec.jobTemplate.spec.template, start_of_path)
    run_as_group_fixpath := evaluate_workload_run_as_group(container, wl.spec.jobTemplate.spec.template, start_of_path)
    all_fixpaths := array.concat(run_as_user_fixpath, run_as_group_fixpath)
    count(all_fixpaths) > 0
    fixPaths := get_fixed_paths_ephemeral(all_fixpaths, i)
    msga := {
        "alertMessage": sprintf("ephemeralContainer: %v in %v: %v may run as root", [container.name, wl.kind, wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "reviewPaths": [],
        "failedPaths": [],
        "fixPaths": fixPaths,
        "alertObject": {"k8sApiObjects": [wl]}
    }
}

rewrite_fixpaths(all_fixpaths, i, container_key) = [
    {
        "path": replace(
            replace(fp.path, "container_ndx", format_int(i, 10)),
            "containers[",
            sprintf("%v[", [container_key])
        ),
        "value": fp.value
    } |
    fp := all_fixpaths[_]
]

get_fixed_paths(all_fixpaths, i) = rewrite_fixpaths(all_fixpaths, i, "containers")

get_fixed_paths_init(all_fixpaths, i) = rewrite_fixpaths(all_fixpaths, i, "initContainers")

get_fixed_paths_ephemeral(all_fixpaths, i) = rewrite_fixpaths(all_fixpaths, i, "ephemeralContainers")

evaluate_workload_run_as_user(container, pod, start_of_path) = fixPath {
    runAsNonRootValue := get_run_as_non_root_value(container, pod, start_of_path)
    runAsNonRootValue.value == false
    runAsUserValue := get_run_as_user_value(container, pod, start_of_path)
    runAsUserValue.value == 0
    alertInfo := choose_first_if_defined(runAsUserValue, runAsNonRootValue)
    fixPath := alertInfo.fixPath
} else = []

evaluate_workload_run_as_group(container, pod, start_of_path) = fixPath {
    runAsGroupValue := get_run_as_group_value(container, pod, start_of_path)
    runAsGroupValue.value == 0
    fixPath := runAsGroupValue.fixPath
} else = []

get_run_as_non_root_value(container, pod, start_of_path) = runAsNonRoot {
    runAsNonRoot := {"value": container.securityContext.runAsNonRoot, "fixPath": [{"path": sprintf("%v.containers[container_ndx].securityContext.runAsNonRoot", [start_of_path]), "value": "true"}], "defined": true}
} else = runAsNonRoot {
    runAsNonRoot := {"value": pod.spec.securityContext.runAsNonRoot, "fixPath": [{"path": sprintf("%v.containers[container_ndx].securityContext.runAsNonRoot", [start_of_path]), "value": "true"}], "defined": true}
} else = {"value": false, "fixPath": [{"path": sprintf("%v.containers[container_ndx].securityContext.runAsNonRoot", [start_of_path]), "value": "true"}], "defined": false}

get_run_as_user_value(container, pod, start_of_path) = runAsUser {
    path := sprintf("%v.containers[container_ndx].securityContext.runAsUser", [start_of_path])
    runAsUser := {"value": container.securityContext.runAsUser, "fixPath": [{"path": path, "value": "1000"}], "defined": true}
} else = runAsUser {
    path := sprintf("%v.securityContext.runAsUser", [start_of_path])
    runAsUser := {"value": pod.spec.securityContext.runAsUser, "fixPath": [{"path": path, "value": "1000"}], "defined": true}
} else = {"value": 0, "fixPath": [{"path": sprintf("%v.containers[container_ndx].securityContext.runAsNonRoot", [start_of_path]), "value": "true"}], "defined": false}

get_run_as_group_value(container, pod, start_of_path) = runAsGroup {
    path := sprintf("%v.containers[container_ndx].securityContext.runAsGroup", [start_of_path])
    runAsGroup := {"value": container.securityContext.runAsGroup, "fixPath": [{"path": path, "value": "1000"}], "defined": true}
} else = runAsGroup {
    path := sprintf("%v.securityContext.runAsGroup", [start_of_path])
    runAsGroup := {"value": pod.spec.securityContext.runAsGroup, "fixPath": [{"path": path, "value": "1000"}], "defined": true}
} else = {"value": 0, "fixPath": [{"path": sprintf("%v.containers[container_ndx].securityContext.runAsGroup", [start_of_path]), "value": "1000"}], "defined": false}

choose_first_if_defined(l1, l2) = c {
    l1.defined
    c := l1
} else = l2