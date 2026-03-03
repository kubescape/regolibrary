package armo_builtins

# Fails if pod has container with mutable filesystem
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.containers[i]
    start_of_path := "spec."
    is_mutable_filesystem(container)
    fixPath = {"path": sprintf("%vcontainers[%d].securityContext.readOnlyRootFilesystem", [start_of_path, i]), "value": "true"}
    msga := {
        "alertMessage": sprintf("container: %v in pod: %v has mutable filesystem", [container.name, pod.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "failedPaths": [],
        "fixPaths": [fixPath],
        "alertObject": {"k8sApiObjects": [pod]}
    }
}

# Fails if pod has initContainer with mutable filesystem
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.initContainers[i]
    start_of_path := "spec."
    is_mutable_filesystem(container)
    fixPath = {"path": sprintf("%vinitContainers[%d].securityContext.readOnlyRootFilesystem", [start_of_path, i]), "value": "true"}
    msga := {
        "alertMessage": sprintf("initContainer: %v in pod: %v has mutable filesystem", [container.name, pod.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "failedPaths": [],
        "fixPaths": [fixPath],
        "alertObject": {"k8sApiObjects": [pod]}
    }
}

# Fails if pod has ephemeralContainer with mutable filesystem
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.ephemeralContainers[i]
    start_of_path := "spec."
    is_mutable_filesystem(container)
    fixPath = {"path": sprintf("%vephemeralContainers[%d].securityContext.readOnlyRootFilesystem", [start_of_path, i]), "value": "true"}
    msga := {
        "alertMessage": sprintf("ephemeralContainer: %v in pod: %v has mutable filesystem", [container.name, pod.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "failedPaths": [],
        "fixPaths": [fixPath],
        "alertObject": {"k8sApiObjects": [pod]}
    }
}

# Fails if workload has container with mutable filesystem
deny[msga] {
    wl := input[_]
    spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
    spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]
    start_of_path := "spec.template.spec."
    is_mutable_filesystem(container)
    fixPath = {"path": sprintf("%vcontainers[%d].securityContext.readOnlyRootFilesystem", [start_of_path, i]), "value": "true"}
    msga := {
        "alertMessage": sprintf("container: %v in %v: %v has mutable filesystem", [container.name, wl.kind, wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "failedPaths": [],
        "fixPaths": [fixPath],
        "alertObject": {"k8sApiObjects": [wl]}
    }
}

# Fails if workload has initContainer with mutable filesystem
deny[msga] {
    wl := input[_]
    spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
    spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.initContainers[i]
    start_of_path := "spec.template.spec."
    is_mutable_filesystem(container)
    fixPath = {"path": sprintf("%vinitContainers[%d].securityContext.readOnlyRootFilesystem", [start_of_path, i]), "value": "true"}
    msga := {
        "alertMessage": sprintf("initContainer: %v in %v: %v has mutable filesystem", [container.name, wl.kind, wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "failedPaths": [],
        "fixPaths": [fixPath],
        "alertObject": {"k8sApiObjects": [wl]}
    }
}

# Fails if workload has ephemeralContainer with mutable filesystem
deny[msga] {
    wl := input[_]
    spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
    spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.ephemeralContainers[i]
    start_of_path := "spec.template.spec."
    is_mutable_filesystem(container)
    fixPath = {"path": sprintf("%vephemeralContainers[%d].securityContext.readOnlyRootFilesystem", [start_of_path, i]), "value": "true"}
    msga := {
        "alertMessage": sprintf("ephemeralContainer: %v in %v: %v has mutable filesystem", [container.name, wl.kind, wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "failedPaths": [],
        "fixPaths": [fixPath],
        "alertObject": {"k8sApiObjects": [wl]}
    }
}

# Fails if cronjob has container with mutable filesystem
deny[msga] {
    wl := input[_]
    wl.kind == "CronJob"
    container = wl.spec.jobTemplate.spec.template.spec.containers[i]
    start_of_path := "spec.jobTemplate.spec.template.spec."
    is_mutable_filesystem(container)
    fixPath = {"path": sprintf("%vcontainers[%d].securityContext.readOnlyRootFilesystem", [start_of_path, i]), "value": "true"}
    msga := {
        "alertMessage": sprintf("container: %v in %v: %v has mutable filesystem", [container.name, wl.kind, wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "failedPaths": [],
        "fixPaths": [fixPath],
        "alertObject": {"k8sApiObjects": [wl]}
    }
}

# Fails if cronjob has initContainer with mutable filesystem
deny[msga] {
    wl := input[_]
    wl.kind == "CronJob"
    container = wl.spec.jobTemplate.spec.template.spec.initContainers[i]
    start_of_path := "spec.jobTemplate.spec.template.spec."
    is_mutable_filesystem(container)
    fixPath = {"path": sprintf("%vinitContainers[%d].securityContext.readOnlyRootFilesystem", [start_of_path, i]), "value": "true"}
    msga := {
        "alertMessage": sprintf("initContainer: %v in %v: %v has mutable filesystem", [container.name, wl.kind, wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "failedPaths": [],
        "fixPaths": [fixPath],
        "alertObject": {"k8sApiObjects": [wl]}
    }
}

# Fails if cronjob has ephemeralContainer with mutable filesystem
deny[msga] {
    wl := input[_]
    wl.kind == "CronJob"
    container = wl.spec.jobTemplate.spec.template.spec.ephemeralContainers[i]
    start_of_path := "spec.jobTemplate.spec.template.spec."
    is_mutable_filesystem(container)
    fixPath = {"path": sprintf("%vephemeralContainers[%d].securityContext.readOnlyRootFilesystem", [start_of_path, i]), "value": "true"}
    msga := {
        "alertMessage": sprintf("ephemeralContainer: %v in %v: %v has mutable filesystem", [container.name, wl.kind, wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "failedPaths": [],
        "fixPaths": [fixPath],
        "alertObject": {"k8sApiObjects": [wl]}
    }
}

is_mutable_filesystem(container) {
    container.securityContext.readOnlyRootFilesystem == false
}

is_mutable_filesystem(container) {
    not container.securityContext.readOnlyRootFilesystem == false
    not container.securityContext.readOnlyRootFilesystem == true
}