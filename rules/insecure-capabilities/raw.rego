package armo_builtins
import data.cautils

deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.containers[i]
    start_of_path := "spec."
    result := is_dangerous_capabilities(container, start_of_path, i, "containers")
    msga := {
        "alertMessage": sprintf("container: %v in pod: %v has dangerous capabilities", [container.name, pod.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "deletePaths": result,
        "failedPaths": result,
        "fixPaths": [],
        "alertObject": {"k8sApiObjects": [pod]}
    }
}

deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.initContainers[i]
    start_of_path := "spec."
    result := is_dangerous_capabilities(container, start_of_path, i, "initContainers")
    msga := {
        "alertMessage": sprintf("initContainer: %v in pod: %v has dangerous capabilities", [container.name, pod.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "deletePaths": result,
        "failedPaths": result,
        "fixPaths": [],
        "alertObject": {"k8sApiObjects": [pod]}
    }
}

deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.ephemeralContainers[i]
    start_of_path := "spec."
    result := is_dangerous_capabilities(container, start_of_path, i, "ephemeralContainers")
    msga := {
        "alertMessage": sprintf("ephemeralContainer: %v in pod: %v has dangerous capabilities", [container.name, pod.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "deletePaths": result,
        "failedPaths": result,
        "fixPaths": [],
        "alertObject": {"k8sApiObjects": [pod]}
    }
}

deny[msga] {
    wl := input[_]
    workload_template_kinds[wl.kind]
    container := wl.spec.template.spec.containers[i]
    start_of_path := "spec.template.spec."
    result := is_dangerous_capabilities(container, start_of_path, i, "containers")
    msga := {
        "alertMessage": sprintf("container: %v in workload: %v has dangerous capabilities", [container.name, wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "deletePaths": result,
        "failedPaths": result,
        "fixPaths": [],
        "alertObject": {"k8sApiObjects": [wl]}
    }
}

deny[msga] {
    wl := input[_]
    workload_template_kinds[wl.kind]
    container := wl.spec.template.spec.initContainers[i]
    start_of_path := "spec.template.spec."
    result := is_dangerous_capabilities(container, start_of_path, i, "initContainers")
    msga := {
        "alertMessage": sprintf("initContainer: %v in workload: %v has dangerous capabilities", [container.name, wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "deletePaths": result,
        "failedPaths": result,
        "fixPaths": [],
        "alertObject": {"k8sApiObjects": [wl]}
    }
}

deny[msga] {
    wl := input[_]
    workload_template_kinds[wl.kind]
    container := wl.spec.template.spec.ephemeralContainers[i]
    start_of_path := "spec.template.spec."
    result := is_dangerous_capabilities(container, start_of_path, i, "ephemeralContainers")
    msga := {
        "alertMessage": sprintf("ephemeralContainer: %v in workload: %v has dangerous capabilities", [container.name, wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "deletePaths": result,
        "failedPaths": result,
        "fixPaths": [],
        "alertObject": {"k8sApiObjects": [wl]}
    }
}

deny[msga] {
    wl := input[_]
    wl.kind == "CronJob"
    container := wl.spec.jobTemplate.spec.template.spec.containers[i]
    start_of_path := "spec.jobTemplate.spec.template.spec."
    result := is_dangerous_capabilities(container, start_of_path, i, "containers")
    msga := {
        "alertMessage": sprintf("container: %v in cronjob: %v has dangerous capabilities", [container.name, wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "deletePaths": result,
        "failedPaths": result,
        "fixPaths": [],
        "alertObject": {"k8sApiObjects": [wl]}
    }
}

deny[msga] {
    wl := input[_]
    wl.kind == "CronJob"
    container := wl.spec.jobTemplate.spec.template.spec.initContainers[i]
    start_of_path := "spec.jobTemplate.spec.template.spec."
    result := is_dangerous_capabilities(container, start_of_path, i, "initContainers")
    msga := {
        "alertMessage": sprintf("initContainer: %v in cronjob: %v has dangerous capabilities", [container.name, wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "deletePaths": result,
        "failedPaths": result,
        "fixPaths": [],
        "alertObject": {"k8sApiObjects": [wl]}
    }
}

deny[msga] {
    wl := input[_]
    wl.kind == "CronJob"
    container := wl.spec.jobTemplate.spec.template.spec.ephemeralContainers[i]
    start_of_path := "spec.jobTemplate.spec.template.spec."
    result := is_dangerous_capabilities(container, start_of_path, i, "ephemeralContainers")
    msga := {
        "alertMessage": sprintf("ephemeralContainer: %v in cronjob: %v has dangerous capabilities", [container.name, wl.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "deletePaths": result,
        "failedPaths": result,
        "fixPaths": [],
        "alertObject": {"k8sApiObjects": [wl]}
    }
}

is_dangerous_capabilities(container, start_of_path, i, container_type) = path {
    insecureCapabilities := data.postureControlInputs.insecureCapabilities
    path = [sprintf("%v%v[%v].securityContext.capabilities.add[%v]", [start_of_path, container_type, format_int(i, 10), format_int(k, 10)]) | capability = container.securityContext.capabilities.add[k]; cautils.list_contains(insecureCapabilities, capability)]
    count(path) > 0
}