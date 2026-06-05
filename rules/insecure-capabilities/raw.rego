package armo_builtins

import data.cautils

workload_template_kinds := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}

# --- Target enumeration (resource selector + spec scope + path prefix + container field + message labels)

targets[t] {
    pod := input[_]
    pod.kind == "Pod"
    t := {
        "obj": pod,
        "spec": pod.spec,
        "start_of_path": "spec.",
        "container_field": "containers",
        "container_label": "container",
        "target_label": "pod",
    }
}

targets[t] {
    pod := input[_]
    pod.kind == "Pod"
    t := {
        "obj": pod,
        "spec": pod.spec,
        "start_of_path": "spec.",
        "container_field": "initContainers",
        "container_label": "initContainer",
        "target_label": "pod",
    }
}

targets[t] {
    pod := input[_]
    pod.kind == "Pod"
    t := {
        "obj": pod,
        "spec": pod.spec,
        "start_of_path": "spec.",
        "container_field": "ephemeralContainers",
        "container_label": "ephemeralContainer",
        "target_label": "pod",
    }
}

targets[t] {
    wl := input[_]
    workload_template_kinds[wl.kind]
    t := {
        "obj": wl,
        "spec": wl.spec.template.spec,
        "start_of_path": "spec.template.spec.",
        "container_field": "containers",
        "container_label": "container",
        "target_label": "workload",
    }
}

targets[t] {
    wl := input[_]
    workload_template_kinds[wl.kind]
    t := {
        "obj": wl,
        "spec": wl.spec.template.spec,
        "start_of_path": "spec.template.spec.",
        "container_field": "initContainers",
        "container_label": "initContainer",
        "target_label": "workload",
    }
}

targets[t] {
    wl := input[_]
    workload_template_kinds[wl.kind]
    t := {
        "obj": wl,
        "spec": wl.spec.template.spec,
        "start_of_path": "spec.template.spec.",
        "container_field": "ephemeralContainers",
        "container_label": "ephemeralContainer",
        "target_label": "workload",
    }
}

targets[t] {
    cj := input[_]
    cj.kind == "CronJob"
    t := {
        "obj": cj,
        "spec": cj.spec.jobTemplate.spec.template.spec,
        "start_of_path": "spec.jobTemplate.spec.template.spec.",
        "container_field": "containers",
        "container_label": "container",
        "target_label": "cronjob",
    }
}

targets[t] {
    cj := input[_]
    cj.kind == "CronJob"
    t := {
        "obj": cj,
        "spec": cj.spec.jobTemplate.spec.template.spec,
        "start_of_path": "spec.jobTemplate.spec.template.spec.",
        "container_field": "initContainers",
        "container_label": "initContainer",
        "target_label": "cronjob",
    }
}

targets[t] {
    cj := input[_]
    cj.kind == "CronJob"
    t := {
        "obj": cj,
        "spec": cj.spec.jobTemplate.spec.template.spec,
        "start_of_path": "spec.jobTemplate.spec.template.spec.",
        "container_field": "ephemeralContainers",
        "container_label": "ephemeralContainer",
        "target_label": "cronjob",
    }
}

# --- Single consolidated deny

deny[msga] {
    t := targets[_]

    obj := t.obj
    spec := t.spec
    start_of_path := t.start_of_path
    container_field := t.container_field

    # If the field doesn't exist, object.get -> [] and nothing matches (safe).
    containers := object.get(spec, container_field, [])
    container := containers[i]

    result := is_dangerous_capabilities(container, start_of_path, i, container_field)

    msga := {
        "alertMessage": sprintf("%v: %v in %v: %v has dangerous capabilities", [
            t.container_label,
            container.name,
            obj.kind,
            obj.metadata.name,
        ]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "deletePaths": result,
        "failedPaths": result,
        "fixPaths": [],
        "alertObject": {"k8sApiObjects": [obj]},
    }
}

is_dangerous_capabilities(container, start_of_path, i, container_type) = path {
    insecureCapabilities := data.postureControlInputs.insecureCapabilities
    path = [sprintf("%v%v[%v].securityContext.capabilities.add[%v]", [
        start_of_path,
        container_type,
        format_int(i, 10),
        format_int(k, 10),
    ]) |
        capability = container.securityContext.capabilities.add[k]
        cautils.list_contains(insecureCapabilities, capability)
    ]
    count(path) > 0
}