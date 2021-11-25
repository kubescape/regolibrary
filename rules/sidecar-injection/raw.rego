package armo_builtins

# =========== looks for containers with lifecycle.type "Sidecar" ===========
#pods
deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	container.lifecycle.type == "Sidecar"
	path := sprintf("spec.containers[%v].lifecycle.type", [format_int(i, 10)])
    msga := {
		"alertMessage": sprintf("The pod: %v has a sidecar: %v", [pod.metadata.name, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"failedPaths": [path],
         "alertObject": {
			"k8sApiObjects": [pod]
		}
     }
}

#handles majority of workload resources
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	container.lifecycle.type == "Sidecar"
	path := sprintf("spec.template.spec.containers[%v].lifecycle.type", [format_int(i, 10)])

    msga := {
		"alertMessage": sprintf("%v: %v has a sidecar: %v", [wl.kind, wl.metadata.name, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"failedPaths": [path],
         "alertObject": {
			"k8sApiObjects": [wl]
		}
     }
}

#handles cronjob
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	container.lifecycle.type == "Sidecar"
	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].lifecycle.type", [format_int(i, 10)])

    msga := {
		"alertMessage": sprintf("Cronjob: %v has a sidecar: %v", [wl.metadata.name, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"failedPaths": [path],
         "alertObject": {
			"k8sApiObjects": [wl]
		}
     }
}


# =========== looks for containers "sidecar" in name ===========
#pods
deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
    contains(lower(container.name), "sidecar")
	path := sprintf("spec.containers[%v].name", [format_int(i, 10)])

    msga := {
		"alertMessage": sprintf("The pod: %v has a sidecar: %v", [pod.metadata.name, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"failedPaths": [path],
         "alertObject": {
			"k8sApiObjects": [pod]
		}
     }
}

#handles majority of workload resources
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	contains(lower(container.name), "sidecar")
	path := sprintf("spec.template.spec.containers[%v].name", [format_int(i, 10)])

    msga := {
		"alertMessage": sprintf("%v: %v has a sidecar: %v", [wl.kind, wl.metadata.name, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"failedPaths": [path],
         "alertObject": {
			"k8sApiObjects": [wl]
		}
     }
}

#handles cronjob
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	contains(lower(container.name), "sidecar")
	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].name", [format_int(i, 10)])

    msga := {
		"alertMessage": sprintf("Cronjob: %v has a sidecar: %v", [wl.metadata.name, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"failedPaths": [path],
         "alertObject": {
			"k8sApiObjects": [wl]
		}
     }
}