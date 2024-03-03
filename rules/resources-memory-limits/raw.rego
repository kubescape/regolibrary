package armo_builtins

#  ================================== no memory limits ==================================
# Fails if pod does not have container with memory-limits
deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	not container.resources.limits.memory
	fixPaths := [{"path": sprintf("spec.containers[%v].resources.limits.memory", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v does not have memory-limit or request", [container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"failedPaths": [],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

# Fails if workload does not have container with memory-limits
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	not container.resources.limits.memory
	fixPaths := [{"path": sprintf("spec.template.spec.containers[%v].resources.limits.memory", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have memory-limit or request", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"failedPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if cronjob does not have container with memory-limits
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
	not container.resources.limits.memory
	fixPaths := [{"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%v].resources.limits.memory", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have memory-limit or request", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"failedPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}
