package armo_builtins

import rego.v1

#  ================================== no memory requests ==================================
# Fails if pod does not have container with memory requests
deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	not container.resources.requests.memory
	fixPaths := [{"path": sprintf("spec.containers[%v].resources.requests.memory", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v does not have memory-limit or request", [container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"failedPaths": [],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

# Fails if workload does not have container with memory requests
deny contains msga if {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	not container.resources.requests.memory
	fixPaths := [{"path": sprintf("spec.template.spec.containers[%v].resources.requests.memory", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have memory-limit or request", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"failedPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if cronjob does not have container with memory requests
deny contains msga if {
	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
	not container.resources.requests.memory
	fixPaths := [{"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%v].resources.requests.memory", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have memory-limit or request", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"failedPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}
