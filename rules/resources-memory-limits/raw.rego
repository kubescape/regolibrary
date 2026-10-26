# regal ignore:directory-package-mismatch 
package armo_builtins

import rego.v1

# Ephemeral containers are excluded because Kubernetes forbids their resources field.
#  ================================== no memory limits ==================================
# Fails if pod does not have container with memory-limits
deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	some container_type in {"containers", "initContainers"}
	container := pod.spec[container_type][i]
	not container.resources.limits.memory
	fixPaths := [{"path": sprintf("spec.%v[%v].resources.limits.memory", [container_type, format_int(i, 10)]), "value": "YOUR_VALUE"}]

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
deny contains msga if {
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	wl := input[_]
	spec_template_spec_patterns[wl.kind]
	some container_type in {"containers", "initContainers"}
	container := wl.spec.template.spec[container_type][i]
	not container.resources.limits.memory
	fixPaths := [{"path": sprintf("spec.template.spec.%v[%v].resources.limits.memory", [container_type, format_int(i, 10)]), "value": "YOUR_VALUE"}]

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
deny contains msga if {
	wl := input[_]
	wl.kind == "CronJob"
	some container_type in {"containers", "initContainers"}
	container = wl.spec.jobTemplate.spec.template.spec[container_type][i]
	not container.resources.limits.memory
	fixPaths := [{"path": sprintf("spec.jobTemplate.spec.template.spec.%v[%v].resources.limits.memory", [container_type, format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   does not have memory-limit or request", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"failedPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}
