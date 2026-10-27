# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Fails if pod has container with hostPort
deny contains msga if {
	start_of_path := "spec."
	paths_to_containers := {["spec", "containers"], ["spec", "initContainers"], ["spec", "ephemeralContainers"]}
	path_to_containers := paths_to_containers[_]
	pod := input[_]
	pod.kind == "Pod"
	containers := object.get(pod, path_to_containers, [])
	container := containers[i]
	path := is_host_port(container, i, start_of_path, path_to_containers[count(path_to_containers) - 1])
	msga := {
		"alertMessage": sprintf("Container: %v has Host-port", [container.name]),
		"packagename": "armo_builtins",
		"alertScore": 4,
		"deletePaths": path,
		"failedPaths": path,
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

# Fails if workload has container with hostPort
deny contains msga if {
	start_of_path := "spec.template.spec."
	paths_to_containers := {["spec", "template", "spec", "containers"], ["spec", "template", "spec", "initContainers"]}
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	path_to_containers := paths_to_containers[_]
	wl := input[_]
	spec_template_spec_patterns[wl.kind]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]
	path := is_host_port(container, i, start_of_path, path_to_containers[count(path_to_containers) - 1])
	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   has Host-port", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 4,
		"deletePaths": path,
		"failedPaths": path,
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if cronjob has container with hostPort
deny contains msga if {
	start_of_path := "spec.jobTemplate.spec.template.spec."
	paths_to_containers := {["spec", "jobTemplate", "spec", "template", "spec", "containers"], ["spec", "jobTemplate", "spec", "template", "spec", "initContainers"]}
	path_to_containers := paths_to_containers[_]
	wl := input[_]
	wl.kind == "CronJob"
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]
	path := is_host_port(container, i, start_of_path, path_to_containers[count(path_to_containers) - 1])
	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v   has Host-port", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 4,
		"deletePaths": path,
		"failedPaths": path,
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

is_host_port(container, i, start_of_path, container_type) := path if {
	path = [sprintf("%v%v[%v].ports[%v].hostPort", [start_of_path, container_type, format_int(i, 10), format_int(j, 10)]) | port = container.ports[j]; port.hostPort]
	count(path) > 0
}
