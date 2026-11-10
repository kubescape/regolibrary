# regal ignore:directory-package-mismatch  
package armo_builtins

import rego.v1

deny contains msga if {
	start_of_path := "spec."
	paths_to_containers := {["spec", "containers"], ["spec", "initContainers"], ["spec", "ephemeralContainers"]}
	path_to_containers := paths_to_containers[_]
	pod := input[_]
	pod.kind == "Pod"
	containers := object.get(pod, path_to_containers, [])
	container := containers[i]
	result := is_sudo_entrypoint(container, start_of_path, path_to_containers[count(path_to_containers) - 1], i)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  have sudo in entrypoint", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": result,
		"failedPaths": result,
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

deny contains msga if {
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	start_of_path := "spec.template.spec."
	paths_to_containers := {["spec", "template", "spec", "containers"], ["spec", "template", "spec", "initContainers"]}
	path_to_containers := paths_to_containers[_]
	wl := input[_]
	spec_template_spec_patterns[wl.kind]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]
	result := is_sudo_entrypoint(container, start_of_path, path_to_containers[count(path_to_containers) - 1], i)
	msga := {
		"alertMessage": sprintf("container: %v in %v: %v  have sudo in entrypoint", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": result,
		"failedPaths": result,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

deny contains msga if {
	start_of_path := "spec.jobTemplate.spec.template.spec."
	paths_to_containers := {["spec", "jobTemplate", "spec", "template", "spec", "containers"], ["spec", "jobTemplate", "spec", "template", "spec", "initContainers"]}
	path_to_containers := paths_to_containers[_]
	wl := input[_]
	wl.kind == "CronJob"
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]
	result := is_sudo_entrypoint(container, start_of_path, path_to_containers[count(path_to_containers) - 1], i)
	msga := {
		"alertMessage": sprintf("container: %v in cronjob: %v  have sudo in entrypoint", [container.name, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": result,
		"failedPaths": result,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

is_sudo_entrypoint(container, start_of_path, container_type, i) := path if {
	path = [sprintf("%v%v[%v].command[%v]", [start_of_path, container_type, format_int(i, 10), format_int(k, 10)]) | command = container.command[k]; contains(command, "sudo")]
	count(path) > 0
}
