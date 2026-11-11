# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msga if {
	paths_to_containers := {["spec", "containers"], ["spec", "initContainers"], ["spec", "ephemeralContainers"]}
	path_to_containers := paths_to_containers[_]
	pod := input[_]
	pod.kind == "Pod"
	containers := object.get(pod, path_to_containers, [])
	container := containers[i]

	not cosign.has_signature(container.image)

	failedPath := image_path("spec.", path_to_containers, i)

	msga := {
		"alertMessage": sprintf("image: %v is not signed", [container.image]),
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": [failedPath],
		"failedPaths": [failedPath],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

deny contains msga if {
	wl_kinds := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	paths_to_containers := {["spec", "template", "spec", "containers"], ["spec", "template", "spec", "initContainers"]}
	path_to_containers := paths_to_containers[_]
	wl := input[_]
	wl_kinds[wl.kind]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]

	not cosign.has_signature(container.image)

	failedPath := image_path("spec.template.spec.", path_to_containers, i)

	msga := {
		"alertMessage": sprintf("image: %v is not signed", [container.image]),
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": [failedPath],
		"failedPaths": [failedPath],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

deny contains msga if {
	paths_to_containers := {["spec", "jobTemplate", "spec", "template", "spec", "containers"], ["spec", "jobTemplate", "spec", "template", "spec", "initContainers"]}
	path_to_containers := paths_to_containers[_]
	wl := input[_]
	wl.kind == "CronJob"
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]

	not cosign.has_signature(container.image)

	failedPath := image_path("spec.jobTemplate.spec.template.spec.", path_to_containers, i)

	msga := {
		"alertMessage": sprintf("image: %v is not signed", [container.image]),
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": [failedPath],
		"failedPaths": [failedPath],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# image_path - path to the image of container i in the given container array
image_path(start_of_path, path_to_containers, i) := sprintf("%v%v[%v].image", [start_of_path, container_type, format_int(i, 10)]) if {
	container_type := path_to_containers[count(path_to_containers) - 1]
}
