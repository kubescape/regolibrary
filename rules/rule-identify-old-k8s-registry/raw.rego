# regal ignore:directory-package-mismatch  
package armo_builtins

import rego.v1

deprecatedK8sRepo contains msga if {
	paths_to_containers := {["spec", "containers"], ["spec", "initContainers"], ["spec", "ephemeralContainers"]}
	pod := input[_]
	pod.metadata.namespace == "kube-system"
	k := pod.kind
	k == "Pod"
	path_to_containers := paths_to_containers[_]
	containers := object.get(pod, path_to_containers, [])
	container := containers[i]
	path := sprintf("%s[%v].image", [concat(".", path_to_containers), format_int(i, 10)])
	image := container.image
	deprecated_registry(image)

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from the deprecated k8s.gcr.io", [image, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"fixPaths": [],
		"reviewPaths": [path],
		"failedPaths": [path],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

deprecatedK8sRepo contains msga if {
	paths_to_containers := {["spec", "template", "spec", "containers"], ["spec", "template", "spec", "initContainers"]}
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	wl := input[_]
	wl.metadata.namespace == "kube-system"
	spec_template_spec_patterns[wl.kind]
	path_to_containers := paths_to_containers[_]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]
	path := sprintf("%s[%v].image", [concat(".", path_to_containers), format_int(i, 10)])
	image := container.image
	deprecated_registry(image)

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from the deprecated k8s.gcr.io", [image, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"fixPaths": [],
		"reviewPaths": [path],
		"failedPaths": [path],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

deprecatedK8sRepo contains msga if {
	paths_to_containers := {["spec", "jobTemplate", "spec", "template", "spec", "containers"], ["spec", "jobTemplate", "spec", "template", "spec", "initContainers"]}
	wl := input[_]
	wl.metadata.namespace == "kube-system"
	wl.kind == "CronJob"
	path_to_containers := paths_to_containers[_]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]
	path := sprintf("%s[%v].image", [concat(".", path_to_containers), format_int(i, 10)])
	image := container.image
	deprecated_registry(image)

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from the deprecated k8s.gcr.io", [image, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"fixPaths": [],
		"reviewPaths": [path],
		"failedPaths": [path],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

deprecated_registry(image) if {
	startswith(image, "k8s.gcr.io/")
}
