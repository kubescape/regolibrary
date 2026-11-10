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
	is_bad_container(container)
	paths = container_paths("spec.", path_to_containers, i)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  has 'latest' tag on image but imagePullPolicy is not set to 'Always'", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"reviewPaths": paths,
		"failedPaths": paths,
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

deny contains msga if {
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	paths_to_containers := {["spec", "template", "spec", "containers"], ["spec", "template", "spec", "initContainers"]}
	path_to_containers := paths_to_containers[_]
	wl := input[_]
	spec_template_spec_patterns[wl.kind]
	containers := object.get(wl, path_to_containers, [])
	container := containers[i]
	paths = container_paths("spec.template.spec.", path_to_containers, i)
	is_bad_container(container)
	msga := {
		"alertMessage": sprintf("container: %v in %v: %v  has 'latest' tag on image but imagePullPolicy is not set to 'Always'", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"reviewPaths": paths,
		"failedPaths": paths,
		"fixPaths": [],
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
	paths = container_paths("spec.jobTemplate.spec.template.spec.", path_to_containers, i)
	is_bad_container(container)
	msga := {
		"alertMessage": sprintf("container: %v in cronjob: %v  has 'latest' tag on image but imagePullPolicy is not set to 'Always'", [container.name, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"reviewPaths": paths,
		"failedPaths": paths,
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# container_paths - image and imagePullPolicy paths of container i in the given container array
container_paths(start_of_path, path_to_containers, i) := [
	sprintf("%v%v[%v].image", [start_of_path, container_type, format_int(i, 10)]),
	sprintf("%v%v[%v].imagePullPolicy", [start_of_path, container_type, format_int(i, 10)]),
] if {
	container_type := path_to_containers[count(path_to_containers) - 1]
}

# image tag is latest
is_bad_container(container) if {
	not_image_pull_policy(container)
	reg := ":[\\w][\\w.-]{0,127}(\/)?"
	version := regex.find_all_string_submatch_n(reg, container.image, -1)
	v := version[_]
	img := v[_]
	img == ":latest"
}

# Configured floating image tags are treated as latest-like.

is_bad_container(container) if {
    not_image_pull_policy(container)
    is_floating_image_tag(container.image)
}

# No image tag or digest (== latest)
is_bad_container(container) if {
	not is_tag_image(container.image)
	not_image_pull_policy(container)
}

not_image_pull_policy(container) if {
	container.imagePullPolicy == "Never"
}

not_image_pull_policy(container) if {
	container.imagePullPolicy == "IfNotPresent"
}

is_tag_image(image) if {
	reg := ":[\\w][\\w.-]{0,127}(\/)?"
	version := regex.find_all_string_submatch_n(reg, image, -1)
	v := version[_]
	img := v[_]
	not endswith(img, "/")
}

is_floating_image_tag(image) if {
    not contains(image, "@")
    parts := split(image, "/")
    last := parts[count(parts) - 1]
    tag_parts := split(last, ":")
    count(tag_parts) == 2
    tag := tag_parts[1]
    tag in data.postureControlInputs.floatingImageTags
}
