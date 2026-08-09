# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	is_bad_container(container)
	paths = [sprintf("spec.containers[%v].image", [format_int(i, 10)]), sprintf("spec.containers[%v].imagePullPolicy", [format_int(i, 10)])]
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
	wl := input[_]
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	paths = [sprintf("spec.template.spec.containers[%v].image", [format_int(i, 10)]), sprintf("spec.template.spec.containers[%v].imagePullPolicy", [format_int(i, 10)])]
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
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	paths = [sprintf("spec.jobTemplate.spec.template.spec.containers[%v].image", [format_int(i, 10)]), sprintf("spec.jobTemplate.spec.template.spec.containers[%v].imagePullPolicy", [format_int(i, 10)])]
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

# image tag is latest
is_bad_container(container) if {
	not_image_pull_policy(container)
	reg := ":[\\w][\\w.-]{0,127}(\/)?"
	version := regex.find_all_string_submatch_n(reg, container.image, -1)
	v := version[_]
	img := v[_]
	img == ":latest"
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

# Configured floating image tags are treated as latest-like.

is_bad_container(container) if {
    not_image_pull_policy(container)
    is_floating_image_tag(container.image)
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
