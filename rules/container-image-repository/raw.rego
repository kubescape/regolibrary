package armo_builtins

import future.keywords.if

untrusted_image_repo[msga] {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	image := container.image
	not image_in_allowed_list(image)
	path := sprintf("spec.containers[%v].image", [format_int(i, 10)])

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [image, container.name]),
		"alertScore": 2,
        "packagename": "armo_builtins",
		"reviewPaths": [path],
		"failedPaths": [path],
		"fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

untrusted_image_repo[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	image := container.image
    not image_in_allowed_list(image)

	path := sprintf("spec.template.spec.containers[%v].image", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [image, container.name]),
		"alertScore": 2,
        "packagename": "armo_builtins",
		"reviewPaths": [path],
		"failedPaths": [path],
		"fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

untrusted_image_repo[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	image := container.image
    not image_in_allowed_list(image)

	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].image", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [image, container.name]),
		"alertScore": 2,
        "packagename": "armo_builtins",
		"reviewPaths": [path],
		"failedPaths": [path],
		"fixPaths":[],
			"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# image_in_allowed_list - rule to check if an image complies with imageRepositoryAllowList.
image_in_allowed_list(image){

	# see default-config-inputs.json for list values
	allowedlist := data.postureControlInputs.imageRepositoryAllowList
	registry := allowedlist[_]

	regex.match(regexify(registry), docker_host_wrapper(image))
}


# docker_host_wrapper - wrap an image without a host with a docker hub host 'docker.io'.
# An image that doesn't contain '/' is assumed to not having a host and therefore associated with docker hub.
docker_host_wrapper(image) := result if {
	not contains(image, "/")
	result := sprintf("docker.io/%s", [image])
} else := image


# regexify - returns a registry regex to be searched only for the image host.
regexify(registry) := result {
	endswith(registry, "/")
	result = sprintf("^%s.*$", [registry])
} else := sprintf("^%s\/.*$", [registry])
