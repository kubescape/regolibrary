package armo_builtins

# Check for images from blocklisted repos

untrustedImageRepo[msga] {
	pod := input[_]
	k := pod.kind
	k == "Pod"
	container := pod.spec.containers[i]
	path := sprintf("spec.containers[%v].image", [format_int(i, 10)])
	image := container.image
    untrusted_or_public_registries(image)

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [image, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"fixPaths": [],
		"failedPaths": [path],
         "alertObject": {
			"k8sApiObjects": [pod]
		}
    }
}

untrustedImageRepo[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	path := sprintf("spec.template.spec.containers[%v].image", [format_int(i, 10)])
	image := container.image
    untrusted_or_public_registries(image)

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [image, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"fixPaths": [],
		"failedPaths": [path],
         "alertObject": {
			"k8sApiObjects": [wl]
		}
    }
}

untrustedImageRepo[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].image", [format_int(i, 10)])
	image := container.image
    untrusted_or_public_registries(image)

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [image, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"fixPaths": [],
		"failedPaths": [path],
        "alertObject": {
			"k8sApiObjects": [wl]
		}
    }
}

untrusted_or_public_registries(image){
	# see default-config-inputs.json for list values
	untrusted_registries := data.postureControlInputs.untrustedRegistries
	registry := untrusted_registries[_]
	regex.match(regexify(registry), docker_host_wrapper(image))
}

untrusted_or_public_registries(image){
	# see default-config-inputs.json for list values
	public_registries := data.postureControlInputs.publicRegistries
	registry := public_registries[_]
	regex.match(regexify(registry), docker_host_wrapper(image))
}


# docker_host_wrapper - wrap an image without a host with a docker hub host 'docker.io'.
# An image that doesn't contain '/' is assumed to not having a host and therefore associated with docker hub.
docker_host_wrapper(image) = result {
    not contains(image, "/")
    result := sprintf("docker.io/%s", [image])
} else := image



# regexify - returns a registry regex to be searched only for the image host.
regexify(registry) := result {
	endswith(registry, "/")
	result = sprintf("^%s.*$", [registry])
} else := sprintf("^%s\/.*$", [registry])
