package armo_builtins
import data
import future.keywords.if
# import data.kubernetes.api.client as client

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
		"failedPaths": [path],
		"fixPaths":[],
			"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# image_in_allowed_list - rule to check if an image complies with imageRepositoryAllowList.
image_in_allowed_list(image){

	# extract host from image
	image_host = extract_image_host(docker_host_wrapper(image))

	# see default-config-inputs.json for list values
	allowedlist := data.postureControlInputs.imageRepositoryAllowList
	registry := allowedlist[_]

	#  add "$" to registry regex and match to the image host
	regex.match(append_dollar_to_registry_regex(registry), image_host)
}


# docker_host_wrapper - wrap an image without a host with a docker hub host 'docker.io'. 
# An image that doesn't contain '/' is assumed to not having a host and therefore associated with docker hub.
docker_host_wrapper(image) := result if {
	not contains(image, "/")
	result := concat("/", ["docker.io", image])#, [image])
} else := image


# append_dollar_to_registry_regex - returns a registry with appended regex char "$" at the end.
# rational - registry is expected to be searched only for the image host name. if the registry doesn't end with any regex definition, 
# need to add "$" in order to make sure registry is not searched anywhere in the host.
# if registry ends with "/" - adding "$". otherwise, adding "\/$". 
regexify(registry) := result {
	endswith(registry, "/")
	result = sprintf("^%s.*$", [registry])
} else := sprintf("^%s\/.*$", [registry])


# extract_image_host - extracting the host from the image.  
extract_image_host(image) := result if {
	not endswith("/", image)
    splitted := split(image, "/")
    result = replace(image, splitted[count(splitted)-1], "") 
} else := image


