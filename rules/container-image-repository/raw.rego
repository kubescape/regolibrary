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
	image1 := docker_host_wrapper(image)
	
	# see default-config-inputs.json for list values
	allowedlist := data.postureControlInputs.imageRepositoryAllowList
	registry := allowedlist[_]
	regex.match(registry, image1)
}


# docker_host_wrapper - wrap an image without a host with a docker hub host 'docker.io'. 
# An image that doesn't contain '/' is assumed to not having a host and therefore associated with docker hub.
docker_host_wrapper(image) := result if {
	not contains(image, "/")
	result := concat("", ["docker.io", image])#, [image])
} else := image