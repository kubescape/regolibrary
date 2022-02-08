package armo_builtins
import data
# import data.kubernetes.api.client as client

untrustedImageRepo[msga] {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	image := container.image
	not imageInAllowedList(image)
	path := sprintf("spec.containers[%v].image", [format_int(i, 10)])
    not pod.spec["imagePullSecrets"]

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

untrustedImageRepo[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	image := container.image
    not imageInAllowedList(image)

    not wl.spec.template.spec["imagePullSecrets"]
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

untrustedImageRepo[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	image := container.image
    not imageInAllowedList(image)

    not wl.spec.jobTemplate.spec.template.spec["imagePullSecrets"]
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

imageInAllowedList(image){
	# see default-config-inputs.json for list values
	allowedlist := data.postureControlInputs.imageRepositoryAllowList
	registry := allowedlist[_]
	regex.match(registry, image)
}