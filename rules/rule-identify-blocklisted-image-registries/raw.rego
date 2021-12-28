package armo_builtins
import data
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
		"failedPaths": [path],
        "alertObject": {
			"k8sApiObjects": [wl]
		}
    }
}

untrusted_or_public_registries(image){
	# see default-config-inputs.json for list values
	untrusted_registries := data.postureControlInputs.untrustedRegistries
	repo_prefix := untrusted_registries[_]
	startswith(image, repo_prefix)
}

untrusted_or_public_registries(image){
	# see default-config-inputs.json for list values
	public_registries := data.postureControlInputs.publicRegistries
	repo_prefix := public_registries[_]
	startswith(image, repo_prefix)
}

untrusted_or_public_registries(image){
	# the lack of registry name defaults to docker hub
	not contains(image, "/")
}