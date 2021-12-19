package armo_builtins
import data
# Check for images from blacklisted repos

untrusted_registries(z) = x {
	# see default-config-inputs.json for list values
	x := data.postureControlInputs.untrustedRegistries
}

public_registries(z) = y{
	# see default-config-inputs.json for list values
	y := data.postureControlInputs.publicRegistries
}

untrustedImageRepo[msga] {
	pod := input[_]
	k := pod.kind
	k == "Pod"
	container := pod.spec.containers[i]
	path := sprintf("spec.containers[%v].image", [format_int(i, 10)])
	image := container.image
    repo_prefix := untrusted_registries(image)[_]
	startswith(image, repo_prefix)
	containerName := container.name

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [image, containerName]),
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
    repo_prefix := untrusted_registries(image)[_]
	startswith(image, repo_prefix)
	containerName := container.name

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [image, containerName]),
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
    repo_prefix := untrusted_registries(image)[_]
	startswith(image, repo_prefix)
	containerName := container.name

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [image, containerName]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"failedPaths": [path],
         "alertObject": {
			"k8sApiObjects": [wl]
		}
     }
}

untrustedImageRepo[msga] {
    pod := input[_]
	k := pod.kind
	k == "Pod"
	container := pod.spec.containers[i]
	path := sprintf("spec.containers[%v].image", [format_int(i, 10)])
	image := container.image
    repo_prefix := public_registries(image)[_]
	startswith(image, repo_prefix)
	containerName := container.name

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from public registry", [image, containerName]),
		"packagename": "armo_builtins",
		"alertScore": 1,
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
    repo_prefix := public_registries(image)[_]
	startswith(image, repo_prefix)
	containerName := container.name

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from public registry", [image, containerName]),
		"packagename": "armo_builtins",
		"alertScore": 1,
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
    repo_prefix := public_registries(image)[_]
	startswith(image, repo_prefix)
	containerName := container.name

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from public registry", [image, containerName]),
		"packagename": "armo_builtins",
		"alertScore": 1,
		"failedPaths": [path],
         "alertObject": {
			"k8sApiObjects": [wl]
		}
     }
}