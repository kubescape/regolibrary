package armo_builtins
# Check for images from blacklisted repos
import data

untrusted_registries(z) = x {
	x := data.postureControlInputs.untrustedRegistries	
}

public_registries(z) = y{
	y := data.postureControlInputs.publicRegistries
}

untrustedImageRepo[msga] {
	pod := input[_]
	k := pod.kind
	k == "Pod"
	container := pod.spec.containers[_]
	image := container.image
    repo_prefix := untrusted_registries(image)[_]
	startswith(image, repo_prefix)
	containerName := container.name

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [image, containerName]),
		"packagename": "armo_builtins",
		"alertScore": 2,
         "alertObject": {
			"k8sApiObjects": [pod]
		}
     }
}

untrustedImageRepo[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[_]
	image := container.image
    repo_prefix := untrusted_registries(image)[_]
	startswith(image, repo_prefix)
	containerName := container.name

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [image, containerName]),
		"packagename": "armo_builtins",
		"alertScore": 2,
         "alertObject": {
			"k8sApiObjects": [wl]
		}
     }
}

untrustedImageRepo[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[_]
	image := container.image
    repo_prefix := untrusted_registries(image)[_]
	startswith(image, repo_prefix)
	containerName := container.name

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [image, containerName]),
		"packagename": "armo_builtins",
		"alertScore": 2,
         "alertObject": {
			"k8sApiObjects": [wl]
		}
     }
}

untrustedImageRepo[msga] {
    pod := input[_]
	k := pod.kind
	k == "Pod"
	container := pod.spec.containers[_]
	image := container.image
    repo_prefix := public_registries(image)[_]
	startswith(image, repo_prefix)
	containerName := container.name

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from public registry", [image, containerName]),
		"packagename": "armo_builtins",
		"alertScore": 1,
         "alertObject": {
			"k8sApiObjects": [pod]
		}
     }
}

untrustedImageRepo[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[_]
	image := container.image
    repo_prefix := public_registries(image)[_]
	startswith(image, repo_prefix)
	containerName := container.name

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from public registry", [image, containerName]),
		"packagename": "armo_builtins",
		"alertScore": 1,
         "alertObject": {
			"k8sApiObjects": [wl]
		}
     }
}

untrustedImageRepo[msga] {
    wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[_]
	image := container.image
    repo_prefix := public_registries(image)[_]
	startswith(image, repo_prefix)
	containerName := container.name

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from public registry", [image, containerName]),
		"packagename": "armo_builtins",
		"alertScore": 1,
         "alertObject": {
			"k8sApiObjects": [wl]
		}
     }
}