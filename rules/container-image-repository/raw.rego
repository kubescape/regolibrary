package armo_builtins
import data
# import data.kubernetes.api.client as client

allowlist(z) = x {
	x := data.postureControlInputs.imageRepositoryAllowList
}

untrustedImageRepo[msga] {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[_]
	image := container.image
    registry := allowlist(image)[_]
	not contains(image, registry)

    not pod.spec["imagePullSecrets"]

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [image, container.name]),
		"alertScore": 2,
        "packagename": "armo_builtins",
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
    registry := allowlist(image)[_]
	not contains(image, registry)

    not wl.spec.template.spec["imagePullSecrets"]

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [image, container.name]),
		"alertScore": 2,
        "packagename": "armo_builtins",
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
    registry := allowlist(image)[_]
	not contains(image, registry)

    not wl.spec.jobTemplate.spec.template.spec["imagePullSecrets"]

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [image, container.name]),
		"alertScore": 2,
        "packagename": "armo_builtins",
			"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}