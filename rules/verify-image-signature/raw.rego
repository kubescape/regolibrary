package armo_builtins

deny[msga] {

    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]

    verified_keys := [trusted_key | trusted_key = data.postureControlInputs.trustedCosignPublicKeys[_]; cosign.verify(container.image, trusted_key)]
    count(verified_keys) == 0


	msga := {
		"alertMessage": sprintf("signature not verified for image: %v", [container.image]),
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": [container.image],
		"failedPaths": [container.image],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [pod]
		},
	}
}

deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]

	verified_keys := [trusted_key | trusted_key = data.postureControlInputs.trustedCosignPublicKeys[_]; cosign.verify(container.image, trusted_key)]
    count(verified_keys) == 0

    msga := {
		"alertMessage": sprintf("signature not verified for image: %v", [container.image]),
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": [container.image],
		"failedPaths": [container.image],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl]
		},
	}
}


deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]

    verified_keys := [trusted_key | trusted_key = data.postureControlInputs.trustedCosignPublicKeys[_]; cosign.verify(container.image, trusted_key)]
    count(verified_keys) == 0

    msga := {
		"alertMessage": sprintf("signature not verified for image: %v", [container.image]),
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": [container.image],
		"failedPaths": [container.image],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl]
		},
	}
}
