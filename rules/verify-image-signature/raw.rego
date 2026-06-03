package armo_builtins

import rego.v1

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]

	verified_keys := [trusted_key | trusted_key = data.postureControlInputs.trustedCosignPublicKeys[_]; cosign.verify(container.image, trusted_key)]
	count(verified_keys) == 0

	path := sprintf("spec.containers[%v].image", [i])

	msga := {
		"alertMessage": sprintf("signature not verified for image: %v", [container.image]),
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": [path],
		"failedPaths": [path],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

deny contains msga if {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]

	verified_keys := [trusted_key | trusted_key = data.postureControlInputs.trustedCosignPublicKeys[_]; cosign.verify(container.image, trusted_key)]
	count(verified_keys) == 0

	path := sprintf("spec.template.spec.containers[%v].image", [i])

	msga := {
		"alertMessage": sprintf("signature not verified for image: %v", [container.image]),
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": [path],
		"failedPaths": [path],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

deny contains msga if {
	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]

	verified_keys := [trusted_key | trusted_key = data.postureControlInputs.trustedCosignPublicKeys[_]; cosign.verify(container.image, trusted_key)]
	count(verified_keys) == 0

	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].image", [i])

	msga := {
		"alertMessage": sprintf("signature not verified for image: %v", [container.image]),
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": [path],
		"failedPaths": [path],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [wl]},
	}
}
