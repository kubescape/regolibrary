package armo_builtins
import data

deny[msga] {

    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]

    not cosign.has_signature(container.image)

	msga := {
		"alertMessage": sprintf("image: %v is not signed", [ container.image]),
		"alertScore": 7,
		"fixPaths": [],
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

    not cosign.has_signature(container.image)

    msga := {
		"alertMessage": sprintf("image: %v is not signed", [ container.image]),
		"alertScore": 7,
		"fixPaths": [],
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
	
    not cosign.has_signature(container.image)

    msga := {
		"alertMessage": sprintf("image: %v is not signed", [ container.image]),
		"alertScore": 7,
		"fixPaths": [],
		"failedPaths": [container.image],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl]
		},
	}
}
