package armo_builtins

deny[msga] {

    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]

    not cosign.has_signature(container.image)

    failedPath := sprintf("spec.containers[%v].image", [format_int(i, 10)])

	msga := {
		"alertMessage": sprintf("image: %v is not signed", [ container.image]),
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": [failedPath],
		"failedPaths": [failedPath],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [pod]
		},
	}
}

deny[msga] {
    wl := input[_]
	wl_kinds := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	wl_kinds[wl.kind]
    container := wl.spec.template.spec.containers[i]

    not cosign.has_signature(container.image)

	failedPath := sprintf("spec.template.spec.containers[%v].image", [format_int(i, 10)])


    msga := {
		"alertMessage": sprintf("image: %v is not signed", [ container.image]),
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": [failedPath],
		"failedPaths": [failedPath],
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

	failedPath := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].image", [format_int(i, 10)])

    msga := {
		"alertMessage": sprintf("image: %v is not signed", [ container.image]),
		"alertScore": 7,
		"fixPaths": [],
		"reviewPaths": [failedPath],
		"failedPaths": [failedPath],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [wl]
		},
	}
}
