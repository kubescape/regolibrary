package armo_builtins


deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.containers[i]
    isLatestImageTag(container)
	path := sprintf("spec.containers[%v].image", [format_int(i, 10)])
    msga := {
		"alertMessage": sprintf("Container: %v in pod: %v has latest image tag.", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]
	path := sprintf("spec.template.spec.containers[%v].image", [format_int(i, 10)])
    isLatestImageTag(container)
	msga := {
		"alertMessage": sprintf("Container: %v in %v: %v  has latest image tag.", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


deny[msga] {
  	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].image", [format_int(i, 10)])
    isLatestImageTag(container)
    msga := {
		"alertMessage": sprintf("Container: %v in %v: %v has latest image tag.", [ container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


isLatestImageTag(container) {
    endswith(container.image, ":latest")
}