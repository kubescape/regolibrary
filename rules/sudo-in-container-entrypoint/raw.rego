package armo_builtins


deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]
	begginingOfPath := "spec."
    result := isSudoEntrypoint(container, begginingOfPath, i)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  have sudo in entrypoint", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
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
	begginingOfPath := "spec.template.spec."
    result := isSudoEntrypoint(container, begginingOfPath, i)
	msga := {
		"alertMessage": sprintf("container: %v in %v: %v  have sudo in entrypoint", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

deny[msga] {
    wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	begginingOfPath := "spec.jobTemplate.spec.template.spec."
	result := isSudoEntrypoint(container, begginingOfPath, i)
	msga := {
		"alertMessage": sprintf("container: %v in cronjob: %v  have sudo in entrypoint", [container.name, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

isSudoEntrypoint(container, begginingOfPath, i) = path {
    command := container.command[k]
    contains(command, "sudo") 
	path = sprintf("%vcontainers[%v].command[%v]", [begginingOfPath, format_int(i, 10), format_int(k, 10)])
}