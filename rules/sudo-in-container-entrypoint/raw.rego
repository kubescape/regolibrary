package armo_builtins


deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]
	beggining_of_path := "spec."
    result := is_sudo_entrypoint(container, beggining_of_path, i)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  have sudo in entrypoint", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [],
		"failedPaths": result,
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
	beggining_of_path := "spec.template.spec."
    result := is_sudo_entrypoint(container, beggining_of_path, i)
	msga := {
		"alertMessage": sprintf("container: %v in %v: %v  have sudo in entrypoint", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [],
		"failedPaths": result,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

deny[msga] {
    wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	beggining_of_path := "spec.jobTemplate.spec.template.spec."
	result := is_sudo_entrypoint(container, beggining_of_path, i)
	msga := {
		"alertMessage": sprintf("container: %v in cronjob: %v  have sudo in entrypoint", [container.name, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [],
		"failedPaths": result,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

is_sudo_entrypoint(container, beggining_of_path, i) = path {
	path = [sprintf("%vcontainers[%v].command[%v]", [beggining_of_path, format_int(i, 10), format_int(k, 10)]) |  command = container.command[k];  contains(command, "sudo")]
	count(path) > 0
}
