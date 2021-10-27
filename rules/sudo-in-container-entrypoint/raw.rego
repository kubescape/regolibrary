package armo_builtins


deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[_]
    isSudoEntrypoint(container)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  have sudo in entrypoint", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[_]
    isSudoEntrypoint(container)
	msga := {
		"alertMessage": sprintf("container: %v in %v: %v  have sudo in entrypoint", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

deny[msga] {
    wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[_]
    isSudoEntrypoint(container)
	msga := {
		"alertMessage": sprintf("container: %v in cronjob: %v  have sudo in entrypoint", [container.name, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

isSudoEntrypoint(container){
    command := container.command[_]
    contains(command, "sudo") 
}