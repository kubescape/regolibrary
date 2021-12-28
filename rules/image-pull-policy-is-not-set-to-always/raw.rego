package armo_builtins


deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.containers[i]
	imagePullPolicy := container.imagePullPolicy
	imagePullPolicy != "Always"
	path := sprintf("spec.containers[%v].imagePullPolicy", [format_int(i, 10)])
    msga := {
		"alertMessage": sprintf("container: %v in pod: %v  is imagePullPolicy not set to 'Always'", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"alertScore": 0,
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
	imagePullPolicy := container.imagePullPolicy
	imagePullPolicy != "Always"
	path := sprintf("spec.template.spec.containers[%v].imagePullPolicy", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("container: %v in %v: %v  is imagePullPolicy not set to 'Always'", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"alertScore": 0,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


deny[msga] {
  	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
	imagePullPolicy := container.imagePullPolicy
	imagePullPolicy != "Always"
	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].imagePullPolicy", [format_int(i, 10)])
    msga := {
		"alertMessage": sprintf("container: %v in cronjob: %v  is imagePullPolicy not set to 'Always'", [container.name, wl.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"alertScore": 0,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

