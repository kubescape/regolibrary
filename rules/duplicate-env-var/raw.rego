package armo_builtins

deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	env := container.env[j]
	previous := container.env[k]
	k < j
	env.name == previous.name

	path := sprintf("spec.containers[%v].env[%v].name", [i, j])

	msga := {
		"alertMessage": sprintf("Pod: %v container %v has duplicate environment variable %v", [pod.metadata.name, container.name, env.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"fixPaths": [],
		"alertScore": 3,
		"alertObject": {
			"k8sApiObjects": [pod],
		},
	}
}

deny[msga] {
	wl := input[_]
	workload_kinds := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	workload_kinds[wl.kind]
	container := wl.spec.template.spec.containers[i]
	env := container.env[j]
	previous := container.env[k]
	k < j
	env.name == previous.name

	path := sprintf("spec.template.spec.containers[%v].env[%v].name", [i, j])

	msga := {
		"alertMessage": sprintf("%v: %v container %v has duplicate environment variable %v", [wl.kind, wl.metadata.name, container.name, env.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"fixPaths": [],
		"alertScore": 3,
		"alertObject": {
			"k8sApiObjects": [wl],
		},
	}
}

deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	env := container.env[j]
	previous := container.env[k]
	k < j
	env.name == previous.name

	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].env[%v].name", [i, j])

	msga := {
		"alertMessage": sprintf("CronJob: %v container %v has duplicate environment variable %v", [wl.metadata.name, container.name, env.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"fixPaths": [],
		"alertScore": 3,
		"alertObject": {
			"k8sApiObjects": [wl],
		},
	}
}
