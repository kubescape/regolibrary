package armo_builtins

import future.keywords.contains
import future.keywords.if
import future.keywords.in

same_name_at_other_index(envs, j, name) if {
	k != j
	envs[k].name == name
}

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	env := container.env[j]
	same_name_at_other_index(container.env, j, env.name)

	path := sprintf("spec.containers[%v].env[%v].name", [i, j])

	msga := {
		"alertMessage": sprintf("Pod: %v container %v has duplicate environment variable name %v at this entry", [pod.metadata.name, container.name, env.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"fixPaths": [],
		"alertScore": 3,
		"alertObject": {
			"k8sApiObjects": [pod],
		},
	}
}

deny contains msga if {
	wl := input[_]
	wl.kind in {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	container := wl.spec.template.spec.containers[i]
	env := container.env[j]
	same_name_at_other_index(container.env, j, env.name)

	path := sprintf("spec.template.spec.containers[%v].env[%v].name", [i, j])

	msga := {
		"alertMessage": sprintf("%v: %v container %v has duplicate environment variable name %v at this entry", [wl.kind, wl.metadata.name, container.name, env.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"fixPaths": [],
		"alertScore": 3,
		"alertObject": {
			"k8sApiObjects": [wl],
		},
	}
}

deny contains msga if {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	env := container.env[j]
	same_name_at_other_index(container.env, j, env.name)

	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].env[%v].name", [i, j])

	msga := {
		"alertMessage": sprintf("CronJob: %v container %v has duplicate environment variable name %v at this entry", [wl.metadata.name, container.name, env.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"fixPaths": [],
		"alertScore": 3,
		"alertObject": {
			"k8sApiObjects": [wl],
		},
	}
}
