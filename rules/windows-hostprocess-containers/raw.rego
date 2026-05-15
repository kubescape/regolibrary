package armo_builtins


# Fails if a pod container has hostProcess enabled
deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	container.securityContext.windowsOptions.hostProcess == true
	path := sprintf("spec.containers[%v].securityContext.windowsOptions.hostProcess", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("Pod: %v has a container with hostProcess enabled", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if a pod init container has hostProcess enabled
deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.initContainers[i]
	container.securityContext.windowsOptions.hostProcess == true
	path := sprintf("spec.initContainers[%v].securityContext.windowsOptions.hostProcess", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("Pod: %v has an init container with hostProcess enabled", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}


# Fails if a workload container has hostProcess enabled
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	container.securityContext.windowsOptions.hostProcess == true
	path := sprintf("spec.template.spec.containers[%v].securityContext.windowsOptions.hostProcess", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("%v: %v has a container with hostProcess enabled", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if a workload init container has hostProcess enabled
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.initContainers[i]
	container.securityContext.windowsOptions.hostProcess == true
	path := sprintf("spec.template.spec.initContainers[%v].securityContext.windowsOptions.hostProcess", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("%v: %v has an init container with hostProcess enabled", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if a cronjob container has hostProcess enabled
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	container.securityContext.windowsOptions.hostProcess == true
	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].securityContext.windowsOptions.hostProcess", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("CronJob: %v has a container with hostProcess enabled", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if a cronjob init container has hostProcess enabled
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.initContainers[i]
	container.securityContext.windowsOptions.hostProcess == true
	path := sprintf("spec.jobTemplate.spec.template.spec.initContainers[%v].securityContext.windowsOptions.hostProcess", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("CronJob: %v has an init container with hostProcess enabled", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if a pod ephemeral container has hostProcess enabled
deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.ephemeralContainers[i]
	container.securityContext.windowsOptions.hostProcess == true
	path := sprintf("spec.ephemeralContainers[%v].securityContext.windowsOptions.hostProcess", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("Pod: %v has an ephemeral container with hostProcess enabled", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if a workload ephemeral container has hostProcess enabled
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.ephemeralContainers[i]
	container.securityContext.windowsOptions.hostProcess == true
	path := sprintf("spec.template.spec.ephemeralContainers[%v].securityContext.windowsOptions.hostProcess", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("%v: %v has an ephemeral container with hostProcess enabled", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if a cronjob ephemeral container has hostProcess enabled
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.ephemeralContainers[i]
	container.securityContext.windowsOptions.hostProcess == true
	path := sprintf("spec.jobTemplate.spec.template.spec.ephemeralContainers[%v].securityContext.windowsOptions.hostProcess", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("CronJob: %v has an ephemeral container with hostProcess enabled", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}
