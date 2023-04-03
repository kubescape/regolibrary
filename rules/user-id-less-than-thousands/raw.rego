package armo_builtins

# TODO - FIX FAILED PATHS IF THE CONTROL WILL BE ACTIVE AGAIN

# Fails if pod has container  configured to run with id less than 1000
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]
	start_of_path := "spec."
    result := is_root_container(container, start_of_path, i)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  runs with id less than 1000", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [],
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if pod has container  configured to run with id less than 1000
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]
	start_of_path := ""
    result := is_root_pod(pod, container, start_of_path)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  runs with id less than 1000", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [],
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}



# Fails if workload has container configured to run with id less than 1000
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]
	start_of_path := "spec.template.spec."
    result := is_root_container(container, start_of_path, i)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v runs with id less than 1000", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [],
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if workload has container configured to run with id less than 1000
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]
	start_of_path := "spec.template."
    result := is_root_pod(wl.spec.template, container, start_of_path)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v runs with id less than 1000", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [],
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if cronjob has a container configured to run with id less than 1000
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
	start_of_path := "spec.jobTemplate.spec.template.spec."
	result := is_root_container(container, start_of_path, i)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v  runs with id less than 1000", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [],
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}



# Fails if workload has container configured to run with id less than 1000
deny[msga] {
  	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
	start_of_path := "spec.jobTemplate.spec.template."
    result := is_root_pod(wl.spec.jobTemplate.spec.template, container, start_of_path)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v runs with id less than 1000", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [],
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


is_root_pod(pod, container, start_of_path) = path {
	not container.securityContext.runAsGroup
    not container.securityContext.runAsUser
    pod.spec.securityContext.runAsUser < 1000
	not pod.spec.securityContext.runAsGroup
	path = sprintf("%vspec.securityContext.runAsUser", [start_of_path])
}

is_root_pod(pod, container, start_of_path) = path {
	not container.securityContext.runAsUser
    not container.securityContext.runAsGroup
    pod.spec.securityContext.runAsGroup < 1000
	not pod.spec.securityContext.runAsUser
	path = sprintf("%vspec.securityContext.runAsGroup", [start_of_path])
}

is_root_pod(pod, container, start_of_path) = path {
    pod.spec.securityContext.runAsGroup > 1000
	 pod.spec.securityContext.runAsUser < 1000
	path = sprintf("%vspec.securityContext.runAsUser", [start_of_path])
}

is_root_pod(pod, container, start_of_path) = path {
    pod.spec.securityContext.runAsGroup < 1000
	pod.spec.securityContext.runAsUser > 1000
	path = sprintf("%vspec.securityContext.runAsGroup", [start_of_path])
}

is_root_pod(pod, container, start_of_path) = path {
    pod.spec.securityContext.runAsGroup < 1000
	 pod.spec.securityContext.runAsUser < 1000
	path = sprintf("%vspec.securityContext", [start_of_path])
}


is_root_container(container, start_of_path, i) = path {
    container.securityContext.runAsUser < 1000
	not container.securityContext.runAsGroup
	path = sprintf("%vcontainers[%v].securityContext.runAsUser", [start_of_path, format_int(i, 10)])
}

is_root_container(container, start_of_path, i) = path {
    container.securityContext.runAsGroup < 1000
	not container.securityContext.runAsUser
	path = sprintf("%vcontainers[%v].securityContext.runAsGroup", [start_of_path, format_int(i, 10)])
}