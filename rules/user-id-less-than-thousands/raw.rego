package armo_builtins

# TODO - FIX FAILED PATHS IF THE CONTROL WILL BE ACTIVE AGAIN

# Fails if pod has container  configured to run with id less than 1000
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]
	begginingOfPath := "spec."
    result := isRootContainer(container, begginingOfPath, i)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  runs with id less than 1000", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
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
	begginingOfPath := ""
    result := isRootPod(pod, container, begginingOfPath)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  runs with id less than 1000", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
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
	begginingOfPath := "spec.template.spec."
    result := isRootContainer(container, begginingOfPath, i)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v runs with id less than 1000", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
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
	begginingOfPath := "spec.template."
    result := isRootPod(wl.spec.template, container, begginingOfPath)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v runs with id less than 1000", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
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
	begginingOfPath := "spec.jobTemplate.spec.template.spec."
	result := isRootContainer(container, begginingOfPath, i)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v  runs with id less than 1000", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
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
	begginingOfPath := "spec.jobTemplate.spec.template."
    result := isRootPod(wl.spec.jobTemplate.spec.template, container, begginingOfPath)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v runs with id less than 1000", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


isRootPod(pod, container, begginingOfPath) = path {
	path = ""
    not container.securityContext.runAsUser
    pod.spec.securityContext.runAsUser < 1000
	path = sprintf("%vspec.securityContext.runAsUser", [begginingOfPath])
}

isRootPod(pod, container, begginingOfPath) = path {
	path = ""
    not container.securityContext.runAsGroup
    pod.spec.securityContext.runAsGroup < 1000
	path = sprintf("%vspec.securityContext.runAsGroup", [begginingOfPath])
}

isRootContainer(container, begginingOfPath, i) = path {
	path = ""
    container.securityContext.runAsUser < 1000
	path = sprintf("%vcontainers[%v].securityContext.runAsUser", [begginingOfPath, format_int(i, 10)])
}

isRootContainer(container, begginingOfPath, i) = path {
	path = ""
     container.securityContext.runAsGroup < 1000
	 path = sprintf("%vcontainers[%v].securityContext.runAsGroup", [begginingOfPath, format_int(i, 10)])
}