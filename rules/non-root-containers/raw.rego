package armo_builtins


# Fails if pod has container  configured to run as root
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]
	begginingOfPath := "spec."
    result := isRootContainer(container, i, begginingOfPath)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  may run as root", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if pod has container  configured to run as root
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]
	begginingOfPath ="spec."
    result := isRootPod(pod, container, i, begginingOfPath)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  may run as root", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}



# Fails if workload has container configured to run as root
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]
	begginingOfPath := "spec.template.spec."
    result := isRootContainer(container, i, begginingOfPath)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v may run as root", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Fails if workload has container configured to run as root
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]
	begginingOfPath := "spec.template.spec."
    result := isRootPod(wl.spec.template, container, i, begginingOfPath)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v may run as root", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if cronjob has a container configured to run as root
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
	begginingOfPath := "spec.jobTemplate.spec.template.spec."
	result := isRootContainer(container, i, begginingOfPath)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v  may run as root", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}



# Fails if workload has container configured to run as root
deny[msga] {
  	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
	begginingOfPath := "spec.jobTemplate.spec.template.spec."
    result := isRootPod(wl.spec.jobTemplate.spec.template, container, i, begginingOfPath)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v may run as root", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


isRootPod(pod, container, i, begginingOfPath) = path {
    not container.securityContext.runAsUser
    pod.spec.securityContext.runAsUser == 0
	path = "spec.securityContext.runAsUser"
}

isRootPod(pod, container, i, begginingOfPath) = path {
    not container.securityContext.runAsUser
	not container.securityContext.runAsGroup
	not container.securityContext.runAsNonRoot
    not pod.spec.securityContext.runAsUser
	not pod.spec.securityContext.runAsGroup
    pod.spec.securityContext.runAsNonRoot == false
	path = "spec.securityContext.runAsNonRoot"
}

isRootPod(pod, container, i, begginingOfPath) = path {
    not container.securityContext.runAsGroup
    pod.spec.securityContext.runAsGroup == 0
	path = sprintf("%vsecurityContext.runAsGroup", [begginingOfPath])
}

isRootPod(pod, container, i, begginingOfPath)= path  {
	not pod.spec.securityContext.runAsGroup
	not pod.spec.securityContext.runAsUser
   	container.securityContext.runAsNonRoot == false
	path = sprintf("%vcontainers[%v].securityContext.runAsNonRoot", [begginingOfPath, format_int(i, 10)])
}

isRootContainer(container, i, begginingOfPath) = path  {
    container.securityContext.runAsUser == 0
	path = sprintf("%vcontainers[%v].securityContext.runAsUser", [begginingOfPath, format_int(i, 10)])
}

isRootContainer(container, i, begginingOfPath) = path  {
     container.securityContext.runAsGroup == 0
	 path = sprintf("%vcontainers[%v].securityContext.runAsGroup", [begginingOfPath, format_int(i, 10)])
}