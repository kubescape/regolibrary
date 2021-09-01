package armo_builtins


# Fails if pod has container  configured to run as root
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[_]
    isRootContainer(container)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  may run as root", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if pod has container  configured to run as root
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[_]
    isRootPod(pod, container)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  may run as root", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
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
    container := wl.spec.template.spec.containers[_]
    isRootContainer(container)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v may run as root", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
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
    container := wl.spec.template.spec.containers[_]
    isRootPod(wl.spec.template, container)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v may run as root", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if cronjob has a container configured to run as root
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[_]
	  isRootContainer(container)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v  may run as root", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}



# Fails if workload has container configured to run as root
deny[msga] {
  	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[_]
    isRootPod(wl.spec.jobTemplate.spec.template, container)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v may run as root", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


isRootPod(pod, container) {
    not container.securityContext.runAsUser
    pod.spec.securityContext.runAsUser == 0
}

isRootPod(pod, container) {
    not container.securityContext.runAsUser
	not container.securityContext.runAsGroup
	not container.securityContext.runAsNonRoot
    not pod.spec.securityContext.runAsUser
	not pod.spec.securityContext.runAsGroup
    pod.spec.securityContext.runAsNonRoot == false
}

isRootPod(pod, container) {
    not container.securityContext.runAsGroup
    pod.spec.securityContext.runAsGroup == 0
}

isRootPod(pod, container) {
	not pod.spec.securityContext.runAsGroup
	not pod.spec.securityContext.runAsUser
   	container.securityContext.runAsNonRoot == false
}

isRootContainer(container) {
    container.securityContext.runAsUser == 0
}

isRootContainer(container) {
     container.securityContext.runAsGroup == 0
}