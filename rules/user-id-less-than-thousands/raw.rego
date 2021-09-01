package armo_builtins


# Fails if pod has container  configured to run with id less than 1000
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[_]
    isRootContainer(container)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  runs with id less than 1000", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if pod has container  configured to run with id less than 1000
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[_]
    isRootPod(pod, container)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  runs with id less than 1000", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
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
    container := wl.spec.template.spec.containers[_]
    isRootContainer(container)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v runs with id less than 1000", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
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
    container := wl.spec.template.spec.containers[_]
    isRootPod(wl.spec.template, container)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v runs with id less than 1000", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if cronjob has a container configured to run with id less than 1000
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[_]
	  isRootContainer(container)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v  runs with id less than 1000", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}



# Fails if workload has container configured to run with id less than 1000
deny[msga] {
  	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[_]
    isRootPod(wl.spec.jobTemplate.spec.template, container)
    msga := {
		"alertMessage": sprintf("container :%v in %v: %v runs with id less than 1000", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


isRootPod(pod, container) {
    not container.securityContext.runAsUser
    pod.spec.securityContext.runAsUser < 1000
}

isRootPod(pod, container) {
    not container.securityContext.runAsGroup
    pod.spec.securityContext.runAsGroup < 1000
}

isRootContainer(container) {
    container.securityContext.runAsUser < 1000
}

isRootContainer(container) {
     container.securityContext.runAsGroup < 1000
}