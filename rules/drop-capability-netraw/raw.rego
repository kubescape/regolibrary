package armo_builtins

import future.keywords.in

# Fails if pod does not drop the capability NET_RAW 
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.containers[i]
    container_doesnt_drop_NET_RAW(container)

	fixPaths := [{"path": sprintf("spec.containers[%d].securityContext.capabilities.drop", [i]), "value": "NET_RAW"}]

	msga := {
		"alertMessage": sprintf("Pod: %v does not drop the capability NET_RAW", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if workload does not drop the capability NET_RAW
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]
    container_doesnt_drop_NET_RAW(container)

	fixPaths := [{"path": sprintf("spec.template.spec.containers[%v].securityContext.capabilities.drop", [format_int(i, 10)]), "value": "NET_RAW"}]


	msga := {
		"alertMessage": sprintf("Workload: %v does not drop the capability NET_RAW", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if pod does not drop the capability NET_RAW
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
    container_doesnt_drop_NET_RAW(container)

	fixPaths := [{"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%v].securityContext.capabilities.drop", [format_int(i, 10)]), "value": "NET_RAW"}]

	msga := {
		"alertMessage": sprintf("Cronjob: %v does not drop the capability NET_RAW", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

container_doesnt_drop_NET_RAW(container) {
	not "NET_RAW" in container.securityContext.capabilities.drop
}

container_doesnt_drop_NET_RAW(container) {
	not container.securityContext.capabilities.drop
}