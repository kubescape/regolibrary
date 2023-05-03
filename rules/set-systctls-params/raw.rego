package armo_builtins

### POD ###

# Fails if securityContext.systctls is not set
deny[msga] {
    # verify the object kind
	pod := input[_]
	pod.kind = "Pod"

	# check securityContext has systctls set
    not pod.spec.securityContext.systctls

    path := "spec.securityContext.systctls"
    msga := {
		"alertMessage": sprintf("Pod: %v does not set 'securityContext.systctls'", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [{"path": path, "name": "net.ipv4.tcp_syncookie", "value": "1"}],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
    }
}

### WORKLOAD ###

# Fails if securityContext.systctls is not set
deny[msga] {
    # verify the object kind
	wl := input[_]
	manifest_kind := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	manifest_kind[wl.kind]

	# check securityContext has systctls set
    not wl.spec.template.spec.securityContext.systctls

    path := "spec.template.spec.securityContext.systctls"
    msga := {
		"alertMessage": sprintf("Workload: %v does not set 'securityContext.systctls'", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [{"path": path, "name": "net.ipv4.tcp_syncookie", "value": "1"}],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
    }
}

### CRONJOB ###

# Fails if securityContext.systctls is not set
deny[msga] {
    # verify the object kind
	cj := input[_]
    cj.kind == "CronJob"

	# check securityContext has systctls set
    not cj.spec.jobTemplate.spec.template.spec.securityContext.systctls

    path := "spec.jobTemplate.spec.template.spec.securityContext.systctls"
    msga := {
		"alertMessage": sprintf("CronJob: %v does not set 'securityContext.systctls'", [cj.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [{"path": path, "name": "net.ipv4.tcp_syncookie", "value": "1"}],
		"alertObject": {
			"k8sApiObjects": [cj]
		}
    }
}
