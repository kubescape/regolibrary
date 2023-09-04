package armo_builtins

### POD ###

# Fails if securityContext.sysctls is not set
deny[msga] {
    # verify the object kind
	pod := input[_]
	pod.kind = "Pod"

	# check securityContext has sysctls set
    not pod.spec.securityContext.sysctls

    path := "spec.securityContext.sysctls"
    msga := {
		"alertMessage": sprintf("Pod: %v does not set 'securityContext.sysctls'", [pod.metadata.name]),
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

# Fails if securityContext.sysctls is not set
deny[msga] {
    # verify the object kind
	wl := input[_]
	manifest_kind := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	manifest_kind[wl.kind]

	# check securityContext has sysctls set
    not wl.spec.template.spec.securityContext.sysctls

    path := "spec.template.spec.securityContext.sysctls"
    msga := {
		"alertMessage": sprintf("Workload: %v does not set 'securityContext.sysctls'", [wl.metadata.name]),
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

# Fails if securityContext.sysctls is not set
deny[msga] {
    # verify the object kind
	cj := input[_]
    cj.kind == "CronJob"

	# check securityContext has sysctls set
    not cj.spec.jobTemplate.spec.template.spec.securityContext.sysctls

    path := "spec.jobTemplate.spec.template.spec.securityContext.sysctls"
    msga := {
		"alertMessage": sprintf("CronJob: %v does not set 'securityContext.sysctls'", [cj.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [{"path": path, "name": "net.ipv4.tcp_syncookie", "value": "1"}],
		"alertObject": {
			"k8sApiObjects": [cj]
		}
    }
}
