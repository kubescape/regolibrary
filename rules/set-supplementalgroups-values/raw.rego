package armo_builtins

### POD ###

# Fails if securityContext.supplementalGroups is not set
deny[msga] {
    # verify the object kind
	pod := input[_]
	pod.kind = "Pod"

	# check securityContext has supplementalGroups set
    not pod.spec.securityContext.supplementalGroups

    path := "spec.securityContext.supplementalGroups"
    msga := {
		"alertMessage": sprintf("Pod: %v does not set 'securityContext.supplementalGroups'", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
    }
}

### WORKLOAD ###

# Fails if securityContext.supplementalGroups is not set
deny[msga] {
    # verify the object kind
	wl := input[_]
	manifest_kind := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	manifest_kind[wl.kind]

	# check securityContext has supplementalGroups set
    not wl.spec.template.spec.securityContext.supplementalGroups

    path := "spec.template.spec.securityContext.supplementalGroups"
    msga := {
		"alertMessage": sprintf("Workload: %v does not set 'securityContext.supplementalGroups'", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
    }
}

### CRONJOB ###

# Fails if securityContext.supplementalGroups is not set
deny[msga] {
    # verify the object kind
	cj := input[_]
    cj.kind == "CronJob"

	# check securityContext has supplementalGroups set
    not cj.spec.jobTemplate.spec.template.spec.securityContext.supplementalGroups

    path := "spec.jobTemplate.spec.template.spec.securityContext.supplementalGroups"
    msga := {
		"alertMessage": sprintf("CronJob: %v does not set 'securityContext.supplementalGroups'", [cj.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [cj]
		}
    }
}
