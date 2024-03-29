package armo_builtins

import future.keywords.if

### POD ###

# Fails if securityContext.fsGroup does not have a values >= 0
deny[msga] {
	# verify the object kind
	pod := input[_]
	pod.kind = "Pod"

	# check securityContext has fsGroup set properly
	not fsGroupSetProperly(pod.spec.securityContext)

	securityContextPath := "spec.securityContext"

	fixPaths = [{"path": sprintf("%v.fsGroup", [securityContextPath]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Pod: %v does not set 'securityContext.fsGroup' with allowed value", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

### CRONJOB ###

# Fails if securityContext.fsGroup does not have a values >= 0
deny[msga] {
	# verify the object kind
	cj := input[_]
	cj.kind == "CronJob"

	# check securityContext has fsGroup set properly
	not fsGroupSetProperly(cj.spec.jobTemplate.spec.template.spec.securityContext)

	securityContextPath := "spec.jobTemplate.spec.template.spec.securityContext"

	fixPaths = [{"path": sprintf("%v.fsGroup", [securityContextPath]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("CronJob: %v does not set 'securityContext.fsGroup' with allowed value", [cj.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [cj]},
	}
}

### WORKLOAD ###

# Fails if securityContext.fsGroup does not have a values >= 0
deny[msga] {
	# verify the object kind
	wl := input[_]
	manifest_kind := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	manifest_kind[wl.kind]

	# check securityContext has fsGroup set properly
	not fsGroupSetProperly(wl.spec.template.spec.securityContext)

	securityContextPath := "spec.template.spec.securityContext"
	fixPaths = [{"path": sprintf("%v.fsGroup", [securityContextPath]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("Workload: %v does not set 'securityContext.fsGroup' with allowed value", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# fsGroupSetProperly checks if fsGroup has a value >= 0.
fsGroupSetProperly(securityContext) if {
	securityContext.fsGroup >= 0
} else := false
