package armo_builtins

import rego.v1

### POD ###

# Fails if securityContext.sysctls is not set
deny contains msga if {
	# verify the object kind
	pod := input[_]
	pod.kind = "Pod"

	# check securityContext has sysctls set
	not pod.spec.securityContext.sysctls

	path := "spec.securityContext.sysctls"
	fixPaths := [
		{"path": sprintf("%s.name", [path]), "value": "YOUR_VALUE"},
		{"path": sprintf("%s.value", [path]), "value": "YOUR_VALUE"},
	]
	msga := {
		"alertMessage": sprintf("Pod: %v does not set 'securityContext.sysctls'", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

### WORKLOAD ###

# Fails if securityContext.sysctls is not set
deny contains msga if {
	# verify the object kind
	wl := input[_]
	manifest_kind := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	manifest_kind[wl.kind]

	# check securityContext has sysctls set
	not wl.spec.template.spec.securityContext.sysctls

	path := "spec.template.spec.securityContext.sysctls"
	fixPaths := [
		{"path": sprintf("%s.name", [path]), "value": "YOUR_VALUE"},
		{"path": sprintf("%s.value", [path]), "value": "YOUR_VALUE"},
	]
	msga := {
		"alertMessage": sprintf("Workload: %v does not set 'securityContext.sysctls'", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

### CRONJOB ###

# Fails if securityContext.sysctls is not set
deny contains msga if {
	# verify the object kind
	cj := input[_]
	cj.kind == "CronJob"

	# check securityContext has sysctls set
	not cj.spec.jobTemplate.spec.template.spec.securityContext.sysctls

	path := "spec.jobTemplate.spec.template.spec.securityContext.sysctls"
	fixPaths := [
		{"path": sprintf("%s.name", [path]), "value": "YOUR_VALUE"},
		{"path": sprintf("%s.value", [path]), "value": "YOUR_VALUE"},
	]
	msga := {
		"alertMessage": sprintf("CronJob: %v does not set 'securityContext.sysctls'", [cj.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [cj]},
	}
}
