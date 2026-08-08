# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

### POD ###

# Fails if pod-level securityContext sets windowsOptions.hostProcess to true
deny contains msga if {
	path := "spec.securityContext.windowsOptions.hostProcess"

	pod := input[_]
	pod.kind == "Pod"
	is_hostprocess_true(pod.spec.securityContext)

	msga := {
		"alertMessage": sprintf("Pod: %v sets 'securityContext.windowsOptions.hostProcess' to true", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [{"path": path, "value": "false"}],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

# Fails if a container/initContainer/ephemeralContainer in a pod sets windowsOptions.hostProcess to true
deny contains msga if {
	container_types := {"containers", "initContainers", "ephemeralContainers"}
	pod := input[_]
	pod.kind == "Pod"
	array_name := container_types[_]
	containers := object.get(pod.spec, array_name, [])
	container := containers[i]
	is_hostprocess_true(container.securityContext)

	path := sprintf("spec.%v[%d].securityContext.windowsOptions.hostProcess", [array_name, i])

	msga := {
		"alertMessage": sprintf("Pod: %v has a container that sets 'securityContext.windowsOptions.hostProcess' to true", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [{"path": path, "value": "false"}],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

### WORKLOAD ###

# Fails if pod-template-level securityContext sets windowsOptions.hostProcess to true
deny contains msga if {
	manifest_kind := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	path := "spec.template.spec.securityContext.windowsOptions.hostProcess"

	wl := input[_]
	manifest_kind[wl.kind]
	is_hostprocess_true(wl.spec.template.spec.securityContext)

	msga := {
		"alertMessage": sprintf("Workload: %v sets 'securityContext.windowsOptions.hostProcess' to true", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [{"path": path, "value": "false"}],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if a container/initContainer/ephemeralContainer in a workload sets windowsOptions.hostProcess to true
deny contains msga if {
	manifest_kind := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	container_types := {"containers", "initContainers", "ephemeralContainers"}
	wl := input[_]
	manifest_kind[wl.kind]
	array_name := container_types[_]
	containers := object.get(wl.spec.template.spec, array_name, [])
	container := containers[i]
	is_hostprocess_true(container.securityContext)

	path := sprintf("spec.template.spec.%v[%d].securityContext.windowsOptions.hostProcess", [array_name, i])

	msga := {
		"alertMessage": sprintf("Workload: %v has a container that sets 'securityContext.windowsOptions.hostProcess' to true", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [{"path": path, "value": "false"}],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

### CRONJOB ###

# Fails if pod-template-level securityContext sets windowsOptions.hostProcess to true
deny contains msga if {
	path := "spec.jobTemplate.spec.template.spec.securityContext.windowsOptions.hostProcess"

	cj := input[_]
	cj.kind == "CronJob"
	is_hostprocess_true(cj.spec.jobTemplate.spec.template.spec.securityContext)

	msga := {
		"alertMessage": sprintf("CronJob: %v sets 'securityContext.windowsOptions.hostProcess' to true", [cj.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [{"path": path, "value": "false"}],
		"alertObject": {"k8sApiObjects": [cj]},
	}
}

# Fails if a container/initContainer/ephemeralContainer in a CronJob sets windowsOptions.hostProcess to true
deny contains msga if {
	container_types := {"containers", "initContainers", "ephemeralContainers"}
	cj := input[_]
	cj.kind == "CronJob"
	array_name := container_types[_]
	containers := object.get(cj.spec.jobTemplate.spec.template.spec, array_name, [])
	container := containers[i]
	is_hostprocess_true(container.securityContext)

	path := sprintf("spec.jobTemplate.spec.template.spec.%v[%d].securityContext.windowsOptions.hostProcess", [array_name, i])

	msga := {
		"alertMessage": sprintf("CronJob: %v has a container that sets 'securityContext.windowsOptions.hostProcess' to true", [cj.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [{"path": path, "value": "false"}],
		"alertObject": {"k8sApiObjects": [cj]},
	}
}

# is_hostprocess_true checks if windowsOptions.hostProcess is set to true.
is_hostprocess_true(securityContext) if {
	securityContext.windowsOptions.hostProcess == true
}
