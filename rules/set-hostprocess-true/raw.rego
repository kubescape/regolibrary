# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

### POD ###

# Fails if pod-level securityContext sets windowsOptions.hostProcess to true
deny contains msga if {
	obj := input[_]
	is_control_plane_info(obj)
	is_windows_hostprocess_containers_enabled(obj.data.APIServerInfo.cmdLine)

	pod := input[_]
	pod.kind == "Pod"
	is_hostprocess_true(pod.spec.securityContext)

	fixPaths := [{"path": "spec.securityContext.windowsOptions.hostProcess", "value": "false"}]

	msga := {
		"alertMessage": sprintf("Pod: %v sets 'securityContext.windowsOptions.hostProcess' to true", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

# Fails if a container in a pod sets windowsOptions.hostProcess to true
deny contains msga if {
	obj := input[_]
	is_control_plane_info(obj)
	is_windows_hostprocess_containers_enabled(obj.data.APIServerInfo.cmdLine)

	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	is_hostprocess_true(container.securityContext)

	fixPaths := [{"path": sprintf("spec.containers[%d].securityContext.windowsOptions.hostProcess", [i]), "value": "false"}]

	msga := {
		"alertMessage": sprintf("Pod: %v has a container that sets 'securityContext.windowsOptions.hostProcess' to true", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

### WORKLOAD ###

# Fails if pod-template-level securityContext sets windowsOptions.hostProcess to true
deny contains msga if {
	manifest_kind := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}

	obj := input[_]
	is_control_plane_info(obj)
	is_windows_hostprocess_containers_enabled(obj.data.APIServerInfo.cmdLine)

	wl := input[_]
	manifest_kind[wl.kind]
	is_hostprocess_true(wl.spec.template.spec.securityContext)

	fixPaths := [{"path": "spec.template.spec.securityContext.windowsOptions.hostProcess", "value": "false"}]

	msga := {
		"alertMessage": sprintf("Workload: %v sets 'securityContext.windowsOptions.hostProcess' to true", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# Fails if a container in a workload sets windowsOptions.hostProcess to true
deny contains msga if {
	manifest_kind := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}

	obj := input[_]
	is_control_plane_info(obj)
	is_windows_hostprocess_containers_enabled(obj.data.APIServerInfo.cmdLine)

	wl := input[_]
	manifest_kind[wl.kind]
	container := wl.spec.template.spec.containers[i]
	is_hostprocess_true(container.securityContext)

	fixPaths := [{"path": sprintf("spec.template.spec.containers[%d].securityContext.windowsOptions.hostProcess", [i]), "value": "false"}]

	msga := {
		"alertMessage": sprintf("Workload: %v has a container that sets 'securityContext.windowsOptions.hostProcess' to true", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

### CRONJOB ###

# Fails if pod-template-level securityContext sets windowsOptions.hostProcess to true
deny contains msga if {
	obj := input[_]
	is_control_plane_info(obj)
	is_windows_hostprocess_containers_enabled(obj.data.APIServerInfo.cmdLine)

	cj := input[_]
	cj.kind == "CronJob"
	is_hostprocess_true(cj.spec.jobTemplate.spec.template.spec.securityContext)

	fixPaths := [{"path": "spec.jobTemplate.spec.template.spec.securityContext.windowsOptions.hostProcess", "value": "false"}]

	msga := {
		"alertMessage": sprintf("CronJob: %v sets 'securityContext.windowsOptions.hostProcess' to true", [cj.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [cj]},
	}
}

# Fails if a container in a CronJob sets windowsOptions.hostProcess to true
deny contains msga if {
	obj := input[_]
	is_control_plane_info(obj)
	is_windows_hostprocess_containers_enabled(obj.data.APIServerInfo.cmdLine)

	cj := input[_]
	cj.kind == "CronJob"
	container := cj.spec.jobTemplate.spec.template.spec.containers[i]
	is_hostprocess_true(container.securityContext)

	fixPaths := [{"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%d].securityContext.windowsOptions.hostProcess", [i]), "value": "false"}]

	msga := {
		"alertMessage": sprintf("CronJob: %v has a container that sets 'securityContext.windowsOptions.hostProcess' to true", [cj.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [cj]},
	}
}

# check if we are managing ControlPlaneInfo
is_control_plane_info(obj) if {
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	obj.kind == "ControlPlaneInfo"
}

# check if WindowsHostProcessContainers feature-gate is enabled
is_windows_hostprocess_containers_enabled(command) if {
	contains(command, "--feature-gates=")
	args := regex.split(` +`, command)
	some i
	regex.match(`WindowsHostProcessContainers=true`, args[i])
}

# is_hostprocess_true checks if windowsOptions.hostProcess is set to true.
is_hostprocess_true(securityContext) if {
	securityContext.windowsOptions.hostProcess == true
}
