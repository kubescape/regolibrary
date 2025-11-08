package armo_builtins

import rego.v1

# Fails if container does not define the "procMount" parameter as "Default"
deny contains msga if {
	# checks at first if we the procMountType feature gate is enabled on the api-server
	obj := input[_]
	is_control_plane_info(obj)
	is_proc_mount_type_enabled(obj.data.APIServerInfo.cmdLine)

	# checks if procMount paramenter has the right value in containers
	pod := input[_]
	pod.kind = "Pod"

	# retrieve container list
	container := pod.spec.containers[i]
	not procMountSetProperly(container.securityContext)

	fixPaths = [{"path": sprintf("spec.containers[%d].securityContext.procMount", [i]), "value": "Default"}]
	msga := {
		"alertMessage": sprintf("Pod: %v has containers that do not set 'securityContext.procMount' to 'Default'", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

deny contains msga if {
	# checks at first if we the procMountType feature gate is enabled on the api-server
	obj := input[_]
	is_control_plane_info(obj)
	is_proc_mount_type_enabled(obj.data.APIServerInfo.cmdLine)

	# checks if we are managing the right workload kind
	wl := input[_]
	manifest_kind := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	manifest_kind[wl.kind]

	# retrieve container list
	container := wl.spec.template.spec.containers[i]
	not procMountSetProperly(container.securityContext)

	fixPaths = [{"path": sprintf("spec.template.spec.containers[%d].securityContext.procMount", [i]), "value": "Default"}]
	msga := {
		"alertMessage": sprintf("Workload: %v has containers that do not set 'securityContext.procMount' to 'Default'", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixPaths,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

deny contains msga if {
	# checks at first if we the procMountType feature gate is enabled on the api-server
	obj := input[_]
	is_control_plane_info(obj)
	is_proc_mount_type_enabled(obj.data.APIServerInfo.cmdLine)

	# checks if we are managing the right workload kind
	cj := input[_]
	cj.kind = "CronJob"

	# retrieve container list
	container := cj.spec.jobTemplate.spec.template.spec.containers[i]
	not procMountSetProperly(container.securityContext)

	fixPaths = [{"path": sprintf("spec.jobTemplate.spec.template.spec.containers[%d].securityContext.procMount", [i]), "value": "Default"}]
	msga := {
		"alertMessage": sprintf("CronJob: %v has containers that do not set 'securityContext.procMount' to 'Default'", [cj.metadata.name]),
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

# check if ProcMountType feature-gate is enabled
is_proc_mount_type_enabled(command) if {
	contains(command, "--feature-gates=")
	args := regex.split(` +`, command)
	some i
	regex.match(`ProcMountType=true`, args[i])
}

# procMountSetProperly checks if procMount has value of "Default".
procMountSetProperly(securityContext) if {
	securityContext.procMount == "Default"
} else := false
