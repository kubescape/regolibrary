package armo_builtins


deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    volume := pod.spec.volumes[i]
	host_path := volume.hostPath
    is_runtime_socket_mounting(host_path)
	path := sprintf("spec.volumes[%v].hostPath.path", [format_int(i, 10)])
    msga := {
		"alertMessage": sprintf("volume: %v in pod: %v has mounting to Docker internals.", [volume.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths":[],
		"alertScore": 5,
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}	
}



deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    volume := wl.spec.template.spec.volumes[i]
	host_path := volume.hostPath
    is_runtime_socket_mounting(host_path)
	path := sprintf("spec.template.spec.volumes[%v].hostPath.path", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("volume: %v in %v: %v has mounting to Docker internals.", [ volume.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths":[],
		"alertScore": 5,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


deny[msga] {
  	wl := input[_]
	wl.kind == "CronJob"
	volume = wl.spec.jobTemplate.spec.template.spec.volumes[i]
    host_path := volume.hostPath
    is_runtime_socket_mounting(host_path)
	path := sprintf("spec.jobTemplate.spec.template.spec.volumes[%v].hostPath.path", [format_int(i, 10)])
    msga := {
		"alertMessage": sprintf("volume: %v in %v: %v has mounting to Docker internals.", [ volume.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths":[],
		"alertScore": 5,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


is_runtime_socket_mounting(host_path) {
	host_path.path == "/var/run/docker.sock"
}

is_runtime_socket_mounting(host_path) {
	host_path.path == "/var/run/docker"
}

is_runtime_socket_mounting(host_path) {
	host_path.path == "/run/containerd/containerd.sock"
}

is_runtime_socket_mounting(host_path) {
	host_path.path == "/var/run/crio/crio.sock"
}
