package armo_builtins

import rego.v1

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	volume := pod.spec.volumes[i]
	host_path := volume.hostPath
	is_runtime_socket_mounting(host_path)
	path := sprintf("spec.volumes[%v]", [format_int(i, 10)])
	volumeMounts := pod.spec.containers[j].volumeMounts
	pathMounts = volume_mounts(volume.name, volumeMounts, sprintf("spec.containers[%v]", [j]))
	finalPath := array.concat([path], pathMounts)
	msga := {
		"alertMessage": sprintf("volume: %v in pod: %v has mounting to Docker internals.", [volume.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"deletePaths": finalPath,
		"failedPaths": finalPath,
		"fixPaths": [],
		"alertScore": 5,
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

deny contains msga if {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]
	volume := wl.spec.template.spec.volumes[i]
	host_path := volume.hostPath
	is_runtime_socket_mounting(host_path)
	path := sprintf("spec.template.spec.volumes[%v]", [format_int(i, 10)])
	volumeMounts := wl.spec.template.spec.containers[j].volumeMounts
	pathMounts = volume_mounts(volume.name, volumeMounts, sprintf("spec.template.spec.containers[%v]", [j]))
	finalPath := array.concat([path], pathMounts)
	msga := {
		"alertMessage": sprintf("volume: %v in %v: %v has mounting to Docker internals.", [volume.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"deletePaths": finalPath,
		"failedPaths": finalPath,
		"fixPaths": [],
		"alertScore": 5,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

deny contains msga if {
	wl := input[_]
	wl.kind == "CronJob"
	volume = wl.spec.jobTemplate.spec.template.spec.volumes[i]
	host_path := volume.hostPath
	is_runtime_socket_mounting(host_path)
	path := sprintf("spec.jobTemplate.spec.template.spec.volumes[%v]", [format_int(i, 10)])
	volumeMounts := wl.spec.jobTemplate.spec.template.spec.containers[j].volumeMounts
	pathMounts = volume_mounts(volume.name, volumeMounts, sprintf("spec.jobTemplate.spec.template.spec.containers[%v]", [j]))
	finalPath := array.concat([path], pathMounts)
	msga := {
		"alertMessage": sprintf("volume: %v in %v: %v has mounting to Docker internals.", [volume.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"deletePaths": finalPath,
		"failedPaths": finalPath,
		"fixPaths": [],
		"alertScore": 5,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

volume_mounts(name, volume_mounts, str) := [path] if {
	name == volume_mounts[j].name
	path := sprintf("%s.volumeMounts[%v]", [str, j])
} else := []

is_runtime_socket_mounting(host_path) if {
	host_path.path == "/var/run/docker.sock"
}

is_runtime_socket_mounting(host_path) if {
	host_path.path == "/var/run/docker"
}

is_runtime_socket_mounting(host_path) if {
	host_path.path == "/run/containerd/containerd.sock"
}

is_runtime_socket_mounting(host_path) if {
	host_path.path == "/var/run/crio/crio.sock"
}
