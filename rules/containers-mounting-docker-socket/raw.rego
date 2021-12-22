package armo_builtins


deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    volume := pod.spec.volumes[i]
	hostPath := volume.hostPath
    isDockerMounting(hostPath)
	path := sprintf("spec.volumes[%v].hostPath.path", [format_int(i, 10)])
    msga := {
		"alertMessage": sprintf("volume: %v in pod: %v has mounting to Docker internals.", [volume.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"alertScore": 0,
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
	hostPath := volume.hostPath
    isDockerMounting(hostPath)
	path := sprintf("spec.template.spec.volumes[%v].hostPath.path", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("volume: %v in %v: %v has mounting to Docker internals.", [ volume.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"alertScore": 0,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


deny[msga] {
  	wl := input[_]
	wl.kind == "CronJob"
	volume = wl.spec.jobTemplate.spec.template.spec.volumes[i]
    hostPath := volume.hostPath
    isDockerMounting(hostPath)
	path := sprintf("spec.jobTemplate.spec.template.spec.volumes[%v].hostPath.path", [format_int(i, 10)])
    msga := {
		"alertMessage": sprintf("volume: %v in %v: %v has mounting to Docker internals.", [ volume.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"alertScore": 0,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


isDockerMounting(hostPath) {
	hostPath.path == "/var/run/docker.sock"
}

isDockerMounting(hostPath) {
	hostPath.path == "/var/run/docker"
}
