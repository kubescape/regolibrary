package armo_builtins


deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    volumes := pod.spec.volumes
    volume := volumes[i]
	start_of_path := "spec."
	result  := is_dangerous_volume(volume, start_of_path, i)
    podname := pod.metadata.name
	volumeMounts := pod.spec.containers[j].volumeMounts
	pathMounts = volume_mounts(volume.name, volumeMounts, sprintf("spec.containers[%v]", [j]))
	finalPath := array.concat([result], pathMounts)


	msga := {
		"alertMessage": sprintf("pod: %v has: %v as hostPath volume", [podname, volume.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": finalPath,
		"failedPaths": finalPath,
		"fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# handles majority of workload resources
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    volumes := wl.spec.template.spec.volumes
    volume := volumes[i]
	start_of_path := "spec.template.spec."
    result  := is_dangerous_volume(volume, start_of_path, i)
	volumeMounts := wl.spec.template.spec.containers[j].volumeMounts
	pathMounts = volume_mounts(volume.name,volumeMounts, sprintf("spec.template.spec.containers[%v]", [j]))
	finalPath := array.concat([result], pathMounts)


	msga := {
		"alertMessage": sprintf("%v: %v has: %v as hostPath volume", [wl.kind, wl.metadata.name, volume.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": finalPath,
		"failedPaths": finalPath,
		"fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# handles CronJobs
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
    volumes := wl.spec.jobTemplate.spec.template.spec.volumes
    volume := volumes[i]
	start_of_path := "spec.jobTemplate.spec.template.spec."
    result  := is_dangerous_volume(volume, start_of_path, i)
	volumeMounts := wl.spec.jobTemplate.spec.template.spec.containers[j].volumeMounts
	pathMounts = volume_mounts(volume.name,volumeMounts, sprintf("spec.jobTemplate.spec.template.spec.containers[%v]", [j]))
	finalPath := array.concat([result], pathMounts)

	msga := {
		"alertMessage": sprintf("%v: %v has: %v as hostPath volume", [wl.kind, wl.metadata.name, volume.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": finalPath,
		"failedPaths": finalPath,
		"fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

is_dangerous_volume(volume, start_of_path, i) = path {
    volume.hostPath.path
    path = sprintf("%vvolumes[%v]", [start_of_path, format_int(i, 10)])
}

volume_mounts(name, volume_mounts, str) = [path] {
	name == volume_mounts[j].name
	path := sprintf("%s.volumeMounts[%v]", [str, j])
} else = []