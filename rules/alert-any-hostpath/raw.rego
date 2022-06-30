package armo_builtins


deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    volumes := pod.spec.volumes
    volume := volumes[i]
	beggining_of_path := "spec."
	result  := is_dangerous_host_path(volume, beggining_of_path, i)
    podname := pod.metadata.name


	msga := {
		"alertMessage": sprintf("pod: %v has: %v as hostPath volume", [podname, volume.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

#handles majority of workload resources
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    volumes := wl.spec.template.spec.volumes
    volume := volumes[i]
	beggining_of_path := "spec.template.spec."
    result  := is_dangerous_host_path(volume, beggining_of_path, i)


	msga := {
		"alertMessage": sprintf("%v: %v has: %v as hostPath volume", [wl.kind, wl.metadata.name, volume.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

#handles CronJobs
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
    volumes := wl.spec.jobTemplate.spec.template.spec.volumes
    volume := volumes[i]
	beggining_of_path := "spec.jobTemplate.spec.template.spec."
    result  := is_dangerous_host_path(volume, beggining_of_path, i)
	msga := {
		"alertMessage": sprintf("%v: %v has: %v as hostPath volume", [wl.kind, wl.metadata.name, volume.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}



is_dangerous_host_path(volume, beggining_of_path, i) = path {
    startswith(volume.hostPath.path, "/etc")
	path = sprintf("%vvolumes[%v].hostPath.path", [beggining_of_path, format_int(i, 10)])
}

is_dangerous_host_path(volume, beggining_of_path, i) = path {
    startswith(volume.hostPath.path, "/var")
	path = sprintf("%vvolumes[%v].hostPath.path", [beggining_of_path, format_int(i, 10)])
}