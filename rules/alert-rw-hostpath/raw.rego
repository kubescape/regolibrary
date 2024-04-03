package armo_builtins

# Fails if container has a hostPath volume which is not readOnly

deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    volumes := pod.spec.volumes
    volume := volumes[_]
    volume.hostPath
	container := pod.spec.containers[i]
	volume_mount := container.volumeMounts[k]
	volume_mount.name == volume.name
	start_of_path := "spec."
	fix_path := is_rw_mount(volume_mount, start_of_path,  i, k)

    podname := pod.metadata.name

	msga := {
		"alertMessage": sprintf("pod: %v has: %v as hostPath volume", [podname, volume.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [fix_path],
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
    volume := volumes[_]
    volume.hostPath
	container := wl.spec.template.spec.containers[i]
	volume_mount := container.volumeMounts[k]
	volume_mount.name == volume.name
	start_of_path := "spec.template.spec."
	fix_path := is_rw_mount(volume_mount, start_of_path,  i, k)

	msga := {
		"alertMessage": sprintf("%v: %v has: %v as hostPath volume", [wl.kind, wl.metadata.name, volume.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": [fix_path],
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
    volume := volumes[_]
    volume.hostPath

	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
	volume_mount := container.volumeMounts[k]
	volume_mount.name == volume.name
	start_of_path := "spec.jobTemplate.spec.template.spec."
	fix_path := is_rw_mount(volume_mount, start_of_path,  i, k) 


	msga := {
	"alertMessage": sprintf("%v: %v has: %v as hostPath volume", [wl.kind, wl.metadata.name, volume.name]),
	"packagename": "armo_builtins",
	"alertScore": 7,
	"fixPaths": [fix_path],
	"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


is_rw_mount(mount, start_of_path,  i, k) = fix_path {
	not mount.readOnly == true
    fix_path = {"path": sprintf("%vcontainers[%v].volumeMounts[%v].readOnly", [start_of_path, i, k]), "value":"true"}
}
