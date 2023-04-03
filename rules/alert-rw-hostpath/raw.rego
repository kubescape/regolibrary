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
	result := is_rw_mount(volume_mount, start_of_path,  i, k)
	failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)

    podname := pod.metadata.name

	msga := {
		"alertMessage": sprintf("pod: %v has: %v as hostPath volume", [podname, volume.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixed_path,
		"failedPaths": failed_path,
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
    volume := volumes[_]
    volume.hostPath
	container := wl.spec.template.spec.containers[i]
	volume_mount := container.volumeMounts[k]
	volume_mount.name == volume.name
	start_of_path := "spec.template.spec."
	result := is_rw_mount(volume_mount, start_of_path,  i, k)
	failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)

	msga := {
		"alertMessage": sprintf("%v: %v has: %v as hostPath volume", [wl.kind, wl.metadata.name, volume.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixed_path,
		"failedPaths": failed_path,
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
    volume := volumes[_]
    volume.hostPath

	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
	volume_mount := container.volumeMounts[k]
	volume_mount.name == volume.name
	start_of_path := "spec.jobTemplate.spec.template.spec."
	result := is_rw_mount(volume_mount, start_of_path,  i, k) 
	failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)


	msga := {
	"alertMessage": sprintf("%v: %v has: %v as hostPath volume", [wl.kind, wl.metadata.name, volume.name]),
	"packagename": "armo_builtins",
	"alertScore": 7,
	"fixPaths": fixed_path,
	"failedPaths": failed_path,
	"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

get_failed_path(paths) = [paths[0]] {
	paths[0] != ""
} else = []


get_fixed_path(paths) = [paths[1]] {
	paths[1] != ""
} else = []


is_rw_mount(mount, start_of_path,  i, k) =  [failed_path, fix_path] {
	not mount.readOnly == true
 	not mount.readOnly == false
	failed_path = ""
    fix_path = {"path": sprintf("%vcontainers[%v].volumeMounts[%v].readOnly", [start_of_path, format_int(i, 10), format_int(k, 10)]), "value":"true"}
}

is_rw_mount(mount, start_of_path,  i, k) =  [failed_path, fix_path] {
  	mount.readOnly == false
  	failed_path = sprintf("%vcontainers[%v].volumeMounts[%v].readOnly", [start_of_path, format_int(i, 10), format_int(k, 10)])
    fix_path = ""
} 