package armo_builtins

# Fails if container has a hostPath volume which is not readOnly

deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    volumes := pod.spec.volumes
    volume := volumes[_]
    volume.hostPath
	container := pod.spec.containers[i]
	volumeMount := container.volumeMounts[k]
	volumeMount.name == volume.name
	begginingOfPath := "spec."
	result := isRWMount(volumeMount, begginingOfPath,  i, k)
	failedPath := getFailedPath(result)
    fixedPath := getFixedPath(result)

    podname := pod.metadata.name

	msga := {
		"alertMessage": sprintf("pod: %v has: %v as hostPath volume", [podname, volume.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixedPath,
		"failedPaths": failedPath,
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
	volumeMount := container.volumeMounts[k]
	volumeMount.name == volume.name
	begginingOfPath := "spec.template.spec."
	result := isRWMount(volumeMount, begginingOfPath,  i, k)
	failedPath := getFailedPath(result)
    fixedPath := getFixedPath(result)

	msga := {
		"alertMessage": sprintf("%v: %v has: %v as hostPath volume", [wl.kind, wl.metadata.name, volume.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"fixPaths": fixedPath,
		"failedPaths": failedPath,
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
	volumeMount := container.volumeMounts[k]
	volumeMount.name == volume.name
	begginingOfPath := "spec.jobTemplate.spec.template.spec."
	result := isRWMount(volumeMount, begginingOfPath,  i, k) 
	failedPath := getFailedPath(result)
    fixedPath := getFixedPath(result)


	msga := {
	"alertMessage": sprintf("%v: %v has: %v as hostPath volume", [wl.kind, wl.metadata.name, volume.name]),
	"packagename": "armo_builtins",
	"alertScore": 7,
	"fixPaths": fixedPath,
	"failedPaths": failedPath,
	"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

getFailedPath(paths) = [paths[0]] {
	paths[0] != ""
} else = []


getFixedPath(paths) = [paths[1]] {
	paths[1] != ""
} else = []


isRWMount(mount, begginingOfPath,  i, k) =  [failedPath, fixPath] {
	not mount.readOnly == true
 	not mount.readOnly == false
	failedPath = ""
    fixPath = {"path": sprintf("%vcontainers[%v].volumeMounts[%v].readOnly", [begginingOfPath, format_int(i, 10), format_int(k, 10)]), "value":"true"}
}

isRWMount(mount, begginingOfPath,  i, k) =  [failedPath, fixPath] {
  	mount.readOnly == false
  	failedPath = sprintf("%vcontainers[%v].volumeMounts[%v].readOnly", [begginingOfPath, format_int(i, 10), format_int(k, 10)])
    fixPath = ""
} 